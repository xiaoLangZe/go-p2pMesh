// Package bootstrap implements the control-plane connection logic.
//
// The server accepts TCP connections from clients, performs the Noise IK
// handshake, and routes control messages to the appropriate subsystems.
// The client dials the bootstrap server, performs the handshake, and
// sends/receives control messages.
package bootstrap

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/internal/crypto"
	"github.com/xiaoLangZe/go-p2pmesh/internal/protocol"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// AddrResolver derives the mesh addresses a node should use. The server injects
// this so the bootstrap layer does not need to know about room keys or storage.
type AddrResolver func(nodeID types.NodeID) (ipv6, ipv4, subnet string, err error)

// Server is the server-side control-plane handler.
type Server struct {
	addr     string
	listener net.Listener
	logger   *slog.Logger
	addrFn   AddrResolver
	mu       sync.Mutex
	clients  map[string]*clientConn // keyed by remote address
}

// clientConn wraps a single accepted client connection.
type clientConn struct {
	conn  net.Conn
	nodeID types.NodeID
	pubKey []byte
	nonce []byte // challenge nonce issued to this client, awaiting proof
	r     *bufio.Reader
	w     *bufio.Writer
	mu    sync.Mutex
}

// NewServer creates a bootstrap Server bound to addr ("host:port").
func NewServer(addr string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		addr:    addr,
		logger:  logger,
		clients: make(map[string]*clientConn),
	}
}

// SetAddrResolver installs the callback used to compute the mesh addresses
// reported in AUTH_OK. Until one is set, AUTH_OK carries empty addresses.
func (s *Server) SetAddrResolver(fn AddrResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addrFn = fn
}

// Start begins listening for incoming client connections.
func (s *Server) Start(ctx context.Context) error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	s.listener = l
	s.logger.Info("bootstrap server listening", "addr", s.addr)

	go s.acceptLoop(ctx)
	return nil
}

// acceptLoop accepts connections until the context is cancelled.
func (s *Server) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Warn("accept error", "err", err)
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn processes one client connection.
// In the P1 baseline it performs the protocol handshake and message loop.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	cc := &clientConn{
		conn: conn,
		r:    bufio.NewReader(conn),
		w:    bufio.NewWriter(conn),
	}
	remoteAddr := conn.RemoteAddr().String()

	s.mu.Lock()
	s.clients[remoteAddr] = cc
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, remoteAddr)
		s.mu.Unlock()
	}()

	s.logger.Info("client connected", "addr", remoteAddr)

	// Message loop: read and dispatch messages until connection closes.
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Set a read deadline for keepalive timeout.
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		msgType, body, err := protocol.Decode(cc.r)
		if err != nil {
			if err != io.EOF {
				s.logger.Debug("read error", "addr", remoteAddr, "err", err)
			}
			return
		}
		conn.SetReadDeadline(time.Time{}) // reset

		if err := s.handleMessage(ctx, cc, msgType, body); err != nil {
			s.logger.Warn("handle message", "addr", remoteAddr, "type", msgType, "err", err)
			return
		}
	}
}

// handleMessage dispatches a single message from the client.
func (s *Server) handleMessage(ctx context.Context, cc *clientConn, msgType protocol.MessageType, body []byte) error {
	switch msgType {
	case protocol.MsgHello:
		var hello protocol.Hello
		if err := json.Unmarshal(body, &hello); err != nil {
			return fmt.Errorf("decode hello: %w", err)
		}
		nodeID := types.NodeID(hello.NodeID)
		if err := nodeID.Validate(); err != nil {
			return fmt.Errorf("reject hello: %w", err)
		}
		cc.nodeID = nodeID
		cc.pubKey = hello.PubKey
		s.logger.Info("hello received", "node_id", hello.NodeID, "version", hello.Version)
		return s.sendChallenge(cc, hello)

	case protocol.MsgAuth:
		var auth protocol.Auth
		if err := json.Unmarshal(body, &auth); err != nil {
			return fmt.Errorf("decode auth: %w", err)
		}
		if err := s.verifyProofOfPossession(cc, &auth); err != nil {
			s.logger.Warn("rejecting registration", "node_id", cc.nodeID, "err", err)
			return err
		}
		s.logger.Info("registration accepted", "node_id", cc.nodeID)
		return s.sendAuthOK(cc)

	case protocol.MsgKeepalive:
		return nil

	case protocol.MsgNATProbe:
		var probe protocol.NATProbe
		if err := json.Unmarshal(body, &probe); err != nil {
			return fmt.Errorf("decode nat_probe: %w", err)
		}
		s.logger.Info("nat probe", "node_id", probe.NodeID, "nat_type", probe.NATType, "public_addr", probe.PublicAddr)
		return nil

	case protocol.MsgRoomJoin:
		var join protocol.RoomJoin
		if err := json.Unmarshal(body, &join); err != nil {
			return fmt.Errorf("decode room_join: %w", err)
		}
		s.logger.Info("room join", "node_id", cc.nodeID, "room_id", join.RoomID)
		return nil

	case protocol.MsgRoomLeave:
		s.logger.Info("room leave", "node_id", cc.nodeID)
		return nil

	case protocol.MsgPunchReq:
		var req protocol.PunchReq
		if err := json.Unmarshal(body, &req); err != nil {
			return fmt.Errorf("decode punch_req: %w", err)
		}
		s.logger.Info("punch request", "from", cc.nodeID, "target", req.TargetNodeID)
		return nil

	default:
		return fmt.Errorf("unknown message type %d", msgType)
	}
}

// sendChallenge sends a Challenge message carrying a fresh random nonce.
//
// The nonce must be unpredictable: the client's proof-of-possession signature is
// over this value, so a fixed or guessed nonce would let a captured signature be
// replayed by an attacker claiming the same NodeID.
func (s *Server) sendChallenge(cc *clientConn, hello protocol.Hello) error {
	nonce := make([]byte, protocol.ChallengeNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate challenge nonce: %w", err)
	}
	cc.nonce = nonce
	chal := protocol.Challenge{Nonce: nonce}
	if err := s.send(cc, protocol.MsgChallenge, chal); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	return nil
}

// verifyProofOfPossession checks the client's Ed25519 signature over the
// challenge nonce (D5).
//
// Two things must hold:
//  1. A challenge was actually issued on this connection.
//  2. The signature verifies against the public key the client presented.
//
// What this does and does not buy: it proves the registrant holds the private
// key for the NodeID it claims, so a binding is attributable and can be revoked.
// It does not by itself stop a first-mover from registering an unused ID — that
// is why the operator also needs an unbind path (see the store's UnbindNodeID).
func (s *Server) verifyProofOfPossession(cc *clientConn, auth *protocol.Auth) error {
	if len(cc.nonce) == 0 {
		return fmt.Errorf("auth received before challenge")
	}
	if len(cc.pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length %d", len(cc.pubKey))
	}
	if auth.NodeID != "" && auth.NodeID != cc.nodeID.String() {
		return fmt.Errorf("proof node id %q does not match hello %q", auth.NodeID, cc.nodeID)
	}
	payload := protocol.ChallengePayload(cc.nonce, cc.nodeID.String())
	if !ed25519.Verify(ed25519.PublicKey(cc.pubKey), payload, auth.Signature) {
		return fmt.Errorf("invalid proof of possession signature")
	}
	// Consume the nonce so a second AUTH on this connection cannot replay it.
	cc.nonce = nil
	return nil
}

// sendAuthOK acknowledges a verified registration and reports the addresses the
// client should configure.
func (s *Server) sendAuthOK(cc *clientConn) error {
	ok := protocol.AuthOK{}
	if s.addrFn != nil {
		ipv6, ipv4, subnet, err := s.addrFn(cc.nodeID)
		if err != nil {
			return fmt.Errorf("derive addresses: %w", err)
		}
		ok.IPv6Addr = ipv6
		ok.IPv4Addr = ipv4
		ok.RoomSubnet = subnet
	}
	return s.send(cc, protocol.MsgAuthOK, ok)
}

// send writes a message to the client connection.
func (s *Server) send(cc *clientConn, msgType protocol.MessageType, payload any) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if err := protocol.Encode(cc.w, msgType, payload); err != nil {
		return err
	}
	return cc.w.Flush()
}

// Stop gracefully closes the listener and all client connections.
func (s *Server) Stop() error {
	s.mu.Lock()
	for _, cc := range s.clients {
		cc.conn.Close()
	}
	s.clients = make(map[string]*clientConn)
	s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Client is the client-side control-plane connector.
type Client struct {
	serverAddr string
	logger     *slog.Logger
	mu         sync.Mutex
	conn       net.Conn
	r          *bufio.Reader
	w          *bufio.Writer
	connected  bool
}

// NewClient creates a bootstrap Client targeting the given server address.
func NewClient(serverAddr string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		serverAddr: serverAddr,
		logger:     logger,
	}
}

// Connect dials the server and begins the handshake.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connected {
		return fmt.Errorf("already connected")
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.serverAddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.serverAddr, err)
	}
	c.conn = conn
	c.r = bufio.NewReader(conn)
	c.w = bufio.NewWriter(conn)
	c.connected = true
	c.logger.Info("connected to bootstrap server", "addr", c.serverAddr)
	return nil
}

// SendHello sends a HELLO message with the node's identity.
func (c *Client) SendHello(nodeID types.NodeID, pubKey []byte) error {
	return c.send(protocol.MsgHello, protocol.Hello{
		NodeID: nodeID.String(),
		PubKey: pubKey,
		Version: "0.1.0",
	})
}

// SendNATProbe sends the NAT detection results to the server.
func (c *Client) SendNATProbe(natType, publicAddr string, portSamples []int) error {
	return c.send(protocol.MsgNATProbe, protocol.NATProbe{
		NodeID:     "", // server already knows from hello
		NATType:    natType,
		PublicAddr: publicAddr,
		PortSamples: portSamples,
	})
}

// SendRoomJoin requests to join a room.
func (c *Client) SendRoomJoin(roomID, password string) error {
	return c.send(protocol.MsgRoomJoin, protocol.RoomJoin{
		RoomID:   roomID,
		Password: password,
	})
}

// SendKeepalive sends a heartbeat.
func (c *Client) SendKeepalive() error {
	return c.send(protocol.MsgKeepalive, protocol.Keepalive{
		Timestamp: time.Now().Unix(),
	})
}

// SendAuth answers the server's challenge with a proof of possession.
//
// signPriv is the node's Ed25519 private key; the signature binds the challenge
// nonce to this NodeID so the server can attribute the registration.
func (c *Client) SendAuth(nodeID types.NodeID, nonce []byte, signPriv ed25519.PrivateKey) error {
	payload := protocol.ChallengePayload(nonce, nodeID.String())
	sig := ed25519.Sign(signPriv, payload)
	return c.send(protocol.MsgAuth, protocol.Auth{
		NodeID:    nodeID.String(),
		Signature: sig,
	})
}

// RecvMessage reads one message from the server (blocking).
func (c *Client) RecvMessage() (protocol.MessageType, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		return 0, nil, fmt.Errorf("not connected")
	}
	c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	return protocol.Decode(c.r)
}

// send writes a message to the server.
func (c *Client) send(msgType protocol.MessageType, payload any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	if err := protocol.Encode(c.w, msgType, payload); err != nil {
		return err
	}
	return c.w.Flush()
}

// Close closes the connection to the server.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsConnected reports whether the client is connected to the server.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// NoiseHandshakeSession bundles the crypto state for one handshake.
type NoiseHandshakeSession struct {
	Initiator *crypto.NoiseIK
	Responder *crypto.NoiseIK
}

// NewInitiatorSession creates a Noise IK initiator session.
func NewInitiatorSession(localPriv, remotePub [32]byte) *NoiseHandshakeSession {
	return &NoiseHandshakeSession{
		Initiator: crypto.NewNoiseIKInitiator(localPriv, remotePub),
	}
}

// NewResponderSession creates a Noise IK responder session.
func NewResponderSession(localPriv [32]byte) *NoiseHandshakeSession {
	return &NoiseHandshakeSession{
		Responder: crypto.NewNoiseIKResponder(localPriv),
	}
}
