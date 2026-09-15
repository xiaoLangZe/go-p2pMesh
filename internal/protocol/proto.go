// Package protocol defines the control-plane message types and encoding
// for the go-p2pmesh control plane.
//
// Messages use a simple length-prefixed binary format:
//   [4 bytes: message type (big-endian uint32)]
//   [4 bytes: payload length (big-endian uint32)]
//   [N bytes: JSON-encoded payload]
//
// This avoids the need for protoc/protobuf code generation in P1.
// A later phase can swap to protobuf if binary size or performance demands it.
package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// MessageType enumerates control-plane message types.
type MessageType uint32

const (
	MsgHello       MessageType = 1 // C→S: client announces itself
	MsgChallenge   MessageType = 2 // S→C: server sends challenge + server table
	MsgAuth        MessageType = 3 // C→S: Noise handshake response
	MsgAuthOK      MessageType = 4 // S→C: auth success, IPv6 assigned
	MsgNATProbe    MessageType = 5 // C→S: client reports NAT detection results
	MsgNATResult   MessageType = 6 // S→C: server confirms NAT info to peers
	MsgPunchReq    MessageType = 7 // C→S: request punch info for a target
	MsgPunchInfo   MessageType = 8 // S→C: target's public addr + NAT type + predict range
	MsgKeepalive   MessageType = 9 // C↔S: heartbeat
	MsgPeerList    MessageType = 10 // S→C: periodic online node list
	MsgRoomMembers MessageType = 11 // S→C: room member list push
	MsgRoomJoin    MessageType = 12 // C→S: join a room
	MsgRoomLeave   MessageType = 13 // C→S: leave a room
	MsgPortRuleSync MessageType = 14 // S→C: port rules push to client
)

func (m MessageType) String() string {
	names := []string{
		"", "HELLO", "CHALLENGE", "AUTH", "AUTH_OK",
		"NAT_PROBE", "NAT_RESULT", "PUNCH_REQ", "PUNCH_INFO",
		"KEEPALIVE", "PEER_LIST", "ROOM_MEMBERS",
		"ROOM_JOIN", "ROOM_LEAVE", "PORT_RULE_SYNC",
	}
	if int(m) >= len(names) || m == 0 {
		return "UNKNOWN"
	}
	return names[m]
}

// Hello is sent by the client to announce its identity.
type Hello struct {
	NodeID  string `json:"node_id"`
	PubKey  []byte `json:"pubkey"`
	Cert    []byte `json:"cert,omitempty"`
	Version string `json:"version"`
}

// ChallengeNonceLen is the byte length of the challenge nonce. 32 bytes matches
// the security level of the Ed25519 signature made over it.
const ChallengeNonceLen = 32

// ChallengePayload returns the exact byte string a client must sign to prove
// possession of its NodeID's key. Both sides must build it the same way, so it
// lives here rather than being duplicated in the client and server.
//
// Binding the NodeID into the signed payload (not just the nonce) prevents a
// proof captured for one identity from being replayed for another.
func ChallengePayload(nonce []byte, nodeID string) []byte {
	out := make([]byte, 0, len(nonce)+len(nodeID)+16)
	out = append(out, []byte("gop2pmesh/pop/v1:")...)
	out = append(out, nonce...)
	out = append(out, ':')
	out = append(out, []byte(nodeID)...)
	return out
}

// Challenge is sent by the server with a nonce and server table snapshot.
type Challenge struct {
	Nonce      []byte         `json:"nonce"`
	ServerCert []byte         `json:"server_cert"`
	Servers    []ServerEntry  `json:"servers"`
}

// ServerEntry is one entry in the server table.
type ServerEntry struct {
	Addr   string `json:"addr"`
	PubKey []byte `json:"pubkey"`
	ID     string `json:"id"`
}

// Auth answers the server's challenge.
//
// It carries the Noise handshake message plus a proof of possession: an Ed25519
// signature over the challenge nonce made with the machine-identity key. The
// proof exists because NodeIDs are derived from non-secret machine fingerprints
// (D5) — without it, anyone who guesses an ID could register it and lock the
// legitimate machine out. With it, a binding is always tied to a key the
// registrant actually holds, so an abusive registration is attributable.
type Auth struct {
	HandshakeMsg []byte `json:"hs_msg"`
	NodeID       string `json:"node_id"`
	Signature    []byte `json:"signature"` // Ed25519 over (nonce || node_id)
}

// AuthOK confirms authentication and assigns both IPv6 and IPv4 addresses.
type AuthOK struct {
	IPv6Addr       string        `json:"ipv6_addr"`
	IPv4Addr       string        `json:"ipv4_addr"`
	RoomSubnet     string        `json:"room_subnet,omitempty"` // e.g. "240.10.20.0/24"
	BootstrapPeers []ServerEntry `json:"bootstrap_peers"`
}

// NATProbe reports the client's NAT detection results.
type NATProbe struct {
	NodeID      string `json:"node_id"`
	NATType     string `json:"nat_type"`
	PublicAddr  string `json:"public_addr"`
	PublicV6Addr string `json:"public_v6_addr,omitempty"`
	PortSamples []int  `json:"port_samples,omitempty"` // symmetric port prediction data
}

// NATResult confirms NAT info and may relay peer's NAT info.
type NATResult struct {
	NodeID     string `json:"node_id"`
	NATType    string `json:"nat_type"`
	PublicAddr string `json:"public_addr"`
}

// PunchReq requests punch info for a target node.
type PunchReq struct {
	TargetNodeID string `json:"target_node_id"`
}

// PunchInfo carries the target's public address and prediction data.
type PunchInfo struct {
	TargetNodeID  string `json:"target_node_id"`
	PublicAddr    string `json:"public_addr"`
	NATType       string `json:"nat_type"`
	PredictRange  [2]int `json:"predict_range"` // [start, end]
	FireAt        int64  `json:"fire_at"`       // Unix timestamp for synchronized firing
}

// Keepalive is a simple heartbeat.
type Keepalive struct {
	Timestamp int64 `json:"timestamp"`
}

// PeerList is a periodic push of online nodes.
type PeerList struct {
	Peers []PeerEntry `json:"peers"`
}

// PeerEntry is one online node in the peer list.
type PeerEntry struct {
	NodeID     string `json:"node_id"`
	IPv6Addr   string `json:"ipv6_addr"`
	IPv4Addr   string `json:"ipv4_addr"`
	PublicAddr string `json:"public_addr"`
	NATType    string `json:"nat_type"`
	RoomID     string `json:"room_id"`
}

// RoomMembers pushes the member list of a room.
type RoomMembers struct {
	RoomID  string       `json:"room_id"`
	Members []PeerEntry  `json:"members"`
}

// RoomJoin requests to join a room.
type RoomJoin struct {
	RoomID   string `json:"room_id"`
	Password string `json:"password,omitempty"`
}

// RoomLeave requests to leave the current room.
type RoomLeave struct {
	RoomID string `json:"room_id"`
}

// PortRuleSync pushes port access rules to a client.
type PortRuleSync struct {
	Rules []PortRule `json:"rules"`
}

// PortRule is one port access rule.
type PortRule struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	LocalPort   int    `json:"local_port"`
	VirtualPort int    `json:"virtual_port"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// Encode writes a length-prefixed message to the writer.
func Encode(w io.Writer, msgType MessageType, payload any) error {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], uint32(msgType))
	binary.BigEndian.PutUint32(header[4:8], uint32(len(body)))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return fmt.Errorf("write body: %w", err)
		}
	}
	return nil
}

// Decode reads a length-prefixed message from the reader.
// Returns the message type and the raw JSON payload bytes.
// The caller should json.Unmarshal the payload into the appropriate struct.
func Decode(r io.Reader) (MessageType, []byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, fmt.Errorf("read header: %w", err)
	}
	msgType := MessageType(binary.BigEndian.Uint32(header[0:4]))
	bodyLen := binary.BigEndian.Uint32(header[4:8])
	if bodyLen > 16*1024*1024 { // 16MB max
		return 0, nil, fmt.Errorf("payload too large: %d bytes", bodyLen)
	}
	body := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, fmt.Errorf("read body: %w", err)
		}
	}
	return msgType, body, nil
}

// DecodeTo reads and decodes a message into the provided payload struct.
func DecodeTo(r io.Reader, payload any) (MessageType, error) {
	msgType, body, err := Decode(r)
	if err != nil {
		return 0, err
	}
	if len(body) == 0 || payload == nil {
		return msgType, nil
	}
	if err := json.Unmarshal(body, payload); err != nil {
		return 0, fmt.Errorf("unmarshal payload: %w", err)
	}
	return msgType, nil
}

// EncodeToBuffer encodes a message into a byte buffer and returns it.
func EncodeToBuffer(msgType MessageType, payload any) ([]byte, error) {
	var buf bytes.Buffer
	if err := Encode(&buf, msgType, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
