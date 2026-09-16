package stun

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestBuildBindingRequest checks that the STUN Binding Request is well-formed:
// correct message type, magic cookie, and a non-zero transaction ID.
func TestBuildBindingRequest(t *testing.T) {
	req, txID, err := buildBindingRequest()
	if err != nil {
		t.Fatalf("buildBindingRequest: %v", err)
	}
	if len(req) < 20 {
		t.Fatalf("request too short: %d bytes", len(req))
	}
	if binary.BigEndian.Uint16(req[0:2]) != 0x0001 {
		t.Error("expected Binding Request type 0x0001")
	}
	if binary.BigEndian.Uint32(req[4:8]) != stunMagicCookie {
		t.Errorf("magic cookie mismatch: got 0x%08x", binary.BigEndian.Uint32(req[4:8]))
	}
	// Transaction ID should not be all zeros.
	var zero [12]byte
	if txID == zero {
		t.Error("transaction ID is all zeros")
	}
}

// TestParseBindingResponseValid constructs a minimal valid STUN success
// response with XOR-MAPPED-ADDRESS and verifies the parser extracts it.
func TestParseBindingResponseValid(t *testing.T) {
	expectedIP := net.IPv4(203, 0, 113, 42)
	expectedPort := 12345

	// Build a XOR-MAPPED-ADDRESS attribute.
	xPort := uint16(expectedPort) ^ uint16(stunMagicCookie>>16)
	xIP := binary.BigEndian.Uint32(expectedIP.To4()) ^ stunMagicCookie

	attr := make([]byte, 8) // family + reserved + port + ip
	attr[1] = 0x01          // IPv4
	binary.BigEndian.PutUint16(attr[2:4], xPort)
	binary.BigEndian.PutUint32(attr[4:8], xIP)

	// Build the full message.
	var txID [12]byte
	for i := range txID {
		txID[i] = byte(i + 1)
	}

	bodyLen := uint16(4 + len(attr)) // type + length + value
	msg := make([]byte, 20+bodyLen)
	binary.BigEndian.PutUint16(msg[0:2], 0x0101) // Success Response
	binary.BigEndian.PutUint16(msg[2:4], bodyLen)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID[:])

	// XOR-MAPPED-ADDRESS attribute header
	binary.BigEndian.PutUint16(msg[20:22], attrXORMappedAddress)
	binary.BigEndian.PutUint16(msg[22:24], uint16(len(attr)))
	copy(msg[24:], attr)

	addr, err := parseBindingResponse(msg, txID)
	if err != nil {
		t.Fatalf("parseBindingResponse: %v", err)
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}
	if udp.Port != expectedPort {
		t.Errorf("port: got %d, want %d", udp.Port, expectedPort)
	}
	if !udp.IP.Equal(expectedIP) {
		t.Errorf("ip: got %s, want %s", udp.IP, expectedIP)
	}
}

// TestParseBindingResponseBadTxID ensures a mismatched transaction ID is rejected.
func TestParseBindingResponseBadTxID(t *testing.T) {
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], 0x0101)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)

	var txID [12]byte
	var expectedTxID [12]byte
	txID[0] = 0xFF
	expectedTxID[0] = 0x00
	copy(msg[8:20], txID[:])

	_, err := parseBindingResponse(msg, expectedTxID)
	if err == nil {
		t.Fatal("expected error for mismatched txID, got nil")
	}
}

// TestAnalyzePortSequenceLinear checks that a linearly increasing port
// sequence is classified as linear with correct next-port prediction.
func TestAnalyzePortSequenceLinear(t *testing.T) {
	now := time.Now()
	samples := []PortSample{
		{Port: 50000, Timestamp: now},
		{Port: 50005, Timestamp: now.Add(10 * time.Millisecond)},
		{Port: 50010, Timestamp: now.Add(20 * time.Millisecond)},
		{Port: 50015, Timestamp: now.Add(30 * time.Millisecond)},
	}
	pp := AnalyzePortSequence(samples)
	if pp.Pattern != PatternLinear {
		t.Errorf("pattern: got %s, want %s", pp.Pattern, PatternLinear)
	}
	if pp.NextPort != 50020 {
		t.Errorf("nextPort: got %d, want 50020", pp.NextPort)
	}
}

// TestAnalyzePortSequenceRandom checks that a chaotic port sequence is
// classified as random.
func TestAnalyzePortSequenceRandom(t *testing.T) {
	now := time.Now()
	samples := []PortSample{
		{Port: 50000, Timestamp: now},
		{Port: 30000, Timestamp: now.Add(10 * time.Millisecond)},
		{Port: 60000, Timestamp: now.Add(20 * time.Millisecond)},
		{Port: 10000, Timestamp: now.Add(30 * time.Millisecond)},
	}
	pp := AnalyzePortSequence(samples)
	if pp.Pattern != PatternRandom {
		t.Errorf("pattern: got %s, want %s", pp.Pattern, PatternRandom)
	}
}

// TestAnalyzePortSequenceInsufficient checks that fewer than 2 samples
// produces an insufficient classification.
func TestAnalyzePortSequenceInsufficient(t *testing.T) {
	pp := AnalyzePortSequence([]PortSample{{Port: 50000, Timestamp: time.Now()}})
	if pp.Pattern != PatternInsufficient {
		t.Errorf("pattern: got %s, want %s", pp.Pattern, PatternInsufficient)
	}
}
