package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// NLAStatus describes the result of a TCP-only NLA fingerprint probe.
type NLAStatus int

const (
	NLAUnknown NLAStatus = iota
	NLANotEnforced
	NLARequired
	NLAHybridEx
)

// FingerprintNLA opens a TCP connection to the RDP target, sends an
// X.224 Connection Request with RDPneg requesting all protocols, and
// classifies the server response.
func FingerprintNLA(ctx context.Context, target string, timeout time.Duration) (NLAStatus, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return NLAUnknown, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// X.224 Connection Request with RDPneg requesting PROTOCOL_RDP|SSL|HYBRID|HYBRID_EX (0x0F).
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT header, length 19
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x08, 0x00, 0x0f, 0x00, 0x00, 0x00, // RDPneg req, requested 0x0F
	}
	if _, err := conn.Write(req); err != nil {
		return NLAUnknown, fmt.Errorf("write: %w", err)
	}
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	if err != nil {
		return NLAUnknown, fmt.Errorf("read: %w", err)
	}
	if n < 19 {
		return NLAUnknown, fmt.Errorf("short read: got %d bytes, want >= 19", n)
	}
	// Bytes 11..18 carry the RDPneg response. Byte 11 is type:
	//   0x02 = RDP_NEG_RSP (server picked one protocol — selectedProtocols at bytes 15..18)
	//   0x03 = RDP_NEG_FAILURE
	if resp[11] != 0x02 {
		return NLAUnknown, nil
	}
	selected := binary.LittleEndian.Uint32(resp[15:19])
	switch {
	case selected&0x08 != 0:
		return NLAHybridEx, nil
	case selected&0x02 != 0:
		return NLARequired, nil
	case selected&0x01 != 0 || selected == 0:
		return NLANotEnforced, nil
	}
	return NLAUnknown, nil
}
