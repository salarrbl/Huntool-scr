// Package rdp implements the smallest slice of the RDP protocol that is needed
// to answer a question a TCP connect cannot: "is an RDP service really running
// on this port, and does it work?".
//
// The probe is the standard X.224/RDP Negotiation request (MS-RDPBCGR
// 2.2.1.1.1 + 2.2.1.2.1) — the very first PDU every RDP client sends. It is a
// 19-byte, credential-free handshake opener: we send it, look at the reply,
// and close the socket. Nothing else is transmitted; no authentication, no
// MCS/C19 session setup, no brute force. Services that are *not* RDP (a web
// server or an SSH daemon bound to 3389, a load balancer that accepts and
// stays silent) are classified apart from real RDP hosts, which is what makes
// the result actionable instead of just "port open".
package rdp

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Mode selects how thoroughly a host that accepted a TCP connection is
// verified before it is reported.
type Mode uint8

const (
	// ModePort reports a host as live when the TCP handshake completes.
	// Cheapest option: one connect, no bytes on the wire.
	ModePort Mode = iota

	// ModeRDP additionally performs the X.224 RDP negotiation exchange and
	// only reports hosts whose RDP service actually answers. This is the
	// default, because "3389 accepts connections" and "RDP works here" are
	// different findings.
	ModeRDP
)

// String renders the mode for --help and the summary line.
func (m Mode) String() string {
	if m == ModeRDP {
		return "rdp"
	}
	return "port"
}

// ParseMode maps the --check flag value onto a Mode. Accepted spellings:
// "rdp" (verify the service answers) and "port"/"tcp"/"connect" (TCP only).
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "rdp", "service", "verify":
		return ModeRDP, nil
	case "port", "tcp", "connect", "open":
		return ModePort, nil
	default:
		return 0, errors.New(`unknown --check mode ` + strconv.Quote(s) + ` (use "rdp" or "port")`)
	}
}

// State classifies a host that completed a TCP handshake.
type State uint8

const (
	// StateRDP: an RDP service answered the negotiation (or answered the way
	// pre-negotiation RDP servers do). Safe to treat as "RDP up and working".
	StateRDP State = iota

	// StateOpen: the port accepted a connection but gave us no protocol
	// evidence — either nothing was answered within the timeout, or we did
	// not look because --check port was used.
	StateOpen

	// StateNotRDP: the port answered with something that is not RDP
	// (another service, or a listener that closes immediately).
	StateNotRDP
)

// String renders the state for the report file and console output.
func (s State) String() string {
	switch s {
	case StateRDP:
		return "rdp"
	case StateNotRDP:
		return "not-rdp"
	default:
		return "open"
	}
}

// Protocol bits of the RDP Negotiation (MS-RDPBCGR 2.2.1.1.1.2).
const (
	ProtoStandard uint32 = 0x00000000 // RDP security layer
	ProtoSSL      uint32 = 0x00000001 // TLS
	ProtoHybrid   uint32 = 0x00000002 // NLA / CredSSP over TLS
	ProtoHybridEx uint32 = 0x00000008 // NLA with early user info
	ProtoRDSAsg   uint32 = 0x00000010 // Remote Credential Guard
	ProtoRDSAsgEx uint32 = 0x00000020 // Remote Credential Guard + early user info
)

// RequestedProtocols is what we offer in the negotiation request. SSL|HYBRID
// is what an mstsc/FreeRDP client with NLA enabled sends: servers that require
// NLA answer instead of refusing us, so the probe identifies modern hosts
// without ever attempting authentication.
const RequestedProtocols = ProtoSSL | ProtoHybrid

// maxResponse caps how much of the peer's reply is read. A real RDP
// negotiation response is 19 bytes; the extra room covers servers that piggy-
// back an X.224 routing token or a TLS/alert record in the same segment.
const maxResponse = 256

// Request builds the client PDU: TPKT header + X.224 Connection Request + RDP
// Negotiation Request. It is exported (and separated from Probe) so that tests
// and other tools can pin the exact wire bytes.
func Request(requested uint32) []byte {
	b := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: v3, reserved, length 19
		0x0e, // X.224 length indicator (14 bytes follow)
		0xe0, // CR
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00, // CLASS 0
		0x01, // TYPE_RDP_NEG_REQ
		0x00, // flags
		0x08, 0x00, // length = 8
		0x00, 0x00, 0x00, 0x00, // requestedProtocols (LE)
	}
	binary.LittleEndian.PutUint32(b[15:], requested)
	return b
}

// Inspect classifies a peer reply. It is pure — no socket, no clock — so the
// classification can be unit-tested against recorded captures.
func Inspect(b []byte) (State, string) {
	if len(b) == 0 {
		return StateOpen, "no answer"
	}
	// TPKT (RFC 1006): version 3, reserved 0, 16-bit total length. Anything
	// that does not even start with a TPKT header is not RDP — usually the
	// banner of whatever else is listening on 3389.
	if b[0] != 0x03 || len(b) < 7 {
		if line := firstLine(b); line != "" {
			return StateNotRDP, "not RDP — answered: " + line
		}
		return StateNotRDP, "not RDP — non-TPKT response"
	}

	// Where the RDP Negotiation structure starts depends on the X.224 PDU
	// type, not on the length indicator: servers disagree on whether the
	// indicator covers the user data (MS-RDPBCGR says yes, Windows says 0x06
	// for the CC header). Deriving the offset from the code handles both.
	code := b[5] & 0xf0
	var off int
	switch code {
	case 0xd0: // X.224 CONNECT CONFIRM: LI, code, DST-REF, SRC-REF, CLASS
		off = 11
	case 0xf0: // X.224 DATA: LI, code, EOT
		off = 7
	case 0x80: // X.224 DISCONNECT REQUEST
		return StateRDP, "RDP refused the negotiation (X.224 disconnect)"
	case 0xa0: // X.224 REJECT
		return StateRDP, "RDP rejected the request (X.224 reject)"
	default:
		return StateNotRDP, "not RDP — unexpected X.224 code 0x" +
			strconv.FormatUint(uint64(b[5]), 16)
	}
	if neg, ok := findNeg(b, off); ok {
		if neg[0] == 0x03 { // TYPE_RDP_NEG_FAILURE
			return StateRDP, "RDP up — negotiation refused: " +
				failureName(binary.LittleEndian.Uint32(neg[4:8]))
		}
		sel := binary.LittleEndian.Uint32(neg[4:8]) // TYPE_RDP_NEG_RSP
		detail := "RDP up — " + securityName(sel)
		switch {
		case neg[1]&0x01 != 0:
			detail += " (restricted admin mode)"
		case neg[1]&0x02 != 0:
			detail += " (redirected authentication)"
		}
		return StateRDP, detail
	}
	// No negotiation structure at all: a pre-negotiation server, which still
	// is an RDP service — it just speaks the legacy RDP security layer.
	return StateRDP, "RDP up — " + securityName(ProtoStandard) + " (no negotiation)"
}

// findNeg locates the 8-byte RDP Negotiation structure, first at its canonical
// offset and then anywhere plausible in the header area, because real
// implementations pad the X.224 header differently (gateways, NetScaler,
// xrdp and Windows all vary).
func findNeg(b []byte, off int) ([]byte, bool) {
	if off+8 <= len(b) && plausibleNeg(b[off:]) {
		return b[off : off+8], true
	}
	end := len(b) - 8
	if end > 24 { // never dig into an MCS payload: the header area is enough
		end = 24
	}
	for i := 7; i <= end; i++ {
		if plausibleNeg(b[i:]) {
			return b[i : i+8], true
		}
	}
	return nil, false
}

// plausibleNeg reports whether s begins with a well-formed negotiation
// response/failure: type, flags, length 8 and only defined protocol bits.
func plausibleNeg(s []byte) bool {
	if len(s) < 8 || s[2] != 0x08 || s[3] != 0x00 {
		return false
	}
	if s[0] != 0x02 && s[0] != 0x03 {
		return false
	}
	return binary.LittleEndian.Uint32(s[4:8])&^0x3f == 0
}

// Probe runs the verification on an established connection and classifies it.
// The socket is never closed here: the caller owns it.
func Probe(c net.Conn, mode Mode, timeout time.Duration) (State, string) {
	if mode != ModeRDP {
		return StateOpen, ""
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetDeadline(time.Time{}) }()

	if _, err := c.Write(Request(RequestedProtocols)); err != nil {
		// The port answered the handshake but would not take our request —
		// commonly a listener with a full backlog or a filtered mid-session.
		return StateOpen, "no answer (request not accepted)"
	}

	buf := make([]byte, maxResponse)
	n, err := c.Read(buf)
	if n < 4 {
		if n == 0 && err != nil {
			if isTimeout(err) {
				return StateOpen, "no RDP answer within the timeout"
			}
			return StateNotRDP, "closed without an RDP answer"
		}
		return Inspect(buf[:n])
	}

	// Honour the TPKT length so a response split over segments is still
	// parsed. The deadline above bounds this loop; m == 0 also breaks it.
	// Only chase the declared length when the reply really is TPKT-framed:
	// for a foreign banner (HTTP, SSH, ...) one read is all we need.
	total := n
	if buf[0] == 0x03 {
		total = int(buf[2])<<8 | int(buf[3])
		if total > len(buf) {
			total = len(buf)
		}
	}
	for n < total {
		m, rerr := c.Read(buf[n:])
		n += m
		if m == 0 || rerr != nil {
			break
		}
	}
	return Inspect(buf[:n])
}

// securityName describes the security layer an RDP server selected.
func securityName(sel uint32) string {
	switch sel {
	case ProtoStandard:
		return "standard RDP security"
	case ProtoSSL:
		return "TLS"
	case ProtoHybrid:
		return "NLA (CredSSP)"
	case ProtoHybridEx:
		return "NLA with early user info"
	case ProtoRDSAsg, ProtoRDSAsgEx:
		return "Remote Credential Guard"
	}
	return "security layer 0x" + strconv.FormatUint(uint64(sel), 16)
}

// failureName decodes RDP Negotiation Failure codes (MS-RDPBCGR 2.2.1.2.2).
func failureName(code uint32) string {
	switch code {
	case 1:
		return "SSL required by server"
	case 2:
		return "SSL not allowed by server"
	case 3:
		return "no SSL certificate on server"
	case 4:
		return "inconsistent negotiation flags"
	case 5:
		return "NLA (HYBRID) required by server"
	case 6:
		return "SSL with user authentication required by server"
	case 7:
		return "unsupported compression flag"
	}
	return "code " + strconv.FormatUint(uint64(code), 16)
}

// firstLine renders the first line of a foreign banner, quoted and truncated,
// so the report can say `not RDP — answered: "SSH-2.0-OpenSSH_9.6"`. Binary
// noise is rejected rather than quoted, because the caller's next question is
// "what is this?" and an unanswerable blob only adds confusion.
func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return ""
	}
	printable := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x20 && s[i] < 0x7f {
			printable++
		}
	}
	if printable*10 < len(s)*9 { // mostly non-text: not a banner
		return ""
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 72 {
		s = s[:72] + "…"
	}
	return strconv.Quote(s)
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}
