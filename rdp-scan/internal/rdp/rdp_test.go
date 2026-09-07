package rdp

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// negResponse builds the PDU an RDP server sends back: TPKT + X.224 + an
// 8-byte negotiation structure.
func negResponse(li, x224Code, negType, flags byte, value uint32) []byte {
	pkt := []byte{li, x224Code}
	if x224Code == 0xf0 {
		pkt = append(pkt, 0x80) // X.224 DATA: end-of-TPDU marker
	} else {
		pkt = append(pkt, 0x00, 0x00, 0x12, 0x34, 0x00) // DST-REF, SRC-REF, CLASS
	}
	neg := []byte{negType, flags, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(neg[4:], value)
	pkt = append(pkt, neg...)
	total := len(pkt) + 4
	return append([]byte{0x03, 0x00, byte(total>>8), byte(total)}, pkt...)
}

func TestRequestBytes(t *testing.T) {
	// The exact PDU mstsc/FreeRDP send for "TLS or NLA, no cookie": pinned so
	// a future refactor cannot silently change what goes on the wire.
	want := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT v3, length 19
		0x0e,                                     // X.224 LI: 14 bytes follow
		0xe0,                                     // CR
		0x00, 0x00, 0x00, 0x00, 0x00,             // DST-REF, SRC-REF, CLASS
		0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ, flags 0, length 8
		0x03, 0x00, 0x00, 0x00, // requestedProtocols = SSL|HYBRID
	}
	got := Request(RequestedProtocols)
	if !bytes.Equal(got, want) {
		t.Fatalf("Request() =\n % x\nwant\n % x", got, want)
	}
	if len(got) != 19 {
		t.Fatalf("request must be 19 bytes, got %d", len(got))
	}
	if int(binary.BigEndian.Uint16(got[2:4])) != len(got) {
		t.Fatal("TPKT length must count the whole packet")
	}
	if int(got[4])+5 != len(got) {
		t.Fatalf("X.224 length indicator (%d) must cover every byte after itself", got[4])
	}
	if v := binary.LittleEndian.Uint32(got[15:19]); v != RequestedProtocols {
		t.Fatalf("requestedProtocols = %#x, want %#x", v, RequestedProtocols)
	}
	// The request must be a valid CR for our own parser's framing rules too.
	if s, d := Inspect(got); s != StateNotRDP {
		t.Fatalf("a client CR is not a server answer, got %s (%s)", s, d)
	}
}

func TestInspectResponses(t *testing.T) {
	cases := []struct {
		name        string
		in          []byte
		want        State
		wantSubstrs []string
	}{
		{
			name: "windows nla (LI covers the negotiation data)",
			in:   negResponse(0x0e, 0xd0, 0x02, 0x01, ProtoHybrid),
			want: StateRDP, wantSubstrs: []string{"RDP up", "NLA (CredSSP)"},
		},
		{
			name: "windows nla (LI counts only the X.224 header)",
			in:   negResponse(0x06, 0xd0, 0x02, 0x01, ProtoHybrid),
			want: StateRDP, wantSubstrs: []string{"NLA (CredSSP)"},
		},
		{
			name: "tls only",
			in:   negResponse(0x0e, 0xd0, 0x02, 0x01, ProtoSSL),
			want: StateRDP, wantSubstrs: []string{"TLS"},
		},
		{
			name: "standard rdp security selected",
			in:   negResponse(0x0e, 0xd0, 0x02, 0x00, ProtoStandard),
			want: StateRDP, wantSubstrs: []string{"standard RDP security"},
		},
		{
			name: "nla with early user info",
			in:   negResponse(0x0e, 0xd0, 0x02, 0x00, ProtoHybridEx),
			want: StateRDP, wantSubstrs: []string{"early user info"},
		},
		{
			name: "remote credential guard",
			in:   negResponse(0x0e, 0xd0, 0x02, 0x00, ProtoRDSAsg),
			want: StateRDP, wantSubstrs: []string{"Credential Guard"},
		},
		{
			name: "restricted admin mode flag",
			in:   negResponse(0x0e, 0xd0, 0x02, 0x01, ProtoSSL),
			want: StateRDP, wantSubstrs: []string{"restricted admin mode"},
		},
		{
			name: "negotiation failure: hybrid required",
			in:   negResponse(0x0e, 0xd0, 0x03, 0x01, 5),
			want: StateRDP, wantSubstrs: []string{"NLA (HYBRID) required by server"},
		},
		{
			name: "negotiation failure: no certificate",
			in:   negResponse(0x0e, 0xd0, 0x03, 0x01, 3),
			want: StateRDP, wantSubstrs: []string{"no SSL certificate on server"},
		},
		{
			name: "legacy server: plain X.224 CC, no negotiation",
			in:   legacyCC(),
			want: StateRDP, wantSubstrs: []string{"no negotiation", "standard"},
		},
		{
			name: "x.224 data reply (server already past negotiation)",
			in:   x224DataNoNeg(),
			want: StateRDP, wantSubstrs: []string{"no negotiation"},
		},
		{
			name: "x.224 disconnect",
			in:   x224(0x80),
			want: StateRDP, wantSubstrs: []string{"disconnect"},
		},
		{
			name: "x.224 reject",
			in:   x224(0xa0),
			want: StateRDP, wantSubstrs: []string{"reject"},
		},
		{
			name: "a web server on 3389",
			in:   []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
			want: StateNotRDP, wantSubstrs: []string{"not RDP", "HTTP/1.1 400"},
		},
		{
			name: "an ssh daemon on 3389",
			in:   []byte("SSH-2.0-OpenSSH_9.6\r\n"),
			want: StateNotRDP, wantSubstrs: []string{"SSH-2.0-OpenSSH_9.6"},
		},
		{
			name: "tls alert instead of TPKT",
			in:   []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2a},
			want: StateNotRDP, wantSubstrs: []string{"non-TPKT"},
		},
		{
			name: "no answer",
			in:   nil,
			want: StateOpen, wantSubstrs: []string{"no answer"},
		},
		{
			name: "truncated TPKT header",
			in:   []byte{0x03, 0x00, 0x00},
			want: StateNotRDP,
		},
		{
			name: "header says more than we were given",
			in:   []byte{0x03, 0x00, 0x00, 0x40, 0x0e, 0xd0, 0x00},
			want: StateRDP, wantSubstrs: []string{"no negotiation"},
		},
	}
	for _, c := range cases {
		got, detail := Inspect(c.in)
		if got != c.want {
			t.Errorf("%s: state = %s, want %s (detail %q)", c.name, got, c.want, detail)
			continue
		}
		for _, sub := range c.wantSubstrs {
			if !strings.Contains(detail, sub) {
				t.Errorf("%s: detail %q does not mention %q", c.name, detail, sub)
			}
		}
	}
}

func legacyCC() []byte {
	pkt := []byte{0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00}
	return append([]byte{0x03, 0x00, 0x00, byte(4 + len(pkt))}, pkt...)
}

func x224DataNoNeg() []byte {
	pkt := []byte{0x02, 0xf0, 0x80}
	return append([]byte{0x03, 0x00, 0x00, byte(4 + len(pkt))}, pkt...)
}

func x224(code byte) []byte {
	pkt := []byte{0x06, code, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append([]byte{0x03, 0x00, 0x00, byte(4 + len(pkt))}, pkt...)
}

// TestInspectNeverInventsRDP feeds random noise through the parser: claiming
// "RDP up" for something that has no X.224 header at all would be the worst
// possible false positive for a scanner.
func TestInspectNeverInventsRDP(t *testing.T) {
	seed := uint32(0x1234567)
	rnd := func() uint32 { // xorshift, deterministic without importing math/rand
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		return seed
	}
	for i := 0; i < 20000; i++ {
		n := int(rnd()%60) + 1
		b := make([]byte, n)
		for j := range b {
			b[j] = byte(rnd())
		}
		if i%7 == 0 && n > 6 { // sprinkle in plausible-looking TPKT prefixes
			b[0] = 0x03
			b[1] = 0x00
		}
		st, _ := Inspect(b)
		if st == StateRDP {
			if n < 7 || b[0] != 0x03 {
				t.Fatalf("claimed RDP for a non-TPKT reply: % x", b)
			}
			switch b[5] & 0xf0 {
			case 0xd0, 0xf0, 0x80, 0xa0:
			default:
				t.Fatalf("claimed RDP for X.224 code %#x: % x", b[5], b)
			}
		}
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{
		"rdp": ModeRDP, "": ModeRDP, "service": ModeRDP, "verify": ModeRDP,
		"port": ModePort, "tcp": ModePort, "connect": ModePort, "OPEN": ModePort,
	} {
		got, err := ParseMode(in)
		if err != nil {
			t.Errorf("ParseMode(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMode(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParseMode("icmp"); err == nil {
		t.Error("ParseMode(icmp) should fail")
	}
}

// TestProbeAgainstFakeRDP exercises the real socket path: a listener that
// behaves like a Windows RDP host, one that behaves like a web server, one
// that accepts and says nothing, and one that hangs up.
func TestProbeAgainstFakeRDP(t *testing.T) {
	responses := map[string][]byte{
		"rdp":    negResponse(0x0e, 0xd0, 0x02, 0x01, ProtoHybrid),
		"http":   []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		"silent": nil,
		"hangup": {},
	}
	states := map[string][]State{
		"rdp": {StateRDP},
		// A peer that hangs up immediately can beat our write, which reads as
		// "open but the request was not accepted" rather than "closed". Both
		// verdicts are honest, so the test accepts either.
		"hangup": {StateNotRDP, StateOpen},
		"http":   {StateNotRDP},
		"silent": {StateOpen},
	}
	details := map[string]string{
		"rdp": "NLA", "http": "HTTP/1.1 200 OK", "silent": "timeout", "hangup": "",
	}

	for kind, resp := range responses {
		kind, resp := kind, resp
		t.Run(kind, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						if resp == nil { // silent: read the request, answer nothing
							b := make([]byte, 64)
							_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
							_, _ = c.Read(b)
							return
						}
						if len(resp) == 0 { // hangup: close right away
							return
						}
						b := make([]byte, 64)
						_ = c.SetReadDeadline(time.Now().Add(time.Second))
						_, _ = c.Read(b) // the negotiation request
						_, _ = c.Write(resp)
					}(c)
				}
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			st, detail := Probe(c, ModeRDP, 200*time.Millisecond)
			ok := false
			for _, want := range states[kind] {
				if st == want {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("state = %s, want one of %v (detail %q)", st, states[kind], detail)
			}
			if sub := details[kind]; !strings.Contains(detail, sub) {
				t.Errorf("detail %q should mention %q", detail, sub)
			}

			// ModePort must never look at the protocol at all.
			c2, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c2.Close()
			if st, d := Probe(c2, ModePort, time.Second); st != StateOpen || d != "" {
				t.Errorf("ModePort: %s %q, want open/\"\"", st, d)
			}
		})
	}
}
