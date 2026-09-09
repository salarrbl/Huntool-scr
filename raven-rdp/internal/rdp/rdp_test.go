package rdp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	grdpclient "github.com/x90skysn3k/grdp/client"
	"github.com/x90skysn3k/grdp/core"
)

// fakeRDPServer is a minimal TCP responder for the X.224/RDPneg
// fingerprint exchange used by probes.
type fakeRDPServer struct {
	ln      net.Listener
	resp    []byte
	reads   int64
	mu      sync.Mutex
	closers []func()
}

func startFakeRDP(t *testing.T, resp []byte, delayBeforeResp time.Duration) *fakeRDPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeRDPServer{ln: ln, resp: resp}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				if _, err := c.Read(buf); err != nil {
					return
				}
				s.mu.Lock()
				s.reads++
				s.mu.Unlock()
				if delayBeforeResp > 0 {
					time.Sleep(delayBeforeResp)
				}
				if resp != nil {
					_, _ = c.Write(resp)
				}
				time.Sleep(50 * time.Millisecond) // let the client read
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

// hybridResp builds a 19-byte RDPneg response. selected is written
// little-endian at bytes 15..18 as in a real RDP_NEG_RSP.
func hybridResp(selected byte) []byte {
	return []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, // RDP_NEG_RSP
		0x00, 0x08, 0x00,
		selected, 0x00, 0x00, 0x00,
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in      string
		defPort int
		want    Target
		wantErr bool
	}{
		{in: "10.0.0.5", defPort: 3389, want: Target{Host: "10.0.0.5", Port: 3389}},
		{in: "  host.example.com  ", defPort: 3389, want: Target{Host: "host.example.com", Port: 3389}},
		{in: "10.0.0.5:3390", defPort: 3389, want: Target{Host: "10.0.0.5", Port: 3390}},
		{in: "[2001:db8::1]:3389", defPort: 3389, want: Target{Host: "2001:db8::1", Port: 3389}},
		{in: "2001:db8::1", defPort: 3389, want: Target{Host: "2001:db8::1", Port: 3389}},
		{in: "host:0", defPort: 3389, wantErr: true},
		{in: "host:70000", defPort: 3389, wantErr: true},
		{in: "host:abc", defPort: 3389, wantErr: true},
		{in: ":3389", defPort: 3389, wantErr: true},
		{in: "", defPort: 3389, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in, tc.defPort)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseTarget(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestTargetAddress(t *testing.T) {
	cases := []struct {
		t    Target
		want string
	}{
		{Target{Host: "10.0.0.5", Port: 3389}, "10.0.0.5:3389"},
		{Target{Host: "2001:db8::1", Port: 3389}, "[2001:db8::1]:3389"},
	}
	for _, tc := range cases {
		if got := tc.t.Address(); got != tc.want {
			t.Errorf("Address() = %q, want %q", got, tc.want)
		}
	}
}

// timeoutErr is a minimal net.Error reporting a timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyProbeError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name       string
		err        error
		ctx        context.Context
		wantStatus Status
	}{
		{"cancelled ctx", errors.New("x"), ctx, StatusCancelled},
		{"timeout", &timeoutErr{}, context.Background(), StatusTimeout},
		{"refused", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, context.Background(), StatusClosed},
		{"generic", errors.New("boom"), context.Background(), StatusClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := classifyProbeError(tc.err, tc.ctx)
			if st != tc.wantStatus {
				t.Errorf("classifyProbeError = %s, want %s", st, tc.wantStatus)
			}
		})
	}
}

func TestClassifyAuthError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name       string
		err        error
		ctx        context.Context
		wantStatus Status
	}{
		{"cancelled ctx", errors.New("x"), ctx, StatusCancelled},
		{"rdp auth", &core.RDPError{Kind: core.ErrKindAuth, Message: "nla failed"}, context.Background(), StatusAuthFailure},
		{"rdp timeout", &core.RDPError{Kind: core.ErrKindTimeout, Message: "deadline"}, context.Background(), StatusTimeout},
		{"rdp network", &core.RDPError{Kind: core.ErrKindNetwork, Message: "reset"}, context.Background(), StatusClosed},
		{"rdp tls", &core.RDPError{Kind: core.ErrKindTLS, Message: "handshake"}, context.Background(), StatusError},
		{"rdp protocol", &core.RDPError{Kind: core.ErrKindProtocol, Message: "neg"}, context.Background(), StatusError},
		{"nla required", grdpclient.ErrNLARequired, context.Background(), StatusError},
		{"net timeout", &timeoutErr{}, context.Background(), StatusTimeout},
		{"deadline", context.DeadlineExceeded, context.Background(), StatusTimeout},
		{"generic", errors.New("weird"), context.Background(), StatusError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, msg := classifyAuthError(tc.err, tc.ctx)
			if st != tc.wantStatus {
				t.Errorf("classifyAuthError = %s, want %s", st, tc.wantStatus)
			}
			if strings.Contains(strings.ToLower(msg), "password") {
				t.Errorf("error message must never mention password material: %q", msg)
			}
		})
	}
}

func TestClassifyAuthErrorTruncation(t *testing.T) {
	long := strings.Repeat("x", 500)
	st, msg := classifyAuthError(errors.New(long), context.Background())
	if st != StatusError {
		t.Fatalf("status = %s, want %s", st, StatusError)
	}
	if len(msg) > 210 {
		t.Fatalf("message not truncated: %d chars", len(msg))
	}
}

// fingerprintForTest is the library fingerprint, exposed for tests.
func fingerprintForTest(ctx context.Context, addr string, timeout time.Duration) (NLAStatus, error) {
	st, err := grdpclient.FingerprintNLA(ctx, addr, timeout)
	var n NLAStatus
	switch st {
	case grdpclient.NLARequired:
		n = NLARequired
	case grdpclient.NLAHybridEx:
		n = NLAHybridEx
	case grdpclient.NLANotEnforced:
		n = NLANotEnforced
	default:
		n = NLAUnknown
	}
	return n, err
}

func TestFingerprintNLA(t *testing.T) {
	cases := []struct {
		name     string
		selected byte
		want     NLAStatus
	}{
		{"hybrid-ex", 0x08, NLAHybridEx},
		{"required", 0x02, NLARequired},
		{"not-enforced", 0x01, NLANotEnforced},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeRDP(t, hybridResp(tc.selected), 0)
			st, err := fingerprintForTest(context.Background(), srv.ln.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatalf("FingerprintNLA: %v", err)
			}
			if st != tc.want {
				t.Fatalf("got %v, want %v", st, tc.want)
			}
		})
	}
}

func TestFingerprintNLAFailureResponse(t *testing.T) {
	// RDP_NEG_FAILURE (type 0x03) must classify as unknown without error.
	fail := hybridResp(0x02)
	fail[11] = 0x03
	srv := startFakeRDP(t, fail, 0)
	st, err := fingerprintForTest(context.Background(), srv.ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("FingerprintNLA: %v", err)
	}
	if st != NLAUnknown {
		t.Fatalf("got %v, want NLAUnknown", st)
	}
}

func TestProbeClosedPort(t *testing.T) {
	// Reserve a port, then close it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := NewClient(500 * time.Millisecond)
	res := c.Probe(context.Background(), Target{Host: "127.0.0.1", Port: portOf(addr)})
	if res.Status != StatusClosed {
		t.Fatalf("status = %s, want CLOSED (err=%q)", res.Status, res.Error)
	}
}

func TestProbeTimeout(t *testing.T) {
	// Accept connections but never answer: the fingerprint read times out.
	srv := startFakeRDP(t, nil, 5*time.Second)
	c := NewClient(200 * time.Millisecond)
	res := c.Probe(context.Background(), Target{Host: "127.0.0.1", Port: portOf(srv.ln.Addr().String())})
	if res.Status != StatusTimeout {
		t.Fatalf("status = %s, want TIMEOUT (err=%q)", res.Status, res.Error)
	}
}

func TestProbeOpenIncompleteFingerprint(t *testing.T) {
	// Server closes right after reading: the dial succeeded, so the
	// port must be reported OPEN with an incomplete-fingerprint note.
	srv := startFakeRDP(t, nil, 0)
	c := NewClient(500 * time.Millisecond)
	res := c.Probe(context.Background(), Target{Host: "127.0.0.1", Port: portOf(srv.ln.Addr().String())})
	if res.Status != StatusOpen {
		t.Fatalf("status = %s, want OPEN (err=%q)", res.Status, res.Error)
	}
}

func TestProbeCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewClient(500 * time.Millisecond)
	res := c.Probe(ctx, Target{Host: "127.0.0.1", Port: 1})
	if res.Status != StatusCancelled {
		t.Fatalf("status = %s, want CANCELLED", res.Status)
	}
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}
