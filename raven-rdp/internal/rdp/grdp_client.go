package rdp

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	grdpclient "github.com/x90skysn3k/grdp/client"
	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
)

// grdpClient is the production Client implementation backed by the
// pure-Go grdp RDP stack.
type grdpClient struct {
	timeout time.Duration
}

// NewClient returns the production RDP client. Every operation is
// bounded by the supplied timeout and honours context cancellation.
func NewClient(timeout time.Duration) Client {
	return &grdpClient{timeout: timeout}
}

// Probe checks RDP reachability with a lightweight NLA/X.224
// fingerprint rather than a full session, keeping probe noise low.
func (c *grdpClient) Probe(ctx context.Context, target Target) ProbeResult {
	start := time.Now()
	res := ProbeResult{Target: target}

	fingerprint, err := grdpclient.FingerprintNLA(ctx, target.Address(), c.timeout)
	res.Duration = time.Since(start)
	if err != nil {
		status, msg := classifyProbeError(err, ctx)
		// A failed read/write after a successful dial still proves the
		// port is open: report it as open with an incomplete
		// fingerprint. Timeouts keep their TIMEOUT classification.
		var netErr net.Error
		isTimeout := errors.As(err, &netErr) && netErr.Timeout()
		if e := err.Error(); (strings.Contains(e, "read:") || strings.Contains(e, "write:")) && !isTimeout {
			status, msg = StatusOpen, "port open; RDP fingerprint incomplete"
		}
		res.Status, res.Error = status, msg
		return res
	}

	// Any answered fingerprint means the service is listening and
	// speaking RDP.
	res.Status = StatusOpen
	switch fingerprint {
	case grdpclient.NLARequired:
		res.NLA, res.Error = NLARequired, "NLA enforced"
	case grdpclient.NLAHybridEx:
		res.NLA, res.Error = NLAHybridEx, "NLA enforced (hybrid-ex)"
	case grdpclient.NLANotEnforced:
		res.NLA, res.Error = NLANotEnforced, "NLA not enforced"
	default:
		res.NLA, res.Error = NLAUnknown, "port open; no RDP negotiation response"
	}
	return res
}

// Authenticate performs a single NLA (CredSSP) credential check without
// establishing a full RDP session.
func (c *grdpClient) Authenticate(ctx context.Context, target Target, username, password string) AuthResult {
	start := time.Now()
	res := AuthResult{Target: target, Username: username}

	cl := grdpclient.NewClient(target.Address(), username, password, grdpclient.TC_RDP, &grdpclient.Setting{
		Width:    1024,
		Height:   768,
		LogLevel: glog.NONE,
		AuthOnly: true,
	})
	defer cl.Close()

	err := cl.LoginAuthOnly(ctx)
	res.Duration = time.Since(start)

	if err == nil {
		res.Status = StatusAuthSuccess
		return res
	}
	res.Status, res.Error = classifyAuthError(err, ctx)
	return res
}

// classifyProbeError maps dial/fingerprint failures to probe statuses.
func classifyProbeError(err error, ctx context.Context) (Status, string) {
	if ctx.Err() != nil {
		return StatusCancelled, "cancelled"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StatusTimeout, "connection timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return StatusTimeout, "connection timeout"
	}
	if isRefused(err) {
		return StatusClosed, "connection refused"
	}
	return StatusClosed, sanitizeError(err)
}

// classifyAuthError maps authentication failures to statuses, keeping
// credentials out of the message.
func classifyAuthError(err error, ctx context.Context) (Status, string) {
	if ctx.Err() != nil {
		return StatusCancelled, "cancelled"
	}

	var rdpErr *core.RDPError
	if errors.As(err, &rdpErr) {
		switch rdpErr.Kind {
		case core.ErrKindAuth:
			return StatusAuthFailure, "invalid credentials"
		case core.ErrKindTimeout:
			return StatusTimeout, "authentication timeout"
		case core.ErrKindNetwork:
			return StatusClosed, "connection lost"
		case core.ErrKindTLS, core.ErrKindProtocol:
			return StatusError, sanitizeError(err)
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StatusTimeout, "authentication timeout"
	}
	if errors.Is(err, grdpclient.ErrNLARequired) {
		return StatusError, "server does not support NLA credential checking"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return StatusTimeout, "authentication timeout"
	}
	return StatusError, sanitizeError(err)
}

// isRefused reports whether a network error is a connection refusal.
func isRefused(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

// sanitizeError returns a short, credential-safe error summary.
func sanitizeError(err error) string {
	msg := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}
