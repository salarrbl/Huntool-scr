package client

import (
	"context"
	"net"
	"strings"

	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/protocol/nla"
	"github.com/x90skysn3k/grdp/protocol/pdu"
	"github.com/x90skysn3k/grdp/protocol/sec"
	"github.com/x90skysn3k/grdp/protocol/t125"
	"github.com/x90skysn3k/grdp/protocol/tpkt"
	"github.com/x90skysn3k/grdp/protocol/x224"
)

type RdpClient struct {
	tpkt    *tpkt.TPKT
	x224    *x224.X224
	mcs     *t125.MCSClient
	sec     *sec.Client
	pdu     *pdu.Client
	setting *Setting
}

func newRdpClient(s *Setting) *RdpClient {
	return &RdpClient{setting: s}
}

func bitmapDecompress(bitmap *pdu.BitmapData) []byte {
	return core.Decompress(bitmap.BitmapDataStream, int(bitmap.Width), int(bitmap.Height), Bpp(bitmap.BitsPerPixel))
}
func split(user string) (domain string, uname string) {
	if strings.Index(user, "\\") != -1 {
		t := strings.Split(user, "\\")
		domain = t[0]
		uname = t[len(t)-1]
	} else if strings.Index(user, "/") != -1 {
		t := strings.Split(user, "/")
		domain = t[0]
		uname = t[len(t)-1]
	} else {
		uname = user
	}
	return
}
func (c *RdpClient) dialAndSetup(ctx context.Context, host, user, pwd string) (string, string, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		if ctx.Err() != nil {
			return "", "", NewRDPError(ErrKindTimeout, "dial timed out", err)
		}
		return "", "", NewRDPError(ErrKindNetwork, "dial failed", err)
	}

	domain, user := split(user)
	sock := core.NewSocketLayer(conn)
	if c.setting != nil {
		if c.setting.TLSMinVersion != 0 {
			sock.TLSMinVersion = c.setting.TLSMinVersion
		}
		sock.TLSVerify = c.setting.TLSVerify
	}
	c.tpkt = tpkt.New(sock, nla.NewNTLMv2(domain, user, pwd))
	if c.setting != nil && c.setting.VerifyServer {
		c.tpkt.VerifyServer = true
	}
	c.x224 = x224.New(c.tpkt)
	return domain, user, nil
}

// Login connects to the RDP server and initiates authentication. The context
// controls the overall timeout and cancellation for the entire operation
// including TCP dial, TLS handshake, and NLA authentication.
func (c *RdpClient) Login(ctx context.Context, host, user, pwd string, width, height int) error {
	domain, user, err := c.dialAndSetup(ctx, host, user, pwd)
	if err != nil {
		return err
	}

	c.mcs = t125.NewMCSClient(c.x224)
	c.sec = sec.NewClient(c.mcs)
	c.pdu = pdu.NewClient(c.sec)

	c.mcs.SetClientDesktop(uint16(width), uint16(height))

	c.sec.SetUser(user)
	c.sec.SetPwd(pwd)
	c.sec.SetDomain(domain)

	c.tpkt.SetFastPathListener(c.sec)
	c.sec.SetFastPathListener(c.pdu)

	if c.setting != nil && c.setting.RequestedProtocol != 0 {
		c.x224.SetRequestedProtocol(c.setting.RequestedProtocol)
	}

	err = c.x224.Connect(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return NewRDPError(ErrKindTimeout, "connection timed out", err)
		}
		return NewRDPError(ErrKindProtocol, "x224 connect failed", err)
	}
	return nil
}

// LoginAuthOnly connects and performs NLA authentication only, without setting
// up the full RDP session (MCS/SEC/PDU). This is significantly faster for
// credential checking. Requires the server to support NLA (PROTOCOL_HYBRID).
// Returns nil if authentication succeeds, or an error (check with errors.As
// for *core.RDPError to get the Kind).
func (c *RdpClient) LoginAuthOnly(ctx context.Context, host, user, pwd string) error {
	_, _, err := c.dialAndSetup(ctx, host, user, pwd)
	if err != nil {
		return err
	}

	c.x224.SetRequestedProtocol(x224.PROTOCOL_HYBRID)

	resultCh := make(chan error, 1)
	c.x224.On("connect", func(proto uint32) {
		resultCh <- nil
	})
	c.x224.On("error", func(e error) {
		resultCh <- e
	})

	err = c.x224.Connect(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return NewRDPError(ErrKindTimeout, "connection timed out", err)
		}
		return NewRDPError(ErrKindProtocol, "x224 connect failed", err)
	}

	select {
	case err := <-resultCh:
		return err
	case <-ctx.Done():
		return NewRDPError(ErrKindTimeout, "auth timed out", ctx.Err())
	}
}
func (c *RdpClient) On(event string, f interface{}) {
	if c.pdu != nil {
		c.pdu.On(event, f)
	}
}
func (c *RdpClient) KeyUp(sc int, name string) {
	p := &pdu.ScancodeKeyEvent{}
	p.KeyCode = uint16(sc)
	p.KeyboardFlags |= pdu.KBDFLAGS_RELEASE
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_SCANCODE, []pdu.InputEventsInterface{p})
}
func (c *RdpClient) KeyDown(sc int, name string) {
	p := &pdu.ScancodeKeyEvent{}
	p.KeyCode = uint16(sc)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_SCANCODE, []pdu.InputEventsInterface{p})
}

// KeyDownExt sends a key-press event for an extended-set scancode
// (PS/2 Set 1 keys prefixed with 0xE0: Win, arrow keys, right Ctrl/Alt,
// numpad Enter, etc.). It sets KBDFLAGS_EXTENDED on the input PDU.
func (c *RdpClient) KeyDownExt(sc int, name string) {
	p := &pdu.ScancodeKeyEvent{}
	p.KeyCode = uint16(sc)
	p.KeyboardFlags |= pdu.KBDFLAGS_EXTENDED
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_SCANCODE, []pdu.InputEventsInterface{p})
}

// KeyUpExt sends a key-release event for an extended-set scancode.
func (c *RdpClient) KeyUpExt(sc int, name string) {
	p := &pdu.ScancodeKeyEvent{}
	p.KeyCode = uint16(sc)
	p.KeyboardFlags |= pdu.KBDFLAGS_EXTENDED | pdu.KBDFLAGS_RELEASE
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_SCANCODE, []pdu.InputEventsInterface{p})
}

func (c *RdpClient) MouseMove(x, y int) {
	p := &pdu.PointerEvent{}
	p.PointerFlags |= pdu.PTRFLAGS_MOVE
	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}

func (c *RdpClient) MouseWheel(scroll, x, y int) {
	p := &pdu.PointerEvent{}
	p.PointerFlags |= pdu.PTRFLAGS_WHEEL
	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}

func (c *RdpClient) MouseUp(button int, x, y int) {
	p := &pdu.PointerEvent{}

	switch button {
	case 0:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON1
	case 2:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON2
	case 1:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON3
	default:
		p.PointerFlags |= pdu.PTRFLAGS_MOVE
	}

	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}
func (c *RdpClient) MouseDown(button int, x, y int) {
	p := &pdu.PointerEvent{}

	p.PointerFlags |= pdu.PTRFLAGS_DOWN

	switch button {
	case 0:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON1
	case 2:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON2
	case 1:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON3
	default:
		p.PointerFlags |= pdu.PTRFLAGS_MOVE
	}

	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}
func (c *RdpClient) Close() {
	if c != nil && c.tpkt != nil {
		c.tpkt.Close()
	}
}
