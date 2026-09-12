// client.go
package client

import (
	"context"
	"log"
	"os"

	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/pdu"
)

const (
	CLIP_OFF = 0
	CLIP_IN  = 0x1
	CLIP_OUT = 0x2
)

const (
	TC_RDP = 0
)

type Control interface {
	Login(ctx context.Context, host, user, passwd string, width, height int) error
	KeyUp(sc int, name string)
	KeyDown(sc int, name string)
	MouseMove(x, y int)
	MouseWheel(scroll, x, y int)
	MouseUp(button int, x, y int)
	MouseDown(button int, x, y int)
	On(event string, msg interface{})
	Close()
}

type Client struct {
	host    string
	user    string
	passwd  string
	ctl     Control
	tc      int
	setting *Setting
}

func NewClient(host, user, passwd string, t int, s *Setting) *Client {
	if s == nil {
		s = NewSetting()
	}
	c := &Client{
		host:    host,
		user:    user,
		passwd:  passwd,
		tc:      t,
		setting: s,
	}

	c.ctl = newRdpClient(s)

	glog.SetLogger(log.New(os.Stdout, "", 0))
	s.SetLogLevel()
	return c
}

func (c *Client) Login() error {
	return c.LoginContext(context.Background())
}

// LoginContext connects and authenticates using the provided context for
// timeout and cancellation control.
func (c *Client) LoginContext(ctx context.Context) error {
	return c.ctl.Login(ctx, c.host, c.user, c.passwd, c.setting.Width, c.setting.Height)
}

// LoginAuthOnly performs NLA authentication only without establishing a full
// RDP session. This is faster for credential checking (e.g., brute-force tools).
// Requires the server to support NLA (CredSSP).
func (c *Client) LoginAuthOnly(ctx context.Context) error {
	rdp, ok := c.ctl.(*RdpClient)
	if !ok {
		return NewRDPError(ErrKindProtocol, "auth-only mode requires RDP transport", nil)
	}
	return rdp.LoginAuthOnly(ctx, c.host, c.user, c.passwd)
}

func (c *Client) KeyUp(sc int, name string) {
	c.ctl.KeyUp(sc, name)
}
func (c *Client) KeyDown(sc int, name string) {
	c.ctl.KeyDown(sc, name)
}
func (c *Client) MouseMove(x, y int) {
	c.ctl.MouseMove(x, y)
}
func (c *Client) MouseWheel(scroll, x, y int) {
	c.ctl.MouseWheel(scroll, x, y)
}
func (c *Client) MouseUp(button, x, y int) {
	c.ctl.MouseUp(button, x, y)
}
func (c *Client) MouseDown(button, x, y int) {
	c.ctl.MouseDown(button, x, y)
}
func (c *Client) Close() {
	c.ctl.Close()
}

func (c *Client) OnError(f func(e error)) {
	c.ctl.On("error", f)
}
func (c *Client) OnClose(f func()) {
	c.ctl.On("close", f)
}
func (c *Client) OnSuccess(f func()) {
	c.ctl.On("success", f)
}
func (c *Client) OnReady(f func()) {
	c.ctl.On("ready", f)
}
func (c *Client) OnBitmap(f func([]Bitmap)) {
	f1 := func(data interface{}) {
		bs := make([]Bitmap, 0, 50)
		for _, v := range data.([]pdu.BitmapData) {
			IsCompress := v.IsCompress()
			stream := v.BitmapDataStream
			if IsCompress {
				stream = bitmapDecompress(&v)
				IsCompress = false
			}

			b := Bitmap{int(v.DestLeft), int(v.DestTop), int(v.DestRight), int(v.DestBottom),
				int(v.Width), int(v.Height), Bpp(v.BitsPerPixel), IsCompress, stream}
			bs = append(bs, b)
		}
		f(bs)
	}

	c.ctl.On("bitmap", f1)
}

type Bitmap struct {
	DestLeft     int    `json:"destLeft"`
	DestTop      int    `json:"destTop"`
	DestRight    int    `json:"destRight"`
	DestBottom   int    `json:"destBottom"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	BitsPerPixel int    `json:"bitsPerPixel"`
	IsCompress   bool   `json:"isCompress"`
	Data         []byte `json:"data"`
}

func Bpp(bp uint16) int {
	return int(bp / 8)
}

type Setting struct {
	Width             int
	Height            int
	RequestedProtocol uint32
	LogLevel          glog.LEVEL
	TLSMinVersion     uint16
	TLSVerify         bool
	VerifyServer      bool // Verify server PubKeyAuth in NLA (MITM protection)
	AuthOnly          bool // Stop after NLA auth; skip MCS/SEC/PDU (fast credential check)
}

func NewSetting() *Setting {
	return &Setting{
		Width:    1024,
		Height:   768,
		LogLevel: glog.INFO,
	}
}
func (s *Setting) SetLogLevel() {
	glog.SetLevel(s.LogLevel)
}

func (s *Setting) SetRequestedProtocol(p uint32) {
	s.RequestedProtocol = p
}
