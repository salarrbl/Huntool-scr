package client

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"sync"
	"time"

	"github.com/x90skysn3k/grdp/protocol/pdu"
	"github.com/x90skysn3k/grdp/protocol/sec"
	"github.com/x90skysn3k/grdp/protocol/t125"
	"github.com/x90skysn3k/grdp/protocol/x224"
)

const (
	logonScreenWidth  = 1024
	logonScreenHeight = 768
)

// LogonTrigger identifies which pre-auth keystroke sequence to send.
type LogonTrigger int

const (
	// TriggerShift5x sends Left-Shift 5 times — triggers sticky-keys (sethc.exe backdoor).
	TriggerShift5x LogonTrigger = iota
	// TriggerWinU sends Win+U — triggers utilman.exe backdoor.
	TriggerWinU
)

// CaptureLogonScreen connects to an RDP target using standard RDP (no NLA)
// so it reaches the GINA/logon screen, collects a framebuffer snapshot,
// sends the requested trigger keystrokes, waits for any repaint, then
// collects a second snapshot. Both snapshots are returned as PNG-encoded
// byte slices so callers can analyse them without depending on grdp internals.
//
// Only uncompressed bitmap rectangles (or rectangles grdp's RLE decoder can
// handle) are blitted into the framebuffer. Rectangles whose decompressed
// data length does not match the expected pixel count are silently skipped
// — this means severely corrupted or unsupported codec tiles may produce a
// partially blank framebuffer, but the top-left region (where a cmd.exe
// console appears) is typically sent as fast-path uncompressed tiles.
//
// Caller is responsible for calling c.Close() after use.
func (c *RdpClient) CaptureLogonScreen(
	ctx context.Context,
	host string,
	trigger LogonTrigger,
	timeout time.Duration,
) (before, after []byte, err error) {

	captureCtx, captureCancel := context.WithTimeout(ctx, timeout)
	defer captureCancel()

	// --- 1. TCP + TPKT + x224 setup (no credentials needed for standard RDP) ---
	if _, _, err = c.dialAndSetup(captureCtx, host, "", ""); err != nil {
		return nil, nil, err
	}

	// Standard RDP — no NLA, no CredSSP; server will show the GINA/logon screen.
	c.x224.SetRequestedProtocol(x224.PROTOCOL_RDP)

	// --- 2. Build the full protocol stack (needed to receive bitmap events) ---
	c.mcs = t125.NewMCSClient(c.x224)
	c.sec = sec.NewClient(c.mcs)
	c.pdu = pdu.NewClient(c.sec)

	c.mcs.SetClientDesktop(uint16(logonScreenWidth), uint16(logonScreenHeight))
	// Empty credentials — we are not authenticating, just reaching the logon screen.
	c.sec.SetUser("")
	c.sec.SetPwd("")
	c.sec.SetDomain("")

	c.tpkt.SetFastPathListener(c.sec)
	c.sec.SetFastPathListener(c.pdu)

	// --- 3. Allocate the framebuffer ---
	fb := &framebuffer{
		img: image.NewRGBA(image.Rect(0, 0, logonScreenWidth, logonScreenHeight)),
	}

	// Subscribe to bitmap events before connecting so we never miss early updates.
	c.pdu.On("bitmap", func(rectangles []pdu.BitmapData) {
		fb.blit(rectangles)
	})

	// --- 4. Connect (initiates the full RDP connection sequence) ---
	readyCh := make(chan struct{}, 1)
	c.pdu.On("ready", func() {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	})

	if err = c.x224.Connect(captureCtx); err != nil {
		return nil, nil, NewRDPError(ErrKindProtocol, "x224 connect failed", err)
	}

	// Wait for the PDU "ready" event (FontMap received — session is live).
	select {
	case <-readyCh:
	case <-captureCtx.Done():
		return nil, nil, NewRDPError(ErrKindTimeout, "timed out waiting for RDP ready", captureCtx.Err())
	}

	// --- 5. Allow the initial framebuffer paint to flush ---
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-captureCtx.Done():
		return nil, nil, NewRDPError(ErrKindTimeout, "timed out during initial paint", captureCtx.Err())
	}

	// --- 6. Snapshot before ---
	before = fb.snapshot()

	// --- 7. Send trigger ---
	sendTrigger(c, trigger)

	// --- 8. Wait for repaint ---
	select {
	case <-time.After(1000 * time.Millisecond):
	case <-captureCtx.Done():
		return nil, nil, NewRDPError(ErrKindTimeout, "timed out after trigger", captureCtx.Err())
	}

	// --- 9. Snapshot after ---
	after = fb.snapshot()

	return before, after, nil
}

// sendTrigger delivers the appropriate keypress sequence for the chosen trigger.
func sendTrigger(c *RdpClient, trigger LogonTrigger) {
	const (
		scLShift = 0x2A // Left Shift
		scLWin   = 0x5B // Left Windows key (extended)
		scU      = 0x16 // 'U'
	)
	switch trigger {
	case TriggerShift5x:
		for i := 0; i < 5; i++ {
			c.KeyDown(scLShift, "shift")
			c.KeyUp(scLShift, "shift")
		}
	case TriggerWinU:
		// Left Windows key is an extended-set scancode (PS/2 Set 1 with the
		// 0xE0 prefix), so it must be sent via KeyDownExt/KeyUpExt which set
		// KBDFLAGS_EXTENDED. Sending bare 0x5B as a non-extended key causes
		// the RDP server to interpret it as numpad '0' or similar — not Win.
		c.KeyDownExt(scLWin, "lwin")
		c.KeyDown(scU, "u")
		c.KeyUp(scU, "u")
		c.KeyUpExt(scLWin, "lwin")
	}
}

// framebuffer holds a thread-safe RGBA image that bitmap rectangles are
// blitted into as they arrive from the RDP server.
type framebuffer struct {
	mu  sync.Mutex
	img *image.RGBA
}

// blit paints a slice of BitmapData rectangles into the framebuffer.
// Compressed rectangles are decompressed via grdp's RLE decoder (core.Decompress).
// Rectangles whose decompressed length doesn't match the expected pixel count
// are silently skipped to avoid corrupting the image.
func (fb *framebuffer) blit(rects []pdu.BitmapData) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	bounds := fb.img.Bounds()

	for i := range rects {
		r := &rects[i]

		dstLeft := int(r.DestLeft)
		dstTop := int(r.DestTop)
		w := int(r.Width)
		h := int(r.Height)
		bpp := Bpp(r.BitsPerPixel) // bytes per pixel

		if w == 0 || h == 0 || bpp == 0 {
			continue
		}

		// Resolve the raw pixel data (decompress if needed).
		var pixdata []byte
		if r.IsCompress() {
			pixdata = bitmapDecompress(r)
		} else {
			pixdata = r.BitmapDataStream
		}

		expected := w * h * bpp
		if len(pixdata) < expected {
			// Insufficient data — skip this rectangle rather than panic or corrupt.
			continue
		}

		// Blit pixels. RDP bitmap rows are stored bottom-up.
		for row := 0; row < h; row++ {
			srcRow := (h - 1 - row) // RDP is bottom-up
			for col := 0; col < w; col++ {
				px := (srcRow*w + col) * bpp
				if px+bpp > len(pixdata) {
					break
				}
				rgba := pixelToRGBA(pixdata[px:px+bpp], bpp)

				dx := dstLeft + col
				dy := dstTop + row
				if dx >= bounds.Min.X && dx < bounds.Max.X &&
					dy >= bounds.Min.Y && dy < bounds.Max.Y {
					fb.img.Set(dx, dy, rgba)
				}
			}
		}
	}
}

// pixelToRGBA converts a raw pixel in the server's format to color.RGBA.
// grdp negotiates 16-bit (RGB565) or 32-bit (BGRA/BGRX) colour depth;
// 24-bit BGR is also possible. The number of bytes per pixel (bpp) drives
// the switch.
func pixelToRGBA(p []byte, bpp int) color.RGBA {
	switch bpp {
	case 4: // 32-bit BGRA or BGRX (most common in modern RDP)
		return color.RGBA{R: p[2], G: p[1], B: p[0], A: 255}
	case 3: // 24-bit BGR
		return color.RGBA{R: p[2], G: p[1], B: p[0], A: 255}
	case 2: // 16-bit RGB565
		v := uint16(p[0]) | uint16(p[1])<<8
		r := uint8((v >> 11) & 0x1F)
		g := uint8((v >> 5) & 0x3F)
		b := uint8(v & 0x1F)
		// Scale to 8-bit range
		return color.RGBA{
			R: (r << 3) | (r >> 2),
			G: (g << 2) | (g >> 4),
			B: (b << 3) | (b >> 2),
			A: 255,
		}
	case 1: // 8-bit palette index — treat as greyscale for the heuristic
		return color.RGBA{R: p[0], G: p[0], B: p[0], A: 255}
	default:
		return color.RGBA{A: 255}
	}
}

// snapshot PNG-encodes a copy of the current framebuffer and returns the bytes.
func (fb *framebuffer) snapshot() []byte {
	fb.mu.Lock()
	// Copy the image so the caller is unaffected by future blits.
	bounds := fb.img.Bounds()
	cp := image.NewRGBA(bounds)
	copy(cp.Pix, fb.img.Pix)
	fb.mu.Unlock()

	var buf bytes.Buffer
	if err := png.Encode(&buf, cp); err != nil {
		return nil
	}
	return buf.Bytes()
}
