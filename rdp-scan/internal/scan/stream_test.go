package scan

import (
	"context"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/cidr"
	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/rdp"
)

// These tests exercise the streaming pipeline and the RDP verification
// end-to-end on loopback: no privileges, no network, no external tools.

// rdpResponse is the PDU a Windows host with NLA sends back to a negotiation
// request: X.224 CONNECT CONFIRM + RDP_NEG_RSP, selectedProtocol = HYBRID.
var rdpResponse = []byte{
	0x03, 0x00, 0x00, 0x13,
	0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	0x02, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
}

// serveFake starts a TCP host on addr. An empty reply means "accept and say
// nothing"; otherwise the bytes are written once the request has been read.
func serveFake(t *testing.T, addr string, reply []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				if len(reply) > 0 {
					_, _ = c.Write(reply)
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
}

// freePort picks a port, releases it and hands the number back, so two
// loopback addresses can serve the same port at the same time.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func TestScanSpansRDPVerification(t *testing.T) {
	p := freePort(t)
	serveFake(t, "127.0.0.1:"+itoa(p), rdpResponse)                                     // real RDP
	serveFake(t, "127.0.0.2:"+itoa(p), []byte("HTTP/1.1 418 I'm a teapot\r\n\r\n"))      // wrong service
	                                                                                       // 127.0.0.3: nothing listening

	spans := []cidr.Span{
		{Start: ipu(t, "127.0.0.1"), End: ipu(t, "127.0.0.1")},
		{Start: ipu(t, "127.0.0.2"), End: ipu(t, "127.0.0.2")},
		{Start: ipu(t, "127.0.0.3"), End: ipu(t, "127.0.0.3")},
	}

	var mu sync.Mutex
	var got []Result
	stats, err := ScanSpans(context.Background(), spans, cidr.Shard{}, 3, Options{
		Concurrency: 4,
		Timeout:     2 * time.Second,
		Port:        p,
		Chunk:       MinChunk,
		Check:       rdp.ModeRDP,
		RDPTimeout:  500 * time.Millisecond,
		OnResult:    func(r Result) { mu.Lock(); got = append(got, r); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 3 || stats.Live != 2 || stats.RDP != 1 || stats.NotRDP != 1 || stats.Refused != 1 {
		t.Fatalf("stats = %+v, want total=3 live=2 rdp=1 not-rdp=1 refused=1", stats)
	}
	if stats.Open != 0 {
		t.Fatalf("silent hosts = %d, want 0 (both hosts answered)", stats.Open)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("results = %v, want 2", got)
	}
	if got[0].IP != ipu(t, "127.0.0.1") || got[0].State != rdp.StateRDP {
		t.Errorf("first result = %+v, want 127.0.0.1 marked rdp", got[0])
	}
	if !strings.Contains(got[0].Detail, "NLA (CredSSP)") {
		t.Errorf("detail %q should name the security layer", got[0].Detail)
	}
	if got[1].IP != ipu(t, "127.0.0.2") || got[1].State != rdp.StateNotRDP {
		t.Errorf("second result = %+v, want 127.0.0.2 marked not-rdp", got[1])
	}
	if !strings.Contains(got[1].Detail, "418") {
		t.Errorf("detail %q should quote the foreign banner", got[1].Detail)
	}
	if got[1].IP <= got[0].IP {
		t.Errorf("results must arrive in ascending order: %v", got)
	}
	if got[0].Port != p || got[1].Port != p {
		t.Errorf("results must carry the probed port: %v", got)
	}
}

func TestScanSpansStreamingEqualsSliceScan(t *testing.T) {
	// 16 loopback addresses, one of them listening: the streamed (span) path
	// and the materialised path must agree exactly.
	p := freePort(t)
	serveFake(t, "127.0.0.1:"+itoa(p), rdpResponse)

	// 64 addresses in chunks of 16 (MinChunk): four chunks per code path.
	base := ipu(t, "127.0.0.0")
	spans := []cidr.Span{{Start: base, End: base + 63}}
	ips, err := cidr.Expand(spans, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	s1, err := ScanSpans(context.Background(), spans, cidr.Shard{}, uint64(len(ips)), Options{
		Concurrency: 8, Timeout: time.Second, Port: p, Chunk: MinChunk, Check: rdp.ModePort,
	})
	if err != nil {
		t.Fatal(err)
	}
	live2, s2, err := Scan(context.Background(), ips, Options{
		Concurrency: 8, Timeout: time.Second, Port: p, Chunk: MinChunk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s1.Total != 64 || s2.Total != 64 {
		t.Fatalf("totals %d/%d, want 64", s1.Total, s2.Total)
	}
	if s1.Done != s2.Done || s1.Live != s2.Live || s1.Refused != s2.Refused {
		t.Fatalf("stats differ: %+v vs %+v", s1, s2)
	}
	if s1.Live != 1 || len(live2) != 1 || live2[0] != base+1 {
		t.Fatalf("live hosts differ: %d vs %v", s1.Live, live2)
	}
	if s1.Chunks != 4 || s2.Chunks != 4 {
		t.Fatalf("chunks = %d/%d, want 4", s1.Chunks, s2.Chunks)
	}
	if s1.Sockets != 8 {
		t.Fatalf("sockets = %d, want 8", s1.Sockets)
	}
	if s1.Open != 1 {
		t.Fatalf("with --check port every live host is 'open', got %d", s1.Open)
	}
}

func TestScanSpansNeverExpandsTheTargetList(t *testing.T) {
	// A /8 is 16.7M addresses. Materialising that list is exactly what used to
	// cost hundreds of megabytes of RAM; streamed, the first chunk must be
	// reached in milliseconds and an early cancel must stop the scan inside it.
	span := cidr.Span{Start: ipu(t, "10.0.0.0"), End: ipu(t, "10.255.255.255")}
	ctx, cancel := context.WithCancel(context.Background())

	var mu sync.Mutex
	var results []Result
	flushes := 0
	const chunk = 64
	opts := Options{
		Concurrency: 8,
		Timeout:     10 * time.Millisecond,
		Port:        9,
		Chunk:       chunk,
		Check:       rdp.ModePort,
		OnResult:    func(r Result) { mu.Lock(); results = append(results, r); mu.Unlock() },
		OnFlush:     func() { mu.Lock(); flushes++; mu.Unlock(); cancel() },
	}
	start := time.Now()
	stats, err := ScanSpans(ctx, []cidr.Span{span}, cidr.Shard{}, cidr.CountIPs([]cidr.Span{span}), opts)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Done != chunk {
		t.Fatalf("done = %d, want exactly one chunk (%d)", stats.Done, chunk)
	}
	if want := uint64(1<<24) - chunk; stats.Skipped != want {
		t.Fatalf("skipped = %d, want %d", stats.Skipped, want)
	}
	if flushes == 0 {
		t.Fatal("the chunk boundary callback never ran")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("reaching the first chunk of a /8 took %s — the pipeline is not streaming", elapsed)
	}
	mu.Lock()
	n := len(results)
	mu.Unlock()
	if n > chunk {
		t.Fatalf("buffered %d results, want at most one chunk", n)
	}
}

func TestSpanSourceShardsTileTheTargetSet(t *testing.T) {
	base := ipu(t, "127.0.0.0")
	spans := []cidr.Span{{Start: base, End: base + 9}}
	merged := cidr.MergeSpans(spans)

	var union []uint32
	for k := uint64(0); k < 2; k++ {
		sh := cidr.Shard{Index: k, Count: 2}
		src := &spanSource{spans: merged, sh: sh, ip: uint64(merged[0].Start)}
		var got []uint32
		buf := make([]uint32, 3) // deliberately not a divisor of anything
		for {
			n := src.Next(buf)
			if n == 0 {
				break
			}
			got = append(got, buf[:n]...)
		}
		if want := cidr.ShardCount(cidr.CountIPs(spans), sh); uint64(len(got)) != want {
			t.Fatalf("shard %d/2 yielded %d addresses, ShardCount says %d", k, len(got), want)
		}
		for _, ip := range got {
			if (ip-base)%2 != uint32(k) {
				t.Fatalf("shard %d/2 produced %s, which belongs to the other shard", k, cidr.FormatIPv4(ip))
			}
		}
		union = append(union, got...)
	}
	want, _ := cidr.Expand(spans, 1<<20)
	sortU32(union)
	if !reflect.DeepEqual(union, want) {
		t.Fatalf("shards must tile the target set:\n got %v\nwant %v", union, want)
	}
}

func TestScanMaxLiveStopsEarly(t *testing.T) {
	p := freePort(t)
	serveFake(t, "127.0.0.1:"+itoa(p), rdpResponse)
	serveFake(t, "127.0.0.2:"+itoa(p), rdpResponse)

	base := ipu(t, "127.0.0.0")
	spans := []cidr.Span{{Start: base, End: base + 255}}
	stats, err := ScanSpans(context.Background(), spans, cidr.Shard{}, 256, Options{
		Concurrency: 16,
		Timeout:     time.Second,
		Port:        p,
		Chunk:       16,
		Check:       rdp.ModeRDP,
		RDPTimeout:  500 * time.Millisecond,
		MaxLive:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Live != 2 {
		t.Fatalf("live = %d, want exactly 2", stats.Live)
	}
	if stats.MaxLive != 2 {
		t.Fatalf("stats.MaxLive = %d, want 2 so the CLI can explain the early stop", stats.MaxLive)
	}
	if stats.Done >= 256 {
		t.Fatalf("scan kept going after --max-live: done=%d", stats.Done)
	}
	if stats.Skipped == 0 {
		t.Fatal("skipped addresses were not accounted for")
	}
}

func TestScanChunkPauseIsRespected(t *testing.T) {
	base := ipu(t, "127.0.0.0")
	spans := []cidr.Span{{Start: base, End: base + 63}}
	start := time.Now()
	stats, err := ScanSpans(context.Background(), spans, cidr.Shard{}, 64, Options{
		Concurrency: 8, Timeout: time.Second, Port: 9,
		Chunk: MinChunk, ChunkDelay: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Chunks != 4 {
		t.Fatalf("chunks = %d, want 4", stats.Chunks)
	}
	// Four chunks, each followed by a pause of at least the requested delay.
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Fatalf("only %s elapsed: --chunk-delay was ignored", el)
	}
}

func TestLimiterPaces(t *testing.T) {
	l := newLimiter(500) // 500/s with a 125-token burst
	start := time.Now()
	for i := 0; i < 250; i++ {
		if err := l.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	el := time.Since(start)
	if el < 200*time.Millisecond {
		t.Fatalf("250 tokens at 500/s took %s: the bucket is leaking", el)
	}
	if el > 900*time.Millisecond {
		t.Fatalf("250 tokens at 500/s took %s: the bucket is too strict", el)
	}
}

func TestLimiterHonoursCancellation(t *testing.T) {
	l := newLimiter(1) // 1/s: after the burst, waiting is unavoidable
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.wait(ctx); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if err := l.wait(ctx); err == nil {
		t.Fatal("wait should return the cancellation error")
	}
}

func TestSocketBudgetKeepsTheProcessUsable(t *testing.T) {
	b := socketBudget()
	if b == 0 {
		t.Skip("no descriptor limit readable on this platform")
	}
	if b < 16 || b > 1<<16 {
		t.Fatalf("socketBudget = %d, out of the plausible range", b)
	}
	if soft := fdSoftLimit(); soft > 0 && soft <= 1<<16 && b >= soft {
		t.Fatalf("socketBudget %d should stay below the soft limit %d", b, soft)
	}
	// A scan asking for far more sockets than the machine allows must be
	// clamped, not turned into thousands of EMFILE errors.
	base := ipu(t, "127.0.0.0")
	stats, err := ScanSpans(context.Background(), []cidr.Span{{Start: base, End: base + 31}},
		cidr.Shard{}, 32, Options{
			Concurrency: 1 << 20, Timeout: time.Second, Port: 9, Chunk: MinChunk,
		})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Sockets > b {
		t.Fatalf("sockets = %d, budget = %d", stats.Sockets, b)
	}
	if stats.TooMany != 0 {
		t.Fatalf("%d attempts hit the descriptor limit despite the clamp", stats.TooMany)
	}
}

func TestScanRejectsBrokenSources(t *testing.T) {
	base := ipu(t, "127.0.0.1")
	if _, err := ScanSpans(context.Background(), nil, cidr.Shard{}, 0, Options{
		Concurrency: 1, Timeout: time.Second, Port: 9,
	}); err == nil {
		t.Fatal("no spans should be an error")
	}
	if _, err := ScanSpans(context.Background(), []cidr.Span{{Start: base, End: base}}, cidr.Shard{}, 0, Options{
		Concurrency: 1, Timeout: time.Second, Port: 9,
	}); err == nil {
		t.Fatal("a zero total should be an error")
	}
	// Chunk is clamped, not fatal: a silly value must not break the scan.
	if _, err := ScanSpans(context.Background(), []cidr.Span{{Start: base, End: base}}, cidr.Shard{}, 1, Options{
		Concurrency: 1, Timeout: time.Second, Port: 9, Chunk: -5,
	}); err != nil {
		t.Fatalf("negative chunk should be clamped, got %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func sortU32(v []uint32) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
