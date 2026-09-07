package scan

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/cidr"
)

func ipu(t *testing.T, s string) uint32 {
	t.Helper()
	u, err := cidr.ParseIPv4(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestScanLiveAndRefused runs a real listener on loopback and verifies that
// only the IP with a listening socket is reported live; the other loopback
// address must be classified as refused.
func TestScanLiveAndRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// Accept and immediately close so the dial handshake completes.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ips := []uint32{
		ipu(t, "127.0.0.1"), // live
		ipu(t, "127.0.0.2"), // refused (loopback has no listener here)
	}
	live, stats, err := Scan(context.Background(), ips, Options{
		Concurrency: 8,
		Timeout:     2 * time.Second,
		Port:        port,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0] != ips[0] {
		t.Fatalf("live = %v, want just 127.0.0.1", live)
	}
	if stats.Live != 1 || stats.Refused != 1 || stats.Total != 2 {
		t.Fatalf("stats = %+v, want live=1 refused=1 total=2", stats)
	}
}

// TestScanProgress verifies the progress callback counts every attempt
// exactly once and ends at the total.
func TestScanProgress(t *testing.T) {
	var maxDone atomic.Uint64
	var calls atomic.Uint64
	ips := []uint32{ipu(t, "127.0.0.2"), ipu(t, "127.0.0.3"), ipu(t, "127.0.0.4")}
	_, _, err := Scan(context.Background(), ips, Options{
		Concurrency: 3,
		Timeout:     2 * time.Second,
		Port:        1, // nothing listens here; refused quickly
		OnProgress: func(done, total uint64) {
			calls.Add(1)
			for {
				cur := maxDone.Load()
				if done <= cur || maxDone.CompareAndSwap(cur, done) {
					break
				}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("progress calls = %d, want 3", calls.Load())
	}
	if maxDone.Load() != 3 {
		t.Fatalf("final done = %d, want 3", maxDone.Load())
	}
}

// TestScanCancel verifies that canceling the context aborts the scan
// promptly without hanging and without reporting false live hosts.
func TestScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the scan starts

	ips := []uint32{ipu(t, "127.0.0.1"), ipu(t, "127.0.0.2")}
	live, stats, err := Scan(ctx, ips, Options{
		Concurrency: 2,
		Timeout:     5 * time.Second,
		Port:        9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Fatalf("live = %v, want none after cancellation", live)
	}
	if stats.Live+stats.Refused+stats.Timeout+stats.Other > 2 {
		t.Fatalf("attempts exceeded total: %+v", stats)
	}
}

// TestScanValidation checks the argument guards.
func TestScanValidation(t *testing.T) {
	ips := []uint32{ipu(t, "127.0.0.1")}
	_, _, err := Scan(context.Background(), ips, Options{Concurrency: 0, Timeout: time.Second, Port: 3389})
	if err == nil {
		t.Fatal("concurrency 0 should error")
	}
	_, _, err = Scan(context.Background(), ips, Options{Concurrency: 1, Timeout: 0, Port: 3389})
	if err == nil {
		t.Fatal("timeout 0 should error")
	}
	_, _, err = Scan(context.Background(), ips, Options{Concurrency: 1, Timeout: time.Second, Port: 70000})
	if err == nil {
		t.Fatal("port 70000 should error")
	}
	_, _, err = Scan(context.Background(), nil, Options{Concurrency: 1, Timeout: time.Second, Port: 3389})
	if err == nil {
		t.Fatal("empty input should error")
	}
}

// TestClassify covers the error-bucketing logic directly.
func TestClassify(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantTimeout bool
		wantRefused bool
	}{
		{"deadline", os.ErrDeadlineExceeded, true, false},
		{"net timeout", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, true, false},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, false, true},
		{"canceled", context.Canceled, false, false},
		{"generic", errors.New("network is unreachable"), false, false},
	}
	for _, c := range cases {
		var nTimeout, nRefused, nOther atomic.Uint64
		classify(context.Background(), c.err, &nRefused, &nTimeout, &nOther)
		if (nTimeout.Load() > 0) != c.wantTimeout {
			t.Fatalf("%s: timeout bucket = %d, want %v", c.name, nTimeout.Load(), c.wantTimeout)
		}
		if (nRefused.Load() > 0) != c.wantRefused {
			t.Fatalf("%s: refused bucket = %d, want %v", c.name, nRefused.Load(), c.wantRefused)
		}
		if nOther.Load() > 0 && (c.wantTimeout || c.wantRefused) {
			t.Fatalf("%s: unexpected other bucket = %d", c.name, nOther.Load())
		}
	}
}
