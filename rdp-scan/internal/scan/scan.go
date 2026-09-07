// Package scan performs bounded-concurrency TCP connectivity checks against
// a list of IPv4 addresses (uint32 form) and reports which ones accepted a
// connection. The TCP connect itself is the liveness test: no ICMP, no UDP,
// no banner exchange, no authentication — a completed TCP handshake on the
// target port marks the host live, the connection is then closed.
package scan

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/cidr"
)

// Kind classifies the outcome of a single connection attempt.
type Kind uint8

const (
	KindLive    Kind = iota // TCP handshake completed
	KindRefused             // peer answered with RST (ECONNREFUSED)
	KindTimeout             // no answer within the timeout (dropped/filtered)
	KindOther               // everything else (unreachable, interrupted, ...)
)

func (k Kind) String() string {
	switch k {
	case KindLive:
		return "live"
	case KindRefused:
		return "refused"
	case KindTimeout:
		return "timeout"
	default:
		return "other"
	}
}

// Options configures a scan.
type Options struct {
	// Concurrency is the maximum number of in-flight TCP connection
	// attempts (worker count).
	Concurrency int

	// Timeout is the per-connection timeout (dial deadline).
	Timeout time.Duration

	// Port is the TCP port to probe (3389 for RDP).
	Port int

	// OnProgress, if set, is called after each completed attempt with the
	// number done and the total.
	OnProgress func(done, total uint64)

	// OnLive, if set, is called for each host that accepted a connection.
	// It runs on the worker goroutine, so keep it quick.
	OnLive func(ip uint32)
}

// Stats aggregates per-attempt outcomes.
type Stats struct {
	Total   uint64
	Live    uint64
	Refused uint64
	Timeout uint64
	Other   uint64
	Elapsed time.Duration
}

// Scan probes every IP in ips and returns the live ones (sorted ascending).
// Bounded worker-pool concurrency keeps the number of open sockets and
// goroutines fixed regardless of the input size. Canceling ctx aborts the
// remaining attempts; hosts already confirmed live are still returned.
func Scan(ctx context.Context, ips []uint32, opts Options) ([]uint32, Stats, error) {
	if opts.Concurrency <= 0 {
		return nil, Stats{}, errors.New("concurrency must be >= 1")
	}
	if opts.Timeout <= 0 {
		return nil, Stats{}, errors.New("timeout must be > 0")
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return nil, Stats{}, errors.New("port must be 1-65535")
	}
	if len(ips) == 0 {
		return nil, Stats{}, errors.New("no IPs to scan")
	}
	if opts.Concurrency > len(ips) {
		opts.Concurrency = len(ips)
	}

	start := time.Now()
	total := uint64(len(ips))
	stats := Stats{Total: total}

	var done atomic.Uint64
	var nLive, nRefused, nTimeout, nOther atomic.Uint64

	// Live results are streamed to a collector goroutine through a
	// buffered channel so workers never block on shared state.
	liveCh := make(chan uint32, 1024)
	var liveWg sync.WaitGroup
	var liveMu sync.Mutex
	var live []uint32
	liveWg.Add(1)
	go func() {
		defer liveWg.Done()
		for ip := range liveCh {
			liveMu.Lock()
			live = append(live, ip)
			liveMu.Unlock()
		}
	}()

	dialer := &net.Dialer{Timeout: opts.Timeout}

	check := func(ip uint32) {
		defer func() {
			if opts.OnProgress != nil {
				opts.OnProgress(done.Add(1), total)
			} else {
				done.Add(1)
			}
		}()

		addr := net.JoinHostPort(cidr.FormatIPv4(ip), strconv.Itoa(opts.Port))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			classify(ctx, err, &nRefused, &nTimeout, &nOther)
			return
		}
		_ = conn.Close()
		nLive.Add(1)
		liveCh <- ip
		if opts.OnLive != nil {
			opts.OnLive(ip)
		}
	}

	jobs := make(chan uint32, opts.Concurrency*2)
	var wg sync.WaitGroup
	for w := 0; w < opts.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-jobs:
					if !ok {
						return
					}
					check(ip)
				}
			}
		}()
	}

feed:
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- ip:
		}
	}
	close(jobs)
	wg.Wait()
	close(liveCh)
	liveWg.Wait()

	stats.Live = nLive.Load()
	stats.Refused = nRefused.Load()
	stats.Timeout = nTimeout.Load()
	stats.Other = nOther.Load()
	stats.Elapsed = time.Since(start)

	sort.Sort(u32Slice(live))
	return live, stats, nil
}

// classify buckets a dial error into refused / timeout / other counters.
func classify(ctx context.Context, err error, nRefused, nTimeout, nOther *atomic.Uint64) {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		nTimeout.Add(1)
		return
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		nRefused.Add(1)
		return
	}
	if errors.Is(err, context.Canceled) {
		nOther.Add(1) // attempt aborted by user interrupt
		return
	}
	nOther.Add(1)
}

// u32Slice implements sort.Interface for []uint32.
type u32Slice []uint32

func (s u32Slice) Len() int           { return len(s) }
func (s u32Slice) Less(i, j int) bool { return s[i] < s[j] }
func (s u32Slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
