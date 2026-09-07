// Package scan probes a stream of IPv4 addresses and reports which ones run a
// working RDP service.
//
// Two properties make it usable on a laptop rather than only on a scan box:
//
//   - Bounded memory. Addresses are pulled from a Source in chunks of
//     Options.Chunk and never materialised as a full list, so a /8 target
//     costs the same RAM as a /24 (a few small buffers) instead of hundreds of
//     megabytes. Only hosts that answer are kept, one small record each.
//   - Bounded pressure. A fixed worker pool caps the number of open sockets,
//     an optional token bucket caps probes per second, and an optional pause
//     between chunks lets the machine (and the Wi-Fi/NAT gateway) catch up.
//     Socket use is additionally clamped to the process file-descriptor limit.
//
// Detection is a TCP connect (no raw sockets, no root). With Check ==
// rdp.ModeRDP every host that completes the handshake is additionally asked
// for its RDP negotiation PDU, so "3389 is open" and "RDP answers here" are
// reported apart. No ICMP, no UDP, no authentication attempt.
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
	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/rdp"
)

// Defaults for Options; the CLI mirrors them so --help tells the truth.
const (
	// DefaultChunk is how many addresses are scheduled and drained per
	// batch. 4096 keeps ~16 KB of buffers in flight while still giving the
	// worker pool plenty to do.
	DefaultChunk = 4096

	// MinChunk/MaxChunk bound the user's --chunk, which also bounds the
	// memory and the burst size of a scan.
	MinChunk = 16
	MaxChunk = 1 << 20
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

// Source produces the addresses to probe, a chunk at a time. Next copies at
// most len(dst) ascending, deduplicated addresses into dst and returns how many
// it wrote; returning 0 ends the scan. The interface is what keeps memory flat:
// the scanner never sees the whole target list at once.
type Source interface {
	Next(dst []uint32) int
}

// Result is one host that completed a TCP handshake.
type Result struct {
	IP     uint32
	Port   int
	State  rdp.State // rdp.StateRDP means "an RDP service answered here"
	Detail string    // human-readable verdict (security layer, foreign banner, ...)
	RTT    time.Duration
}

// Options configures a scan.
type Options struct {
	// Concurrency is the maximum number of in-flight connection attempts
	// and therefore of open sockets. It is additionally clamped to the
	// process file-descriptor budget when one can be read.
	Concurrency int

	// Timeout is the per-connection dial deadline.
	Timeout time.Duration

	// Port is the TCP port to probe (3389 for RDP).
	Port int

	// Chunk is the batch size of the streaming pipeline: how many
	// addresses are scheduled at once, and how often results are flushed.
	Chunk int

	// ChunkDelay is slept after each chunk has fully drained. On a laptop
	// this is what keeps the scan from saturating the NIC/CPU continuously,
	// and it also gives an over-eager NAT gateway time to forget sockets.
	ChunkDelay time.Duration

	// Rate caps probes per second (0 = unlimited). Together with Concurrency
	// it decides how gentle the scan is: the pool size bounds simultaneous
	// sockets, the rate bounds sustained pressure.
	Rate float64

	// Check selects TCP-connect-only (rdp.ModePort) versus RDP service
	// verification (rdp.ModeRDP).
	Check rdp.Mode

	// RDPTimeout bounds the negotiation read; defaults to Timeout.
	RDPTimeout time.Duration

	// MaxLive stops the scan once that many reported hosts have been found
	// (0 = scan everything).
	MaxLive uint64

	// OnProgress, if set, is called after each completed attempt with the
	// number done and the total.
	OnProgress func(done, total uint64)

	// OnResult, if set, is called once per chunk for every host that
	// accepted a connection, in ascending IP order. It runs on the scanning
	// goroutine, so it may write files without extra locking, but it must
	// not block for long: workers wait for nothing else, the feeder does.
	OnResult func(r Result)

	// OnFlush, if set, is called right after all OnResult callbacks of a
	// chunk have been delivered. That is the drain barrier — the moment at
	// which a caller can safely flush an output file and know that every
	// result found so far is on disk.
	OnFlush func()
}

// Stats aggregates per-attempt outcomes.
type Stats struct {
	Total   uint64
	Done    uint64
	Chunks  uint64
	Live    uint64 // TCP handshake completed
	RDP     uint64 // of those, an RDP service answered
	Open    uint64 // of those, no protocol evidence
	NotRDP  uint64 // of those, something that is not RDP answered
	Refused uint64
	Timeout uint64
	Other   uint64

	Skipped uint64 // addresses never attempted (interrupt or --max-live)
	TooMany uint64 // attempts that hit the descriptor limit (and were retried)
	MaxLive uint64 // set when the --max-live stop triggered
	Sockets int    // worker count actually used, after the descriptor clamp

	Elapsed time.Duration
}

// ScanSpans streams a deduplicated target list (merged CIDR spans, optionally
// sharded) through the scanner. It returns the tally of what it saw; hosts that
// answered are delivered through opts.OnResult as they are found, chunk by
// chunk, which is what lets the caller write results incrementally and keep
// them after an interrupt.
func ScanSpans(ctx context.Context, spans []cidr.Span, sh cidr.Shard, total uint64, opts Options) (Stats, error) {
	if len(spans) == 0 {
		return Stats{}, errors.New("no IPs to scan")
	}
	// Cheap insurance: the streamer needs canonical ranges. Merging is
	// O(ranges log ranges) and idempotent, so callers that already merged pay
	// almost nothing while callers that did not still get correct results.
	spans = cidr.MergeSpans(spans)
	src := &spanSource{spans: spans, sh: sh, ip: uint64(spans[0].Start)}
	return run(ctx, total, src, opts)
}

// Scan probes a materialised list of addresses and returns the live ones,
// sorted ascending. It is the simple front door for callers that already hold
// a []uint32 (small target sets, tests); ScanSpans is the variant that keeps
// memory flat for gigantic ones.
func Scan(ctx context.Context, ips []uint32, opts Options) ([]uint32, Stats, error) {
	var (
		mu   sync.Mutex
		live []uint32
	)
	userCB := opts.OnResult
	opts.OnResult = func(r Result) {
		if userCB != nil {
			userCB(r)
		}
		mu.Lock()
		live = append(live, r.IP)
		mu.Unlock()
	}
	stats, err := run(ctx, uint64(len(ips)), &sliceSource{ips: ips}, opts)
	if err != nil {
		return nil, stats, err
	}
	sort.Slice(live, func(i, j int) bool { return live[i] < live[j] })
	return live, stats, nil
}

// run is the chunked, bounded pipeline shared by both entry points.
func run(ctx context.Context, total uint64, src Source, opts Options) (Stats, error) {
	stats := Stats{Total: total}
	if opts.Concurrency <= 0 {
		return stats, errors.New("concurrency must be >= 1")
	}
	if opts.Timeout <= 0 {
		return stats, errors.New("timeout must be > 0")
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return stats, errors.New("port must be 1-65535")
	}
	if src == nil || total == 0 {
		return stats, errors.New("no IPs to scan")
	}
	if opts.Chunk <= 0 {
		opts.Chunk = DefaultChunk
	}
	if opts.Chunk < MinChunk {
		opts.Chunk = MinChunk
	}
	if opts.Chunk > MaxChunk {
		opts.Chunk = MaxChunk
	}
	if total > 0 && uint64(opts.Concurrency) > total {
		opts.Concurrency = int(total)
	}
	if opts.Check == rdp.ModeRDP && opts.RDPTimeout <= 0 {
		opts.RDPTimeout = opts.Timeout
	}
	// Never keep more open sockets than the process can afford: a laptop with
	// the macOS default of 256 descriptors would otherwise turn every
	// attempt into EMFILE and report a scan full of noise.
	if max := socketBudget(); max > 0 && opts.Concurrency > max {
		opts.Concurrency = max
	}
	stats.Sockets = opts.Concurrency

	// The feeder needs at most two chunks of addresses in flight: one being
	// dispatched, one being drained by the workers.
	buf := make([]uint32, opts.Chunk)
	jobs := make(chan job, opts.Concurrency)

	// inner is canceled when the user stops us *or* when --max-live is hit,
	// which makes both the source and the remaining dials bail out.
	inner, cancel := context.WithCancel(ctx)
	defer cancel()

	var done, nLive, nRDP, nOpen, nNotRDP, nRefused, nTimeout, nOther, nTooMany atomic.Uint64
	var pendingMu sync.Mutex
	var pending []Result

	s := &prober{
		opts:    opts,
		dialer:  &net.Dialer{Timeout: opts.Timeout},
		inner:   inner,
		done:    &done,
		nLive:   &nLive,
		nRDP:    &nRDP,
		nOpen:   &nOpen,
		nNotRDP: &nNotRDP,
		nReused: &nTooMany,
		pending: &pending,
		pmu:     &pendingMu,
		stop:    cancel,
		total:   total,
	}

	var pool sync.WaitGroup
	for w := 0; w < opts.Concurrency; w++ {
		pool.Add(1)
		go func() {
			defer pool.Done()
			for j := range jobs {
				s.check(j.ip)
				j.wg.Done()
			}
		}()
	}

	var lim *limiter
	if opts.Rate > 0 {
		lim = newLimiter(opts.Rate)
	}

	start := time.Now()

	// publish hands a drained chunk to the caller: ascending, then flushed.
	// Because the chunk barrier has just closed, nothing else may touch
	// pending at this point.
	publish := func() {
		pendingMu.Lock()
		list := pending
		pending = nil
		pendingMu.Unlock()
		if len(list) > 1 {
			sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
		}
		for _, r := range list {
			if opts.OnResult != nil {
				opts.OnResult(r)
			}
		}
		if opts.OnFlush != nil {
			opts.OnFlush()
		}
	}

feed:
	for {
		if err := inner.Err(); err != nil {
			break
		}
		n := src.Next(buf)
		if n == 0 {
			break
		}
		stats.Chunks++

		// One WaitGroup per chunk is the drain barrier: the chunk's results
		// are complete the moment it opens, so they can be sorted and flushed
		// while nothing else is in flight — that is what bounds memory (no
		// result backlog) and what makes an interrupt lose at most one chunk.
		var wg sync.WaitGroup
		for _, ip := range buf[:n] {
			if lim != nil {
				if err := lim.wait(inner); err != nil {
					break feed // interrupted while pacing
				}
			}
			wg.Add(1)
			select {
			case jobs <- job{ip: ip, wg: &wg}:
			case <-inner.Done():
				wg.Done()
				break feed
			}
		}
		wg.Wait()
		publish()

		if opts.ChunkDelay > 0 {
			t := time.NewTimer(opts.ChunkDelay)
			select {
			case <-inner.Done():
				t.Stop()
				break feed
			case <-t.C:
			}
		}
	}

	close(jobs)
	pool.Wait()
	publish() // anything found in a chunk that was cut short by an interrupt

	stats.Done = done.Load()
	stats.Live = nLive.Load()
	stats.RDP = nRDP.Load()
	stats.Open = nOpen.Load()
	stats.NotRDP = nNotRDP.Load()
	stats.Refused = nRefused.Load()
	stats.Timeout = nTimeout.Load()
	stats.Other = nOther.Load()
	stats.TooMany = nTooMany.Load()
	if opts.MaxLive > 0 && stats.Live >= opts.MaxLive {
		stats.MaxLive = opts.MaxLive
	}
	if stats.Done < stats.Total {
		stats.Skipped = stats.Total - stats.Done
	}
	stats.Elapsed = time.Since(start)
	return stats, nil
}

type job struct {
	ip uint32
	wg *sync.WaitGroup
}

// prober carries the per-attempt state shared by the worker goroutine pool.
type prober struct {
	opts    Options
	dialer  *net.Dialer
	inner   context.Context
	done    *atomic.Uint64
	nLive   *atomic.Uint64
	nRDP    *atomic.Uint64
	nOpen   *atomic.Uint64
	nNotRDP *atomic.Uint64
	nReused *atomic.Uint64
	pmu     *sync.Mutex
	pending *[]Result
	stop    context.CancelFunc
	total   uint64
}

// check performs one attempt: connect, optionally verify RDP, classify.
func (p *prober) check(ip uint32) {
	defer func() {
		n := p.done.Add(1)
		if p.opts.OnProgress != nil {
			p.opts.OnProgress(n, p.total)
		}
	}()

	addr := net.JoinHostPort(cidr.FormatIPv4(ip), strconv.Itoa(p.opts.Port))
	t0 := time.Now()
	conn, err := p.dialer.DialContext(p.inner, "tcp", addr)
	if err != nil {
		if isTooManyFDs(err) {
			// Hit the descriptor ceiling: back off a moment so finished
			// sockets can be recycled, then try once more instead of
			// reporting a bogus result.
			p.nReused.Add(1)
			t := time.NewTimer(20 * time.Millisecond)
			select {
			case <-p.inner.Done():
				t.Stop()
			case <-t.C:
			}
			conn, err = p.dialer.DialContext(p.inner, "tcp", addr)
		}
		if err != nil {
			classify(p.inner, err, p.nRefused, p.nTimeout, p.nOther)
			return
		}
	}
	lat := time.Since(t0)

	state, detail := rdp.Probe(conn, p.opts.Check, p.opts.RDPTimeout)
	_ = conn.Close()

	p.nLive.Add(1)
	switch state {
	case rdp.StateRDP:
		p.nRDP.Add(1)
	case rdp.StateNotRDP:
		p.nNotRDP.Add(1)
	default:
		p.nOpen.Add(1)
	}

	p.pmu.Lock()
	*p.pending = append(*p.pending, Result{IP: ip, Port: p.opts.Port, State: state, Detail: detail, RTT: lat})
	p.pmu.Unlock()

	if p.opts.MaxLive > 0 && p.nLive.Load() >= p.opts.MaxLive {
		p.stop() // stop feeding; the in-flight chunk finishes normally
	}
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

// sliceSource walks a materialised list; used by Scan and by tests.
type sliceSource struct {
	ips []uint32
	pos int
}

func (s *sliceSource) Next(dst []uint32) int {
	n := copy(dst, s.ips[s.pos:])
	s.pos += n
	return n
}

// spanSource walks merged, ascending spans address by address, honouring a
// shard, without ever building the address list. pos counts the addresses
// *seen* (not emitted) so that sharding stays positional across range gaps.
type spanSource struct {
	spans []cidr.Span
	sh    cidr.Shard
	si    int
	ip    uint64
	pos   uint64
}

// Next fills dst with the following addresses of the (merged, ascending) span
// list, honouring the shard. It is O(chunk) work and O(1) memory: the scanner
// never holds more than one chunk of addresses, however big the target set is.
func (s *spanSource) Next(dst []uint32) int {
	n := 0
	for n < len(dst) {
		for s.si < len(s.spans) && s.ip > uint64(s.spans[s.si].End) {
			s.si++
			if s.si < len(s.spans) {
				s.ip = uint64(s.spans[s.si].Start)
			}
		}
		if s.si >= len(s.spans) {
			break
		}
		end := uint64(s.spans[s.si].End)
		for s.ip <= end && n < len(dst) {
			if !s.sh.Active() || s.pos%s.sh.Count == s.sh.Index {
				dst[n] = uint32(s.ip)
				n++
			}
			s.ip++
			s.pos++
		}
	}
	return n
}
