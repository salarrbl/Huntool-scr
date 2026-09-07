// Command rdp-scan finds hosts that actually run RDP, not just hosts whose TCP
// port 3389 accepts a connection.
//
// It reads IPv4 targets (CIDR ranges, single IPs, AS numbers, dash ranges and
// wildcards) from files or the command line, deduplicates them as ranges, and
// probes each address: a TCP connect first, then — with the default --check
// rdp — the X.224 RDP negotiation request that every RDP client sends. A host
// is reported as a live RDP host when the RDP service itself answers. Nothing
// is authenticated, no exploit is attempted, no root rights are needed.
//
// Large target sets are handled by streaming: addresses are never expanded
// into a list, they are walked in --chunk batches and results are written as
// each batch drains, so RAM stays flat for a /8 and an interrupt still leaves
// the findings so far on disk. --eco turns on the laptop profile (few sockets,
// paced probes, pauses between chunks, low CPU priority), --rate caps probes
// per second, --max-cpu caps CPU usage and --shard splits one huge range
// across several machines.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/cidr"
	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/rdp"
	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/scan"
)

const (
	toolName = "rdp-scan"
	version  = "1.1.0"

	defaultOutput  = "rdp_live.txt"
	defaultTimeout = 3 * time.Second
	defaultPort    = 3389 // RDP
	// defaultMaxIPs is a scope guard, not a memory guard: expansion is
	// streamed now, so scanning beyond it only costs time.
	defaultMaxIPs = 67108864 // 2^26

	// Laptop profile applied by --eco. Values set explicitly on the command
	// line always win.
	ecoConcurrency = 64
	ecoRate        = 120.0
	ecoChunk       = 512
	ecoChunkDelay  = 200 * time.Millisecond
	ecoNice        = 10
)

// exit codes
const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitInterrupt = 130
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// config is the validated command line.
type config struct {
	output  string
	report  string
	asnFile string
	exclude string
	shard   cidr.Shard

	concurrency int
	rate        float64
	chunk       int
	chunkDelay  time.Duration
	timeout     time.Duration
	rdpTimeout  time.Duration
	port        int
	maxIPs      uint64
	maxLive     uint64
	nice        int
	maxCPU      int

	check       rdp.Mode
	includeOpen bool
	eco         bool
	dryRun      bool
	quiet       bool

	// done is set when argument parsing produced the final answer already
	// (--help, --version); code is the exit status to use.
	done bool
	code int

	// requested records which flags the user actually typed, so --eco only
	// replaces defaults and never overrides an explicit choice.
	requested map[string]bool
}

func run(args []string) int {
	cfg, inputs, err := parseArgs(args)
	if cfg.done {
		return cfg.code
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no input given — provide at least one file, CIDR, IP or ASN (see --help)")
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ---------- 0. be a good guest on this machine ----------
	applyResourceProfile(&cfg)

	// ---------- 1. load and normalise targets ----------
	log1(cfg, "[*] Loading targets...")
	spans, err := loadTargets(cfg, inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if len(spans) == 0 {
		fmt.Fprintln(os.Stderr, "error: no valid targets found in the given inputs")
		return exitError
	}
	holes, err := cidr.ParseSpanList(cfg.exclude)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --exclude: %v\n", err)
		return exitUsage
	}
	if len(holes) > 0 {
		before := cidr.CountIPs(spans)
		spans = cidr.Subtract(spans, holes)
		if len(spans) == 0 {
			fmt.Fprintln(os.Stderr, "error: --exclude removed every target")
			return exitError
		}
		log1(cfg, "[*] --exclude removed %s addresses (%s left)",
			humanInt(before-cidr.CountIPs(spans)), humanInt(cidr.CountIPs(spans)))
	}
	spans = cidr.MergeSpans(spans)

	total := cidr.CountIPs(spans)
	if total > cfg.maxIPs {
		fmt.Fprintf(os.Stderr, "error: %s unique IPs exceeds the safety cap of %s (raise --max-ips if this is intended)\n",
			humanInt(total), humanInt(cfg.maxIPs))
		return exitError
	}
	shardTotal := cidr.ShardCount(total, cfg.shard)
	if shardTotal == 0 {
		fmt.Fprintf(os.Stderr, "error: --shard %s selects no addresses (this shard is empty)\n", cfg.shard)
		return exitUsage
	}
	chunks := cidr.TotalChunks(shardTotal, cfg.chunk)

	log1(cfg, "[+] %s unique IPs in %s range(s) after deduplication", humanInt(total), humanInt(uint64(len(spans))))
	if cfg.shard.Active() {
		log1(cfg, "[*] shard %s → %s addresses in %s chunks of %d",
			cfg.shard, humanInt(shardTotal), humanInt(chunks), cfg.chunk)
	} else {
		log1(cfg, "[*] streaming %s addresses in %s chunks of %d — memory stays flat at any range size",
			humanInt(shardTotal), humanInt(chunks), cfg.chunk)
	}
	log1(cfg, "[*] Scanning TCP/%d — %s (%d concurrent, %s timeout%s)",
		cfg.port, checkLabel(cfg.check), cfg.concurrency, cfg.timeout, rateLabel(cfg.rate))

	if cfg.dryRun {
		log1(cfg, "[i] plan: %s | output %s | nothing was sent (--dry-run)",
			etaText(shardTotal, cfg), cfg.output)
		return exitOK
	}

	// ---------- 2. results sink, opened before the scan and flushed per chunk ----------
	out, err := newSink(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	// ---------- 3. scan ----------
	prog := newProgress(cfg, shardTotal)
	opts := scan.Options{
		Concurrency: cfg.concurrency,
		Timeout:     cfg.timeout,
		Port:        cfg.port,
		Chunk:       cfg.chunk,
		ChunkDelay:  cfg.chunkDelay,
		Rate:        cfg.rate,
		Check:       cfg.check,
		RDPTimeout:  cfg.rdpTimeout,
		MaxLive:     cfg.maxLive,
		OnProgress:  prog.tick,
		OnResult:    out.add,
		OnFlush:     func() { _ = out.flush(); prog.render() },
	}
	stats, err := scan.ScanSpans(ctx, spans, cfg.shard, shardTotal, opts)
	prog.finish()
	if werr := out.close(); werr != nil {
		if err == nil {
			err = werr
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	// ---------- 4. summary ----------
	switch {
	case ctx.Err() != nil:
		fmt.Println("[!] Scan interrupted — everything found so far is already on disk")
	case stats.MaxLive > 0:
		fmt.Printf("[!] Stopped after %s live host(s) as requested by --max-live\n", humanInt(stats.MaxLive))
	default:
		fmt.Println("[+] Scan complete")
	}

	line := fmt.Sprintf("[*] %s/%s probed | %d refused | %d timeout | %d other",
		humanInt(stats.Done), humanInt(stats.Total), stats.Refused, stats.Timeout, stats.Other)
	if stats.Skipped > 0 {
		line += fmt.Sprintf(" | %d not attempted", stats.Skipped)
	}
	if stats.TooMany > 0 {
		line += fmt.Sprintf(" | %d retried after the descriptor limit", stats.TooMany)
	}
	if rate := throughput(stats); rate > 0 {
		line += fmt.Sprintf(" | %s ip/s", humanInt(uint64(rate+0.5)))
	}
	line += fmt.Sprintf(" | elapsed %s", stats.Elapsed.Round(10*time.Millisecond))
	fmt.Println(line)

	if cfg.check == rdp.ModeRDP {
		fmt.Printf("[*] %s host(s) answered on TCP/%d: %d run RDP, %d silent, %d run another service\n",
			humanInt(stats.Live), cfg.port, stats.RDP, stats.Open, stats.NotRDP)
		out.printTally()
		if stats.Open > 0 && !cfg.includeOpen {
			fmt.Printf("[i] %d host(s) had 3389 open but never answered the RDP negotiation — not listed; use --include-open or --report to keep them\n", stats.Open)
		}
	} else {
		fmt.Printf("[+] %s host(s) with TCP/%d open\n", humanInt(stats.Live), cfg.port)
	}
	if out.written > 0 {
		fmt.Printf("[+] Results saved to: %s (%s host%s)\n", cfg.output, humanInt(out.written), plural(out.written))
	} else {
		fmt.Printf("[+] No live host found — %s is empty\n", cfg.output)
	}
	if cfg.report != "" {
		fmt.Printf("[+] Report with every answered host (incl. non-RDP): %s\n", cfg.report)
	}

	if ctx.Err() != nil {
		return exitInterrupt
	}
	return exitOK
}

// ---------- resource profile ----------

// applyResourceProfile bounds CPU, socket and scheduling pressure for the
// whole process. This is the "runs on a laptop" part: an optional GOMAXPROCS
// cap, an optional niceness penalty, and a descriptor-limit adjustment so the
// scan never turns into thousands of EMFILE errors on a machine whose default
// ulimit is small (256 on macOS, for instance).
func applyResourceProfile(cfg *config) {
	if cfg.maxCPU > 0 {
		if max := runtime.NumCPU(); cfg.maxCPU > max {
			cfg.maxCPU = max
		}
		runtime.GOMAXPROCS(cfg.maxCPU)
		log1(*cfg, "[i] scheduler capped at %d core(s) of %d to keep the machine responsive", cfg.maxCPU, runtime.NumCPU())
	}
	if cfg.nice > 0 {
		if err := setNiceness(cfg.nice); err != nil {
			log1(*cfg, "[!] could not lower scheduling priority: %v", err)
		} else {
			log1(*cfg, "[i] scheduling priority lowered (nice +%d)", cfg.nice)
		}
	}
	// The scanner clamps itself to this budget; mirror it here so the plan the
	// user is shown is the plan that runs.
	if n := scan.FDLimit(); n > 0 {
		budget := n * 8 / 10
		if budget < 16 {
			budget = 16
		}
		if cfg.concurrency > budget {
			log1(*cfg, "[!] only %d file descriptors: concurrency capped to %d (a larger `ulimit -n` — and hard limit — allows faster scans)", n, budget)
			cfg.concurrency = budget
		}
	}
}

// etaText estimates the wall-clock time of the planned scan.
func etaText(n uint64, cfg config) string {
	if n == 0 {
		return "eta 0s"
	}
	perSec := cfg.rate
	if d := float64(cfg.concurrency) / cfg.timeout.Seconds(); perSec == 0 || d < perSec {
		perSec = d
	}
	if perSec <= 0 {
		return "eta unknown"
	}
	secs := float64(n) / perSec
	if secs > 1e9 {
		secs = 1e9
	}
	eta := (time.Duration(secs * float64(time.Second))).Round(time.Second)
	return fmt.Sprintf("worst-case eta %s (assumes every host is filtered; hosts that answer are far faster)", eta)
}

func throughput(s scan.Stats) float64 {
	if s.Elapsed <= 0 || s.Done == 0 {
		return 0
	}
	return float64(s.Done) / s.Elapsed.Seconds()
}

func checkLabel(m rdp.Mode) string {
	if m == rdp.ModeRDP {
		return "RDP service verification"
	}
	return "TCP connect check"
}

func rateLabel(rate float64) string {
	if rate <= 0 {
		return ""
	}
	return fmt.Sprintf(", %.0f/s max", rate)
}

func plural(n uint64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ---------- targets ----------

func loadTargets(cfg config, inputs []string) ([]cidr.Span, error) {
	parser := &cidr.Parser{
		ASNPath: cfg.asnFile,
		Warn: func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
		},
	}
	var spans []cidr.Span
	for _, in := range inputs {
		st, statErr := os.Stat(in)
		switch {
		case statErr == nil && st.Mode().IsRegular():
			log1(cfg, "[*] Loading file: %s", in)
			sp, err := parser.ParseFile(in)
			if err != nil {
				return nil, err
			}
			spans = append(spans, sp...)
		case statErr == nil:
			return nil, fmt.Errorf("%q is not a regular file", in)
		default:
			sp, err := parser.ParseToken(in)
			if err != nil {
				if strings.ContainsAny(in, `/\`) {
					return nil, fmt.Errorf("input file not found: %q", in)
				}
				return nil, fmt.Errorf("invalid target %q: %w", in, err)
			}
			spans = append(spans, sp...)
		}
	}
	return spans, nil
}

// ---------- result sink ----------

// sink writes results while the scan is still running: matching hosts go to the
// output file (one IP per line, ascending — chunks are drained in order, so
// streaming preserves the sorted output contract) and, when --report is given,
// one tab-separated line per answered host goes to the report. Both are
// flushed at every chunk boundary, so an interrupt loses at most the chunk in
// flight, not the scan.
type sink struct {
	cfg     config
	tty     bool
	f       *os.File
	w       *bufio.Writer
	rf      *os.File
	rw      *bufio.Writer
	written uint64
	counts  map[string]int
	err     error
}

func newSink(cfg config) (*sink, error) {
	s := &sink{cfg: cfg, tty: isTerminal(os.Stdout), counts: map[string]int{}}
	f, err := os.Create(cfg.output)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file %s: %w", cfg.output, err)
	}
	s.f, s.w = f, bufio.NewWriterSize(f, 32*1024)
	if cfg.report != "" {
		rf, err := os.Create(cfg.report)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("cannot create report file %s: %w", cfg.report, err)
		}
		s.rf, s.rw = rf, bufio.NewWriterSize(rf, 32*1024)
		fmt.Fprintln(s.rw, "# ip\tport\tstate\trtt\tdetail")
	}
	return s, nil
}

// add records one result. The scanner calls it from a single goroutine, once per
// host, in ascending order within a chunk — so no locking and no buffering of
// the whole result set is needed here.
func (s *sink) add(r scan.Result) {
	if s.err != nil {
		return
	}
	s.counts[keyFor(r)]++
	if s.rw != nil {
		fmt.Fprintf(s.rw, "%s\t%d\t%s\t%s\t%s\n",
			cidr.FormatIPv4(r.IP), r.Port, r.State, r.RTT.Round(time.Millisecond), orDash(r.Detail))
	}
	if s.includes(r) {
		if _, err := s.w.WriteString(cidr.FormatIPv4(r.IP)); err != nil {
			s.err = fmt.Errorf("writing output file %s: %w", s.cfg.output, err)
			return
		}
		if err := s.w.WriteByte('\n'); err != nil {
			s.err = fmt.Errorf("writing output file %s: %w", s.cfg.output, err)
			return
		}
		s.written++
	}
	if !s.cfg.quiet {
		s.print(r)
	}
}

// includes decides what the bare-IP output file receives: with --check rdp only
// hosts whose RDP service answered (plus unverified ones when --include-open
// asks for them); with --check port everything that completed a handshake.
func (s *sink) includes(r scan.Result) bool {
	if s.cfg.check != rdp.ModeRDP {
		return true
	}
	switch r.State {
	case rdp.StateRDP:
		return true
	case rdp.StateOpen:
		return s.cfg.includeOpen
	default:
		return false
	}
}

// print reports one finding, clearing the progress line first on a terminal.
func (s *sink) print(r scan.Result) {
	ip := cidr.FormatIPv4(r.IP)
	if s.tty {
		fmt.Print("\r\033[K")
	}
	switch r.State {
	case rdp.StateRDP:
		fmt.Printf("[+] %s:%d RDP UP — %s\n", ip, r.Port, detailOr(r.Detail, "RDP service answered"))
	case rdp.StateNotRDP:
		fmt.Printf("[!] %s:%d open but NOT RDP — %s\n", ip, r.Port, detailOr(r.Detail, "another service answered"))
	default:
		if s.cfg.check == rdp.ModeRDP {
			fmt.Printf("[!] %s:%d open, no RDP answer — %s\n", ip, r.Port, detailOr(r.Detail, "silent"))
		} else {
			fmt.Printf("[+] %s:%d OPEN\n", ip, r.Port)
		}
	}
}

func detailOr(d, fallback string) string {
	if strings.TrimSpace(d) == "" {
		return fallback
	}
	return d
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// keyFor buckets findings for the summary tally.
func keyFor(r scan.Result) string {
	switch r.State {
	case rdp.StateRDP:
		return securityBucket(r.Detail)
	case rdp.StateNotRDP:
		return "not-rdp"
	default:
		return "open-no-answer"
	}
}

func securityBucket(d string) string {
	switch {
	case strings.Contains(d, "Credential Guard"):
		return "rdp(rcg)"
	case strings.Contains(d, "early user info"):
		return "rdp(nla-ex)"
	case strings.Contains(d, "NLA"):
		return "rdp(nla)"
	case strings.Contains(d, "TLS"):
		return "rdp(tls)"
	case strings.Contains(d, "disconnect"):
		return "rdp(refused)"
	case strings.Contains(d, "negotiation refused"):
		return "rdp(neg-fail)"
	case strings.Contains(d, "standard"):
		return "rdp(standard)"
	}
	return "rdp"
}

func (s *sink) flush() error {
	if s.err != nil {
		return s.err
	}
	if s.w != nil {
		if err := s.w.Flush(); err != nil {
			s.err = fmt.Errorf("writing output file %s: %w", s.cfg.output, err)
			return s.err
		}
	}
	if s.rw != nil {
		if err := s.rw.Flush(); err != nil {
			s.err = fmt.Errorf("writing report file %s: %w", s.cfg.report, err)
			return s.err
		}
	}
	return nil
}

func (s *sink) close() error {
	err := s.flush()
	if s.w != nil {
		_ = s.w.Flush()
	}
	if s.rw != nil {
		_ = s.rw.Flush()
	}
	if s.f != nil {
		_ = s.f.Close()
	}
	if s.rf != nil {
		_ = s.rf.Close()
	}
	return err
}

// printTally summarises what kind of answers came back, e.g.
// "[*] verdicts: rdp(nla)×28, rdp(tls)×6, open-no-answer×2".
func (s *sink) printTally() {
	if len(s.counts) == 0 {
		return
	}
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(s.counts))
	for k, v := range s.counts {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	var b strings.Builder
	for i, e := range all {
		if i == 8 {
			fmt.Fprintf(&b, " +%d more", len(all)-8)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s×%d", e.k, e.v)
	}
	fmt.Printf("[*] verdicts: %s\n", b.String())
}

// ---------- progress ----------

type progress struct {
	cfg   config
	total uint64
	start time.Time
	tty   bool
	last  atomic.Int64
	cur   atomic.Uint64
	any   atomic.Bool
}

func newProgress(cfg config, total uint64) *progress {
	return &progress{cfg: cfg, total: total, start: time.Now(), tty: isTerminal(os.Stdout)}
}

// tick runs on the worker goroutines for every completed attempt; rendering is
// rate-limited so a fast scan does not spend its time formatting escape codes,
// and the CompareAndSwap serialises the renders (which is also what makes
// updating the "shown" flag race-free).
func (p *progress) tick(done, total uint64) {
	p.cur.Store(done)
	if p.cfg.quiet {
		return
	}
	now := time.Now().UnixMilli()
	last := p.last.Load()
	if now-last < 250 {
		return
	}
	if !p.last.CompareAndSwap(last, now) {
		return
	}
	p.any.Store(true)
	p.draw(done, total)
}

// render is called at chunk boundaries (from OnFlush) so that progress advances
// even when a chunk finishes between two throttled ticks.
func (p *progress) render() {
	if p.cfg.quiet {
		return
	}
	p.any.Store(true)
	p.draw(p.cur.Load(), p.total)
}

func (p *progress) draw(done, total uint64) {
	pct := 0.0
	if total > 0 {
		pct = float64(done) / float64(total) * 100
	}
	line := fmt.Sprintf("Progress: %s/%s (%.1f%%)", humanInt(done), humanInt(total), pct)
	if el := time.Since(p.start); el > 0 && done > 0 {
		perSec := float64(done) / el.Seconds()
		line += fmt.Sprintf(" | %s ip/s", humanInt(uint64(perSec+0.5)))
		if perSec > 0 && total > done {
			left := time.Duration(float64(total-done) / perSec * float64(time.Second))
			line += fmt.Sprintf(" | eta %s", left.Round(time.Second))
		}
	}
	if p.tty {
		fmt.Printf("\r\033[K%s", line)
	} else {
		fmt.Println(line)
	}
}

func (p *progress) finish() {
	if p.tty && p.any.Load() {
		fmt.Print("\r\033[K")
	}
}

// ---------- helpers ----------

func log1(cfg config, format string, args ...interface{}) {
	if cfg.quiet {
		return
	}
	fmt.Printf(format+"\n", args...)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// humanInt writes large numbers with thousands separators.
func humanInt(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ---------- argument parsing ----------

func parseArgs(args []string) (config, []string, error) {
	cfg := config{
		output:    defaultOutput,
		timeout:   defaultTimeout,
		port:      defaultPort,
		maxIPs:    defaultMaxIPs,
		check:     rdp.ModeRDP,
		requested: map[string]bool{},
	}

	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printUsage(fs) }

	var (
		conc    = fs.Int("c", 0, "concurrent probes (0 = auto from the CPU count; --eco lowers it)")
		rate    = fs.Float64("rate", 0, "max probes per second (0 = uncapped) — keeps a laptop's CPU, NIC and NAT table alive")
		chunk   = fs.Int("chunk", scan.DefaultChunk, "addresses per chunk: bounds memory and sets how often results are flushed")
		cdelay  = fs.Duration("chunk-delay", 0, "pause after each drained chunk (e.g. 200ms) — spreads the load in time")
		niceLvl = fs.Int("nice", 0, "scheduling priority penalty, 0-19 (Unix only); --eco uses 10")
		maxCPU  = fs.Int("max-cpu", 0, "use at most N CPU cores (0 = all)")
		outFile = fs.String("o", defaultOutput, "output file for live hosts (one IP per line)")
		repFile = fs.String("report", "", "also write a TSV report with one line per answered host, non-RDP included")
		timeout = fs.Duration("t", defaultTimeout, "per-connection TCP timeout (e.g. 2s, 500ms)")
		rt      = fs.Duration("rdp-timeout", 0, "timeout for the RDP negotiation answer (default: --timeout)")
		port    = fs.Int("port", defaultPort, "TCP port to probe (3389 = RDP)")
		check   = fs.String("check", "rdp", `hit criterion: "rdp" = an RDP service must answer; "port" = TCP connect is enough`)
		asnFile = fs.String("asn-file", "", "ASN-to-CIDR database (TSV: asn, range_start, range_end)")
		maxIPs  = fs.Uint64("max-ips", defaultMaxIPs, "safety cap on the number of expanded IPs")
		maxLive = fs.Uint64("max-live", 0, "stop after N live hosts (0 = scan the whole list)")
		excl    = fs.String("exclude", "", "ranges to drop from the target list, e.g. \"10.0.0.0/8,192.168.0.0/16\"")
		shard   = fs.String("shard", "", `scan only shard k of n, "k/n" — split a huge range across machines`)
		inclOpn = fs.Bool("include-open", false, "with --check rdp: also list hosts that answered TCP but gave no RDP evidence")
		eco     = fs.Bool("eco", false, "laptop profile: few sockets, paced probes, chunk pauses, low priority")
		dryRun  = fs.Bool("dry-run", false, "expand, deduplicate and print the plan; send no packets")
		showVer = fs.Bool("v", false, "print version and exit")
		quiet   = fs.Bool("q", false, "no progress or informational output (findings and errors only)")
	)

	// The standard flag package stops at the first positional argument, but the
	// documented usage allows flags after the input files
	// ("rdp-scan ranges.txt -o out.txt -c 200"). Reorder: flags (with their
	// values) first, positionals after; "--" forces everything that follows to
	// be positional. Long aliases are normalised to short flag names so the
	// flag set stays minimal.
	flagArgs, positional := reorderArgs(args)

	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			cfg.done, cfg.code = true, exitOK
			return cfg, nil, nil
		}
		cfg.done, cfg.code = true, exitUsage
		return cfg, nil, nil
	}
	fs.Visit(func(f *flag.Flag) { cfg.requested[f.Name] = true })

	if *showVer {
		fmt.Printf("%s v%s\n", toolName, version)
		cfg.done, cfg.code = true, exitOK
		return cfg, nil, nil
	}

	cfg.quiet = *quiet
	if *eco {
		cfg.eco = true
		if !cfg.requested["c"] {
			*conc = ecoConcurrency
		}
		if !cfg.requested["rate"] {
			*rate = ecoRate
		}
		if !cfg.requested["chunk"] {
			*chunk = ecoChunk
		}
		if !cfg.requested["chunk-delay"] {
			*cdelay = ecoChunkDelay
		}
		if !cfg.requested["nice"] {
			*niceLvl = ecoNice
		}
		if !cfg.requested["t"] {
			*timeout = 2 * time.Second
		}
		log1(cfg, "[i] --eco laptop profile: concurrency %d, %d chunks with %s pauses, %s timeout, %.0f probes/s, nice %d",
			ecoConcurrency, ecoChunk, ecoChunkDelay, *timeout, ecoRate, ecoNice)
	}

	cfg.concurrency = *conc
	if cfg.concurrency <= 0 {
		cfg.concurrency = autoConcurrency()
	}
	cfg.rate = *rate
	cfg.chunk = *chunk
	cfg.chunkDelay = *cdelay
	cfg.nice = *niceLvl
	cfg.maxCPU = *maxCPU
	cfg.output = *outFile
	cfg.report = *repFile
	cfg.timeout = *timeout
	cfg.rdpTimeout = *rt
	cfg.port = *port
	cfg.asnFile = *asnFile
	cfg.maxIPs = *maxIPs
	cfg.maxLive = *maxLive
	cfg.exclude = *excl
	cfg.includeOpen = *inclOpn
	cfg.dryRun = *dryRun

	mode, err := rdp.ParseMode(*check)
	if err != nil {
		return cfg, nil, err
	}
	cfg.check = mode
	if cfg.chunk < scan.MinChunk || cfg.chunk > scan.MaxChunk {
		return cfg, nil, fmt.Errorf("--chunk must be between %d and %d", scan.MinChunk, scan.MaxChunk)
	}
	if cfg.rate < 0 {
		return cfg, nil, errors.New("--rate must be >= 0 (0 disables the cap)")
	}
	if cfg.timeout <= 0 {
		return cfg, nil, fmt.Errorf("timeout must be > 0 (got %s)", cfg.timeout)
	}
	if cfg.rdpTimeout < 0 {
		return cfg, nil, errors.New("--rdp-timeout must be >= 0")
	}
	if cfg.port < 1 || cfg.port > 65535 {
		return cfg, nil, fmt.Errorf("port must be 1-65535 (got %d)", cfg.port)
	}
	if cfg.nice < 0 || cfg.nice > 19 {
		return cfg, nil, fmt.Errorf("nice must be 0-19 (got %d)", cfg.nice)
	}
	if cfg.maxCPU < 0 {
		return cfg, nil, errors.New("--max-cpu must be >= 0")
	}
	sh, err := cidr.ParseShard(*shard)
	if err != nil {
		return cfg, nil, err
	}
	cfg.shard = sh
	return cfg, positional, nil
}

// autoConcurrency sizes the worker pool to the machine: enough sockets to keep
// the pipe full even when most hosts are filtered, but not so many that a
// laptop spends its time context-switching. The scan package clamps the result
// to the process file-descriptor budget as well.
func autoConcurrency() int {
	n := 128 * runtime.NumCPU()
	if n < 128 {
		n = 128
	}
	if n > 1024 {
		n = 1024
	}
	return n
}

// reorderArgs moves flag arguments (with their values) ahead of positional
// arguments so that "rdp-scan ranges.txt -o out.txt -c 200" parses. Flags that
// take a value consume the following argument as their value, unless it looks
// like another flag. "--" terminates flag parsing. Long aliases (--output,
// --concurrency, --timeout, --version, --quiet) normalize to their short forms
// so the flag set stays minimal.
func reorderArgs(args []string) (flagArgs, positional []string) {
	longAlias := map[string]string{
		"output": "o", "concurrency": "c", "timeout": "t", "version": "v", "quiet": "q",
	}
	needsValue := map[string]bool{
		"o": true, "c": true, "t": true, "rate": true, "chunk": true, "chunk-delay": true,
		"nice": true, "max-cpu": true, "report": true, "rdp-timeout": true, "check": true,
		"port": true, "asn-file": true, "max-ips": true, "max-live": true, "exclude": true,
		"shard": true,
	}
	afterSep := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if afterSep {
			positional = append(positional, a)
			continue
		}
		if a == "--" {
			afterSep = true
			continue
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		val := ""
		hasValue := false
		if j := strings.IndexByte(name, '='); j >= 0 {
			name, val, hasValue = name[:j], name[j+1:], true
		}
		if alias, ok := longAlias[name]; ok {
			if hasValue {
				a = "-" + alias + "=" + val
			} else {
				a = "-" + alias
			}
			name = alias
		}
		if !hasValue && needsValue[name] && i+1 < len(args) {
			next := args[i+1]
			if !strings.HasPrefix(next, "-") || isNegativeNumber(next) {
				flagArgs = append(flagArgs, a, next)
				i++
				continue
			}
		}
		flagArgs = append(flagArgs, a)
	}
	return flagArgs, positional
}

// isNegativeNumber reports whether s looks like a negative numeric flag value
// ("-5", "-1.5s"), which flag parsing consumes as a value.
func isNegativeNumber(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	return s[1] >= '0' && s[1] <= '9'
}

func printUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s v%s — RDP exposure scanner: find hosts where RDP is live, not just ports that answer

USAGE:
  %s [flags] <input> [input ...]

HIT CRITERION (--check):
  rdp    (default) the host must answer the X.224 RDP negotiation request —
         i.e. an RDP service is really running and working on that port. The
         answer also reports the security layer it wants (NLA / TLS / legacy)
         and negotiation failures, without any authentication attempt.
  port   a completed TCP handshake is enough: "3389 is open", whatever runs
         behind it. Cheaper, useful for very large sweeps.

INPUTS (one or more, in any mix):
  <file>       target file, one entry per line (CIDRs, IPs, ASNs, ranges, wildcards)
  <cidr>       10.0.0.0/24
  <ip>         10.0.0.5
  <asn>        AS15169            (needs an ASN database, see --asn-file)
  <range>      10.0.0.1-10.0.0.9
  <wildcard>   10.0.0.*

  Lines starting with '#' are comments; inline '# comments' and blank lines
  are ignored. Malformed entries are skipped with a warning. No ICMP, no UDP,
  no authentication is ever attempted; no root rights are needed.

  Long aliases: --output, --concurrency, --timeout, --version, --quiet.

BIG RANGES ON A SMALL MACHINE:
  --chunk N        targets are streamed in batches of N (default %d), so a /8
                   costs the same memory as a /24; results are flushed per batch
  --chunk-delay d  pause between batches, e.g. 200ms
  --rate n         probes per second cap (0 = off)
  --eco            laptop profile: concurrency %d, %s chunks, %s pauses, nice %d
  --max-cpu N      use at most N CPU cores
  --max-live N     stop as soon as N live hosts were found
  --shard k/n      scan only every n-th address (offset k); run several shards
                   in parallel on different boxes, then concatenate the outputs
  --exclude c      drop ranges from the target list (VPN/lab/RFC1918 noise)
  --dry-run        expand, deduplicate, print the plan, send nothing

FLAGS:
`, toolName, version, toolName, toolName, scan.DefaultChunk, ecoConcurrency,
		ecoChunk, ecoChunkDelay, ecoNice)
	if fs != nil {
		fs.PrintDefaults()
	}
	fmt.Printf(`
EXAMPLES:
  %s ranges.txt                                   # verified RDP hosts only
  %s ranges.txt -o rdp_live.txt --report rdp.tsv   # + detail per answered host
  %s 10.0.0.0/16 --eco                              # laptop-friendly
  %s 10.0.0.0/8 --chunk 8192 --rate 400             # huge range, paced, flat memory
  %s 10.0.0.0/8 --dry-run                           # what would this cost?
  %s 10.0.0.0/16 --check port                       # only care that 3389 is open
  %s AS15169 --asn-file ip2asn-v4.tsv
  %s 10.0.0.0/8 --shard 0/2 -o part0.txt & %s 10.0.0.0/8 --shard 1/2 -o part1.txt &

EXIT CODES:
  0    scan finished (zero found hosts is still exit 0)
  1    runtime error (unreadable input, unwritable output, ...)
  2    usage error (bad flags, no input)
  130  interrupted (SIGINT/SIGTERM) — results found so far are already on disk
`, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName)
}
