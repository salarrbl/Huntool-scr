package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/cidr"
	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/rdp"
	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/scan"
)

func TestReorderArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		fl   []string // flag arguments, in order, values attached
		pos  []string // target arguments, in order
	}{
		{
			name: "a bool flag does not swallow the targets",
			in:   []string{"-q", "10.0.0.0/24"},
			fl:   []string{"-q"}, pos: []string{"10.0.0.0/24"},
		},
		{
			name: "a flag with a value moves with its value",
			in:   []string{"-c", "64", "targets.txt"},
			fl:   []string{"-c", "64"}, pos: []string{"targets.txt"},
		},
		{
			name: "--flag=value stays one token",
			in:   []string{"--check=port", "-v", "1.2.3.4"},
			fl:   []string{"--check=port", "-v"}, pos: []string{"1.2.3.4"},
		},
		{
			name: "-c64 is already one token",
			in:   []string{"-c64", "1.2.3.4"},
			fl:   []string{"-c64"}, pos: []string{"1.2.3.4"},
		},
		{
			name: "flags after the files are picked up",
			in:   []string{"ranges.txt", "-o", "out.txt", "-c", "200"},
			fl:   []string{"-o", "out.txt", "-c", "200"}, pos: []string{"ranges.txt"},
		},
		{
			name: "a value that looks negative is still a value",
			in:   []string{"-c", "-1", "1.2.3.4"},
			fl:   []string{"-c", "-1"}, pos: []string{"1.2.3.4"},
		},
		{
			name: "a flag last on the command line keeps its value",
			in:   []string{"1.2.3.4", "-o"},
			fl:   []string{"-o"}, pos: []string{"1.2.3.4"},
		},
		{
			name: "everything mixed",
			in:   []string{"--eco", "-v", "-c", "32", "a.txt", "b.txt"},
			fl:   []string{"--eco", "-v", "-c", "32"}, pos: []string{"a.txt", "b.txt"},
		},
		{
			name: "-- ends the flags",
			in:   []string{"--", "-o", "--weird"},
			fl:   nil, pos: []string{"-o", "--weird"},
		},
		{
			name: "nothing to do", in: nil, fl: nil, pos: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, pos := reorderArgs(tt.in)
			if !reflect.DeepEqual(fl, tt.fl) {
				t.Errorf("flagArgs = %v, want %v", fl, tt.fl)
			}
			if !reflect.DeepEqual(pos, tt.pos) {
				t.Errorf("positional = %v, want %v", pos, tt.pos)
			}
			// Reordering must never lose or invent an argument (only "--" is
			// consumed, and it is not an argument to anything).
			var got []string
			got = append(got, fl...)
			got = append(got, pos...)
			want := make([]string, 0, len(tt.in))
			for _, a := range tt.in {
				if a != "--" {
					want = append(want, a)
				}
			}
			if len(got) == len(want) {
				sort.Strings(got)
				sort.Strings(want)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("argument multiset changed: %v -> %v", tt.in, append(fl, pos...))
				}
			} else {
				t.Errorf("got %d arguments back, input had %d", len(got), len(want))
			}
		})
	}
}

func TestLongAliasesResolveToShortFlags(t *testing.T) {
	fl, _ := reorderArgs([]string{"--output", "x.txt", "--concurrency", "5", "--timeout", "500ms", "--quiet", "--version"})
	want := []string{"-o", "x.txt", "-c", "5", "-t", "500ms", "-q", "-v"}
	if !reflect.DeepEqual(fl, want) {
		t.Fatalf("reorderArgs aliases:\n got %v\nwant %v", fl, want)
	}
	cfg, _, err := parseArgs([]string{"--output", "x.txt", "--concurrency", "5", "--timeout", "500ms", "--quiet", "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.output != "x.txt" || cfg.concurrency != 5 || cfg.timeout != 500*time.Millisecond || !cfg.quiet {
		t.Fatalf("long aliases not applied: %+v", cfg)
	}
}

func TestHumanInt(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{0, "0"}, {7, "7"}, {999, "999"}, {1000, "1,000"}, {1234567, "1,234,567"},
		{1 << 24, "16,777,216"}, {1 << 32, "4,294,967,296"},
	}
	for _, tt := range tests {
		if got := humanInt(tt.n); got != tt.want {
			t.Errorf("humanInt(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestParseArgsDefaults(t *testing.T) {
	cfg, pos, err := parseArgs([]string{"targets.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.done {
		t.Fatalf("unexpected early exit: %+v", cfg)
	}
	if !reflect.DeepEqual(pos, []string{"targets.txt"}) {
		t.Fatalf("positional = %v", pos)
	}
	if cfg.concurrency <= 0 {
		t.Errorf("concurrency should be auto (>=1), got %d", cfg.concurrency)
	}
	if cfg.check != rdp.ModeRDP {
		t.Errorf("verification must default to RDP, got %q", cfg.check)
	}
	if cfg.chunk != scan.DefaultChunk {
		t.Errorf("chunk = %d, want %d", cfg.chunk, scan.DefaultChunk)
	}
	if cfg.rate != 0 || cfg.chunkDelay != 0 || cfg.nice != 0 || cfg.maxCPU != 0 {
		t.Errorf("resource pacing must be off by default: %+v", cfg)
	}
	if cfg.output != defaultOutput || cfg.report != "" {
		t.Errorf("output/report = %q/%q", cfg.output, cfg.report)
	}
	if cfg.maxIPs != defaultMaxIPs {
		t.Errorf("max-ips = %d, want %d", cfg.maxIPs, defaultMaxIPs)
	}
	if cfg.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", cfg.timeout, defaultTimeout)
	}
	if cfg.port != defaultPort {
		t.Errorf("port = %d, want %d", cfg.port, defaultPort)
	}
	if len(cfg.requested) != 0 {
		t.Errorf("nothing was typed, but requested = %v", cfg.requested)
	}
}

func TestParseArgsTracksWhatTheUserTyped(t *testing.T) {
	cfg, _, err := parseArgs([]string{"-c", "7", "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.requested["c"] {
		t.Fatal(`"-c 7" must be recorded as user-set (that is what --eco respects)`)
	}
	if cfg.requested["chunk"] || cfg.requested["rate"] {
		t.Fatalf("untyped flags must stay unmarked: %v", cfg.requested)
	}
}

func TestParseArgsEcoOverridesOnlyDefaults(t *testing.T) {
	cfg, _, err := parseArgs([]string{"--eco", "-c", "999", "--rate", "7", "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.concurrency != 999 || cfg.rate != 7 {
		t.Errorf("--eco overwrote explicit flags: c=%d rate=%v", cfg.concurrency, cfg.rate)
	}
	if cfg.chunk != ecoChunk || cfg.chunkDelay != ecoChunkDelay || cfg.nice != ecoNice {
		t.Errorf("--eco profile not applied: %+v", cfg)
	}
	if cfg.timeout != 2*time.Second {
		t.Errorf("--eco timeout = %v, want 2s", cfg.timeout)
	}
	if !cfg.eco {
		t.Error("cfg.eco should be set")
	}
	cfg, _, err = parseArgs([]string{"--eco", "-t", "250ms", "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.timeout != 250*time.Millisecond {
		t.Errorf("an explicit -t must win over --eco, got %v", cfg.timeout)
	}
	if cfg.concurrency != ecoConcurrency {
		t.Errorf("--eco default concurrency lost: %d", cfg.concurrency)
	}
}

func TestParseArgsAcceptsAttachedValues(t *testing.T) {
	cfg, pos, err := parseArgs([]string{"-c16", "--chunk=64", "-t", "1s", "targets.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.concurrency != 16 || cfg.chunk != 64 || cfg.timeout != time.Second {
		t.Errorf("attached values not parsed: %+v", cfg)
	}
	if !reflect.DeepEqual(pos, []string{"targets.txt"}) {
		t.Errorf("positional = %v", pos)
	}
}

func TestParseArgsRejectsBadValues(t *testing.T) {
	for _, args := range [][]string{
		{"--check", "http", "1.2.3.4"},
		{"--shard", "3/3", "1.2.3.4"},
		{"--shard", "0/0", "1.2.3.4"},
		{"--shard", "a/b", "1.2.3.4"},
		{"--port", "0", "1.2.3.4"},
		{"--port", "70000", "1.2.3.4"},
		{"--chunk", "3", "1.2.3.4"},                     // below MinChunk
		{"--chunk", "99999999", "1.2.3.4"},              // above MaxChunk
		{"--rate", "-5", "1.2.3.4"},                     // negative pacing
		{"-t", "0s", "1.2.3.4"},                         // zero timeout
		{"--rdp-timeout", "-1s", "1.2.3.4"},             // negative
		{"--nice", "25", "1.2.3.4"},                     // out of range
		{"--max-cpu", "-1", "1.2.3.4"},                  // negative
		{"1.2.3.4"},                                     // fine, see below
	} {
		_, _, err := parseArgs(args)
		if args[0] == "1.2.3.4" {
			if err != nil {
				t.Fatalf("parseArgs(%v) should be fine: %v", args, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("parseArgs(%v) should fail", args)
			continue
		}
		if strings.TrimSpace(err.Error()) == "" || err.Error() == "flag provided but not defined" {
			t.Errorf("parseArgs(%v) error should explain itself: %q", args, err)
		}
	}
}

func TestParseArgsEarlyExits(t *testing.T) {
	cfg, _, err := parseArgs([]string{"-v"})
	if err != nil || !cfg.done || cfg.code != exitOK {
		t.Fatalf("-v should print the version and exit 0, got %+v %v", cfg, err)
	}
	cfg, _, err = parseArgs([]string{"--help"})
	if err != nil || !cfg.done || cfg.code != exitOK {
		t.Fatalf("--help should exit 0, got %+v %v", cfg, err)
	}
	cfg, _, err = parseArgs([]string{"-nope", "1.2.3.4"})
	if err != nil || !cfg.done || cfg.code != exitUsage {
		t.Fatalf("an unknown flag should exit 2, got %+v %v", cfg, err)
	}
	cfg, _, err = parseArgs([]string{"-c", "notanumber", "1.2.3.4"})
	if err != nil || !cfg.done || cfg.code != exitUsage {
		t.Fatalf("a malformed flag value should exit 2, got %+v %v", cfg, err)
	}
}

func TestParseArgsNegativeConcurrencyMeansAuto(t *testing.T) {
	// "-c -1" is documented as "0 = auto"; a negative value must not produce a
	// pool of negative size (the scan package would reject it).
	cfg, _, err := parseArgs([]string{"-c", "-1", "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.concurrency < 1 {
		t.Fatalf("concurrency = %d, want a positive auto value", cfg.concurrency)
	}
}

func TestParseArgsEmptyCheckMeansRDP(t *testing.T) {
	// "" is the flag's zero value, and the zero value means the safe default.
	cfg, _, err := parseArgs([]string{"--check", "", "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.check != rdp.ModeRDP {
		t.Fatalf("--check \"\" = %q, want rdp", cfg.check)
	}
}

func TestAutoConcurrencyFitsTheMachine(t *testing.T) {
	n := autoConcurrency()
	if n < 128 || n > 1024 {
		t.Fatalf("autoConcurrency = %d, want between 128 and 1024", n)
	}
	if max := 128 * runtime.NumCPU(); n > max && max >= 128 {
		t.Fatalf("autoConcurrency %d exceeds the CPU-derived cap %d", n, max)
	}
}

func TestSinkWritesWhatItPromises(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "live.txt")
	rep := filepath.Join(dir, "report.tsv")
	cfg := config{output: out, report: rep, check: rdp.ModeRDP, quiet: true}
	s, err := newSink(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The scanner hands results over in ascending order within a chunk; the
	// sink preserves that order instead of buffering and re-sorting, so the
	// test feeds them the same way.
	results := []scan.Result{
		{IP: v4("10.0.0.1"), Port: 3389, State: rdp.StateNotRDP, Detail: "not RDP — answered: HTTP/1.1 418", RTT: time.Millisecond},
		{IP: v4("10.0.0.2"), Port: 3389, State: rdp.StateOpen, Detail: "no answer", RTT: 2 * time.Millisecond},
		{IP: v4("10.0.0.5"), Port: 3389, State: rdp.StateRDP, Detail: "RDP up — NLA (CredSSP)", RTT: 3 * time.Millisecond},
		{IP: v4("10.0.0.6"), Port: 3389, State: rdp.StateRDP, Detail: "RDP up — standard RDP security (no negotiation)"},
	}
	for _, r := range results {
		s.add(r)
	}
	if s.err != nil {
		t.Fatal(s.err)
	}
	// With --check rdp and no --include-open: only RDP-verified hosts are hits.
	if s.written != 2 {
		t.Fatalf("written = %d, want 2 (the RDP-verified hosts only)", s.written)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, out); !reflect.DeepEqual(got, []string{"10.0.0.5", "10.0.0.6"}) {
		t.Fatalf("output file = %v, want the two RDP hosts in ascending order", got)
	}
	report := readLines(t, rep)
	if len(report) != 1+len(results) {
		t.Fatalf("report has %d lines, want header + %d", len(report), len(results))
	}
	if !strings.HasPrefix(report[0], "# ip\tport\tstate") {
		t.Errorf("report header = %q", report[0])
	}
	// The report is the "everything that answered" file, non-RDP included.
	body := strings.Join(report[1:], "\n")
	for _, want := range []string{"10.0.0.1\t3389\tnot-rdp", "10.0.0.2\t3389\topen", "10.0.0.5\t3389\trdp", "10.0.0.6\t3389\trdp", "3ms"} {
		if !strings.Contains(body, want) {
			t.Errorf("report should contain %q, got:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "-\t\n") && !strings.Contains(body, "no answer") {
		t.Errorf("an empty detail should be written as \"-\" or kept verbatim:\n%s", body)
	}
}

func TestSinkIncludeOpenAdmitsSilentHosts(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "live.txt")
	s, err := newSink(config{output: out, check: rdp.ModeRDP, includeOpen: true, quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	s.add(scan.Result{IP: v4("10.0.0.2"), Port: 3389, State: rdp.StateOpen})
	s.add(scan.Result{IP: v4("10.0.0.3"), Port: 3389, State: rdp.StateNotRDP}) // never, even with --include-open
	s.add(scan.Result{IP: v4("10.0.0.4"), Port: 3389, State: rdp.StateRDP})
	_ = s.close()
	if got := readLines(t, out); !reflect.DeepEqual(got, []string{"10.0.0.2", "10.0.0.4"}) {
		t.Fatalf("output = %v, want the silent and the RDP host", got)
	}
}

func TestSinkPortModeKeepsEveryLiveHost(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "live.txt")
	s, err := newSink(config{output: out, check: rdp.ModePort, quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []scan.Result{
		{IP: v4("10.0.0.8"), State: rdp.StateNotRDP},
		{IP: v4("10.0.0.9"), State: rdp.StateOpen},
	} {
		s.add(r)
	}
	_ = s.close()
	if got := readLines(t, out); !reflect.DeepEqual(got, []string{"10.0.0.8", "10.0.0.9"}) {
		t.Fatalf("output = %v, want both live hosts", got)
	}
}

func TestSinkReportsWriteErrorsInsteadOfPanicking(t *testing.T) {
	if _, err := newSink(config{output: filepath.Join(t.TempDir(), "missing-dir", "live.txt"), check: rdp.ModePort}); err == nil {
		t.Fatal("an unwritable output path must be reported as an error")
	}
}

func TestKeyForAndSecurityBucket(t *testing.T) {
	tests := []struct{ detail, want string }{
		{"RDP up — NLA (CredSSP)", "rdp(nla)"},
		{"RDP up — NLA with early user info", "rdp(nla-ex)"},
		{"RDP up — TLS", "rdp(tls)"},
		{"RDP up — Remote Credential Guard", "rdp(rcg)"},
		{"RDP up — standard RDP security (no negotiation)", "rdp(standard)"},
		{"RDP up — negotiation refused: NLA (HYBRID) required by server", "rdp(neg-fail)"},
		{"RDP refused the negotiation (X.224 disconnect)", "rdp(refused)"},
	}
	for _, tt := range tests {
		if got := securityBucket(tt.detail); got != tt.want {
			t.Errorf("securityBucket(%q) = %q, want %q", tt.detail, got, tt.want)
		}
		k := keyFor(scan.Result{State: rdp.StateRDP, Detail: tt.detail})
		if k != tt.want {
			t.Errorf("keyFor(rdp %q) = %q, want %q", tt.detail, k, tt.want)
		}
	}
	if k := keyFor(scan.Result{State: rdp.StateNotRDP, Detail: "not RDP — answered: HTTP/1.1 200 OK"}); k != "not-rdp" {
		t.Errorf("keyFor(not-rdp) = %q", k)
	}
	if k := keyFor(scan.Result{State: rdp.StateOpen, Detail: "no answer"}); k != "open-no-answer" {
		t.Errorf("keyFor(open) = %q", k)
	}
}

func TestProgressCallbackFiresOnEmptyChunks(t *testing.T) {
	// Regression: a chunk with zero hits used to be invisible (the publish fast
	// path returned early), so progress and per-chunk flushing stalled on the
	// common case of a range full of dead addresses.
	ips := []uint32{v4("127.0.0.1"), v4("127.0.0.2"), v4("127.0.0.3")}
	flushes := 0
	stats, err := scan.Scan(context.Background(), ips, scan.Options{
		Concurrency: 2, Timeout: 50 * time.Millisecond, Port: 9,
		OnFlush: func() { flushes++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if flushes == 0 {
		t.Fatal("OnFlush never ran: results would never be flushed on a quiet chunk")
	}
	if stats.Chunks != 1 {
		t.Fatalf("chunks = %d, want 1", stats.Chunks)
	}
	if stats.Live != 0 {
		t.Fatalf("live = %d, want 0 on loopback with nothing bound", stats.Live)
	}
}

func TestRunDryRunPlansWithoutTouchingTheNetwork(t *testing.T) {
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	body := "10.0.0.0/24\n# comment\n10.0.1.0/24   # inline comment\n10.0.2.5\n10.0.2.10-10.0.2.20\n"
	if err := os.WriteFile(targets, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "should-not-exist.txt")
	code := run([]string{"--dry-run", "-q", "-o", out, targets})
	if code != exitOK {
		t.Fatalf("dry run exit code = %d, want 0", code)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("--dry-run must not create the output file")
	}
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targets, []byte("10.0.0.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no input at all", []string{}, exitUsage},
		{"only flags", []string{"-c", "8"}, exitUsage},
		{"bad flag", []string{"--nope"}, exitUsage},
		{"missing input file", []string{filepath.Join(dir, "nope.txt")}, exitError},
		{"file without a single target", []string{filepath.Join(dir, "empty.txt")}, exitError},
		{"beyond the safety cap", []string{"--dry-run", "-q", "--max-ips", "10", "10.0.0.0/8"}, exitError},
		{"shard 0/1 is inert", []string{"--dry-run", "-q", "--shard", "0/1", filepath.Join(dir, "one.txt")}, exitOK},
		{"shard with no addresses in it", []string{"--dry-run", "-q", "--shard", "1/4", filepath.Join(dir, "one.txt")}, exitUsage},
		{"exclude removes everything", []string{"--dry-run", "-q", "--exclude", "10.0.0.0/24", targets}, exitError},
		{"bad --exclude syntax", []string{"--dry-run", "-q", "--exclude", "10.0.0.0/99", targets}, exitUsage},
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), []byte("# nothing here\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte("10.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args); got != tt.want {
				t.Errorf("run(%v) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}

func TestLoadTargetsDeduplicatesAndCounts(t *testing.T) {
	dir := t.TempDir()
	targets := filepath.Join(dir, "t.txt")
	body := "10.0.0.0/24\n10.0.0.128/25\n10.0.0.0\n10.0.1.0-10.0.1.3\ngarbage-line\n"
	if err := os.WriteFile(targets, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	spans, err := loadTargets(config{}, []string{targets})
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.0/24 plus the 11-address dash range; the /25 and the bare IP are
	// already inside the /24, and the garbage line is skipped with a warning.
	if got := cidr.CountIPs(cidr.MergeSpans(spans)); got != 256+11 {
		t.Fatalf("CountIPs = %d, want %d", got, 256+11)
	}
	// A directory is not a target file.
	if _, err := loadTargets(config{}, []string{dir}); err == nil {
		t.Fatal("a directory input should be an error")
	}
}

func TestExcludeAndShardAffectThePlan(t *testing.T) {
	base := v4("10.0.0.0")
	spans := cidr.MergeSpans([]cidr.Span{{Start: base, End: base + 255}})
	holes, err := cidr.ParseSpanList("10.0.0.64-10.0.0.127")
	if err != nil {
		t.Fatal(err)
	}
	left := cidr.Subtract(spans, holes)
	if got := cidr.CountIPs(left); got != 192 { // 256 - 64
		t.Fatalf("after --exclude: %d addresses, want 192", got)
	}
	sh := cidr.Shard{Index: 1, Count: 4}
	if got := cidr.ShardCount(192, sh); got != 48 {
		t.Fatalf("shard 1/4 of 192 = %d, want 48", got)
	}
	if got := cidr.TotalChunks(192, 64); got != 3 {
		t.Fatalf("chunks = %d, want 3", got)
	}
}

// ---------- helpers ----------

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func v4(s string) uint32 {
	var v uint32
	for _, part := range strings.Split(s, ".") {
		n := 0
		for i := 0; i < len(part); i++ {
			n = n*10 + int(part[i]-'0')
		}
		v = v<<8 | uint32(n)
	}
	return v
}
