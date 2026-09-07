// Command rdp-scan is a lightweight RDP exposure scanner for authorized
// penetration-testing engagements.
//
// It reads IPv4 targets (CIDR ranges, single IPs, AS numbers, dash ranges
// and wildcards) from files or the command line, expands and deduplicates
// them, then checks TCP/3389 connectivity on each address. A host is
// reported only when the TCP handshake itself succeeds — no ICMP, no UDP,
// no banner exchange, no authentication. The reachable IPs are written to
// an output file, one per line.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/cidr"
	"github.com/salarrbl/Huntool-scr/rdp-scan/internal/scan"
)

const (
	toolName = "rdp-scan"
	version  = "1.0.0"

	defaultOutput      = "rdp_live.txt"
	defaultConcurrency = 500
	defaultTimeout     = 3 * time.Second
	defaultPort        = 3389     // RDP
	defaultMaxIPs      = 33554432 // 2^25: safety cap on expanded IPs
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

func run(args []string) int {
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printUsage(fs) }

	var (
		outFile = fs.String("o", defaultOutput, "output file for reachable IPs (one per line)")
		conc    = fs.Int("c", defaultConcurrency, "number of concurrent TCP connection attempts")
		timeout = fs.Duration("t", defaultTimeout, "per-connection TCP timeout (e.g. 2s, 500ms)")
		port    = fs.Int("port", defaultPort, "TCP port to probe (3389 = RDP)")
		asnFile = fs.String("asn-file", "", "ASN-to-CIDR database (TSV: asn, range_start, range_end)")
		maxIPs  = fs.Uint64("max-ips", defaultMaxIPs, "safety cap on the number of expanded IPs")
		showVer = fs.Bool("v", false, "print version and exit")
	)
	// The standard flag package stops at the first positional argument, but
	// the documented usage allows flags after the input files
	// ("rdp-scan ranges.txt -o out.txt -c 200"). Reorder: flags (with their
	// values) first, positionals after; "--" forces everything following to
	// be positional.
	flagArgs, positional := reorderArgs(args)

	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *showVer {
		fmt.Printf("%s v%s\n", toolName, version)
		return exitOK
	}

	inputs := positional
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no input given — provide at least one file, CIDR, IP or ASN")
		fs.Usage()
		return exitUsage
	}
	if *conc < 1 {
		fmt.Fprintf(os.Stderr, "error: concurrency must be >= 1 (got %d)\n", *conc)
		return exitUsage
	}
	if *timeout <= 0 {
		fmt.Fprintf(os.Stderr, "error: timeout must be > 0 (got %s)\n", *timeout)
		return exitUsage
	}
	if *port < 1 || *port > 65535 {
		fmt.Fprintf(os.Stderr, "error: port must be 1-65535 (got %d)\n", *port)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ---------- 1. load targets ----------
	fmt.Println("[*] Loading targets...")
	parser := &cidr.Parser{
		ASNPath: *asnFile,
		Warn: func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
		},
	}
	var spans []cidr.Span
	for _, in := range inputs {
		st, statErr := os.Stat(in)
		switch {
		case statErr == nil && st.Mode().IsRegular():
			fmt.Printf("[*] Loading file: %s\n", in)
			sp, err := parser.ParseFile(in)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return exitError
			}
			spans = append(spans, sp...)
		case statErr == nil:
			fmt.Fprintf(os.Stderr, "error: %q is not a regular file\n", in)
			return exitError
		default:
			sp, err := parser.ParseToken(in)
			if err != nil {
				if strings.ContainsAny(in, `/\`) {
					fmt.Fprintf(os.Stderr, "error: input file not found: %q\n", in)
				} else {
					fmt.Fprintf(os.Stderr, "error: invalid target %q: %v\n", in, err)
				}
				return exitError
			}
			spans = append(spans, sp...)
		}
	}
	if len(spans) == 0 {
		fmt.Fprintln(os.Stderr, "error: no valid targets found in the given inputs")
		return exitError
	}

	// ---------- 2. expand + deduplicate ----------
	fmt.Printf("[*] Expanding %d range(s)...\n", len(spans))
	ips, err := cidr.Expand(spans, *maxIPs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Printf("[+] %d unique IPs\n", len(ips))

	// ---------- 3. scan TCP/3389 ----------
	fmt.Printf("[*] Scanning TCP/%d (%d concurrent, %s timeout)...\n", *port, *conc, *timeout)

	tty := isTerminal(os.Stdout)
	var lastTick atomic.Int64 // unix millis of last progress render
	progressShown := false
	onProgress := func(done, total uint64) {
		now := time.Now().UnixMilli()
		last := lastTick.Load()
		if now-last < 250 {
			return
		}
		if !lastTick.CompareAndSwap(last, now) {
			return
		}
		pct := 0.0
		if total > 0 {
			pct = float64(done) / float64(total) * 100
		}
		line := fmt.Sprintf("Progress: %d/%d (%.1f%%)", done, total, pct)
		if tty {
			fmt.Printf("\r\033[K%s", line)
		} else {
			fmt.Println(line)
		}
		progressShown = true
	}
	onLive := func(ip uint32) {
		if tty {
			fmt.Printf("\r\033[K")
		}
		fmt.Printf("[+] %s:%d OPEN\n", cidr.FormatIPv4(ip), *port)
	}

	live, stats, err := scan.Scan(ctx, ips, scan.Options{
		Concurrency: *conc,
		Timeout:     *timeout,
		Port:        *port,
		OnProgress:  onProgress,
		OnLive:      onLive,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if progressShown && tty {
		fmt.Printf("\r\033[K")
	}
	if ctx.Err() != nil {
		fmt.Println("[!] Scan interrupted — results below are partial")
	} else {
		fmt.Println("[+] Scan complete")
	}
	fmt.Printf("[*] %d live | %d refused | %d timeout | %d other | elapsed %s\n",
		stats.Live, stats.Refused, stats.Timeout, stats.Other, stats.Elapsed.Round(10*time.Millisecond))
	fmt.Printf("[+] %d RDP host(s) found\n", stats.Live)

	// ---------- 4. write results ----------
	if err := writeResults(*outFile, live); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Printf("[+] Results saved to: %s\n", *outFile)

	if ctx.Err() != nil {
		return exitInterrupt
	}
	return exitOK
}

// writeResults writes one IP per line to path, truncating any existing file.
func writeResults(path string, ips []uint32) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create output file %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, ip := range ips {
		if _, err := w.WriteString(cidr.FormatIPv4(ip)); err != nil {
			return fmt.Errorf("writing output file %s: %w", path, err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return fmt.Errorf("writing output file %s: %w", path, err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("writing output file %s: %w", path, err)
	}
	return nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// reorderArgs moves flag arguments (with their values) ahead of positional
// arguments so that "rdp-scan ranges.txt -o out.txt -c 200" parses. Flags
// that take a value consume the following argument as their value, unless
// it looks like another flag. "--" terminates flag parsing. Long aliases
// (--output, --concurrency, --timeout, --version) are normalized to their
// short forms so the flag set stays minimal.
func reorderArgs(args []string) (flagArgs, positional []string) {
	longAlias := map[string]string{
		"output": "o", "concurrency": "c", "timeout": "t", "version": "v",
	}
	needsValue := map[string]bool{
		"o": true, "c": true, "t": true,
		"port": true, "asn-file": true, "max-ips": true,
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

// isNegativeNumber reports whether s looks like a negative numeric flag
// value ("-5", "-1.5s"), which flag parsing consumes as a value.
func isNegativeNumber(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	return s[1] >= '0' && s[1] <= '9'
}

func printUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s v%s — RDP exposure scanner (TCP connect discovery only)

USAGE:
  %s [flags] <input> [input ...]

INPUTS (one or more, in any mix):
  <file>       target file, one entry per line (CIDRs, IPs, ASNs, ranges, wildcards)
  <cidr>       10.0.0.0/24
  <ip>         10.0.0.5
  <asn>        AS15169            (needs an ASN database, see --asn-file)
  <range>      10.0.0.1-10.0.0.9
  <wildcard>   10.0.0.*

  Lines starting with '#' are comments; inline '# comments' and blank
  lines are ignored. Malformed entries are skipped with a warning.
  TCP port %d is the only port probed — connectivity itself is the
  liveness test. No ICMP, no UDP, no authentication is ever attempted.

  Long aliases: --output, --concurrency, --timeout, --version.

FLAGS:
`, toolName, version, toolName, defaultPort)
	fs.PrintDefaults()
	fmt.Printf(`
EXAMPLES:
  %s ranges.txt
  %s ranges.txt -o rdp_live.txt -c 200 -t 2s
  %s 10.0.0.0/16 AS15169 10.9.9.9 -o live.txt
  %s targets1.txt targets2.txt AS32934 --asn-file ip2asn-v4.tsv

EXIT CODES:
  0    scan finished (zero found hosts is still exit 0)
  1    runtime error (unreadable input, bad output path, ...)
  2    usage error (bad flags, no input)
  130  interrupted (SIGINT/SIGTERM) — partial results were still saved
`, toolName, toolName, toolName, toolName)
}
