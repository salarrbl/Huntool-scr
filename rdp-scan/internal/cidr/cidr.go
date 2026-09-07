// Package cidr parses target specifications (IPv4, CIDR, ASN, ranges and
// wildcards) from command-line arguments and input files, and expands them
// into a deduplicated, sorted list of individual IPv4 addresses.
//
// No external libraries are used: everything is stdlib only. Addresses are
// represented internally as uint32 values (big-endian byte order) so that
// expansion and deduplication stay fast even for tens of millions of IPs.
package cidr

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Span is an inclusive IPv4 range [Start, End] stored as uint32 endpoints.
type Span struct {
	Start uint32
	End   uint32
}

// Count returns the number of IPv4 addresses in the span.
func (s Span) Count() uint64 { return uint64(s.End) - uint64(s.Start) + 1 }

// ParseIPv4 parses a strict dotted-quad IPv4 address ("1.2.3.4") into a
// uint32 in big-endian byte order. It rejects malformed input such as
// "1.2.3", "1.2.3.4.5", "256.0.0.1", "1..2.3" or "1.2.3.a".
func ParseIPv4(s string) (uint32, error) {
	var out uint32
	val, parts := -1, 0
	// Iterate one byte past the end so the loop body can flush the final
	// octet with a sentinel.
	for i := 0; i <= len(s); i++ {
		var c byte
		if i < len(s) {
			c = s[i]
		}
		if c >= '0' && c <= '9' {
			if val == -1 {
				val = 0
			}
			val = val*10 + int(c-'0')
			if val > 255 {
				return 0, fmt.Errorf("octet %d out of range (0-255) in %q", parts+1, s)
			}
			continue
		}
		if c == '.' || i == len(s) {
			if val == -1 {
				return 0, fmt.Errorf("empty octet in %q", s)
			}
			if parts >= 4 {
				return 0, fmt.Errorf("too many octets in %q", s)
			}
			out = out<<8 | uint32(val)
			parts++
			val = -1
			continue
		}
		return 0, fmt.Errorf("invalid character %q in %q", c, s)
	}
	if parts != 4 {
		return 0, fmt.Errorf("expected 4 octets in %q, got %d", s, parts)
	}
	return out, nil
}

// FormatIPv4 renders a uint32 back into dotted-quad notation.
func FormatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff)
}

// maskBits returns a /n netmask as a uint32. maskBits(0) == 0 and
// maskBits(32) == 0xffffffff.
func maskBits(n int) uint32 {
	if n == 0 {
		return 0
	}
	return ^uint32(0) << (32 - n)
}

// Parser converts raw target tokens into Spans. Malformed tokens are
// reported through Warn (if set) and skipped so that a single bad line never
// aborts a whole scan.
type Parser struct {
	// ASNPath is the path to an ASN-to-CIDR database in TSV form. It is
	// loaded lazily on the first ASN token. If empty, standard locations
	// are tried (see defaultASNPath).
	ASNPath string

	// Warn receives non-fatal parse diagnostics. It may be nil.
	Warn func(format string, args ...interface{})

	asnOnce sync.Once
	asnDB   *ASNDB
	asnErr  error
}

// ParseFile reads a target file line by line and returns the spans it found.
// Blank lines, comment lines, and inline comments (after '#') are ignored,
// as are whitespace-separated extra tokens on a line. Malformed tokens are
// reported via Warn and skipped. An error is returned only for I/O problems.
func (p *Parser) ParseFile(path string) ([]Span, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open input file: %w", err)
	}
	defer f.Close()

	var spans []Span
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		sp, err := p.ParseLine(sc.Text())
		if err != nil && p.Warn != nil {
			p.Warn("skipping %q: %v", sc.Text(), err)
		}
		spans = append(spans, sp...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", path, err)
	}
	return spans, nil
}

// ParseLine parses one line of target input. It strips inline comments,
// skips blank/comment-only lines, and parses every whitespace-separated
// token on the line. Malformed tokens are reported via Warn and skipped;
// the returned error covers the whole line (first failure).
func (p *Parser) ParseLine(line string) ([]Span, error) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	var spans []Span
	for _, tok := range strings.Fields(line) {
		sp, err := p.ParseToken(tok)
		if err != nil {
			if p.Warn != nil {
				p.Warn("skipping %q: %v", tok, err)
			}
			continue
		}
		spans = append(spans, sp...)
	}
	return spans, nil
}

// ParseToken parses a single target token, which may be:
//
//	10.0.0.0/24        CIDR (also /0-/32; base address is canonicalized)
//	10.0.0.5           single IPv4 address
//	10.0.0.1-10.0.0.9  inclusive IPv4 range
//	10.0.0.*           wildcard octets ("10.0.*.*" == /16)
//	AS15169            AS number (requires an ASN database, see ASNPath)
//	15169              bare AS number
func (p *Parser) ParseToken(tok string) ([]Span, error) {
	switch {
	case strings.Contains(tok, "/"):
		return p.parseCIDR(tok)
	case strings.Contains(tok, "-"):
		return p.parseRange(tok)
	case strings.Contains(tok, "*"):
		return p.parseWildcard(tok)
	case isASNToken(tok):
		return p.parseASN(tok)
	default:
		ip, err := ParseIPv4(tok)
		if err != nil {
			return nil, err
		}
		return []Span{{Start: ip, End: ip}}, nil
	}
}

func (p *Parser) parseCIDR(tok string) ([]Span, error) {
	parts := strings.Split(tok, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed CIDR %q", tok)
	}
	ip, err := ParseIPv4(parts[0])
	if err != nil {
		return nil, fmt.Errorf("malformed CIDR %q: %v", tok, err)
	}
	bits, err := strconv.Atoi(parts[1])
	if err != nil || bits < 0 || bits > 32 {
		return nil, fmt.Errorf("malformed CIDR %q: prefix must be 0-32", tok)
	}
	mask := maskBits(bits)
	return []Span{{Start: ip & mask, End: ip | ^mask}}, nil
}

func (p *Parser) parseRange(tok string) ([]Span, error) {
	parts := strings.Split(tok, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed range %q", tok)
	}
	start, err := ParseIPv4(parts[0])
	if err != nil {
		return nil, fmt.Errorf("malformed range %q: %v", tok, err)
	}
	end, err := ParseIPv4(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed range %q: %v", tok, err)
	}
	if start > end {
		return nil, fmt.Errorf("range %q: start is greater than end", tok)
	}
	return []Span{{Start: start, End: end}}, nil
}

func (p *Parser) parseWildcard(tok string) ([]Span, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("malformed wildcard %q: expected 4 octets", tok)
	}
	var start, end uint32
	for _, part := range parts {
		if part == "*" {
			start = start<<8 | 0
			end = end<<8 | 0xff
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("malformed wildcard %q: octet %q is not 0-255 or '*'", tok, part)
		}
		start = start<<8 | uint32(n)
		end = end<<8 | uint32(n)
	}
	return []Span{{Start: start, End: end}}, nil
}

// isASNToken reports whether tok is an AS number in one of the accepted
// forms: "AS15169", "ASN15169", "as15169" or a bare number "15169".
func isASNToken(tok string) bool {
	s := tok
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
		if len(s) >= 1 && (s[0] == 'N' || s[0] == 'n') {
			s = s[1:]
		}
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (p *Parser) parseASN(tok string) ([]Span, error) {
	s := tok
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
		if len(s) >= 1 && (s[0] == 'N' || s[0] == 'n') {
			s = s[1:]
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("malformed ASN %q", tok)
	}
	p.asnOnce.Do(func() {
		path := p.ASNPath
		if path == "" {
			path = defaultASNPath()
		}
		if path == "" {
			p.asnErr = fmt.Errorf(
				"ASN target %q requires an ASN-to-CIDR database: use --asn-file or set RDP_SCAN_ASN_FILE (TSV with columns: asn, range_start, range_end)", tok)
			return
		}
		p.asnDB, p.asnErr = LoadASNFile(path)
		if p.asnErr != nil {
			p.asnErr = fmt.Errorf("loading ASN database %s: %w", path, p.asnErr)
		}
	})
	if p.asnErr != nil {
		return nil, p.asnErr
	}
	spans, ok := p.asnDB.Lookup(uint32(n))
	if !ok {
		return nil, fmt.Errorf("AS%d not found in ASN database", n)
	}
	return spans, nil
}

// defaultASNPath returns the first of the conventional ASN database file
// names that exists in the current directory ("" if none), after checking
// the RDP_SCAN_ASN_FILE environment variable.
func defaultASNPath() string {
	if p := os.Getenv("RDP_SCAN_ASN_FILE"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, name := range []string{"ip2asn-v4.tsv", "ipasn.tsv", "ip2asn.tsv"} {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return ""
}

// ASNDB is a parsed ASN-to-CIDR database mapping AS numbers to IPv4 spans.
// It accepts the TSV formats produced by pyasn (asn, range_start, range_end)
// and iptoasn (range_start, range_end, AS_number, country_code, description).
type ASNDB struct {
	byASN map[uint32][]Span
}

// LoadASNFile parses a TSV ASN database. Header, comment and blank lines are
// skipped. Every line must contain one numeric ASN field and two IPv4
// fields; the column order is detected automatically.
func LoadASNFile(path string) (*ASNDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	db := &ASNDB{byASN: make(map[uint32][]Span)}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	rows := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		var asn uint64
		asnOK := false
		var ips []uint32
		for _, fld := range fields {
			fld = strings.TrimSpace(fld)
			if fld == "" {
				continue
			}
			if !asnOK {
				if n, ok := parseASNNumber(fld); ok {
					asn, asnOK = n, true
					continue
				}
			}
			if u, err := ParseIPv4(fld); err == nil {
				ips = append(ips, u)
			}
		}
		if !asnOK || len(ips) < 2 {
			continue // header/metadata line
		}
		start, end := ips[0], ips[1]
		if start > end {
			start, end = end, start
		}
		db.byASN[uint32(asn)] = append(db.byASN[uint32(asn)], Span{Start: start, End: end})
		rows++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if rows == 0 {
		return nil, fmt.Errorf("no ASN ranges found (expected TSV: asn, range_start, range_end)")
	}
	return db, nil
}

// Lookup returns the spans registered for an AS number.
func (db *ASNDB) Lookup(asn uint32) ([]Span, bool) {
	spans, ok := db.byASN[asn]
	return spans, ok
}

// parseASNNumber parses a bare number or an "ASnnnn"/"ASNnnnn" field.
func parseASNNumber(s string) (uint64, bool) {
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
		if len(s) >= 1 && (s[0] == 'N' || s[0] == 'n') {
			s = s[1:]
		}
	}
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Expand flattens the spans into a deduplicated, sorted slice of individual
// IPv4 addresses. Overlapping and duplicate ranges collapse naturally.
// maxIPs is a safety cap: expansion fails before allocating if the total
// would exceed it (this also rejects runaway ranges such as /0 or /1).
func Expand(spans []Span, maxIPs uint64) ([]uint32, error) {
	var total uint64
	for _, sp := range spans {
		total += sp.Count()
		if total > maxIPs {
			return nil, fmt.Errorf("expanded set exceeds the safety cap of %d IPs (raise --max-ips if this is intended)", maxIPs)
		}
	}
	if total == 0 {
		return nil, fmt.Errorf("no IP addresses to scan")
	}

	hint := total
	if hint > 4<<20 { // don't pre-allocate buckets for gigantic sets
		hint = 4 << 20
	}
	seen := make(map[uint32]struct{}, int(hint))
	for _, sp := range spans {
		for ip := sp.Start; ; {
			seen[ip] = struct{}{}
			if ip == sp.End {
				break
			}
			ip++
		}
	}

	out := make([]uint32, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Sort(u32Slice(out))
	return out, nil
}

// u32Slice implements sort.Interface for []uint32.
type u32Slice []uint32

func (s u32Slice) Len() int           { return len(s) }
func (s u32Slice) Less(i, j int) bool { return s[i] < s[j] }
func (s u32Slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
