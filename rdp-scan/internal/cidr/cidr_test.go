package cidr

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseIPv4Valid(t *testing.T) {
	cases := map[string]uint32{
		"0.0.0.0":         0x00000000,
		"1.2.3.4":         0x01020304,
		"10.0.0.1":        0x0a000001,
		"127.0.0.1":       0x7f000001,
		"255.255.255.255": 0xffffffff,
		"192.168.1.1":     0xc0a80101,
	}
	for in, want := range cases {
		got, err := ParseIPv4(in)
		if err != nil {
			t.Fatalf("ParseIPv4(%q): unexpected error %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseIPv4(%q) = %#x, want %#x", in, got, want)
		}
		if FormatIPv4(got) != in {
			t.Fatalf("FormatIPv4(%#x) = %q, want %q", got, FormatIPv4(got), in)
		}
	}
}

func TestParseIPv4Invalid(t *testing.T) {
	cases := []string{
		"", "1.2.3", "1.2.3.4.5", "256.0.0.1", "1.2.3.4.", ".1.2.3.4",
		"1.2.3.a", "1..2.3", "1.2.3.-1", " 1.2.3.4", "1.2.3.4 ", "1.2.3.4/",
		"0x0a.1.2.3", "1.2.3.04x",
	}
	for _, in := range cases {
		if _, err := ParseIPv4(in); err == nil {
			t.Fatalf("ParseIPv4(%q): expected error, got none", in)
		}
	}
}

func newParser() *Parser { return &Parser{} }

func TestParseTokenCIDR(t *testing.T) {
	p := newParser()
	cases := []struct {
		in    string
		start uint32
		end   uint32
		count uint64
	}{
		{"10.0.0.5/32", 0x0a000005, 0x0a000005, 1},
		{"10.0.0.0/31", 0x0a000000, 0x0a000001, 2},
		{"10.0.0.0/30", 0x0a000000, 0x0a000003, 4},
		{"1.0.1.0/24", 0x01000100, 0x010001ff, 256},
		{"1.0.1.14/24", 0x01000100, 0x010001ff, 256}, // non-canonical base
		{"10.0.0.0/0", 0x00000000, 0xffffffff, 1 << 32},
		{"255.255.255.255/32", 0xffffffff, 0xffffffff, 1},
		{"0.0.0.0/32", 0x00000000, 0x00000000, 1},
	}
	for _, c := range cases {
		spans, err := p.ParseToken(c.in)
		if err != nil {
			t.Fatalf("ParseToken(%q): unexpected error %v", c.in, err)
		}
		if len(spans) != 1 {
			t.Fatalf("ParseToken(%q): got %d spans, want 1", c.in, len(spans))
		}
		sp := spans[0]
		if sp.Start != c.start || sp.End != c.end {
			t.Fatalf("ParseToken(%q) = [%#x,%#x], want [%#x,%#x]", c.in, sp.Start, sp.End, c.start, c.end)
		}
		if sp.Count() != c.count {
			t.Fatalf("ParseToken(%q).Count() = %d, want %d", c.in, sp.Count(), c.count)
		}
	}
}

func TestParseTokenRangeAndWildcard(t *testing.T) {
	p := newParser()
	spans, err := p.ParseToken("10.0.0.1-10.0.0.9")
	if err != nil || len(spans) != 1 || spans[0].Start != 0x0a000001 || spans[0].End != 0x0a000009 {
		t.Fatalf("range parse failed: %v %+v", err, spans)
	}
	if _, err := p.ParseToken("10.0.0.9-10.0.0.1"); err == nil {
		t.Fatal("reversed range should fail")
	}

	spans, err = p.ParseToken("10.0.0.*")
	if err != nil || len(spans) != 1 || spans[0].Count() != 256 {
		t.Fatalf("wildcard parse failed: %v %+v", err, spans)
	}
	spans, err = p.ParseToken("10.0.*.*")
	if err != nil || len(spans) != 1 || spans[0].Count() != 65536 {
		t.Fatalf("wildcard /16 parse failed: %v %+v", err, spans)
	}
	if _, err := p.ParseToken("10.*.300.1"); err == nil {
		t.Fatal("wildcard with out-of-range octet should fail")
	}
}

func TestParseTokenInvalid(t *testing.T) {
	p := newParser()
	cases := []string{
		"10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/24/8", "10.0.0.0/a",
		"999.0.0.1", "hello", "10.0.0.1-", "-10.0.0.1", "10.0.0.1--10.0.0.2",
	}
	for _, in := range cases {
		if _, err := p.ParseToken(in); err == nil {
			t.Fatalf("ParseToken(%q): expected error, got none", in)
		}
	}
}

func TestParseLineCommentsBlankWhitespace(t *testing.T) {
	p := newParser()
	var warned []string
	p.Warn = func(format string, args ...interface{}) {
		warned = append(warned, format)
	}

	spans, err := p.ParseLine("   # full-line comment")
	if err != nil || len(spans) != 0 {
		t.Fatalf("comment line should yield no spans: %v %+v", err, spans)
	}
	spans, _ = p.ParseLine("")
	if len(spans) != 0 {
		t.Fatal("blank line should yield no spans")
	}
	spans, _ = p.ParseLine("    ")
	if len(spans) != 0 {
		t.Fatal("whitespace-only line should yield no spans")
	}
	spans, _ = p.ParseLine("10.0.0.0/30   # inline comment")
	if len(spans) != 1 {
		t.Fatal("inline comment line should yield 1 span")
	}
	spans, _ = p.ParseLine("10.0.0.1 10.0.0.2\t10.0.0.3")
	if len(spans) != 3 {
		t.Fatalf("multi-token line should yield 3 spans, got %d", len(spans))
	}
	spans, _ = p.ParseLine("10.0.0.1 not-an-ip 10.0.0.2")
	if len(spans) != 2 {
		t.Fatalf("line with one bad token should yield 2 spans, got %d", len(spans))
	}
	if len(warned) == 0 {
		t.Fatal("expected a warning for the malformed token")
	}
}

func TestExpandDedupOverlapSort(t *testing.T) {
	spans := []Span{
		{Start: 0x0a000000, End: 0x0a000003}, // 10.0.0.0/30
		{Start: 0x0a000002, End: 0x0a000005}, // overlaps the previous span
		{Start: 0x0a000005, End: 0x0a000005}, // duplicate of the last IP
	}
	ips, err := Expand(spans, 1000)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{0x0a000000, 0x0a000001, 0x0a000002, 0x0a000003, 0x0a000004, 0x0a000005}
	if len(ips) != len(want) {
		t.Fatalf("Expand: got %d IPs, want %d", len(ips), len(want))
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("Expand[%d] = %#x, want %#x (order must be sorted)", i, ips[i], want[i])
		}
	}
}

func TestExpandSafetyCap(t *testing.T) {
	spans := []Span{{Start: 0x00000000, End: 0x00ffffff}} // a /8: 16.7M IPs
	if _, err := Expand(spans, 1024); err == nil {
		t.Fatal("expected safety-cap error for oversized expansion")
	}
	spans = []Span{{Start: 0x0a000000, End: 0x0a000003}}
	if _, err := Expand(spans, 4); err != nil {
		t.Fatalf("cap of exactly 4 should pass, got %v", err)
	}
	if _, err := Expand(nil, 1024); err == nil {
		t.Fatal("expected error for empty span set")
	}
}

func TestASNDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip2asn-v4.tsv")
	content := "range_start\trange_end\tAS_number\tcountry_code\tAS_description\n" +
		"10.0.0.0\t10.0.0.255\t64512\tZZ\tTEST-AS-A\n" +
		"10.0.1.0\t10.0.1.127\t64513\tZZ\tTEST-AS-B\n" +
		"192.0.2.0\t192.0.2.31\t64512\tZZ\tTEST-AS-A\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Parser{ASNPath: path}
	spans, err := p.ParseToken("AS64512")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 {
		t.Fatalf("AS64512 should have 2 ranges, got %d", len(spans))
	}

	if _, err := p.ParseToken("AS99999"); err == nil {
		t.Fatal("unknown ASN should error")
	}

	noDB := &Parser{}
	if _, err := noDB.ParseToken("AS64512"); err == nil {
		t.Fatal("ASN token without a database should error")
	}
}
