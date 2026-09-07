package cidr

import (
	"reflect"
	"strings"
	"testing"
)

func u(s string) uint32 {
	v, _ := ParseIPv4(s)
	return v
}

func TestMergeSpans(t *testing.T) {
	cases := []struct {
		name  string
		in    []Span
		want  []Span
	}{
		{"empty", nil, nil},
		{"single", []Span{{u("10.0.0.0"), u("10.0.0.9")}}, []Span{{u("10.0.0.0"), u("10.0.0.9")}}},
		{"duplicate", []Span{{u("10.0.0.0"), u("10.0.0.3")}, {u("10.0.0.0"), u("10.0.0.3")}},
			[]Span{{u("10.0.0.0"), u("10.0.0.3")}}},
		{"overlap", []Span{{u("10.0.0.0"), u("10.0.0.5")}, {u("10.0.0.3"), u("10.0.0.9")}},
			[]Span{{u("10.0.0.0"), u("10.0.0.9")}}},
		{"contained", []Span{{u("10.0.0.0"), u("10.0.0.255")}, {u("10.0.0.4"), u("10.0.0.8")}},
			[]Span{{u("10.0.0.0"), u("10.0.0.255")}}},
		{"touching fuses", []Span{{u("10.0.0.0"), u("10.0.0.255")}, {u("10.0.1.0"), u("10.0.1.255")}},
			[]Span{{u("10.0.0.0"), u("10.0.1.255")}}},
		{"gap preserved", []Span{{u("10.0.0.0"), u("10.0.0.1")}, {u("10.0.0.3"), u("10.0.0.4")}},
			[]Span{{u("10.0.0.0"), u("10.0.0.1")}, {u("10.0.0.3"), u("10.0.0.4")}}},
		{"unsorted input", []Span{{u("10.0.2.0"), u("10.0.2.1")}, {u("10.0.0.0"), u("10.0.0.1")}},
			[]Span{{u("10.0.0.0"), u("10.0.0.1")}, {u("10.0.2.0"), u("10.0.2.1")}}},
		// End+1 must not wrap when the last range reaches 255.255.255.255.
		{"top of the space", []Span{{u("255.255.255.254"), u("255.255.255.255")}, {u("0.0.0.0"), u("0.0.0.1")}},
			[]Span{{u("0.0.0.0"), u("0.0.0.1")}, {u("255.255.255.254"), u("255.255.255.255")}}},
	}
	for _, c := range cases {
		got := MergeSpans(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: MergeSpans = %v, want %v", c.name, got, c.want)
		}
		if len(got) > 1 {
			for i := 1; i < len(got); i++ {
				if got[i].Start <= got[i-1].End {
					t.Errorf("%s: output overlaps at %d", c.name, i)
				}
			}
		}
	}
}

func TestMergeSpansDoesNotMutateInput(t *testing.T) {
	in := []Span{{u("10.0.5.0"), u("10.0.5.9")}, {u("1.0.0.0"), u("1.0.0.1")}}
	before := []Span{{u("10.0.5.0"), u("10.0.5.9")}, {u("1.0.0.0"), u("1.0.0.1")}}
	MergeSpans(in)
	if !reflect.DeepEqual(in, before) {
		t.Fatalf("MergeSpans modified its argument: %v", in)
	}
}

func TestCountIPs(t *testing.T) {
	cases := []struct {
		in   []Span
		want uint64
	}{
		{[]Span{{u("10.0.0.0"), u("10.0.0.255")}}, 256},
		{[]Span{{u("10.0.0.0"), u("10.0.0.255")}, {u("10.0.0.0"), u("10.0.0.255")}}, 256},
		{[]Span{{u("10.0.0.0"), u("10.0.0.9")}, {u("10.0.0.5"), u("10.0.0.14")}}, 15},
		{[]Span{{u("10.0.0.0"), u("10.0.0.0")}}, 1},
		{nil, 0},
		// the whole address space: must not overflow
		{[]Span{{0, ^uint32(0)}}, 1 << 32},
	}
	for _, c := range cases {
		if got := CountIPs(c.in); got != c.want {
			t.Errorf("CountIPs(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSubtract(t *testing.T) {
	all := func(spans []Span) []uint32 {
		var out []uint32
		IterateSpans(MergeSpans(spans), Shard{}, func(ip uint32) bool {
			out = append(out, ip)
			return true
		})
		return out
	}
	cases := []struct {
		name  string
		spans []Span
		holes []Span
		want  []string
	}{
		{"no holes", []Span{{u("10.0.0.0"), u("10.0.0.3")}}, nil,
			[]string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"hole in the middle", []Span{{u("10.0.0.0"), u("10.0.0.9")}},
			[]Span{{u("10.0.0.4"), u("10.0.0.5")}},
			[]string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"}},
		{"hole at the edges", []Span{{u("10.0.0.0"), u("10.0.0.9")}},
			[]Span{{u("10.0.0.0"), u("10.0.0.1")}, {u("10.0.0.8"), u("10.0.0.9")}},
			[]string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"}},
		{"hole removes everything", []Span{{u("10.0.0.0"), u("10.0.0.1")}},
			[]Span{{u("10.0.0.0"), u("10.0.0.1")}}, nil},
		{"hole spans two ranges", []Span{{u("10.0.0.0"), u("10.0.0.3")}, {u("10.0.2.0"), u("10.0.2.3")}},
			[]Span{{u("10.0.0.2"), u("10.0.2.1")}},
			[]string{"10.0.0.0", "10.0.0.1", "10.0.2.2", "10.0.2.3"}},
		{"top of the space", []Span{{u("255.255.255.250"), u("255.255.255.255")}},
			[]Span{{u("255.255.255.254"), u("255.255.255.255")}},
			[]string{"255.255.255.250", "255.255.255.251", "255.255.255.252", "255.255.255.253"}},
	}
	for _, c := range cases {
		got := all(Subtract(c.spans, c.holes))
		var want []uint32
		for _, s := range c.want {
			want = append(want, u(s))
		}
		if len(got) != len(want) {
			t.Errorf("%s: got %d addresses, want %d (%v)", c.name, len(got), len(want), got)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: [%d] = %s, want %s", c.name, i, FormatIPv4(got[i]), FormatIPv4(want[i]))
			}
		}
	}
}

func TestIterateSpansStreaming(t *testing.T) {
	spans := MergeSpans([]Span{
		{u("10.0.0.0"), u("10.0.0.3")},
		{u("10.0.0.2"), u("10.0.0.6")},
		{u("10.9.9.9"), u("10.9.9.9")},
	})
	var got []uint32
	IterateSpans(spans, Shard{}, func(ip uint32) bool {
		got = append(got, ip)
		return true
	})
	want, err := Expand(spans, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("streamed %v != expanded %v", got, want)
	}

	// early stop must actually stop the walk
	n := 0
	IterateSpans(spans, Shard{}, func(ip uint32) bool {
		n++
		return n < 2
	})
	if n != 2 {
		t.Fatalf("early stop: visited %d, want 2", n)
	}
}

func TestShardPartitionsTheTargetSet(t *testing.T) {
	spans := MergeSpans([]Span{
		{u("10.0.0.0"), u("10.0.0.9")},
		{u("10.0.5.0"), u("10.0.5.4")}, // a gap between the ranges on purpose
		{u("10.0.9.9"), u("10.0.9.9")},
	})
	total := CountIPs(spans) // 10 + 5 + 1

	for _, count := range []uint64{1, 2, 3, 5} {
		var every []uint32
		for k := uint64(0); k < count; k++ {
			sh := Shard{Index: k, Count: count}
			var got []uint32
			IterateSpans(spans, sh, func(ip uint32) bool {
				got = append(got, ip)
				return true
			})
			if uint64(len(got)) != ShardCount(total, sh) {
				t.Errorf("shard %s: %d addresses, ShardCount says %d", sh, len(got), ShardCount(total, sh))
			}
			if !sortedUnique(got) {
				t.Errorf("shard %s: not ascending/unique: %v", sh, got)
			}
			every = append(every, got...)
		}
		full, _ := Expand(spans, 1<<20)
		if count == 1 && !reflect.DeepEqual(every, full) {
			t.Fatalf("shard 0/1 must be the whole list")
		}
	}

	// the shards must be a partition: same multiset as the unsharded walk
	for _, count := range []uint64{2, 3, 4} {
		var every []uint32
		for k := uint64(0); k < count; k++ {
			IterateSpans(spans, Shard{Index: k, Count: count}, func(ip uint32) bool {
				every = append(every, ip)
				return true
			})
		}
		full, _ := Expand(spans, 1<<20)
		if len(every) != len(full) {
			t.Fatalf("count %d: shards yielded %d, full list %d", count, len(every), len(full))
		}
		// dealt round-robin: sorting the union must reproduce the full list
		insertionSort(every)
		for i := range full {
			if every[i] != full[i] {
				t.Fatalf("count %d: union differs at %d (%s vs %s)", count, i,
					FormatIPv4(every[i]), FormatIPv4(full[i]))
			}
		}
	}
}

func TestParseShard(t *testing.T) {
	sh, err := ParseShard("")
	if err != nil || sh.Active() {
		t.Fatalf("empty shard must be inert: %+v %v", sh, err)
	}
	if sh, err := ParseShard("0/1"); err != nil || sh.Active() {
		t.Fatalf("0/1 must be inert: %+v %v", sh, err)
	}
	sh, err = ParseShard(" 2 / 5 ")
	if err != nil || sh.Index != 2 || sh.Count != 5 || sh.String() != "2/5" {
		t.Fatalf("ParseShard(2/5) = %+v %v", sh, err)
	}
	for _, bad := range []string{"1", "1/0", "5/4", "a/2", "1/x", "-1/2", "1/2/3"} {
		if _, err := ParseShard(bad); err == nil {
			t.Errorf("ParseShard(%q) should fail", bad)
		}
	}
}

func TestTotalChunks(t *testing.T) {
	cases := []struct {
		total uint64
		chunk int
		want  uint64
	}{
		{0, 100, 0},
		{100, 0, 0},
		{100, 100, 1},
		{101, 100, 2},
		{255, 64, 4},
		{1 << 24, 4096, 4096},
	}
	for _, c := range cases {
		if got := TotalChunks(c.total, c.chunk); got != c.want {
			t.Errorf("TotalChunks(%d, %d) = %d, want %d", c.total, c.chunk, got, c.want)
		}
	}
}

func TestParseSpanList(t *testing.T) {
	spans, err := ParseSpanList("10.0.0.0/24, 10.0.1.0-10.0.1.3\n10.0.2.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 3 {
		t.Fatalf("got %d spans, want 3: %v", len(spans), spans)
	}
	if CountIPs(spans) != 256+4+1 {
		t.Fatalf("unexpected coverage: %d", CountIPs(spans))
	}
	if got, err := ParseSpanList(""); err != nil || got != nil {
		t.Fatalf("empty spec should parse to nothing, got %v %v", got, err)
	}
	// strictness: a typo must not be silently dropped
	for _, bad := range []string{"10.0.0.0/33", "not-a-range", "10.0.0.1-10.0.0.0", "1.2.3"} {
		if _, err := ParseSpanList(bad); err == nil {
			t.Errorf("ParseSpanList(%q) should fail", bad)
		} else if !strings.Contains(err.Error(), bad) {
			t.Errorf("ParseSpanList(%q) error should name the bad entry: %v", bad, err)
		}
	}
}

func TestFormatSpans(t *testing.T) {
	spans := []Span{{u("10.0.0.0"), u("10.0.0.255")}, {u("10.0.2.7"), u("10.0.2.7")}}
	if got := FormatSpans(spans, 10); got != "10.0.0.0-10.0.0.255 10.0.2.7" {
		t.Errorf("FormatSpans = %q", got)
	}
	if got := FormatSpans(spans[:1], 0); !strings.Contains(got, "more") {
		t.Errorf("truncation marker missing: %q", got)
	}
	if got := FormatSpans(nil, 4); got != "(empty)" {
		t.Errorf("empty FormatSpans = %q", got)
	}
}

// helpers

func sortedUnique(v []uint32) bool {
	for i := 1; i < len(v); i++ {
		if v[i] <= v[i-1] {
			return false
		}
	}
	return true
}

func insertionSort(v []uint32) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
