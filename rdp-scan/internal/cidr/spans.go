// This file holds the machinery that keeps large scans cheap.
//
// Ranges are normalised, deduplicated and then walked *lazily*: the cost of a
// target list is proportional to the number of ranges (usually thousands, a
// few hundred KB) and never to the number of addresses it covers (up to 2^32).
// Nothing here materialises a list of IPs, which is why a /8 or a /0 scan runs
// comfortably on a laptop instead of needing gigabytes of RAM.
package cidr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MergeSpans returns a canonical view of spans: ascending, non-overlapping and
// duplicate-free. Touching ranges are fused as well (10.0.0.0/24 +
// 10.0.1.0/24 become one run), so the result is the smallest possible set of
// contiguous blocks and the scanner walks them with minimal bookkeeping.
//
// The input slice is not modified. Cost is O(n log n) in the number of ranges.
func MergeSpans(spans []Span) []Span {
	if len(spans) == 0 {
		return nil
	}
	sorted := make([]Span, len(spans))
	copy(sorted, spans)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End < sorted[j].End
	})

	out := make([]Span, 0, len(sorted))
	cur := sorted[0]
	for _, sp := range sorted[1:] {
		// Compare as uint64 so that a span ending on 255.255.255.255 does
		// not overflow while testing "does this touch cur?".
		if uint64(sp.Start) <= uint64(cur.End)+1 {
			if sp.End > cur.End {
				cur.End = sp.End
			}
			continue
		}
		out = append(out, cur)
		cur = sp
	}
	return append(out, cur)
}

// CountIPs returns the number of distinct addresses covered by spans.
// Overlapping and duplicate ranges collapse, so this is the size of the
// deduplicated target set — computed without ever expanding it.
func CountIPs(spans []Span) uint64 {
	var n uint64
	for _, sp := range MergeSpans(spans) {
		n += sp.Count()
	}
	return n
}

// countMergedIPs is CountIPs for a span set known to be merged already.
func countMergedIPs(spans []Span) uint64 {
	var n uint64
	for _, sp := range spans {
		if sp.End >= sp.Start {
			n += sp.Count()
		}
	}
	return n
}

// Subtract removes every address in holes from spans and returns the
// remaining, still-sorted, non-overlapping ranges. It is what powers
// --exclude: "scan this /8 but never touch my VPN/lab blocks".
func Subtract(spans, holes []Span) []Span {
	spans = MergeSpans(spans)
	holes = MergeSpans(holes)
	if len(spans) == 0 {
		return nil
	}
	if len(holes) == 0 {
		return spans
	}

	out := make([]Span, 0, len(spans))
	hi := 0
	for _, sp := range spans {
		start, end := uint64(sp.Start), uint64(sp.End)
		cur := start

		// Advance past holes that sit entirely below this span. Both lists
		// are ascending, so hi never rewinds: total work is linear.
		for hi < len(holes) && uint64(holes[hi].End) < cur {
			hi++
		}
		for j := hi; j < len(holes) && uint64(holes[j].Start) <= end; j++ {
			h := holes[j]
			if uint64(h.Start) > cur {
				out = append(out, Span{Start: uint32(cur), End: uint32(uint64(h.Start) - 1)})
			}
			if uint64(h.End) >= cur {
				cur = uint64(h.End) + 1
			}
			if cur > end {
				break
			}
		}
		if cur <= end {
			out = append(out, Span{Start: uint32(cur), End: uint32(end)})
		}
	}
	return out
}

// Shard partitions a target list across several runs, so a very large scan can
// be split between machines (or resumed in pieces) without any of them holding
// the whole address list. Index selects this run out of Count, counting from 0.
//
// Sharding is positional: the deduplicated, ascending address list is dealt
// round-robin, so every shard gets the same number of addresses (+/-1) no
// matter how gappy the target ranges are. That makes --shard the right tool for
// "this /8 is too much for one laptop, split it in four".
type Shard struct {
	Index uint64
	Count uint64
}

// Active reports whether the shard splits the address space at all.
func (s Shard) Active() bool { return s.Count > 1 && s.Index < s.Count }

// String renders "index/count" ("0/1" when sharding is off).
func (s Shard) String() string {
	if s.Count == 0 {
		return "0/1"
	}
	return strconv.FormatUint(s.Index, 10) + "/" + strconv.FormatUint(s.Count, 10)
}

// ParseShard parses the "k/n" form accepted by --shard. "0/1" (or an empty
// string) disables sharding. Both numbers must be positive, n may be any
// divisor count the operator likes: 4 shards over 2 laptops is "0/2" and "1/2".
func ParseShard(spec string) (Shard, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "0/1" {
		return Shard{}, nil
	}
	i := strings.IndexByte(spec, '/')
	if i < 0 {
		return Shard{}, fmt.Errorf("shard %q must look like index/count (e.g. 1/4)", spec)
	}
	idx, err := strconv.ParseUint(strings.TrimSpace(spec[:i]), 10, 64)
	if err != nil {
		return Shard{}, fmt.Errorf("shard index %q is not a number", spec[:i])
	}
	cnt, err := strconv.ParseUint(strings.TrimSpace(spec[i+1:]), 10, 64)
	if err != nil || cnt == 0 {
		return Shard{}, fmt.Errorf("shard count %q is not a positive number", spec[i+1:])
	}
	if idx >= cnt {
		return Shard{}, fmt.Errorf("shard index %d must be < count %d", idx, cnt)
	}
	return Shard{Index: idx, Count: cnt}, nil
}

// ShardCount reports how many of the total addresses fall into the shard. It is
// exact because sharding is positional: the k-th, (k+n)-th, (k+2n)-th … address
// of the list, and such a list of `total` addresses always holds
// ceil((total-index)/count) of them.
func ShardCount(total uint64, s Shard) uint64 {
	if !s.Active() || total == 0 {
		return total
	}
	if s.Index >= total {
		return 0
	}
	// Addresses s.Index, s.Index+s.Count, s.Index+2*s.Count, ... below total.
	return (total - s.Index + s.Count - 1) / s.Count
}

// IterateSpans walks every address of a *merged, ascending* span set in
// ascending order and calls fn for each of them, stopping the moment fn returns
// false. It allocates nothing per address: this is the streaming replacement for
// materialising []uint32, and it is what ScanSpans feeds from.
//
// When sh.Active(), only every sh.Count-th position of the list is visited
// (starting at sh.Index) — see Shard.
func IterateSpans(spans []Span, sh Shard, fn func(ip uint32) bool) {
	var pos uint64
	for _, sp := range spans {
		if sp.End < sp.Start {
			continue
		}
		for ip := uint64(sp.Start); ip <= uint64(sp.End); ip++ {
			if sh.Active() {
				if pos%sh.Count != sh.Index {
					pos++
					continue
				}
			}
			pos++
			if !fn(uint32(ip)) {
				return
			}
		}
	}
}

// TotalChunks is how many --chunk batches a scan of total addresses needs.
func TotalChunks(total uint64, chunk int) uint64 {
	if chunk <= 0 || total == 0 {
		return 0
	}
	return (total + uint64(chunk) - 1) / uint64(chunk)
}

// ParseSpanList parses a comma- or whitespace-separated list of address
// ranges, e.g. "10.0.0.0/8, 192.168.0.0/16, 172.16.0.1-172.16.0.9". Unlike the
// target file parser it is deliberately strict: a silently-dropped exclusion
// would quietly widen the scan, so a bad entry is an error.
func ParseSpanList(spec string) ([]Span, error) {
	var out []Span
	p := &Parser{}
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		spans, err := p.ParseToken(tok)
		if err != nil {
			return nil, fmt.Errorf("invalid range %q: %w", tok, err)
		}
		if len(spans) != 1 {
			return nil, fmt.Errorf("invalid range %q: expected one CIDR/IP/range, got %d ranges", tok, len(spans))
		}
		out = append(out, spans...)
	}
	return out, nil
}

// FormatSpans renders a span list for humans ("10.0.0.0-10.0.0.255"), used by
// --dry-run. At most n entries are shown, the rest are summarised.
func FormatSpans(spans []Span, n int) string {
	var b strings.Builder
	for i, sp := range spans {
		if i >= n {
			fmt.Fprintf(&b, " … (+%d more)", len(spans)-n)
			break
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		if sp.Start == sp.End {
			b.WriteString(FormatIPv4(sp.Start))
		} else {
			b.WriteString(FormatIPv4(sp.Start))
			b.WriteByte('-')
			b.WriteString(FormatIPv4(sp.End))
		}
	}
	if b.Len() == 0 {
		return "(empty)"
	}
	return b.String()
}
