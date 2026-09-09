package engine

import (
	"fmt"
	"sync"
	"testing"

	"github.com/salarrbl/raven-rdp/internal/rdp"
)

type pair struct {
	user, pass string
}

func nextPairs(t *testing.T, j *Job, users []string, passCount int) []pair {
	t.Helper()
	var out []pair
	for {
		u, p, ok := j.NextCredential(users, passCount, func(i int) string { return fmt.Sprintf("pass%d", i) })
		if !ok {
			return out
		}
		out = append(out, pair{u, p})
	}
}

func TestNextCredentialUserMajorOrder(t *testing.T) {
	j := NewJob(rdp.Target{Host: "h", Port: 1}, 100, 1_000_000)
	got := nextPairs(t, j, []string{"a", "b"}, 2)
	want := []pair{{"a", "pass0"}, {"a", "pass1"}, {"b", "pass0"}, {"b", "pass1"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// Matrix exhausted: the job is finished.
	if u, p, ok := j.NextCredential([]string{"a"}, 1, func(i int) string { return "x" }); ok {
		t.Fatalf("exhausted job returned (%s,%s), want ok=false", u, p)
	}
}

func TestNextCredentialStopsAtAttemptLimit(t *testing.T) {
	j := NewJob(rdp.Target{Host: "h", Port: 1}, 3, 1_000_000)
	got := nextPairs(t, j, []string{"a", "b", "c", "d"}, 4)
	if len(got) != 3 {
		t.Fatalf("got %d pairs, want 3 (attempt limit): %v", len(got), got)
	}
}

func TestNextCredentialEmptyLists(t *testing.T) {
	if pairs := nextPairs(t, NewJob(rdp.Target{}, 5, 100), []string{}, 3); len(pairs) != 0 {
		t.Fatalf("no users: got %v", pairs)
	}
	if pairs := nextPairs(t, NewJob(rdp.Target{}, 5, 100), []string{"a"}, 0); len(pairs) != 0 {
		t.Fatalf("no passwords: got %v", pairs)
	}
}

func TestNextCredentialAfterSuccess(t *testing.T) {
	j := NewJob(rdp.Target{}, 10, 100)
	j.MarkSuccess()
	if u, p, ok := j.NextCredential([]string{"a"}, 1, func(i int) string { return "x" }); ok {
		t.Fatalf("successful job must not yield credentials, got (%s,%s)", u, p)
	}
	if !j.Success() {
		t.Fatal("Success must be true after MarkSuccess")
	}
}

func TestNextCredentialConcurrent(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 25
	j := NewJob(rdp.Target{}, 10, 1_000_000)

	// 3 users x 4 passwords = 12 pairs, limit 10 => exactly 10 granted.
	users := []string{"a", "b", "c"}
	var wg sync.WaitGroup
	got := make(chan pair, goroutines*perGoroutine)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < perGoroutine; k++ {
				u, p, ok := j.NextCredential(users, 4, func(i int) string { return fmt.Sprintf("pass%d", i) })
				if !ok {
					return
				}
				got <- pair{u, p}
			}
		}()
	}
	wg.Wait()
	close(got)

	seen := make(map[pair]int)
	for p := range got {
		seen[p]++
	}
	if len(seen) != 10 {
		t.Fatalf("granted %d unique pairs, want exactly 10 (limit)", len(seen))
	}
	for p, n := range seen {
		if n != 1 {
			t.Fatalf("pair %v granted %d times, want 1", p, n)
		}
	}
}
