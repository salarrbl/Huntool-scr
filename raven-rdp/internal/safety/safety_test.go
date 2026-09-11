package safety

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPolicyValidate(t *testing.T) {
	// A fully valid policy first.
	ok := Policy{AttemptLimit: 10, TargetRate: 60, Workers: 4, Timeout: time.Second}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Policy)
	}{
		{"zero attempt limit", func(p *Policy) { p.AttemptLimit = 0 }},
		{"negative attempt limit", func(p *Policy) { p.AttemptLimit = -1 }},
		{"zero rate", func(p *Policy) { p.TargetRate = 0 }},
		{"zero workers", func(p *Policy) { p.Workers = 0 }},
		{"zero timeout", func(p *Policy) { p.Timeout = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := ok
			tc.mut(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestPolicySlotInterval(t *testing.T) {
	p := Policy{AttemptLimit: 10, TargetRate: 600, Workers: 2, Timeout: time.Second}
	if got := p.SlotInterval(); got != 100*time.Millisecond {
		t.Fatalf("SlotInterval = %v, want 100ms", got)
	}
}

func TestPolicySummary(t *testing.T) {
	p := Policy{AttemptLimit: 3, TargetRate: 600, Workers: 4, Timeout: 2 * time.Second}
	got := p.Summary()
	for _, want := range []string{"attempt-limit=3", "target-rate=600", "workers=4", "timeout=2s"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Summary %q missing %q", got, want)
		}
	}
}

func TestGuardReserveStopsAtLimit(t *testing.T) {
	g := NewGuard(3)
	if !g.Reserve() || !g.Reserve() || !g.Reserve() {
		t.Fatal("first three reservations must succeed")
	}
	if g.Reserve() {
		t.Fatal("reservation beyond the limit must fail")
	}
	if g.Count() != 3 {
		t.Fatalf("Count = %d, want 3", g.Count())
	}
	if g.Limit() != 3 {
		t.Fatalf("Limit = %d, want 3", g.Limit())
	}
}

func TestGuardFinish(t *testing.T) {
	g := NewGuard(5)
	if !g.Reserve() {
		t.Fatal("reserve failed")
	}
	g.Finish()
	if !g.Done() {
		t.Fatal("Done must be true after Finish")
	}
	if g.Reserve() {
		t.Fatal("a finished target must not reserve more attempts")
	}
	if g.Count() != 1 {
		t.Fatalf("Count = %d, want 1 (no new reservations)", g.Count())
	}
}

func TestGuardRelease(t *testing.T) {
	g := NewGuard(3)
	if !g.Reserve() {
		t.Fatal("reserve failed")
	}
	g.Release()
	if g.Count() != 0 {
		t.Fatalf("Count = %d, want 0 after Release", g.Count())
	}
	// The released slot can be claimed again.
	if !g.Reserve() || !g.Reserve() || !g.Reserve() {
		t.Fatal("slots up to the limit must stay reservable")
	}
	g.Release()
	if g.Count() != 2 {
		t.Fatalf("Count = %d, want 2 after releasing one of three", g.Count())
	}
	// Release must never take the counter below zero.
	for i := 0; i < 5; i++ {
		g.Release()
	}
	if g.Count() != 0 {
		t.Fatalf("Count = %d, want 0 (floor at zero)", g.Count())
	}
}

func TestGuardConcurrent(t *testing.T) {
	const limit = 100
	const goroutines = 16
	const perGoroutine = 20

	g := NewGuard(limit)
	var wg sync.WaitGroup
	granted := make(chan bool, goroutines*perGoroutine)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				granted <- g.Reserve()
			}
		}()
	}
	wg.Wait()
	close(granted)

	var count int
	for ok := range granted {
		if ok {
			count++
		}
	}
	if count != limit {
		t.Fatalf("granted %d reservations, want exactly %d", count, limit)
	}
	if g.Count() != limit {
		t.Fatalf("Count = %d, want %d", g.Count(), limit)
	}
}
