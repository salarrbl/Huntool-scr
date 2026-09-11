package engine

import (
	"sync"
	"testing"
	"time"
)

// TestMetricsStartConcurrent is a regression test for N1: the start
// time is written by Engine.Run while the TUI goroutine reads it via
// Elapsed on every tick. Both sides must go through atomics; with a
// plain time.Time field the race detector flags this test.
func TestMetricsStartConcurrent(t *testing.T) {
	var m Metrics
	if got := m.Elapsed(); got != 0 {
		t.Fatalf("Elapsed before MarkStart = %v, want 0", got)
	}

	const writes = 2000
	stopped := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stopped)
		for i := 0; i < writes; i++ {
			m.MarkStart(time.Now())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopped:
				return
			default:
			}
			if d := m.Elapsed(); d < 0 {
				t.Errorf("Elapsed = %v, want non-negative", d)
				return
			}
		}
	}()

	wg.Wait()

	time.Sleep(time.Millisecond)
	if got := m.Elapsed(); got <= 0 {
		t.Fatalf("Elapsed after MarkStart = %v, want > 0", got)
	}
}

// TestMetricsElapsedTracksMarkStart pins the semantics: Elapsed is
// measured from the value handed to MarkStart.
func TestMetricsElapsedTracksMarkStart(t *testing.T) {
	var m Metrics
	m.MarkStart(time.Now().Add(-2 * time.Second))
	if got := m.Elapsed(); got < 2*time.Second || got > 5*time.Second {
		t.Fatalf("Elapsed = %v, want ~2s", got)
	}
	if rate := m.AttemptsPerSec(); rate != 0 {
		t.Fatalf("AttemptsPerSec with no attempts = %v, want 0", rate)
	}
}
