package engine

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRateLimiterFirstSlotImmediate(t *testing.T) {
	rl := NewRateLimiter(60) // 1s interval
	start := time.Now()
	waited, err := rl.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if waited > 50*time.Millisecond {
		t.Fatalf("first slot waited %v, want immediate", waited)
	}
	_ = start
}

func TestRateLimiterSpacesSecondSlot(t *testing.T) {
	// 3000/min => 20ms between slots.
	rl := NewRateLimiter(3000)
	if _, err := rl.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	waited, err := rl.Wait(context.Background())
	if err != nil {
		t.Fatalf("second Wait: %v", err)
	}
	if waited < 10*time.Millisecond {
		t.Fatalf("second slot waited only %v, want >= ~10ms", waited)
	}
}

func TestRateLimiterConcurrentSpacing(t *testing.T) {
	// 600/min => 100ms between granted slots.
	rl := NewRateLimiter(600)
	const waiters = 4

	start := time.Now()
	var wg sync.WaitGroup
	grants := make(chan time.Time, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := rl.Wait(context.Background()); err != nil {
				t.Errorf("Wait: %v", err)
			}
			grants <- time.Now()
		}()
	}
	wg.Wait()
	close(grants)

	var got []time.Time
	for g := range grants {
		got = append(got, g)
	}
	// Total span: first slot immediate, then ~100ms each => >= 270ms.
	span := got[len(got)-1].Sub(start)
	if span < 250*time.Millisecond {
		t.Fatalf("%d slots took only %v, want >= ~300ms at 600/min", len(got), span)
	}
}

func TestRateLimiterCancelWhileWaiting(t *testing.T) {
	rl := NewRateLimiter(60) // 1s interval
	if _, err := rl.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := rl.Wait(ctx)
		done <- err
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Wait after cancel must return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after cancel")
	}
}

func TestRateLimiterFloor(t *testing.T) {
	// Rate below 1 clamps to 1/min instead of panicking or blocking forever.
	rl := NewRateLimiter(0)
	if rl.interval < time.Minute {
		t.Fatalf("interval = %v, want >= 1s for clamped rate", rl.interval)
	}
}
