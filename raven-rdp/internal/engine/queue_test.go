package engine

import (
	"context"
	"testing"
	"time"
)

func TestQueueFIFO(t *testing.T) {
	ctx := context.Background()
	q := NewQueue[int](8)
	for _, v := range []int{1, 2, 3} {
		if !q.Enqueue(ctx, v) {
			t.Fatalf("Enqueue(%d) failed", v)
		}
	}
	for _, want := range []int{1, 2, 3} {
		v, ok := q.Dequeue(ctx)
		if !ok || v != want {
			t.Fatalf("Dequeue = (%d, %v), want (%d, true)", v, ok, want)
		}
	}
}

func TestQueueCloseDrains(t *testing.T) {
	ctx := context.Background()
	q := NewQueue[int](8)
	q.Enqueue(ctx, 1)
	q.Enqueue(ctx, 2)
	q.Close()

	if v, ok := q.Dequeue(ctx); !ok || v != 1 {
		t.Fatalf("first drain = (%d, %v), want (1, true)", v, ok)
	}
	if v, ok := q.Dequeue(ctx); !ok || v != 2 {
		t.Fatalf("second drain = (%d, %v), want (2, true)", v, ok)
	}
	if v, ok := q.Dequeue(ctx); ok {
		t.Fatalf("drained queue returned (%d, true), want ok=false", v)
	}
}

func TestQueueEnqueueAfterClose(t *testing.T) {
	ctx := context.Background()
	q := NewQueue[int](1)
	q.Close()
	if q.Enqueue(ctx, 1) {
		t.Fatal("Enqueue after Close must fail")
	}
}

func TestQueueDoubleClose(t *testing.T) {
	q := NewQueue[int](1)
	q.Close()
	q.Close() // must not panic
}

func TestQueueEnqueueCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	q := NewQueue[int](1)
	q.Enqueue(ctx, 1) // fill the buffer

	done := make(chan bool, 1)
	go func() { done <- q.Enqueue(ctx, 2) }()

	time.Sleep(20 * time.Millisecond) // let the producer block
	cancel()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("Enqueue after cancel must fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue did not return after cancel")
	}
}

func TestQueueDequeueCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	q := NewQueue[int](1)

	done := make(chan bool, 1)
	go func() {
		_, ok := q.Dequeue(ctx)
		done <- ok
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("Dequeue after cancel must return ok=false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dequeue did not return after cancel")
	}
}

func TestQueueLen(t *testing.T) {
	ctx := context.Background()
	q := NewQueue[int](4)
	if q.Len() != 0 {
		t.Fatal("new queue must be empty")
	}
	q.Enqueue(ctx, 1)
	q.Enqueue(ctx, 2)
	if q.Len() != 2 {
		t.Fatalf("Len = %d, want 2", q.Len())
	}
}
