package engine

import (
	"context"
	"sync"
	"sync/atomic"
)

// Queue is a bounded, context-aware FIFO. Producers block when the
// queue is full (and can be cancelled); consumers block until an item
// arrives or the queue is closed and drained.
type Queue[T any] struct {
	ch     chan T
	closed atomic.Bool
	once   sync.Once
}

// NewQueue creates a bounded queue with the given buffer size.
func NewQueue[T any](buffer int) *Queue[T] {
	if buffer < 1 {
		buffer = 1
	}
	return &Queue[T]{ch: make(chan T, buffer)}
}

// Enqueue blocks until v is accepted or ctx is done / the queue is
// closed.
func (q *Queue[T]) Enqueue(ctx context.Context, v T) bool {
	if q.closed.Load() {
		return false
	}
	select {
	case q.ch <- v:
		return true
	case <-ctx.Done():
		return false
	}
}

// Dequeue blocks until an item is available, ctx is done, or the
// queue is closed and fully drained (in which case ok is false).
// A closed channel always receives its zero value, so the receive's
// ok flag is authoritative.
func (q *Queue[T]) Dequeue(ctx context.Context) (T, bool) {
	var zero T
	select {
	case v, ok := <-q.ch:
		if !ok {
			return zero, false
		}
		return v, true
	case <-ctx.Done():
		return zero, false
	}
}

// Close closes the queue; future Enqueues fail and Dequeues return
// once the queue drains.
func (q *Queue[T]) Close() {
	q.once.Do(func() {
		q.closed.Store(true)
		close(q.ch)
	})
}

// Len reports the number of queued items.
func (q *Queue[T]) Len() int { return len(q.ch) }
