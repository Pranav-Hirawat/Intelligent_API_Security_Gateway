package telemetry

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

var ErrQueueFull = errors.New("telemetry queue is full")

// Writer accepts one record for storage. Production uses AsyncWriter so
// persistence never holds the client connection open.
//
// Generic over the record because arrivals and completions travel to different
// streams with different shapes, but need identical back-pressure behaviour.
// Two copies of the code below would be two chances to get that wrong in only
// one of them.
type Writer[T any] interface {
	WriteEvent(ctx context.Context, rec T) error
}

// AsyncWriter bounds both queued work and the time spent on one write. A slow
// Redis must lose telemetry instead of holding client requests or accumulating
// one goroutine per request until the gateway runs out of memory.
type AsyncWriter[T any] struct {
	writer   Writer[T]
	queue    chan T
	timeout  time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	close    sync.Once
	dropped  atomic.Uint64
	lastDrop atomic.Int64
	what     string
}

// NewNamedAsyncWriter labels the overflow warning. With two queues running,
// "telemetry_queue_full" alone would not say which one is losing records, and
// the arrivals queue overflowing means something different from the events
// queue overflowing: arrivals are written before the backend is called.
func NewNamedAsyncWriter[T any](writer Writer[T], capacity int, timeout time.Duration, what string) *AsyncWriter[T] {
	if capacity < 1 {
		capacity = 1
	}
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	what = cmp.Or(what, "telemetry")
	ctx, cancel := context.WithCancel(context.Background())
	w := &AsyncWriter[T]{
		writer: writer, queue: make(chan T, capacity), timeout: timeout,
		ctx: ctx, cancel: cancel, done: make(chan struct{}), what: what,
	}
	go w.run()
	return w
}

func (w *AsyncWriter[T]) WriteEvent(ctx context.Context, rec T) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	select {
	case w.queue <- rec:
		return nil
	default:
		dropped := w.dropped.Add(1)
		// Overflow is most likely during an attack. Reporting its total once
		// per second avoids replacing an overloaded Redis with a log flood.
		now, last := time.Now().UnixNano(), w.lastDrop.Load()
		if now-last >= int64(time.Second) && w.lastDrop.CompareAndSwap(last, now) {
			slog.Warn(w.what+"_queue_full", "dropped_total", dropped, "capacity", cap(w.queue))
		}
		return ErrQueueFull
	}
}

func (w *AsyncWriter[T]) Dropped() uint64 { return w.dropped.Load() }

// Depth is what the queue is holding right now. Read by the health heartbeat:
// a queue that sits near capacity is about to start dropping, which is the
// warning a drop counter only gives after the loss has happened.
func (w *AsyncWriter[T]) Depth() int { return len(w.queue) }

func (w *AsyncWriter[T]) Capacity() int { return cap(w.queue) }

func (w *AsyncWriter[T]) Close() {
	if w == nil {
		return
	}
	w.close.Do(w.cancel)
	<-w.done
}

func (w *AsyncWriter[T]) run() {
	defer close(w.done)
	for {
		if w.ctx.Err() != nil {
			return
		}
		select {
		case <-w.ctx.Done():
			return
		case rec := <-w.queue:
			ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
			err := w.writer.WriteEvent(ctx, rec)
			cancel()
			if err != nil && w.ctx.Err() == nil {
				slog.Warn(w.what+"_write_failed", "error", err)
			}
		}
	}
}
