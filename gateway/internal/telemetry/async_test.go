package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type waitingWriter struct {
	started chan struct{}
	ended   chan error
}

func (w *waitingWriter) WriteEvent(ctx context.Context, _ Event) error {
	w.started <- struct{}{}
	<-ctx.Done()
	w.ended <- ctx.Err()
	return ctx.Err()
}

func TestStalledStorageCannotHoldAResponseOrGrowTheQueue(t *testing.T) {
	store := &waitingWriter{started: make(chan struct{}, 2), ended: make(chan error, 2)}
	writer := NewNamedAsyncWriter(store, 1, time.Minute, "")
	defer writer.Close()
	if err := writer.WriteEvent(context.Background(), Event{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	if err := writer.WriteEvent(context.Background(), Event{}); err != nil {
		t.Fatalf("one pending event should fit: %v", err)
	}
	if err := writer.WriteEvent(context.Background(), Event{}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("queue exceeded configured capacity: %v", err)
	}
	if writer.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", writer.Dropped())
	}

	handler := Middleware(writer, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/login", nil))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a full telemetry queue held the client response")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("storage failure changed response to %d", rec.Code)
	}
}

func TestAsyncWriterBoundsEachWriteAndCancelsOnClose(t *testing.T) {
	store := &waitingWriter{started: make(chan struct{}, 2), ended: make(chan error, 2)}
	writer := NewNamedAsyncWriter(store, 1, 10*time.Millisecond, "")
	defer writer.Close()
	if err := writer.WriteEvent(context.Background(), Event{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-store.ended:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("write ended with %v, want configured deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("configured write timeout did not stop storage")
	}
	writer.Close()
	if err := writer.WriteEvent(context.Background(), Event{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed writer accepted telemetry: %v", err)
	}
}
