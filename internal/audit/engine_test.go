package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memSink struct {
	mu     sync.Mutex
	events []*Event
	fail   bool
	closed bool
}

func (m *memSink) Name() string { return "mem" }

func (m *memSink) WriteBatch(_ context.Context, evs []*Event) error {
	if m.fail {
		return errors.New("boom")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, evs...)
	return nil
}

func (m *memSink) Close() error { m.closed = true; return nil }

func (m *memSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestEngineFlushesAllEvents(t *testing.T) {
	sink := &memSink{}
	e := NewEngine(1024, 2, sink)
	const n = 500
	for i := 0; i < n; i++ {
		if !e.Emit(&Event{Subject: "u", Status: 200, Decision: "allow"}) {
			t.Fatalf("emit %d was dropped unexpectedly", i)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := sink.count(); got != n {
		t.Fatalf("want %d events persisted, got %d", n, got)
	}
	if !sink.closed {
		t.Fatal("sink must be closed with the engine")
	}
	if e.Dropped() != 0 {
		t.Fatalf("no drops expected, got %d", e.Dropped())
	}
}

func TestEngineDropsInsteadOfBlocking(t *testing.T) {
	// One worker with a slow sink and a tiny queue: the producer must never
	// block, it must shed load and count it.
	sink := &slowSink{delay: 20 * time.Millisecond}
	e := NewEngine(4, 1, sink)

	start := time.Now()
	dropped := 0
	for i := 0; i < 200; i++ {
		if !e.Emit(&Event{Subject: "u"}) {
			dropped++
		}
	}
	elapsed := time.Since(start)
	e.Close()

	if dropped == 0 {
		t.Fatal("expected back pressure to drop events")
	}
	if elapsed > time.Second {
		t.Fatalf("Emit blocked for %s; the request path must never wait on audit", elapsed)
	}
}

func TestEngineAfterClose(t *testing.T) {
	e := NewEngine(8, 1, &memSink{})
	_ = e.Close()
	if e.Emit(&Event{}) {
		t.Fatal("Emit after Close must return false")
	}
}

type slowSink struct{ delay time.Duration }

func (s *slowSink) Name() string { return "slow" }

func (s *slowSink) WriteBatch(_ context.Context, evs []*Event) error {
	time.Sleep(s.delay)
	return nil
}

func (s *slowSink) Close() error { return nil }
