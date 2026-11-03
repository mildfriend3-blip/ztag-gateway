// Package audit implements the decoupled log engine. The request path never
// writes to disk, Redis or a broker: it hands an Event to a bounded channel and
// returns. A worker pool batches events and flushes them to one or more sinks
// (Redis Streams by default, JSONL for local runs, Kafka behind a build tag).
//
// If the queue is full the event is dropped and counted, never blocked on. That
// is the whole point: audit cost must not become an availability lever an
// attacker can pull by flooding the gateway.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Stage timings, in microseconds, for one request.
type Stage struct {
	Auth       int64 `json:"auth_us"`
	Revocation int64 `json:"revocation_us"`
	RateLimit  int64 `json:"ratelimit_us"`
	Policy     int64 `json:"policy_us"`
	Upstream   int64 `json:"upstream_us"`
}

// Event is one audit record.
type Event struct {
	TS        int64  `json:"ts"`
	RequestID string `json:"rid"`
	Subject   string `json:"sub,omitempty"`
	JTI       string `json:"jti,omitempty"`
	Service   string `json:"svc,omitempty"`
	DeviceID  string `json:"did,omitempty"`
	DeviceHK  string `json:"dhk,omitempty"`
	Trust     int    `json:"trust"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Route     string `json:"route,omitempty"`
	Status    int    `json:"status"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason,omitempty"`
	SourceIP  string `json:"src_ip,omitempty"`
	Bytes     int64  `json:"bytes,omitempty"`
	LatencyUS int64  `json:"lat_us"`
	Stage     Stage  `json:"stages_us"`
	Degraded  bool   `json:"degraded,omitempty"`
}

// Sink receives batches of events.
type Sink interface {
	// Name identifies the sink in logs and metrics.
	Name() string
	// WriteBatch persists a batch. Returning an error does not stop other
	// sinks and does not affect the request path.
	WriteBatch(ctx context.Context, events []*Event) error
	// Close releases resources.
	Close() error
}

// Engine owns the queue and the workers.
type Engine struct {
	ch      chan *Event
	sinks   []Sink
	batch   int
	flush   time.Duration
	dropped atomic.Uint64
	written atomic.Uint64
	failed  atomic.Uint64
	wg      sync.WaitGroup
	closed  atomic.Bool
}

// NewEngine starts workers that drain a queue of capacity queueSize.
func NewEngine(queueSize, workers int, sinks ...Sink) *Engine {
	if queueSize <= 0 {
		queueSize = 8192
	}
	if workers <= 0 {
		workers = 2
	}
	e := &Engine{
		ch:    make(chan *Event, queueSize),
		sinks: sinks,
		batch: 64,
		flush: 5 * time.Millisecond,
	}
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.worker()
	}
	return e
}

// Emit enqueues an event without blocking. It reports whether the event was
// accepted; a false return means the queue was full and the record was dropped.
func (e *Engine) Emit(ev *Event) bool {
	if e.closed.Load() {
		return false
	}
	select {
	case e.ch <- ev:
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

// Dropped reports how many events were shed under back pressure.
func (e *Engine) Dropped() uint64 { return e.dropped.Load() }

// Written reports how many events reached at least one sink.
func (e *Engine) Written() uint64 { return e.written.Load() }

// Failed reports sink write failures.
func (e *Engine) Failed() uint64 { return e.failed.Load() }

// Depth reports the current queue occupancy.
func (e *Engine) Depth() int { return len(e.ch) }

// Close stops accepting events, drains the queue and closes every sink.
func (e *Engine) Close() error {
	if e.closed.Swap(true) {
		return nil
	}
	close(e.ch)
	e.wg.Wait()
	var errs []error
	for _, s := range e.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) worker() {
	defer e.wg.Done()
	buf := make([]*Event, 0, e.batch)
	timer := time.NewTimer(e.flush)
	defer timer.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		for _, s := range e.sinks {
			if err := s.WriteBatch(ctx, buf); err != nil {
				e.failed.Add(1)
			} else {
				e.written.Add(1)
			}
		}
		cancel()
		buf = buf[:0]
	}

	for {
		select {
		case ev, ok := <-e.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, ev)
			if len(buf) >= e.batch {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(e.flush)
			}
		case <-timer.C:
			flush()
			timer.Reset(e.flush)
		}
	}
}

// Marshal is the canonical wire encoding used by every sink.
func Marshal(ev *Event) ([]byte, error) { return json.Marshal(ev) }
