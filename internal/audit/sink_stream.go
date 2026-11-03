package audit

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"sync"

	"github.com/ztag/gateway/internal/redisclient"
)

// StreamSink writes audit events to a Redis Stream, which acts as the
// distributed queue in front of the log worker. Redis Streams give the project
// consumer groups, at-least-once delivery and replay without adding a broker
// dependency to the data plane image; the Kafka sink (see docs/kafka-sink.go.txt) is a
// drop-in replacement when the deployment already runs one.
type StreamSink struct {
	rdb    *redisclient.Client
	stream string
	maxLen int
}

// NewStreamSink builds a sink that appends to stream, trimming to roughly
// maxLen entries.
func NewStreamSink(rdb *redisclient.Client, stream string, maxLen int) *StreamSink {
	if maxLen <= 0 {
		maxLen = 200_000
	}
	return &StreamSink{rdb: rdb, stream: stream, maxLen: maxLen}
}

// Name implements Sink.
func (s *StreamSink) Name() string { return "redis-stream:" + s.stream }

// WriteBatch pipelines one XADD per event.
func (s *StreamSink) WriteBatch(_ context.Context, events []*Event) error {
	cmds := make([][]string, 0, len(events))
	maxLen := strconv.Itoa(s.maxLen)
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		cmds = append(cmds, []string{
			"XADD", s.stream, "MAXLEN", "~", maxLen, "*", "e", string(b),
		})
	}
	if len(cmds) == 0 {
		return nil
	}
	_, err := s.rdb.Pipeline(cmds)
	return err
}

// Close implements Sink. The shared client is owned by main.
func (s *StreamSink) Close() error { return nil }

// JSONLSink writes one JSON object per line. It is the zero-infrastructure sink
// for local runs, demos and tests, and the file it produces is directly
// loadable into any log pipeline.
type JSONLSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewJSONLSink opens (or creates) path for appending. An empty path means
// stdout.
func NewJSONLSink(path string) (*JSONLSink, error) {
	if path == "" || path == "-" {
		return &JSONLSink{f: os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &JSONLSink{f: f}, nil
}

// Name implements Sink.
func (s *JSONLSink) Name() string { return "jsonl" }

// WriteBatch implements Sink.
func (s *JSONLSink) WriteBatch(_ context.Context, events []*Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var line []byte
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		line = append(line[:0], b...)
		line = append(line, '\n')
		if _, err := s.f.Write(line); err != nil {
			return err
		}
	}
	return nil
}

// Close implements Sink.
func (s *JSONLSink) Close() error {
	if s.f == os.Stdout {
		return nil
	}
	return s.f.Close()
}
