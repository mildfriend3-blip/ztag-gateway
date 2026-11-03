package audit

import (
	"context"
	"errors"
	"time"

	"github.com/ztag/gateway/internal/redisclient"
)

// Record is one entry read from the audit stream.
type Record struct {
	ID     string
	Fields map[string]string
}

// StreamReader consumes the audit stream through a consumer group, which is
// what makes the log worker horizontally scalable: every replica of the worker
// takes a disjoint slice of the stream, and unacknowledged entries are
// re-delivered after a crash.
type StreamReader struct {
	rdb      *redisclient.Client
	stream   string
	group    string
	consumer string
	block    time.Duration
}

// NewStreamReader builds a consumer for stream/group.
func NewStreamReader(rdb *redisclient.Client, stream, group, consumer string) *StreamReader {
	return &StreamReader{rdb: rdb, stream: stream, group: group, consumer: consumer, block: time.Second}
}

// EnsureGroup creates the consumer group at the start of the stream if it does
// not exist yet. BUSYGROUP means somebody else already created it.
func (r *StreamReader) EnsureGroup() error {
	_, err := r.rdb.Do("XGROUP", "CREATE", r.stream, r.group, "0", "MKSTREAM")
	if err == nil {
		return nil
	}
	var re redisclient.Error
	if errors.As(err, &re) && (len(string(re)) >= 9 && string(re)[:9] == "BUSYGROUP") {
		return nil
	}
	return err
}

// Read blocks for up to the reader's block interval and returns new entries.
// It returns an empty slice (and no error) when nothing arrived.
func (r *StreamReader) Read(ctx context.Context, count int) ([]Record, error) {
	if count <= 0 {
		count = 64
	}
	// The client deadline must exceed the server-side BLOCK, otherwise the
	// long poll would be cancelled before Redis can answer.
	timeout := r.block + 500*time.Millisecond
	reply, err := r.rdb.DoWithTimeout(timeout,
		"XREADGROUP", "GROUP", r.group, r.consumer,
		"COUNT", itoa(count),
		"BLOCK", itoa(int(r.block.Milliseconds())),
		"STREAMS", r.stream, ">",
	)
	if err != nil {
		return nil, err
	}
	_ = ctx
	return parseStreamReply(reply), nil
}

// Ack acknowledges processed entries so they leave the pending list.
func (r *StreamReader) Ack(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]string, 0, 2+len(ids))
	args = append(args, "XACK", r.stream, r.group)
	args = append(args, ids...)
	_, err := r.rdb.Do(args...)
	return err
}

// Len reports the stream length, useful for lag dashboards.
func (r *StreamReader) Len() (int64, error) {
	v, err := r.rdb.Do("XLEN", r.stream)
	if err != nil {
		return 0, err
	}
	return redisclient.Int64(v), nil
}

func parseStreamReply(reply any) []Record {
	streams, ok := reply.([]any)
	if !ok || len(streams) == 0 {
		return nil
	}
	// [ [ streamName, [ [id, [f,v,f,v]], ... ] ] ]
	body, ok := streams[0].([]any)
	if !ok || len(body) < 2 {
		return nil
	}
	entries, ok := body[1].([]any)
	if !ok {
		return nil
	}
	out := make([]Record, 0, len(entries))
	for _, e := range entries {
		pair, ok := e.([]any)
		if !ok || len(pair) < 2 {
			continue
		}
		id, _ := pair[0].(string)
		flat, _ := pair[1].([]any)
		fields := make(map[string]string, len(flat)/2)
		for i := 0; i+1 < len(flat); i += 2 {
			k, _ := flat[i].(string)
			v, _ := flat[i+1].(string)
			fields[k] = v
		}
		out = append(out, Record{ID: id, Fields: fields})
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
