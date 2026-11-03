// Command logworker drains the audit stream and writes it to durable storage.
// It is deliberately a separate process: the data plane only ever appends to a
// queue, so a slow database can never slow down request admission.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ztag/gateway/internal/audit"
	"github.com/ztag/gateway/internal/redisclient"
)

func main() {
	var (
		redisAddr = flag.String("redis", env("ZTAG_REDIS_ADDR", "127.0.0.1:6379"), "redis address")
		stream    = flag.String("stream", env("ZTAG_AUDIT_STREAM", "ztag:audit:stream"), "audit stream key")
		group     = flag.String("group", "audit-writers", "consumer group")
		consumer  = flag.String("consumer", hostname(), "consumer name")
		out       = flag.String("out", env("ZTAG_AUDIT_FILE", "-"), "output file (JSONL, - for stdout)")
		batch     = flag.Int("batch", 64, "entries per read")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "ztag-logworker ", log.LstdFlags|log.LUTC)

	rdb := redisclient.New(*redisAddr, 8, time.Second)
	defer rdb.Close()

	reader := audit.NewStreamReader(rdb, *stream, *group, *consumer)
	if err := reader.EnsureGroup(); err != nil {
		logger.Fatalf("consumer group: %v", err)
	}

	sink, err := audit.NewJSONLSink(*out)
	if err != nil {
		logger.Fatalf("output: %v", err)
	}
	defer sink.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Printf("consuming %s as %s/%s -> %s", *stream, *group, *consumer, *out)

	var total uint64
	for ctx.Err() == nil {
		records, err := reader.Read(ctx, *batch)
		if err != nil {
			logger.Printf("read: %v", err)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if len(records) == 0 {
			continue
		}

		events := make([]*audit.Event, 0, len(records))
		ids := make([]string, 0, len(records))
		for _, rec := range records {
			raw, ok := rec.Fields["e"]
			if !ok {
				ids = append(ids, rec.ID)
				continue
			}
			ev := &audit.Event{}
			if err := json.Unmarshal([]byte(raw), ev); err != nil {
				logger.Printf("decode %s: %v", rec.ID, err)
				ids = append(ids, rec.ID)
				continue
			}
			events = append(events, ev)
			ids = append(ids, rec.ID)
		}

		if len(events) > 0 {
			if err := sink.WriteBatch(ctx, events); err != nil {
				logger.Printf("write: %v", err)
				continue // do not ack: redelivery is the correct behaviour
			}
		}
		if err := reader.Ack(ids); err != nil {
			logger.Printf("ack: %v", err)
		}
		total += uint64(len(ids))
		if total%1000 < uint64(len(ids)) {
			if n, err := reader.Len(); err == nil {
				logger.Printf("persisted %d events, stream len %d", total, n)
			}
		}
	}
	logger.Printf("shutting down after %d events", total)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "worker"
	}
	return h
}
