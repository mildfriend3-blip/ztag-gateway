// Package ratelimit implements a Redis-backed sliding-window limiter that runs
// inside the proxy, before any request can reach an upstream login route. The
// window is a sorted set of request timestamps scored in milliseconds: the
// script trims everything older than now-window, counts what remains and only
// then admits. Because trimming, counting and inserting happen in one Lua
// invocation, the decision is atomic across every proxy replica.
package ratelimit

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ztag/gateway/internal/redisclient"
)

// slidingWindowLua is the whole limiter. KEYS[1] is the bucket key,
// ARGV: now_ms, window_ms, limit, member.
const slidingWindowLua = `
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)

if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = window
  if oldest[2] then
    retry = window - (now - tonumber(oldest[2]))
    if retry < 1 then retry = 1 end
  end
  return {0, count, retry}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)
return {1, count + 1, 0}
`

// Result is the outcome of one admission decision.
type Result struct {
	Allowed    bool
	Count      int64
	Limit      int64
	RetryAfter time.Duration
}

// Limiter admits or rejects requests per key inside a sliding window.
type Limiter struct {
	rdb    *redisclient.Client
	script *redisclient.Script
	limit  int64
	window time.Duration
	prefix string
	seq    atomic.Uint64
	nowFn  func() time.Time
}

// New builds a limiter with limit admissions per window.
func New(rdb *redisclient.Client, prefix string, limit int64, window time.Duration) *Limiter {
	return &Limiter{
		rdb:    rdb,
		script: redisclient.NewScript(slidingWindowLua),
		limit:  limit,
		window: window,
		prefix: prefix,
		nowFn:  time.Now,
	}
}

// Limit returns the configured admission ceiling.
func (l *Limiter) Limit() int64 { return l.limit }

// Allow consumes one slot for key. Keys are namespaced by the limiter prefix so
// independent budgets (per identity, per IP, per route) cannot collide.
func (l *Limiter) Allow(key string) (Result, error) {
	now := l.nowFn().UnixMilli()
	// Unique member: replica-independent sequence plus millisecond. Two
	// requests inside the same millisecond still get distinct members, so a
	// burst is never under-counted.
	member := strconv.FormatInt(now, 10) + ":" + strconv.FormatUint(l.seq.Add(1), 10)

	reply, err := l.script.Run(l.rdb, []string{l.prefix + key},
		strconv.FormatInt(now, 10),
		strconv.FormatInt(l.window.Milliseconds(), 10),
		strconv.FormatInt(l.limit, 10),
		member,
	)
	if err != nil {
		return Result{}, err
	}
	arr, ok := reply.([]any)
	if !ok || len(arr) < 3 {
		return Result{}, errUnexpectedReply
	}
	res := Result{
		Allowed: redisclient.Int64(arr[0]) == 1,
		Count:   redisclient.Int64(arr[1]),
		Limit:   l.limit,
	}
	if !res.Allowed {
		res.RetryAfter = time.Duration(redisclient.Int64(arr[2])) * time.Millisecond
	}
	return res, nil
}

type limiterError string

func (e limiterError) Error() string { return string(e) }

const errUnexpectedReply limiterError = "ratelimit: unexpected script reply"

// MemoryLimiter is an in-process fallback used when Redis is unreachable and
// the operator has chosen fail-open with local accounting. It is deliberately
// per-replica and therefore weaker: documented as degraded mode only.
type MemoryLimiter struct {
	limit  int64
	window time.Duration
	mu     sync.Mutex
	bkts   map[string]*bucket
	nowFn  func() time.Time
}

type bucket struct {
	start time.Time
	count int64
}

// NewMemory builds a degraded-mode limiter.
func NewMemory(limit int64, window time.Duration) *MemoryLimiter {
	return &MemoryLimiter{limit: limit, window: window, bkts: make(map[string]*bucket), nowFn: time.Now}
}

// Allow applies a fixed window locally.
func (m *MemoryLimiter) Allow(key string) Result {
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bkts[key]
	if !ok || now.Sub(b.start) >= m.window {
		b = &bucket{start: now}
		m.bkts[key] = b
	}
	if b.count >= m.limit {
		return Result{Allowed: false, Count: b.count, Limit: m.limit, RetryAfter: m.window - now.Sub(b.start)}
	}
	b.count++
	return Result{Allowed: true, Count: b.count, Limit: m.limit}
}
