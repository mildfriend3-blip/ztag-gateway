// Package revocation keeps the "is this identity still allowed?" answer off the
// request path. Every verified token is checked against a two-level cache:
//
//	L1  in-process map with a short TTL (hundreds of nanoseconds)
//	L2  Redis revocation set, keyed by token id (jti) and by subject (sub)
//
// A revoked entry at either level denies immediately. The L1 negative TTL
// bounds the worst-case staleness of a revocation to a few seconds, which is
// the deliberate trade-off that keeps the p99 lookup well under 2 ms.
package revocation

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ztag/gateway/internal/redisclient"
)

const (
	keyJTI = "ztag:revoked:jti:"
	keySUB = "ztag:revoked:sub:"
)

type entry struct {
	revoked bool
	until   time.Time
}

// Cache answers revocation questions for verified tokens.
type Cache struct {
	rdb      *redisclient.Client
	negTTL   time.Duration
	maxLocal int

	mu      sync.RWMutex
	entries map[string]entry

	lookups  atomic.Uint64
	l1Hits   atomic.Uint64
	errors   atomic.Uint64
	revoked  atomic.Uint64
	nowFn    func() time.Time
	lastGC   atomic.Int64
	gcPeriod time.Duration
}

// New builds a cache with the given negative-cache TTL. Zero TTL disables L1
// caching of "not revoked" answers (every request then costs one Redis MGET).
func New(rdb *redisclient.Client, negTTL time.Duration) *Cache {
	return &Cache{
		rdb:      rdb,
		negTTL:   negTTL,
		maxLocal: 200_000,
		entries:  make(map[string]entry, 1024),
		nowFn:    time.Now,
		gcPeriod: 30 * time.Second,
	}
}

// Stats is a snapshot of cache effectiveness.
type Stats struct {
	Lookups uint64
	L1Hits  uint64
	Revoked uint64
	Errors  uint64
	Local   int
}

// Stats returns counters for /metrics and /admin/stats.
func (c *Cache) Stats() Stats {
	c.mu.RLock()
	n := len(c.entries)
	c.mu.RUnlock()
	return Stats{
		Lookups: c.lookups.Load(),
		L1Hits:  c.l1Hits.Load(),
		Revoked: c.revoked.Load(),
		Errors:  c.errors.Load(),
		Local:   n,
	}
}

// Revoked reports whether the token (by jti) or its whole subject session
// family has been revoked. An error means Redis was unreachable and no cached
// answer existed; callers decide the failure mode (the proxy fails closed by
// default for sensitive routes).
func (c *Cache) Revoked(jti, sub string) (bool, error) {
	now := c.nowFn()
	c.lookups.Add(1)

	if v, ok := c.lookup(jti, sub, now); ok {
		c.l1Hits.Add(1)
		if v {
			c.revoked.Add(1)
		}
		return v, nil
	}

	keys := make([]string, 0, 2)
	if jti != "" {
		keys = append(keys, keyJTI+jti)
	}
	if sub != "" {
		keys = append(keys, keySUB+sub)
	}
	if len(keys) == 0 {
		return false, nil
	}

	reply, err := c.rdb.Do(append([]string{"MGET"}, keys...)...)
	if err != nil {
		c.errors.Add(1)
		return false, err
	}
	revoked := false
	if arr, ok := reply.([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok && s != "" {
				revoked = true
				break
			}
		}
	}

	ttl := c.negTTL
	if revoked {
		ttl = 30 * time.Second
		c.revoked.Add(1)
	}
	if ttl > 0 {
		c.store(jti, sub, revoked, now.Add(ttl), now)
	}
	return revoked, nil
}

func (c *Cache) lookup(jti, sub string, now time.Time) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if jti != "" {
		if e, ok := c.entries[keyJTI+jti]; ok && now.Before(e.until) {
			return e.revoked, true
		}
	}
	if sub != "" {
		if e, ok := c.entries[keySUB+sub]; ok && now.Before(e.until) {
			return e.revoked, true
		}
	}
	return false, false
}

func (c *Cache) store(jti, sub string, revoked bool, until, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxLocal {
		c.gcLocked(now)
		if len(c.entries) >= c.maxLocal {
			// Hard reset is cheaper than an LRU list on the hot path.
			c.entries = make(map[string]entry, 1024)
		}
	}
	if jti != "" {
		c.entries[keyJTI+jti] = entry{revoked: revoked, until: until}
	}
	if sub != "" {
		c.entries[keySUB+sub] = entry{revoked: revoked, until: until}
	}
}

func (c *Cache) gcLocked(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.until) {
			delete(c.entries, k)
		}
	}
}

// GC drops expired local entries. It is called opportunistically; a background
// goroutine is unnecessary because the map is bounded.
func (c *Cache) GC() {
	now := c.nowFn()
	if now.Unix()-c.lastGC.Load() < int64(c.gcPeriod.Seconds()) {
		return
	}
	c.lastGC.Store(now.Unix())
	c.mu.Lock()
	c.gcLocked(now)
	c.mu.Unlock()
}

// RevokeToken adds a jti to the global revocation list for ttl. The proxy admin
// API calls this; the write path is identical for a whole subject family
// (RevokeSubject) so an operator can kill every session of a compromised user
// with one call.
func (c *Cache) RevokeToken(jti string, ttl time.Duration) error {
	if jti == "" {
		return nil
	}
	_, err := c.rdb.Do("SET", keyJTI+jti, "1", "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	if err == nil {
		c.store(jti, "", true, c.nowFn().Add(ttl), c.nowFn())
	}
	return err
}

// RevokeSubject kills every token issued to a subject for ttl seconds.
func (c *Cache) RevokeSubject(sub string, ttl time.Duration) error {
	if sub == "" {
		return nil
	}
	_, err := c.rdb.Do("SET", keySUB+sub, "1", "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	if err == nil {
		c.store("", sub, true, c.nowFn().Add(ttl), c.nowFn())
	}
	return err
}
