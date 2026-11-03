package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestMemoryLimiterAdmitsUpToLimit(t *testing.T) {
	m := NewMemory(3, time.Minute)
	for i := 0; i < 3; i++ {
		if r := m.Allow("k"); !r.Allowed {
			t.Fatalf("request %d should be admitted: %+v", i, r)
		}
	}
	if r := m.Allow("k"); r.Allowed {
		t.Fatalf("fourth request must be rejected: %+v", r)
	}
}

func TestMemoryLimiterWindowsReset(t *testing.T) {
	m := NewMemory(1, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return now }

	if !m.Allow("k").Allowed {
		t.Fatal("first request must pass")
	}
	if m.Allow("k").Allowed {
		t.Fatal("second request in the same window must fail")
	}
	now = now.Add(time.Minute + time.Second)
	if !m.Allow("k").Allowed {
		t.Fatal("a new window must admit again")
	}
}

func TestMemoryLimiterConcurrent(t *testing.T) {
	m := NewMemory(100, time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m.Allow("shared").Allowed {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 100 {
		t.Fatalf("want exactly 100 admissions, got %d", admitted)
	}
}
