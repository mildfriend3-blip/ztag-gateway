// Command loadgen drives traffic at the gateway. It is the measurement tool for
// the evaluation chapter: it reports throughput, latency percentiles and the
// status mix, and it can replay the three attack shapes the project claims to
// stop (bot flood, credential stuffing, stolen token on a new device).
package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	mu        sync.Mutex
	latencies []time.Duration
	status    map[int]int64
	errors    int64
}

func main() {
	var (
		target = flag.String("url", "http://127.0.0.1:8443/api/orders", "target URL")
		token  = flag.String("token", "", "bearer token for legit modes")
		mode   = flag.String("mode", "legit", "legit | stuffing | flood | noauth | badtoken")
		n      = flag.Int("n", 5000, "total requests (ignored with -duration)")
		conc   = flag.Int("c", 50, "concurrent workers")
		dur    = flag.Duration("duration", 0, "run for this long instead of -n")
		device = flag.String("device", "id=d-7712;os=macos;managed=1;posture=compliant", "device fingerprint header")
		spoof  = flag.Bool("spoof-ip", false, "rotate X-Forwarded-For (tests the per-source limiter)")
	)
	flag.Parse()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 1024,
			DisableCompression:  true,
			DisableKeepAlives:   false,
		},
	}

	res := &result{status: make(map[int]int64), latencies: make([]time.Duration, 0, *n)}
	var sent atomic.Int64
	deadline := time.Now().Add(*dur)

	work := make(chan int, *conc*2)
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(int64(worker)*7919 + time.Now().UnixNano()))
			for idx := range work {
				if *dur > 0 && time.Now().After(deadline) {
					return
				}
				req, err := http.NewRequest(http.MethodGet, *target, nil)
				if err != nil {
					continue
				}
				req.Header.Set("X-Ztag-Device", *device)
				if *spoof {
					req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.%d.%d", rnd.Intn(255), rnd.Intn(255)))
				}
				switch *mode {
				case "legit", "flood":
					req.Header.Set("Authorization", "Bearer "+*token)
				case "stuffing":
					// Rotating usernames from a small source pool: the shape of
					// a credential-stuffing run.
					req.Header.Set("Authorization", "Bearer "+*token)
					req.URL.RawQuery = "user=" + strconv.Itoa(rnd.Intn(5000))
				case "badtoken":
					req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.x")
				case "noauth":
					// nothing
				}

				t0 := time.Now()
				resp, err := client.Do(req)
				d := time.Since(t0)
				sent.Add(1)
				if err != nil {
					atomic.AddInt64(&res.errors, 1)
					continue
				}
				io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()

				res.mu.Lock()
				res.latencies = append(res.latencies, d)
				res.status[resp.StatusCode]++
				res.mu.Unlock()
				_ = idx
			}
		}(i)
	}

	if *dur > 0 {
		go func() {
			for i := 0; ; i++ {
				select {
				case work <- i:
				case <-time.After(50 * time.Millisecond):
					if time.Now().After(deadline) {
						close(work)
						return
					}
				}
			}
		}()
	} else {
		go func() {
			for i := 0; i < *n; i++ {
				work <- i
			}
			close(work)
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	res.mu.Lock()
	defer res.mu.Unlock()
	sort.Slice(res.latencies, func(i, j int) bool { return res.latencies[i] < res.latencies[j] })

	fmt.Printf("mode=%s target=%s workers=%d duration=%s\n", *mode, *target, *conc, elapsed.Round(time.Millisecond))
	fmt.Printf("sent=%d ok=%d errors=%d rps=%.0f\n", sent.Load(), len(res.latencies), res.errors,
		float64(sent.Load())/elapsed.Seconds())
	if len(res.latencies) > 0 {
		fmt.Printf("latency p50=%s p90=%s p99=%s max=%s\n",
			pct(res.latencies, 50), pct(res.latencies, 90), pct(res.latencies, 99), res.latencies[len(res.latencies)-1])
	}
	keys := make([]int, 0, len(res.status))
	for k := range res.status {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		fmt.Printf("status %d: %d\n", k, res.status[k])
	}
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

var _ = os.Stdout
