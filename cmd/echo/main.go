// Command echo is a stand-in internal service. It reports what the data plane
// forwarded, which is how you prove that the proxy rewrote identity headers and
// stripped the original bearer token.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	service := flag.String("service", "orders", "service name")
	delay := flag.Duration("delay", 0, "artificial upstream latency")
	flag.Parse()

	logger := log.New(os.Stdout, "ztag-echo ", log.LstdFlags|log.LUTC)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *delay > 0 {
			time.Sleep(*delay)
		}
		headers := make(map[string]string, 8)
		for _, h := range []string{
			"X-Ztag-Subject", "X-Ztag-Jti", "X-Ztag-Service",
			"X-Ztag-Device", "X-Ztag-Trust", "X-Ztag-Request-Id",
			"Authorization", "X-Forwarded-For",
		} {
			if v := r.Header.Get(h); v != "" {
				headers[h] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": *service,
			"method":  r.Method,
			"path":    r.URL.Path,
			"headers": headers,
		})
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Printf("echo service %q listening on %s", *service, *addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatal(err)
	}
}
