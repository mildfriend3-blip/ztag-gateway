// Package metrics exposes the handful of counters the gateway needs, in
// Prometheus text format, without pulling in a client library. Every counter is
// a single atomic add on the request path.
package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// latencyBuckets are upper bounds in microseconds.
var latencyBuckets = []int64{100, 250, 500, 1000, 2000, 5000, 10000, 25000, 50000}

// Metrics is the process-wide registry.
type Metrics struct {
	Requests    atomic.Uint64
	Allowed     atomic.Uint64
	Denied      atomic.Uint64
	RateLimited atomic.Uint64
	Revoked     atomic.Uint64
	UpstreamErr atomic.Uint64

	RedisErrors  atomic.Uint64
	PolicyErrors atomic.Uint64
	PolicyDenies atomic.Uint64

	AuditEmitted atomic.Uint64
	AuditDropped atomic.Uint64

	InFlight atomic.Int64

	latency [9]atomic.Uint64 // last slot is +Inf
	sumUS   atomic.Uint64
}

// Observe records a total request latency.
func (m *Metrics) Observe(d time.Duration) {
	us := d.Microseconds()
	m.sumUS.Add(uint64(us))
	for i, b := range latencyBuckets {
		if us <= b {
			m.latency[i].Add(1)
			return
		}
	}
	m.latency[len(m.latency)-1].Add(1)
}

// WriteProm renders the registry in Prometheus exposition format.
func (m *Metrics) WriteProm(w io.Writer) {
	fmt.Fprint(w, "# HELP ztag_requests_total Requests seen by the data plane.\n")
	fmt.Fprint(w, "# TYPE ztag_requests_total counter\n")
	fmt.Fprintf(w, "ztag_requests_total %d\n", m.Requests.Load())

	fmt.Fprint(w, "# HELP ztag_decisions_total Admission decisions by outcome.\n")
	fmt.Fprint(w, "# TYPE ztag_decisions_total counter\n")
	fmt.Fprintf(w, "ztag_decisions_total{outcome=\"allow\"} %d\n", m.Allowed.Load())
	fmt.Fprintf(w, "ztag_decisions_total{outcome=\"deny\"} %d\n", m.Denied.Load())
	fmt.Fprintf(w, "ztag_decisions_total{outcome=\"rate_limited\"} %d\n", m.RateLimited.Load())
	fmt.Fprintf(w, "ztag_decisions_total{outcome=\"revoked\"} %d\n", m.Revoked.Load())

	fmt.Fprint(w, "# HELP ztag_upstream_errors_total Upstream transport failures.\n")
	fmt.Fprint(w, "# TYPE ztag_upstream_errors_total counter\n")
	fmt.Fprintf(w, "ztag_upstream_errors_total %d\n", m.UpstreamErr.Load())

	fmt.Fprint(w, "# HELP ztag_dependency_errors_total Control-plane dependency failures.\n")
	fmt.Fprint(w, "# TYPE ztag_dependency_errors_total counter\n")
	fmt.Fprintf(w, "ztag_dependency_errors_total{dependency=\"redis\"} %d\n", m.RedisErrors.Load())
	fmt.Fprintf(w, "ztag_dependency_errors_total{dependency=\"opa\"} %d\n", m.PolicyErrors.Load())
	fmt.Fprintf(w, "ztag_policy_denies_total %d\n", m.PolicyDenies.Load())

	fmt.Fprint(w, "# HELP ztag_audit_events_total Audit events emitted or dropped.\n")
	fmt.Fprint(w, "# TYPE ztag_audit_events_total counter\n")
	fmt.Fprintf(w, "ztag_audit_events_total{state=\"emitted\"} %d\n", m.AuditEmitted.Load())
	fmt.Fprintf(w, "ztag_audit_events_total{state=\"dropped\"} %d\n", m.AuditDropped.Load())

	fmt.Fprint(w, "# HELP ztag_inflight_requests Requests currently being processed.\n")
	fmt.Fprint(w, "# TYPE ztag_inflight_requests gauge\n")
	fmt.Fprintf(w, "ztag_inflight_requests %d\n", m.InFlight.Load())

	fmt.Fprint(w, "# HELP ztag_request_duration_microseconds End-to-end latency histogram.\n")
	fmt.Fprint(w, "# TYPE ztag_request_duration_microseconds histogram\n")
	var cum uint64
	for i, b := range latencyBuckets {
		cum += m.latency[i].Load()
		fmt.Fprintf(w, "ztag_request_duration_microseconds_bucket{le=\"%d\"} %d\n", b, cum)
	}
	cum += m.latency[len(m.latency)-1].Load()
	fmt.Fprint(w, "ztag_request_duration_microseconds_bucket{le=\"+Inf\"} ", cum, "\n")
	fmt.Fprintf(w, "ztag_request_duration_microseconds_sum %d\n", m.sumUS.Load())
	fmt.Fprintf(w, "ztag_request_duration_microseconds_count %d\n", cum)
}
