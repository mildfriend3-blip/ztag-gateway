package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWritePromContainsExpectedSeries(t *testing.T) {
	m := &Metrics{}
	m.Requests.Add(10)
	m.Allowed.Add(7)
	m.Denied.Add(3)
	m.Observe(300 * time.Microsecond)
	m.Observe(5 * time.Millisecond)

	var buf bytes.Buffer
	m.WriteProm(&buf)
	out := buf.String()

	for _, want := range []string{
		"ztag_requests_total 10",
		`ztag_decisions_total{outcome="allow"} 7`,
		`ztag_decisions_total{outcome="deny"} 3`,
		`ztag_request_duration_microseconds_bucket{le="500"} 1`,
		`ztag_request_duration_microseconds_bucket{le="+Inf"} 2`,
		"ztag_request_duration_microseconds_count 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in exposition output", want)
		}
	}
}
