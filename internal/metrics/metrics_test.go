package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounterAndGaugeExposition(t *testing.T) {
	r := NewRegistry()
	e := NewEdge(r)

	e.RequestsTotal.Incr("BLOCK")
	e.RequestsTotal.Incr("BLOCK")
	e.RequestsTotal.Incr("ALLOW")
	e.RequestsDenied.Incr("BLOCK", "example.test")
	e.Active.Set(3)
	e.Active.Add(-1)

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, nil)
	body := rec.Body.String()

	for _, want := range []string{
		`waap_requests_total{action="BLOCK"} 2`,
		`waap_requests_total{action="ALLOW"} 1`,
		`waap_requests_denied_total{action="BLOCK",domain="example.test"} 1`,
		`waap_active_requests 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q\n%s", want, body)
		}
	}
}

func TestHistogramExposition(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("waap_request_latency_seconds", "latency")
	h.Observe(0.002)
	h.Observe(0.2)
	h.Observe(0.2)

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, nil)
	body := rec.Body.String()

	for _, want := range []string{
		"# TYPE waap_request_latency_seconds histogram",
		`waap_request_latency_seconds_bucket{le="0.001"} 0`,
		`waap_request_latency_seconds_bucket{le="0.005"} 1`,
		`waap_request_latency_seconds_bucket{le="0.25"} 8`,
		`waap_request_latency_seconds_count 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("histogram missing %q\n%s", want, body)
		}
	}
	if !strings.Contains(body, "waap_request_latency_seconds_sum ") {
		t.Errorf("histogram missing _sum\n%s", body)
	}
}

func TestLabeledCounterDedupe(t *testing.T) {
	r := NewRegistry()
	a := r.Counter("x_total", "help", "action")
	b := r.Counter("x_total", "help", "action")
	if a != b {
		t.Error("expected idempotent registration")
	}
	a.Incr("BLOCK")
	if got := b.Get(); got != 1 {
		t.Errorf("shared counter Get() = %d, want 1", got)
	}
}
