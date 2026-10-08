package ops

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openwaap/openwaap/internal/dashboard"
	"github.com/openwaap/openwaap/internal/metrics"
)

func TestHealthz(t *testing.T) {
	h := New(metrics.NewRegistry(), "test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("healthz body = %s", rec.Body.String())
	}
}

func TestReadyzAllOk(t *testing.T) {
	h := New(metrics.NewRegistry(), "test", nil,
		Named("redis", func(ctx context.Context) error { return nil }),
		Named("geoip", func(ctx context.Context) error { return nil }),
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz code = %d, want 200", rec.Code)
	}
}

func TestReadyzFailure(t *testing.T) {
	h := New(metrics.NewRegistry(), "test", nil,
		Named("redis", func(ctx context.Context) error { return errors.New("redis down") }),
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz code = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "redis down") {
		t.Errorf("readyz body missing error detail: %s", rec.Body.String())
	}
}

func TestMetricsAndFallback(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.Counter("waap_requests_total", "reqs", "action").Incr("BLOCK")

	dash := dashboard.NewHandler(dashboard.HandlerConfig{})
	h := New(reg, "test", dash)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/metrics", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `waap_requests_total{action="BLOCK"} 1`) {
		t.Fatalf("metrics body: code=%d\n%s", rec.Code, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/-/bogus", nil))
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("fallback (dashboard) code = %d, want 404", rec2.Code)
	}
}
