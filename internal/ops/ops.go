package ops

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/openwaap/openwaap/internal/metrics"
)

type Check func(ctx context.Context) error

func Named(label string, fn Check) NamedCheck {
	return NamedCheck{Label: label, Check: fn}
}

type NamedCheck struct {
	Label string
	Check Check
}

type Handler struct {
	registry *metrics.Registry
	version  string
	fallback http.Handler

	mu     sync.RWMutex
	checks []NamedCheck
}

func New(registry *metrics.Registry, version string, fallback http.Handler, checks ...NamedCheck) *Handler {
	return &Handler{registry: registry, version: version, fallback: fallback, checks: checks}
}

func (h *Handler) AddCheck(label string, fn Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks = append(h.checks, Named(label, fn))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/-/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": h.version})
	case "/-/readyz":
		h.readyz(w, r)
	case "/-/metrics":
		h.registry.Handler().ServeHTTP(w, r)
	default:
		if h.fallback != nil {
			h.fallback.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	type result struct {
		Label string `json:"label"`
		OK    bool   `json:"ok"`
		Err   string `json:"error,omitempty"`
	}
	h.mu.RLock()
	checks := make([]NamedCheck, len(h.checks))
	copy(checks, h.checks)
	h.mu.RUnlock()
	results := make([]result, 0, len(checks)+1)
	allOK := true
	for _, c := range checks {
		res := result{Label: c.Label, OK: true}
		if c.Check != nil {
			if err := c.Check(ctx); err != nil {
				res.OK = false
				res.Err = err.Error()
			}
		} else {
			res.OK = false
		}
		if !res.OK {
			allOK = false
		}
		results = append(results, res)
	}
	status := http.StatusOK
	overall := "ok"
	if !allOK {
		status = http.StatusServiceUnavailable
		overall = "unready"
	}
	body := map[string]any{
		"status":  overall,
		"version": h.version,
		"checks":  results,
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
