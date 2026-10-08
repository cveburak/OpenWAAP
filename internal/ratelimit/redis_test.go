package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/metrics"
)

func newTestRule(id, scope string, max int, window time.Duration) config.RateLimitRule {
	return config.RateLimitRule{
		ID:      id,
		Enabled: true,
		Scope:   config.RateLimitScope(scope),
		Max:     max,
		Window:  config.Duration(window),
	}
}

func TestRedisBackendDistributed(t *testing.T) {
	mr := miniredis.RunT(t)

	cfg := config.RedisConfig{Address: mr.Addr(), DB: 0}
	b, client, err := NewRedisBackendFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer b.Close()

	rule := newTestRule("rl1", "ip", 2, time.Second)
	now := time.Now()

	e1 := NewWithBackend([]config.RateLimitRule{rule}, func() time.Time { return now }, b)
	e2 := NewWithBackend([]config.RateLimitRule{rule}, func() time.Time { return now }, b)

	req := Request{Domain: "a", IP: "203.0.113.7", Path: "/", Method: "GET"}
	if got := e1.Check(req); got.Action != config.ActionAllow {
		t.Fatalf("e1 first hit: %v", got.Action)
	}
	if got := e2.Check(req); got.Action != config.ActionAllow {
		t.Fatalf("e2 second hit: %v", got.Action)
	}
	if got := e1.Check(req); got.Action != config.ActionBlock {
		t.Fatalf("cross-edge counting broken, got %v count=%d", got.Action, got.Count)
	}
}

func TestRedisBackendWindowExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	b, client, err := NewRedisBackendFromConfig(config.RedisConfig{Address: mr.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer b.Close()

	rule := newTestRule("rl2", "ip", 1, 500*time.Millisecond)
	now := time.Now()
	e := NewWithBackend([]config.RateLimitRule{rule}, func() time.Time { return now }, b)
	req := Request{Domain: "a", IP: "203.0.113.8", Path: "/", Method: "GET"}

	if got := e.Check(req); got.Count != 1 {
		t.Fatalf("first hit count %d", got.Count)
	}
	if got := e.Check(req); got.Action != config.ActionBlock {
		t.Fatalf("second hit must block, got %v", got.Action)
	}
	now = now.Add(time.Second)
	if got := e.Check(req); got.Action != config.ActionAllow {
		t.Fatalf("hit after expiry must allow, got %v", got.Action)
	}
}

func TestMemoryFallback(t *testing.T) {
	if _, _, err := NewRedisBackendFromConfig(config.RedisConfig{Address: "127.0.0.1:1"}); err == nil {
		t.Skip("expected dial failure on closed port; backend reachable, skipping")
	}

	failing := &errBackend{}
	rule := newTestRule("rl3", "ip", 1, time.Minute)
	now := time.Now()
	e := NewWithBackend([]config.RateLimitRule{rule}, func() time.Time { return now }, failing)
	req := Request{Domain: "a", IP: "203.0.113.9", Path: "/", Method: "GET"}

	reg := metrics.NewRegistry()
	degraded := reg.Counter("waap_ratelimit_backend_degraded_total", "test", "domain")
	e.SetDegradedCounter(degraded, "example.com")

	if got := e.Check(req); got.Action != config.ActionAllow {
		t.Fatalf("first fallback hit: %v", got.Action)
	}
	if got := e.Check(req); got.Action != config.ActionBlock {
		t.Fatalf("fallback must still enforce limits, got %v", got.Action)
	}
	if n := degraded.Get(); n != 2 {
		t.Fatalf("degraded counter = %d, want 2 (one per failed backend call)", n)
	}
}

type errBackend struct{}

func (e *errBackend) Observe(ctx context.Context, ruleKey string, window time.Duration, now time.Time) (int, error) {
	return 0, context.DeadlineExceeded
}
