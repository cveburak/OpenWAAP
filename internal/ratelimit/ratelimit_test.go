package ratelimit

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

func mustDuration(t *testing.T, s string) config.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("parse duration %q: %v", s, err)
	}
	return config.Duration(d)
}

func intPtr(v int) *int { return &v }

func hdr() http.Header { return http.Header{} }

func TestSlidingWindowAllowsUnderMax(t *testing.T) {
	e := New([]config.RateLimitRule{
		{ID: "ip-10", Enabled: true, Scope: config.ScopeIP, Max: 10, Window: mustDuration(t, "60s")},
	}, nil)
	for i := 0; i < 10; i++ {
		oc := e.Check(Request{IP: "1.2.3.4", Headers: hdr()})
		if oc.Action != config.ActionAllow {
			t.Fatalf("request %d: expected allow, got %s", i+1, oc.Action)
		}
	}
	oc := e.Check(Request{IP: "1.2.3.4", Headers: hdr()})
	if oc.Action != config.ActionBlock {
		t.Fatalf("expected block over limit, got %s (count=%d)", oc.Action, oc.Count)
	}
}

func TestThrottleTier(t *testing.T) {
	e := New([]config.RateLimitRule{{
		ID: "throttle", Enabled: true, Scope: config.ScopeIP, Max: 3,
		ThrottleMax: intPtr(6), Window: mustDuration(t, "60s"), Action: config.ActionBlock,
	}}, nil)
	reqs := []config.Action{
		config.ActionAllow, config.ActionAllow, config.ActionAllow,
		config.ActionThrottle, config.ActionThrottle, config.ActionThrottle,
		config.ActionBlock, config.ActionBlock,
	}
	for i, want := range reqs {
		oc := e.Check(Request{IP: "9.9.9.9", Headers: hdr()})
		if oc.Action != want {
			t.Fatalf("req %d: want %s got %s", i+1, want, oc.Action)
		}
	}
}

func TestWindowSlides(t *testing.T) {
	base := time.Now()
	now := base
	e := New([]config.RateLimitRule{{
		ID: "slide", Enabled: true, Scope: config.ScopeIP, Max: 1,
		Window: mustDuration(t, "10s"), Action: config.ActionRateLimit,
	}}, func() time.Time { return now })

	if oc := e.Check(Request{IP: "5.5.5.5", Headers: hdr()}); oc.Action != config.ActionAllow {
		t.Fatalf("first: want allow got %s", oc.Action)
	}
	if oc := e.Check(Request{IP: "5.5.5.5", Headers: hdr()}); oc.Action != config.ActionRateLimit {
		t.Fatalf("second: want RATE_LIMIT got %s", oc.Action)
	}
	now = base.Add(15 * time.Second)
	if oc := e.Check(Request{IP: "5.5.5.5", Headers: hdr()}); oc.Action != config.ActionAllow {
		t.Fatalf("after window: want allow got %s", oc.Action)
	}
}

func TestScopesIndependent(t *testing.T) {
	e := New([]config.RateLimitRule{
		{ID: "per-ip", Enabled: true, Scope: config.ScopeIP, Max: 1, Window: mustDuration(t, "60s"), Action: config.ActionBlock},
		{ID: "per-path", Enabled: true, Scope: config.ScopePath, Path: "/login", Max: 2, Window: mustDuration(t, "60s"), Action: config.ActionBlock},
	}, nil)

	if oc := e.Check(Request{IP: "1.1.1.1", Path: "/login", Headers: hdr()}); oc.Action != config.ActionAllow {
		t.Fatalf("want allow got %s", oc.Action)
	}
	if oc := e.Check(Request{IP: "2.2.2.2", Path: "/login", Headers: hdr()}); oc.Action != config.ActionAllow {
		t.Fatalf("want allow got %s", oc.Action)
	}
	if oc := e.Check(Request{IP: "1.1.1.1", Path: "/login", Headers: hdr()}); oc.Action != config.ActionBlock {
		t.Fatalf("want ip block got %s", oc.Action)
	}
}

func TestHeaderScope(t *testing.T) {
	e := New([]config.RateLimitRule{{
		ID: "api-key", Enabled: true, Scope: config.ScopeHeader, Header: "X-Api-Key",
		Max: 2, Window: mustDuration(t, "60s"), Action: config.ActionRateLimit,
	}}, nil)
	for i := 0; i < 2; i++ {
		if oc := e.Check(Request{IP: "3.3.3.3", Headers: http.Header{"X-Api-Key": {"k1"}}}); oc.Action != config.ActionAllow {
			t.Fatalf("req %d: want allow got %s", i+1, oc.Action)
		}
	}
	if oc := e.Check(Request{IP: "3.3.3.3", Headers: http.Header{"X-Api-Key": {"k1"}}}); oc.Action != config.ActionRateLimit {
		t.Fatalf("want rate limit got %s", oc.Action)
	}
	if oc := e.Check(Request{IP: "3.3.3.3", Headers: http.Header{"X-Api-Key": {"k2"}}}); oc.Action != config.ActionAllow {
		t.Fatalf("want allow for k2 got %s", oc.Action)
	}
}

func TestConcurrentChecks(t *testing.T) {
	e := New([]config.RateLimitRule{{
		ID: "conc", Enabled: true, Scope: config.ScopeIP, Max: 800,
		Window: mustDuration(t, "60s"), Action: config.ActionBlock,
	}}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				e.Check(Request{IP: "7.7.7.7", Headers: hdr()})
			}
		}()
	}
	wg.Wait()
	oc := e.Check(Request{IP: "7.7.7.7", Headers: hdr()})
	if oc.Action != config.ActionBlock {
		t.Fatalf("expected block, got %s (count=%d)", oc.Action, oc.Count)
	}
	if oc.Count != 801 {
		t.Fatalf("expected 801 observed, got %d", oc.Count)
	}
}

func TestInactiveRuleSkipped(t *testing.T) {
	e := New([]config.RateLimitRule{
		{ID: "off", Enabled: false, Scope: config.ScopeIP, Max: 1, Window: mustDuration(t, "60s"), Action: config.ActionBlock},
		{ID: "on", Enabled: true, Scope: config.ScopeIP, Max: 1, Window: mustDuration(t, "60s"), Action: config.ActionBlock},
	}, nil)
	if oc := e.Check(Request{IP: "4.4.4.4", Headers: hdr()}); oc.Action != config.ActionAllow {
		t.Fatalf("only disabled rule matched? got %s", oc.Action)
	}
	if oc := e.Check(Request{IP: "4.4.4.4", Headers: hdr()}); oc.Action != config.ActionBlock {
		t.Fatalf("second: want block got %s", oc.Action)
	}
}

func TestCountsMapBounded(t *testing.T) {
	e := New([]config.RateLimitRule{
		{ID: "r", Enabled: true, Scope: config.ScopeIP, Max: 1000, Window: mustDuration(t, "60s"), Action: config.ActionBlock},
	}, nil)
	e.MaxCountKeys = 100

	for i := 0; i < 1000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		e.Check(Request{IP: ip, Headers: hdr()})
	}

	e.mu.Lock()
	n := len(e.counts)
	e.mu.Unlock()
	if n > e.MaxCountKeys {
		t.Fatalf("counts map grew to %d entries, want <= %d (MaxCountKeys)", n, e.MaxCountKeys)
	}
}
