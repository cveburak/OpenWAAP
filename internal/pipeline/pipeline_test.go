package pipeline

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/bot"
	"github.com/openwaap/openwaap/internal/config"
	reqctx "github.com/openwaap/openwaap/internal/context"
	"github.com/openwaap/openwaap/internal/decision"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/honeypot"
	"github.com/openwaap/openwaap/internal/ratelimit"
	"github.com/openwaap/openwaap/internal/reputation"
	custom "github.com/openwaap/openwaap/internal/rules/custom"
	"github.com/openwaap/openwaap/internal/rules/managed"
)

func defaultLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func baseConfig(t *testing.T) Config {
	t.Helper()
	rs, err := managed.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Ruleset:            rs,
		CustomRules:        nil,
		Honeypot:           nil,
		FailOpen:           true,
		WAFEnabled:         true,
		ManagedMaxParanoia: 1,
	}
}

func makeCtx(query string) *reqctx.RequestContext {
	c := &reqctx.RequestContext{
		RequestID: "req-1",
		RemoteIP:  net.ParseIP("198.51.100.9"),
		Method:    "GET",
		Path:      "/products",
		RawQuery:  query,
		Host:      "example.com",
		Headers:   http.Header{"User-Agent": []string{"curl/8.0"}},
		UA:        "curl/8.0",
	}
	return c
}

func TestCleanRequestAllowed(t *testing.T) {
	p := New(baseConfig(t), nil, defaultLogger())
	c := makeCtx("id=5&sort=asc")
	res := p.Inspect(c, nil)
	if res.Denied {
		t.Fatalf("expected clean request allowed, got %s", res.Decision)
	}
	if res.Score != 0 {
		t.Fatalf("expected score 0, got %d", res.Score)
	}
}

func TestSQLiQueryBlocked(t *testing.T) {
	p := New(baseConfig(t), nil, defaultLogger())
	c := makeCtx("id=1 UNION SELECT username FROM users")
	res := p.Inspect(c, nil)
	if !res.Denied {
		t.Fatal("expected SQLi blocked")
	}
	if res.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", res.Decision)
	}
	if res.Score < 80 {
		t.Fatalf("expected high score, got %d", res.Score)
	}
	if len(res.Reasons) == 0 {
		t.Fatal("expected explainable reasons")
	}
}

func TestHoneypotHitBlocked(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Honeypot = honeypot.NewRegistry(nil, true, 0)
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("")
	c.Path = "/wp-admin"
	res := p.Inspect(c, nil)
	if !res.Denied {
		t.Fatal("expected honeypot hit blocked")
	}
	if res.Score != 99 {
		t.Fatalf("expected honeypot score 99, got %d", res.Score)
	}
	if !c.HoneypotHit {
		t.Fatal("expected honeypot flag on context")
	}
}

func TestHoneypotPointsConfigurable(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Honeypot = honeypot.NewRegistry(nil, true, 50)
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("")
	c.Path = "/wp-admin"
	res := p.Inspect(c, nil)
	if res.Decision != decision.Challenge {
		t.Fatalf("points=50 should land in Challenge, got decision=%s score=%d", res.Decision, res.Score)
	}
	if res.Score != 50 {
		t.Fatalf("expected honeypot score 50, got %d", res.Score)
	}
}

func TestCustomRuleOverride(t *testing.T) {
	cfg := baseConfig(t)
	rule, err := custom.Parse("r-1", "admin block", `IF path starts_with "/admin" THEN BLOCK`)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CustomRules = []*custom.Rule{rule}
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("")
	c.Path = "/admin/settings"
	res := p.Inspect(c, nil)
	if !res.Denied {
		t.Fatal("expected admin path blocked by custom rule")
	}
	if res.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", res.Decision)
	}
}

func TestCustomRuleAllowOverridesManaged(t *testing.T) {
	cfg := baseConfig(t)
	rule, err := custom.Parse("r-1", "allow union in api",
		`IF path starts_with "/api" AND hostname == "example.com" THEN ALLOW`)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CustomRules = []*custom.Rule{rule}
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("id=1 UNION SELECT 1,2,3")
	c.Path = "/api/search"
	res := p.Inspect(c, nil)
	if res.Denied {
		t.Fatalf("expected custom ALLOW to override managed block, got %s", res.Decision)
	}
	if res.Decision != decision.Allow {
		t.Fatalf("expected ALLOW, got %s", res.Decision)
	}
}

func TestWAFDisabledModeAllowsAttack(t *testing.T) {
	cfg := baseConfig(t)
	cfg.WAFEnabled = false
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("id=1 UNION SELECT 1,2,3")
	res := p.Inspect(c, nil)
	if res.Denied {
		t.Fatalf("expected detection-only mode to allow, got %s", res.Decision)
	}
}

func TestBodyInspectionTriggersDetection(t *testing.T) {
	rs, _ := managed.LoadDefault()
	cfg := baseConfig(t)
	cfg.Ruleset = rs
	p := New(cfg, nil, defaultLogger())
	c := &reqctx.RequestContext{
		RequestID: "req-b",
		RemoteIP:  net.ParseIP("198.51.100.9"),
		Method:    "POST",
		Path:      "/submit",
		Host:      "example.com",
		Headers:   http.Header{},
	}
	body := []byte(`<script>alert(1)</script>`)
	res := p.Inspect(c, func() ([]byte, error) { return body, nil })
	if !res.Denied {
		t.Fatalf("expected XSS body blocked, got %s", res.Decision)
	}
}

func TestFormBodyInspectionDecodesPayload(t *testing.T) {
	rs, _ := managed.LoadDefault()
	cfg := baseConfig(t)
	cfg.Ruleset = rs
	p := New(cfg, nil, defaultLogger())
	c := &reqctx.RequestContext{
		RequestID: "req-f",
		RemoteIP:  net.ParseIP("198.51.100.9"),
		Method:    "POST",
		Path:      "/submit",
		Host:      "example.com",
		Headers:   http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
	}
	body := []byte("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	res := p.Inspect(c, func() ([]byte, error) { return body, nil })
	if !res.Denied {
		t.Fatalf("expected form-encoded XSS blocked, got %s", res.Decision)
	}
}

func TestJSONBodyInspectionDecodesPayload(t *testing.T) {
	rs, _ := managed.LoadDefault()
	cfg := baseConfig(t)
	cfg.Ruleset = rs
	p := New(cfg, nil, defaultLogger())
	c := &reqctx.RequestContext{
		RequestID: "req-j",
		RemoteIP:  net.ParseIP("198.51.100.9"),
		Method:    "POST",
		Path:      "/submit",
		Host:      "example.com",
		Headers:   http.Header{"Content-Type": {"application/json"}},
	}
	body := []byte(`{"q":"1' OR '1'='1 --"}`)
	res := p.Inspect(c, func() ([]byte, error) { return body, nil })
	if !res.Denied {
		t.Fatalf("expected JSON body SQLi blocked, got %s", res.Decision)
	}
}

func TestEmittedEvent(t *testing.T) {
	p := New(baseConfig(t), nil, defaultLogger())
	c := makeCtx("id=1 UNION SELECT 1,2,3")
	res := p.Inspect(c, nil)
	if res.Event == nil {
		t.Fatal("expected event attached to result")
	}
	if res.Event.Action != events.ActionBlock {
		t.Fatalf("expected BLOCK event, got %s", res.Event.Action)
	}
	if res.Event.RequestID != "req-1" {
		t.Fatalf("expected request id, got %s", res.Event.RequestID)
	}
	if res.Event.DurationMs < 0 {
		t.Fatalf("expected duration_ms >= 0, got %d", res.Event.DurationMs)
	}
}

func TestPanicGuardFailClosed(t *testing.T) {
	cfg := baseConfig(t)
	cfg.FailOpen = false
	cfg.Ruleset = nil
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("")
	c.RequestID = "panic-req"
	res := p.Inspect(c, nil)
	if !res.Denied {
		t.Fatalf("expected fail-closed block on panic, got %s", res.Decision)
	}
}
func makeRateLimitConfig(t *testing.T) Config {
	cfg := baseConfig(t)
	w, err := time.ParseDuration("60s")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RateLimit = ratelimit.New([]config.RateLimitRule{{
		ID: "rl-ip", Enabled: true, Scope: config.ScopeIP, Max: 2,
		Window: config.Duration(w), Action: config.ActionRateLimit,
	}}, nil)
	return cfg
}

func TestRateLimitPreOverride(t *testing.T) {
	p := New(makeRateLimitConfig(t), nil, defaultLogger())
	c := makeCtx("")
	if res := p.Inspect(c, nil); res.Denied {
		t.Fatalf("request 1 should be allowed, got %s", res.Decision)
	}
	c = makeCtx("")
	if res := p.Inspect(c, nil); res.Denied {
		t.Fatalf("request 2 should be allowed, got %s", res.Decision)
	}
	c = makeCtx("")
	res := p.Inspect(c, nil)
	if res.Decision != decision.RateLimit {
		t.Fatalf("request 3 should be RATE_LIMIT, got %s", res.Decision)
	}
	if !res.Denied {
		t.Fatal("rate limited request must not reach origin")
	}
	if res.RetryAfter != 60 {
		t.Fatalf("expected Retry-After 60, got %d", res.RetryAfter)
	}
}

func TestBotPolicyChallengesCurl(t *testing.T) {
	cfg := baseConfig(t)
	cfg.BotDetector = bot.New(nil, nil)
	cfg.BotChallengeBelow = 20
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("")
	c.UA = "curl/8.0"
	c.Headers.Set("User-Agent", "curl/8.0")
	res := p.Inspect(c, nil)
	if res.Decision != decision.Challenge {
		t.Fatalf("expected bot challenge, got %s (bot_score=%d)", res.Decision, c.BotScore)
	}
	if c.BotScore >= 20 {
		t.Fatalf("curl should score low, got %d", c.BotScore)
	}
}

func TestVerifiedBotNotChallenged(t *testing.T) {
	cfg := baseConfig(t)
	cfg.BotDetector = bot.New(nil, nil)
	cfg.BotChallengeBelow = 20
	p := New(cfg, nil, defaultLogger())
	c := makeCtx("")
	c.UA = "Mozilla/5.0 (compatible; Googlebot/2.1)"
	c.Headers.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
	res := p.Inspect(c, nil)
	if res.Denied {
		t.Fatalf("verified bot should pass, got %s", res.Decision)
	}
}

func TestReputationEscalationAfterBlock(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Reputation = reputation.New(nil)
	cfg.RepBlockScore = 60
	cfg.RepHoneypotPoints = 50
	cfg.RepBlockedPoints = 25
	p := New(cfg, nil, defaultLogger())

	c := makeCtx("")
	c.Path = "/wp-login.php"
	cfg2 := cfg
	cfg2.Honeypot = honeypot.NewRegistry(nil, true, 0)
	p = New(cfg2, nil, defaultLogger())
	res := p.Inspect(c, nil)
	if !c.HoneypotHit {
		t.Fatal("expected honeypot hit")
	}
	if res.Decision != decision.Block {
		t.Fatalf("expected honeypot block, got %s", res.Decision)
	}
	c = makeCtx("")
	res = p.Inspect(c, nil)
	if got := cfg.Reputation.Score("198.51.100.9"); got < 60 {
		t.Fatalf("expected reputation ≥ 60, got %d", got)
	}
	if res.Decision != decision.Block {
		t.Fatalf("expected reputation block, got %s", res.Decision)
	}
	if res.Event == nil || res.Event.Action != events.ActionBlock {
		t.Fatalf("expected BLOCK event, got %+v", res.Event)
	}
}

func TestCustomAllowBeatsRateLimit(t *testing.T) {
	cfg := makeRateLimitConfig(t)
	rule, err := custom.Parse("r-allow", "browser exempt",
		`IF hostname == "example.com" THEN ALLOW`)
	if err != nil {
		t.Fatal(err)
	}
	_ = rule
	cfg.CustomRules = []*custom.Rule{rule}
	p := New(cfg, nil, defaultLogger())
	for i := 0; i < 4; i++ {
		c := makeCtx("")
		if res := p.Inspect(c, nil); res.Denied {
			t.Fatalf("request %d: custom ALLOW must beat rate limit, got %s", i+1, res.Decision)
		}
	}
}

func TestNewDefaultsNilLogger(t *testing.T) {
	p := New(baseConfig(t), nil, nil)
	if p.log == nil {
		t.Fatal("New(cfg, emit, nil) left p.log nil — Inspect's recover() handler would panic on it")
	}
	if res := p.Inspect(makeCtx(""), nil); res.Decision == "" {
		t.Fatal("Inspect with a defaulted logger produced no decision")
	}
}
