package e2e

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/proxy"
	"github.com/openwaap/openwaap/internal/rules/managed"
	testorigin "github.com/openwaap/openwaap/test/origin"
)

func phase2Edge(t *testing.T, mutate func(*config.DomainConfig)) (*testorigin.Origin, *httptest.Server) {
	t.Helper()
	o, err := testorigin.New()
	if err != nil {
		t.Fatal(err)
	}
	_, port, ok := strings.Cut(o.ListenerAddr(), ":")
	if !ok {
		o.Close()
		t.Fatalf("cannot extract port from %s", o.ListenerAddr())
	}
	en := true
	dc := config.DomainConfig{
		Hostname: "example.com",
		Enabled:  &en,
		Origin:   config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: port},
		WAF: config.WAFPolicy{
			Mode:    config.WAFModeBlock,
			Managed: config.ManagedPolicy{RulesetVersion: managed.DefaultRulesetVersion, ParanoiaLevel: 1},
		},
	}
	mutate(&dc)
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{ListenHTTPS: ":0"},
		Security: config.SecurityConfig{
			EngineFailMode:  config.FailOpen,
		},
		Domains: []config.DomainConfig{dc},
	}
	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 128})
	handler, err := proxy.New(cfg, proxy.Options{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		Emit:   emit,
	})
	if err != nil {
		o.Close()
		emit.Close()
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(func() {
		srv.Close()
		o.Close()
		emit.Close()
	})
	return o, srv
}

func browserClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

func browserReq(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := browserClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRateLimitBlocksAfterThreshold(t *testing.T) {
	_, srv := phase2Edge(t, func(dc *config.DomainConfig) {
		dc.RateLimit = &config.RateLimitConfig{
			Enabled: true,
			Limits: []config.RateLimitRule{{
				ID: "r-basic", Enabled: true, Scope: config.ScopeIP, Max: 2,
				Window: config.Duration(60 * time.Second), Action: config.ActionRateLimit,
			}},
		}
	})

	want := []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests, http.StatusTooManyRequests}
	for i, wantStatus := range want {
		resp := browserReq(t, srv, "/products")
		if resp.StatusCode != wantStatus {
			t.Fatalf("request %d: want %d, got %d", i+1, wantStatus, resp.StatusCode)
		}
		if wantStatus == http.StatusTooManyRequests {
			if resp.Header.Get("Retry-After") == "" {
				t.Fatalf("request %d: expected Retry-After on 429", i+1)
			}
		}
		resp.Body.Close()
	}
}

func TestThrottleTierEndToEnd(t *testing.T) {
	tm := config.Duration(60 * time.Second)
	max := 2
	throttle := 5
	_, srv := phase2Edge(t, func(dc *config.DomainConfig) {
		dc.RateLimit = &config.RateLimitConfig{
			Enabled: true,
			Limits: []config.RateLimitRule{{
				ID: "r-throttle", Enabled: true, Scope: config.ScopeIP, Max: max,
				ThrottleMax: &throttle, Window: tm, Action: config.ActionBlock,
			}},
		}
	})

	want := []int{
		http.StatusOK, http.StatusOK,
		http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusTooManyRequests,
		http.StatusForbidden, http.StatusForbidden,
	}
	for i, wantStatus := range want {
		resp := browserReq(t, srv, "/products")
		if resp.StatusCode != wantStatus {
			t.Fatalf("request %d: want %d, got %d", i+1, wantStatus, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestBotPolicyChallengesAutomation(t *testing.T) {
	o, srv := phase2Edge(t, func(dc *config.DomainConfig) {
		dc.Bot = &config.BotConfig{Enabled: true, ChallengeBelow: 20}
	})

	resp := browserReq(t, srv, "/products")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("browser request should be allowed, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/products", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "curl/8.1.2")
	resp, err := browserClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooEarly {
		t.Fatalf("curl request should be challenged (425), got %d", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/products", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	resp, err = browserClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verified googlebot should be allowed, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if o.Requests() < 2 {
		t.Fatalf("expected browser+bot to reach origin, got %d", o.Requests())
	}
}

func TestReputationEscalatesAfterHoneypot(t *testing.T) {
	o, srv := phase2Edge(t, func(dc *config.DomainConfig) {
		dc.Honeypot = &config.HoneypotConfig{Enabled: true, AutoGenerate: true}
		dc.Reputation = &config.ReputationConfig{
			Enabled:              true,
			BlockScore:           60,
			HoneypotPoints:       80,
			BlockedRequestPoints: 25,
		}
	})

	resp := browserReq(t, srv, "/wp-login.php")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("honeypot hit should be blocked (403), got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = browserReq(t, srv, "/products")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("reputation should hard-block the attacker IP, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if o.Requests() != 0 {
		t.Fatalf("origin must receive zero attack traffic, got %d", o.Requests())
	}
}
