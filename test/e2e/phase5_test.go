package e2e

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

const phase5Secret = "e2e-behavior-secret"

const (
	browserUA     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
	acceptHTML    = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	acceptAssets  = "*/*"
	acceptLang    = "en-US,en;q=0.9"
	fpCookie      = "waap_client"
	behaviorBlock = 40
	behaviorCha   = 25
)

type behaviorProber struct {
	client *http.Client
	ua     string
	path   string
	accept string
	lang   string
	honor  bool
	cookie string
}

func (p *behaviorProber) run(t *testing.T, srv *httptest.Server, n int) (allowed int, blocked bool, cookies int) {
	t.Helper()
	for i := 0; i < n; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+p.path, nil)
		req.Host = "example.com"
		req.Header.Set("User-Agent", p.ua)
		req.Header.Set("Accept", p.accept)
		if p.lang != "" {
			req.Header.Set("Accept-Language", p.lang)
		}
		if p.honor && p.cookie != "" {
			req.Header.Set("Cookie", fpCookie+"="+p.cookie)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if sc := resp.Header.Get("Set-Cookie"); strings.HasPrefix(sc, fpCookie+"=") {
			cookies++
			if p.honor {
				p.cookie = strings.TrimPrefix(strings.Split(sc, ";")[0], fpCookie+"=")
			}
		}
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusForbidden:
			blocked = true
		case http.StatusOK:
			allowed++
		}
	}
	return allowed, blocked, cookies
}

func TestBehaviorBlocksScriptedProber(t *testing.T) {
	srv := phase4Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].Behavior = &config.BehaviorConfig{
			Enabled: true, Secret: phase5Secret,
			ChallengeAbove: behaviorCha, BlockAbove: behaviorBlock,
		}
	})
	p := &behaviorProber{
		client: &http.Client{Timeout: 10 * time.Second},
		ua:     "MyScript/2.0", path: "/api/data", accept: "*/*",
	}
	allowed, blocked, cookies := p.run(t, srv, 14)
	if cookies == 0 {
		t.Fatal("scripted prober must receive a waap_client fingerprint on first contact")
	}
	if !blocked {
		t.Fatalf("scripted API probing must be denied (allowed=%d, blocked=%v)", allowed, blocked)
	}
}

func TestBehaviorAllowsHumanLikeSession(t *testing.T) {
	srv := phase4Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].Behavior = &config.BehaviorConfig{
			Enabled: true, Secret: phase5Secret,
			ChallengeAbove: behaviorCha, BlockAbove: behaviorBlock,
		}
	})
	p := &behaviorProber{
		client: &http.Client{Timeout: 10 * time.Second},
		ua:     browserUA, path: "/", accept: acceptHTML, lang: acceptLang, honor: true,
	}
	allowed, blocked, cookies := p.run(t, srv, 1)
	if allowed != 1 || blocked {
		t.Fatalf("document request must pass: allowed=%d blocked=%v", allowed, blocked)
	}
	if cookies != 1 {
		t.Fatalf("first contact must mint a fingerprint cookie, got %d", cookies)
	}
	p.path = "/app.js"
	p.accept = acceptAssets
	allowed2, blocked2, _ := p.run(t, srv, 6)
	if allowed2 != 6 || blocked2 {
		t.Fatalf("asset fetches must stay allowed: allowed=%d blocked=%v", allowed2, blocked2)
	}
}

func TestBehaviorVerifiedBotBypass(t *testing.T) {
	srv := phase4Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].Behavior = &config.BehaviorConfig{
			Enabled: true, Secret: phase5Secret,
			ChallengeAbove: 5, BlockAbove: 10,
		}
		cfg.Domains[0].Bot = &config.BotConfig{
			Enabled: true, ChallengeBelow: 90, BlockBelow: 80,
			VerifiedBots: []string{"googlebot"},
		}
	})
	p := &behaviorProber{
		client: &http.Client{Timeout: 10 * time.Second},
		ua:     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		path:   "/deep/snapshot", accept: "*/*",
	}
	for i := 0; i < 4; i++ {
		allowed, blocked, cookies := p.run(t, srv, 1)
		if allowed != 1 || blocked {
			t.Fatalf("googlebot must never be challenged/blocked (allowed=%d blocked=%v)", allowed, blocked)
		}
		if cookies != 0 {
			t.Fatal("verified bots get no fingerprint cookie")
		}
	}
}

func TestBehaviorDisabledPassesThrough(t *testing.T) {
	srv := phase4Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].Behavior = &config.BehaviorConfig{Enabled: false}
	})
	p := &behaviorProber{
		client: &http.Client{Timeout: 10 * time.Second},
		ua:     "MyScript/2.0", path: "/api/data", accept: "*/*",
	}
	allowed, blocked, cookies := p.run(t, srv, 5)
	if allowed != 5 || blocked || cookies != 0 {
		t.Fatalf("disabled behavior must pass everything through (allowed=%d blocked=%v cookies=%d)", allowed, blocked, cookies)
	}
}
