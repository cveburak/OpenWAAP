package behavior

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	reqctx "github.com/openwaap/openwaap/internal/context"
)

func parseIP(s string) net.IP { return net.ParseIP(s) }

func headersOf(ua, accept, lang, xrw string) http.Header {
	h := http.Header{}
	if ua != "" {
		h.Set("User-Agent", ua)
	}
	if accept != "" {
		h.Set("Accept", accept)
	}
	if lang != "" {
		h.Set("Accept-Language", lang)
	}
	if xrw != "" {
		h.Set("X-Requested-With", xrw)
	}
	return h
}

func testCtx(ua, accept, lang, xrw string) *reqctx.RequestContext {
	return &reqctx.RequestContext{
		RemoteIP: parseIP("127.0.0.1"),
		Method:   http.MethodGet,
		Path:     "/",
		UA:       ua,
		Headers:  headersOf(ua, accept, lang, xrw),
	}
}

func browserSession(e *Engine, n int) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
	lang := "en-US,en;q=0.9"
	cookie := ""
	for i := 0; i < n; i++ {
		path := "/"
		acc := "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		if i > 0 {
			path = "/app.js"
			acc = "*/*"
		}
		c := testCtx(ua, acc, lang, "")
		c.Path = path
		res := e.Inspect(c, cookie, false, time.Unix(int64(1000+i), 0))
		if res.NewClient {
			cookie = res.Cookie
		}
	}
}

func TestFingerprinterRoundTrip(t *testing.T) {
	fp, err := NewFingerprinter("s3cr3t", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	id, cookie, err := fp.Issue("1.2.3.4", now)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || cookie == "" {
		t.Fatal("expected id and cookie")
	}
	if got, ok := fp.Validate(cookie, "1.2.3.4", now); !ok || got != id {
		t.Fatalf("validate own cookie: got %q ok=%v", got, ok)
	}
	if _, ok := fp.Validate(cookie, "5.6.7.8", now); ok {
		t.Fatal("cookie must be IP-bound")
	}
	if _, ok := fp.Validate(cookie, "1.2.3.4", now.Add(2*time.Hour)); ok {
		t.Fatal("expired cookie must be rejected")
	}
	if _, ok := fp.Validate("garbage", "1.2.3.4", now); ok {
		t.Fatal("garbage must be rejected")
	}
	if _, ok := fp.Validate(cookie+"x", "1.2.3.4", now); ok {
		t.Fatal("tampered cookie must be rejected")
	}
}

func TestEngineBrowserSessionClean(t *testing.T) {
	e, err := New(&config.BehaviorConfig{Enabled: true, Secret: "k"})
	if err != nil {
		t.Fatal(err)
	}
	browserSession(e, 8)
	if e.challengeAbove != DefaultChallengeAbove || e.blockAbove != DefaultBlockAbove {
		t.Fatalf("defaults not applied: challenge=%d block=%d", e.challengeAbove, e.blockAbove)
	}
}

func TestEngineDirectAssetBlocked(t *testing.T) {
	e, err := New(&config.BehaviorConfig{Enabled: true, Secret: "k", BlockAbove: 50})
	if err != nil {
		t.Fatal(err)
	}
	ua := "Mozilla/5.0 (compatible; custom/1.0)"
	cookie := ""
	var sawBlock bool
	for i := 0; i < 12; i++ {
		c := testCtx(ua, "*/*", "", "")
		c.Path = "/api/admin"
		res := e.Inspect(c, cookie, false, time.Unix(int64(2000), int64(i)*90_000_000))
		if res.NewClient {
			cookie = res.Cookie
		}
		if res.Action == config.ActionBlock {
			sawBlock = true
		}
	}
	if !sawBlock {
		t.Fatal("bursty direct asset/API probing without any document must escalate to BLOCK")
	}
}

func TestEngineVerifiedBotBypass(t *testing.T) {
	e, err := New(&config.BehaviorConfig{Enabled: true, Secret: "k", BlockAbove: 10})
	if err != nil {
		t.Fatal(err)
	}
	c := testCtx("Googlebot", "*/*", "", "")
	res := e.Inspect(c, "", true, time.Now())
	if res.Action != config.ActionAllow || res.Score != 0 || res.Label != "verified_bot" {
		t.Fatalf("verified bot must bypass: %+v", res)
	}
	if res.NewClient {
		t.Fatal("verified bots get no fingerprint cookie")
	}
}

func TestEngineCookieRefusal(t *testing.T) {
	e, err := New(&config.BehaviorConfig{Enabled: true, Secret: "k", BlockAbove: 40})
	if err != nil {
		t.Fatal(err)
	}
	ua := "Mozilla/5.0 (compatible; custom/1.0)"
	c := testCtx(ua, "*/*", "", "")
	c.Path = "/api/orders"
	var blocked bool
	var issued bool
	for i := 0; i < 10; i++ {
		res := e.Inspect(c, "", false, time.Unix(int64(3000+i), 0))
		if res.NewClient {
			issued = true
		}
		if res.Action == config.ActionBlock {
			blocked = true
		}
	}
	if !issued {
		t.Fatal("expected a fingerprint to be issued on first contact")
	}
	if !blocked {
		t.Fatal("client refusing its cookie while repeatedly fetching must escalate to BLOCK")
	}
}
