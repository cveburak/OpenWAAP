package e2e

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	reqctx "github.com/openwaap/openwaap/internal/context"
	"github.com/openwaap/openwaap/internal/dashboard"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/proxy"
	testorigin "github.com/openwaap/openwaap/test/origin"
)

var challengeEmbed = regexp.MustCompile(`const CH = (\{[^}]*\})`)

func phase3Edge(t *testing.T, mutate func(*config.Config)) (*testorigin.Origin, *httptest.Server) {
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
			Managed: config.ManagedPolicy{RulesetVersion: "1", ParanoiaLevel: 1},
		},
		Bot: &config.BotConfig{Enabled: true, ChallengeBelow: 20},
	}
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{ListenHTTPS: ":0", ListenHTTP: ":0"},
		Security: config.SecurityConfig{
			EngineFailMode:  config.FailOpen,
			HMACSecret:      "e2e-secret",
			Challenge: config.ChallengeConfig{
				Enabled: true, Difficulty: 2,
				TTL:      config.Duration(10 * time.Minute),
				ProofTTL: config.Duration(3 * time.Minute),
			},
		},
		Domains: []config.DomainConfig{dc},
	}
	mutate(cfg)
	if err := cfg.NormalizeAdminPassword(); err != nil {
		t.Fatal(err)
	}
	if cfg.Dashboard.AdminPassword != "" && !config.IsBcryptHash(cfg.Dashboard.AdminPassword) {
		t.Fatalf("admin_password was not hashed by NormalizeAdminPassword: %q", cfg.Dashboard.AdminPassword)
	}

	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 1024})
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	signer := dashboard.NewSigner(cfg.Security.HMACSecret)
	var store *dashboard.Store
	if cfg.Dashboard.Enabled {
		store = dashboard.NewStore(2048, nil)
		emit.AddSink(store)
	}
	chlg := dashboard.NewChallengeManager(signer, cfg.Security.Challenge, nil)
	inner := dashboard.NewHandler(dashboard.HandlerConfig{
		Store: store, Signer: signer, Challenge: chlg,
		Admin: cfg.Dashboard.Enabled, AdminUser: cfg.Dashboard.AdminUser,
		AdminPassword: cfg.Dashboard.AdminPassword,
		SessionTTL:    cfg.Dashboard.SessionTTL.D(),
	})
	page := func(w http.ResponseWriter, r *http.Request) {
		inner.ServeChallengePage(w, r, r.URL.EscapedPath())
	}
	passed := func(c *reqctx.RequestContext) bool {
		return chlg.VerifyAccess(c.RemoteIP.String(), c.Headers, time.Now())
	}
	if !cfg.Security.Challenge.Enabled {
		page, passed = nil, nil
	}
	handler, err := proxy.New(cfg, proxy.Options{
		Logger:          log,
		Emit:            emit,
		Internal:        inner,
		ChallengePage:   page,
		ChallengePassed: passed,
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

func curlReq(t *testing.T, srv *httptest.Server, path string, method string, body io.Reader) *http.Request {
	t.Helper()
	u := srv.URL + path
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	req.Header.Set("User-Agent", "curl/8.1.2")
	return req
}

func TestChallengeEndToEnd(t *testing.T) {
	_, srv := phase3Edge(t, func(cfg *config.Config) { cfg.Dashboard.Enabled = false })

	jar := &memJar{cookies: map[string]*http.Cookie{}}
	noRedirect := func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar, CheckRedirect: noRedirect}

	respDo, err := client.Do(curlReq(t, srv, "/products", http.MethodGet, nil))
	if err != nil {
		t.Fatal(err)
	}
	if respDo.StatusCode != http.StatusForbidden {
		respDo.Body.Close()
		t.Fatalf("want 403 challenge page, got %d", respDo.StatusCode)
	}
	body, _ := io.ReadAll(respDo.Body)
	respDo.Body.Close()
	if !strings.Contains(string(body), "WAAP") {
		t.Fatal("challenge page missing")
	}
	cd := parseE2EChallenge(t, string(body))
	if cd.Difficulty != 2 {
		t.Fatalf("want difficulty 2, got %d", cd.Difficulty)
	}

	nonce, err := dashboard.SolveProof(cd.Cleartext, cd.Difficulty)
	if err != nil {
		t.Fatalf("solve failed: %v", err)
	}

	form := url.Values{}
	form.Set("cleartext", cd.Cleartext)
	form.Set("signature", cd.Signature)
	form.Set("nonce", strconv.Itoa(nonce))
	form.Set("next", cd.Next)
	vreq := curlReq(t, srv, "/-/challenge/verify", http.MethodPost, strings.NewReader(form.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vresp, err := client.Do(vreq)
	if err != nil {
		t.Fatal(err)
	}
	vresp.Body.Close()
	if vresp.StatusCode != http.StatusFound {
		t.Fatalf("verify want 302, got %d", vresp.StatusCode)
	}

	final, err := client.Do(curlReq(t, srv, cd.Next, http.MethodGet, nil))
	if err != nil {
		t.Fatal(err)
	}
	final.Body.Close()
	if final.StatusCode != http.StatusOK {
		t.Fatalf("solved visitor should reach origin, got %d", final.StatusCode)
	}

	fresh := &http.Client{Timeout: 5 * time.Second}
	fresp, err := fresh.Do(curlReq(t, srv, "/other", http.MethodGet, nil))
	if err != nil {
		t.Fatal(err)
	}
	fresp.Body.Close()
	if fresp.StatusCode != http.StatusForbidden {
		t.Fatalf("fresh client without cookie want 403, got %d", fresp.StatusCode)
	}
}

func TestChallengePolicyOffKeepsPhase1Behavior(t *testing.T) {
	_, srv := phase3Edge(t, func(cfg *config.Config) {
		cfg.Security.Challenge.Enabled = false
		cfg.Dashboard.Enabled = false
	})
	client := &http.Client{Timeout: 5 * time.Second}
	respDo, err := client.Do(curlReq(t, srv, "/products", http.MethodGet, nil))
	if err != nil {
		t.Fatal(err)
	}
	respDo.Body.Close()
	if respDo.StatusCode != http.StatusTooEarly {
		t.Fatalf("want phase-1 425 without challenge engine, got %d", respDo.StatusCode)
	}
}

func TestDashboardThroughEdge(t *testing.T) {
	_, srv := phase3Edge(t, func(cfg *config.Config) {
		cfg.Dashboard.Enabled = true
		cfg.Dashboard.AdminUser = "admin"
		cfg.Dashboard.AdminPassword = "e2e-admin-passw0rd"
		cfg.Dashboard.SessionTTL = config.Duration(time.Hour)
	})

	browser := &http.Client{Timeout: 5 * time.Second}

	breq, _ := http.NewRequest(http.MethodGet, srv.URL+"/products", nil)
	breq.Host = "example.com"
	breq.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36")
	breq.Header.Set("Accept", "text/html")
	br, err := browser.Do(breq)
	if err == nil {
		br.Body.Close()
	}

	fetch := func(path, cookie string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Host = "example.com"
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: dashboard.SessionCookie, Value: cookie})
		}
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	unauth := fetch("/-/api/summary?since=300", "")
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated summary want 401, got %d", unauth.StatusCode)
	}

	login, _ := json.Marshal(map[string]string{"user": "admin", "password": "e2e-admin-passw0rd"})
	lreq, _ := http.NewRequest(http.MethodPost, srv.URL+"/-/login", strings.NewReader(string(login)))
	lreq.Host = "example.com"
	lreq.Header.Set("Content-Type", "application/json")
	lr, err := browser.Do(lreq)
	if err != nil {
		t.Fatal(err)
	}
	lr.Body.Close()
	if lr.StatusCode != http.StatusOK {
		t.Fatalf("login want 200, got %d", lr.StatusCode)
	}
	var sessionCookie string
	for _, c := range lr.Cookies() {
		if c.Name == dashboard.SessionCookie {
			sessionCookie = c.Value
		}
	}
	if sessionCookie == "" {
		t.Fatal("no session cookie")
	}

	deadline := time.Now().Add(5 * time.Second)
	var sum dashboard.Summary
	for time.Now().Before(deadline) {
		resp := fetch("/-/api/summary?since=300", sessionCookie)
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&sum)
		}
		resp.Body.Close()
		if sum.Total > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sum.Total == 0 {
		t.Fatal("no events reached the dashboard store")
	}

	for _, endpoint := range []string{"/-/api/topips?since=300&n=3", "/-/api/events?limit=5",
		"/-/api/toppaths?since=300&n=3", "/-/api/series?since=300&bucket=15"} {
		resp := fetch(endpoint, sessionCookie)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s want 200, got %d", endpoint, resp.StatusCode)
		}
	}

	resp := fetch("/-/", sessionCookie)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard UI want 200, got %d", resp.StatusCode)
	}
}

type memJar struct {
	cookies map[string]*http.Cookie
}

func (j *memJar) SetCookies(_ *url.URL, cs []*http.Cookie) {
	for _, c := range cs {
		j.cookies[c.Name] = c
	}
}
func (j *memJar) Cookies(*url.URL) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}

func parseE2EChallenge(t *testing.T, html string) dashboard.ChallengeData {
	t.Helper()
	m := challengeEmbed.FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("challenge data not embedded")
	}
	var cd dashboard.ChallengeData
	if err := json.Unmarshal([]byte(m[1]), &cd); err != nil {
		t.Fatal(err)
	}
	return cd
}
