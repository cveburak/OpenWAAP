package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/logging"
)

var challengeEmbed = regexp.MustCompile(`const CH = (\{[^}]*\})`)

func parseChallengeData(html string) (ChallengeData, error) {
	m := challengeEmbed.FindStringSubmatch(html)
	if len(m) != 2 {
		return ChallengeData{}, &json.SyntaxError{}
	}
	var cd ChallengeData
	if err := json.Unmarshal([]byte(m[1]), &cd); err != nil {
		return ChallengeData{}, err
	}
	return cd, nil
}

func newTestHandler(t *testing.T, now time.Time) (*Handler, *Store) {
	t.Helper()
	store := NewStore(64, func() time.Time { return now })
	signer := NewSigner("secret")
	m := NewChallengeManager(signer, chCfg(2), func() time.Time { return now })
	hash, err := bcrypt.GenerateFromPassword([]byte("adminpass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash test password: %v", err)
	}
	h := NewHandler(HandlerConfig{
		Store:             store,
		Signer:            signer,
		Challenge:         m,
		Admin:             true,
		AdminUser:         "admin",
		AdminPassword:     string(hash),
		SessionTTL:        time.Hour,
		DashboardAssetTag: "test-1",
		Now:               func() time.Time { return now },
	})
	return h, store
}

type fakePanel struct {
	cfg        *config.Config
	applied    *config.Config
	restarted  bool
	applyErr   error
	restartErr error
}

func (f *fakePanel) Config() *config.Config { return f.cfg }

func (f *fakePanel) Apply(c *config.Config) ([]string, error) {
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	f.applied = c
	f.cfg = c
	return []string{"server"}, nil
}

func (f *fakePanel) Restart() error { f.restarted = true; return f.restartErr }

func oracleTime() time.Time { return time.Unix(1_700_000_000, 0) }

func TestLoginThenSummaryAPI(t *testing.T) {
	now := oracleTime()
	h, store := newTestHandler(t, now)

	req := httptest.NewRequest(http.MethodGet, "/-/api/summary?since=300", nil)
	req.RemoteAddr = "10.1.1.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth summary want 401, got %d", rr.Code)
	}

	body, _ := json.Marshal(map[string]string{"user": "admin", "password": "adminpass"})
	req = httptest.NewRequest(http.MethodPost, "/-/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.1.1.1:1234"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rr.Code, rr.Body.String())
	}
	var sessionCookie string
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionCookie {
			sessionCookie = c.Value
		}
	}
	if sessionCookie == "" {
		t.Fatal("no session cookie issued")
	}

	req = httptest.NewRequest(http.MethodGet, "/-/api/summary?since=300", nil)
	req.RemoteAddr = "10.1.1.1:1234"
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: sessionCookie})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("summary want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var sum Summary
	if err := json.Unmarshal(rr.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Total != 0 {
		t.Fatalf("empty store expected, got %+v", sum)
	}

	store.Emit(context.Background(), events.Event{Timestamp: now, SourceIP: "9.9.9.9", Path: "/x", Action: events.ActionBlock})
	req = httptest.NewRequest(http.MethodGet, "/-/api/events?limit=5", nil)
	req.RemoteAddr = "10.1.1.1:1234"
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: sessionCookie})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("events want 200, got %d", rr.Code)
	}
	var evs []events.Event
	if err := json.Unmarshal(rr.Body.Bytes(), &evs); err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Action != events.ActionBlock {
		t.Fatalf("unexpected events: %+v", evs)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	body, _ := json.Marshal(map[string]string{"user": "admin", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/-/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestDashboardUIRequiresLogin(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	req := httptest.NewRequest(http.MethodGet, "/-/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("want redirect to login, got %d", rr.Code)
	}
}

func TestChallengePageAndVerify(t *testing.T) {
	now := oracleTime()
	h, _ := newTestHandler(t, now)

	req := httptest.NewRequest(http.MethodGet, "/-/challenge?next=/app", nil)
	req.RemoteAddr = "10.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("challenge page want 403, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "WAAP") {
		t.Fatal("challenge page missing branding")
	}

	cd, err := parseChallengeData(body)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := SolveProof(cd.Cleartext, cd.Difficulty)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("cleartext", cd.Cleartext)
	form.Set("signature", cd.Signature)
	form.Set("nonce", itoa(nonce))
	form.Set("next", "/app")
	req = httptest.NewRequest(http.MethodPost, "/-/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.9.9.9:1234"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("verify want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	var gotCookie bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == ChallengeCookie && c.Value != "" {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Fatal("challenge cookie not set after successful proof")
	}
	if loc := rr.Header().Get("Location"); loc != "/app" {
		t.Fatalf("want redirect to /app, got %q", loc)
	}
}

func TestHealth(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	req := httptest.NewRequest(http.MethodGet, "/-/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Fatalf("health body unexpected: %s", rr.Body.String())
	}
}

func TestAdminAllowlist(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	h.adminAllow = parseIPPrefixes([]string{"203.0.113.0/24"})

	req := httptest.NewRequest(http.MethodGet, "/-/login", nil)
	req.RemoteAddr = "198.51.100.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("outsider login page: got %d, want 404", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/-/api/config", nil)
	req.RemoteAddr = "198.51.100.9:1234"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("outsider config api: got %d, want 404", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/-/health", nil)
	req.RemoteAddr = "198.51.100.9:1234"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("outsider health: got %d, want 200", rr.Code)
	}

	body := strings.NewReader("user=admin&password=adminpass")
	req = httptest.NewRequest(http.MethodPost, "/-/login", body)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("whitelisted login: got %d, want 200", rr.Code)
	}
}

func TestHiddenConsolePath(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	h.base = "/ops-8x3h"

	for _, p := range []string{"/-/login", "/-/", "/-/api/config", "/-/setup"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("classic console path %s must 404 when hidden, got %d", p, rr.Code)
		}
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/ops-8x3h/", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/ops-8x3h/login" {
		t.Fatalf("hidden panel root: got %d -> %v, want 302 -> /ops-8x3h/login", rr.Code, rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/ops-8x3h/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("hidden login page: got %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "/ops-8x3h/login") {
		t.Fatalf("hidden login page must POST to the hidden base")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/ops-8x3h/api/config", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("hidden api: got %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/-/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("edge health unchanged: got %d, want 200", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/-/challenge?next=/", nil))
	if rr.Code == http.StatusNotFound {
		t.Fatalf("edge challenge must remain reachable at /-/challenge")
	}
}

func TestRootConsole(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	h.base = "/"

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("root console: got %d -> %v, want 302 -> /login", rr.Code, rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("root login page: got %d, want 200", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "/login") || strings.Contains(body, "/-/login") {
		t.Fatalf("root login page must POST to /login and never mention /-/login")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("root api: got %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/-/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("edge health unchanged: got %d, want 200", rr.Code)
	}
}

func parseIPPrefixes(entries []string) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range entries {
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p)
		} else if a, err := netip.ParseAddr(raw); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func TestAnalyticsEndpoints(t *testing.T) {
	now := oracleTime()
	h, store := newTestHandler(t, now)
	session := loginCookie(t, h)
	authed := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}

	seed := []events.Event{
		{Timestamp: now, SourceIP: "5.5.5.5", Path: "/a", RuleID: "sqli-001", Category: "SQL_INJECTION", Country: "TR", Action: events.ActionBlock},
		{Timestamp: now.Add(time.Second), SourceIP: "5.5.5.5", Path: "/b", RuleID: "xss-002", Category: "XSS", Country: "DE", Action: events.ActionBlock},
		{Timestamp: now.Add(2 * time.Second), SourceIP: "6.6.6.6", Path: "/a", RuleID: "", Category: "", Country: "", Action: events.ActionAllow},
	}
	for _, e := range seed {
		store.Emit(context.Background(), e)
	}

	type count struct {
		Label string `json:"label"`
		Count int    `json:"count"`
	}

	rr := authed("/-/api/events?limit=50&ip=5.5.5.5")
	var evs []events.Event
	if err := json.Unmarshal(rr.Body.Bytes(), &evs); err != nil || len(evs) != 2 {
		t.Fatalf("events ip filter: %v %+v", err, evs)
	}
	rr = authed("/-/api/events?limit=50&rule=xss-002")
	if err := json.Unmarshal(rr.Body.Bytes(), &evs); err != nil || len(evs) != 1 || evs[0].RuleID != "xss-002" {
		t.Fatalf("events rule filter: %+v", evs)
	}
	rr = authed("/-/api/events?limit=50&category=SQL_INJECTION")
	if err := json.Unmarshal(rr.Body.Bytes(), &evs); err != nil || len(evs) != 1 {
		t.Fatalf("events category filter: %+v", evs)
	}

	rr = authed("/-/api/topcountries?n=5")
	var countries []count
	if err := json.Unmarshal(rr.Body.Bytes(), &countries); err != nil {
		t.Fatal(err)
	}
	if len(countries) != 2 || countries[0].Label != "DE" || countries[1].Label != "TR" {
		t.Fatalf("topcountries: %+v", countries)
	}

	rr = authed("/-/api/toprules?n=5")
	var rules []count
	if err := json.Unmarshal(rr.Body.Bytes(), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Label != "sqli-001" {
		t.Fatalf("toprules: %+v", rules)
	}

	rr = authed("/-/api/topcategories?n=5")
	var cats []count
	if err := json.Unmarshal(rr.Body.Bytes(), &cats); err != nil {
		t.Fatal(err)
	}
	if len(cats) != 2 || cats[0].Label != "SQL_INJECTION" {
		t.Fatalf("topcategories: %+v", cats)
	}

	store.Emit(context.Background(), events.Event{Timestamp: now, Action: events.ActionRateLimit})
	rr = authed("/-/api/series?since=300&bucket=300")
	var pts []SeriesPoint
	if err := json.Unmarshal(rr.Body.Bytes(), &pts); err != nil {
		t.Fatal(err)
	}
	var rl int
	for _, p := range pts {
		rl += p.RateLimited
	}
	if rl != 1 {
		t.Fatalf("series rate_limited want 1, got %d", rl)
	}
}

func TestConfigAPI(t *testing.T) {
	now := oracleTime()
	cfg := config.Default()
	fk := &fakePanel{cfg: cfg}
	h, _ := newTestHandler(t, now)
	h.panel = fk

	req := httptest.NewRequest(http.MethodGet, "/-/api/config", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("config GET unauth want 401, got %d", rr.Code)
	}

	session := loginCookie(t, h)
	authed := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}

	rr = authed(http.MethodGet, "/-/api/config", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("config GET want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got config.Config
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != cfg.Version {
		t.Fatalf("config GET mismatch: %+v != %+v", got.Version, cfg.Version)
	}

	edited := *cfg
	edited.Dashboard.AdminUser = "root"
	buf, _ := json.Marshal(&edited)
	rr = authed(http.MethodPut, "/-/api/config", string(buf))
	if rr.Code != http.StatusOK {
		t.Fatalf("config PUT want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if fk.applied == nil || fk.applied.Dashboard.AdminUser != "root" {
		t.Fatalf("Apply not called with edited config: %+v", fk.applied)
	}
	var resp struct {
		OK              bool     `json:"ok"`
		RestartRequired []string `json:"restart_required"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || len(resp.RestartRequired) != 1 || resp.RestartRequired[0] != "server" {
		t.Fatalf("unexpected PUT response: %+v", resp)
	}

	fk.applyErr = errors.New("boom")
	rr = authed(http.MethodPut, "/-/api/config", string(buf))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("config PUT invalid want 422, got %d", rr.Code)
	}
	fk.applyErr = nil

	rr = authed(http.MethodPost, "/-/api/restart", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("restart want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !fk.restarted {
		t.Fatal("restart not delegated to controller")
	}
}

func loginCookie(t *testing.T, h *Handler) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"user": "admin", "password": "adminpass"})
	req := httptest.NewRequest(http.MethodPost, "/-/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func cfgWithSecrets() *config.Config {
	c := config.Default()
	c.Security.HMACSecret = "REAL-HMAC-SECRET"
	c.Dashboard.AdminPassword = "REAL-ADMIN-PASSWORD"
	c.Security.Store.Type = "redis"
	c.Security.Store.Redis.Address = "127.0.0.1:6379"
	c.Security.Store.Redis.Password = "REAL-REDIS-PASSWORD"
	c.Security.SIEM = &config.SIEMConfig{
		Enabled: true,
		Endpoints: []config.SIEMEndpoint{
			{Type: "http", URL: "https://siem.example.com", Token: "REAL-SIEM-TOKEN", HMACSecret: "REAL-SIEM-HMAC"},
		},
	}
	c.Domains[0].Behavior = &config.BehaviorConfig{Enabled: true, Secret: "REAL-BEHAVIOR-SECRET"}
	c.Domains[0].APISecurity = &config.APISecurityConfig{
		Enabled: true,
		JWT: &config.JWTConfig{
			Algorithm:    "HS256",
			Secret:       "REAL-JWT-SECRET",
			PublicKeyPEM: "REAL-PUBLIC-KEY-PEM",
		},
	}
	return c
}

var secretValues = []string{
	"REAL-HMAC-SECRET", "REAL-ADMIN-PASSWORD", "REAL-REDIS-PASSWORD",
	"REAL-SIEM-TOKEN", "REAL-SIEM-HMAC", "REAL-BEHAVIOR-SECRET", "REAL-JWT-SECRET",
}

func TestConfigAPI_GETRedactsSecrets(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	fk := &fakePanel{cfg: cfgWithSecrets()}
	h.panel = fk
	session := loginCookie(t, h)

	req := httptest.NewRequest(http.MethodGet, "/-/api/config", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("config GET want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	for _, s := range secretValues {
		if strings.Contains(body, s) {
			t.Fatalf("GET /-/api/config leaked a real secret: %q found in body", s)
		}
	}

	var got config.Config
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Security.HMACSecret != logging.MaskedValue {
		t.Fatalf("hmac_secret not masked: %q", got.Security.HMACSecret)
	}
	if got.Dashboard.AdminPassword != logging.MaskedValue {
		t.Fatalf("admin_password not masked: %q", got.Dashboard.AdminPassword)
	}
	if got.Security.Store.Redis.Password != logging.MaskedValue {
		t.Fatalf("redis password not masked: %q", got.Security.Store.Redis.Password)
	}
	if got.Security.SIEM == nil || len(got.Security.SIEM.Endpoints) != 1 ||
		got.Security.SIEM.Endpoints[0].Token != logging.MaskedValue || got.Security.SIEM.Endpoints[0].HMACSecret != logging.MaskedValue {
		t.Fatalf("siem endpoint secrets not masked: %+v", got.Security.SIEM)
	}
	if got.Domains[0].Behavior == nil || got.Domains[0].Behavior.Secret != logging.MaskedValue {
		t.Fatalf("behavior.secret not masked: %+v", got.Domains[0].Behavior)
	}
	if got.Domains[0].APISecurity == nil || got.Domains[0].APISecurity.JWT == nil || got.Domains[0].APISecurity.JWT.Secret != logging.MaskedValue {
		t.Fatalf("api_security.jwt.secret not masked: %+v", got.Domains[0].APISecurity)
	}
	if got.Domains[0].APISecurity.JWT.PublicKeyPEM != "REAL-PUBLIC-KEY-PEM" {
		t.Fatalf("jwt.public_key_pem was masked, it shouldn't be: %q", got.Domains[0].APISecurity.JWT.PublicKeyPEM)
	}

	live := h.panel.Config()
	if live.Security.HMACSecret != "REAL-HMAC-SECRET" || live.Dashboard.AdminPassword != "REAL-ADMIN-PASSWORD" {
		t.Fatalf("redactConfig mutated the live config: %+v", live.Security)
	}
}

func TestConfigAPI_PUTPreservesOmittedSecrets(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	original := cfgWithSecrets()
	fk := &fakePanel{cfg: original}
	h.panel = fk
	session := loginCookie(t, h)
	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/-/api/config", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}

	getReq := httptest.NewRequest(http.MethodGet, "/-/api/config", nil)
	getReq.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	var asMap map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &asMap); err != nil {
		t.Fatal(err)
	}
	delete(asMap["security"].(map[string]any), "hmac_secret")
	delete(asMap["dashboard"].(map[string]any), "admin_password")
	delete(asMap["security"].(map[string]any)["store"].(map[string]any)["redis"].(map[string]any), "password")
	siemEP := asMap["security"].(map[string]any)["siem"].(map[string]any)["endpoints"].([]any)[0].(map[string]any)
	delete(siemEP, "token")
	delete(siemEP, "hmac_secret")
	dom0 := asMap["domains"].([]any)[0].(map[string]any)
	delete(dom0["behavior"].(map[string]any), "secret")
	delete(dom0["api_security"].(map[string]any)["jwt"].(map[string]any), "secret")
	asMap["dashboard"].(map[string]any)["max_events"] = float64(5000)

	buf, _ := json.Marshal(asMap)
	rr := put(string(buf))
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT with omitted secrets want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	applied := fk.applied
	if applied == nil {
		t.Fatal("Apply not called")
	}
	if applied.Security.HMACSecret != "REAL-HMAC-SECRET" {
		t.Fatalf("omitted hmac_secret was NOT preserved, got %q", applied.Security.HMACSecret)
	}
	if applied.Security.Store.Redis.Password != "REAL-REDIS-PASSWORD" {
		t.Fatalf("omitted redis password was NOT preserved, got %q", applied.Security.Store.Redis.Password)
	}
	if applied.Security.SIEM.Endpoints[0].Token != "REAL-SIEM-TOKEN" || applied.Security.SIEM.Endpoints[0].HMACSecret != "REAL-SIEM-HMAC" {
		t.Fatalf("omitted siem secrets were NOT preserved: %+v", applied.Security.SIEM.Endpoints[0])
	}
	if applied.Domains[0].Behavior.Secret != "REAL-BEHAVIOR-SECRET" {
		t.Fatalf("omitted behavior.secret was NOT preserved, got %q", applied.Domains[0].Behavior.Secret)
	}
	if applied.Domains[0].APISecurity.JWT.Secret != "REAL-JWT-SECRET" {
		t.Fatalf("omitted jwt.secret was NOT preserved, got %q", applied.Domains[0].APISecurity.JWT.Secret)
	}
	if applied.Dashboard.MaxEvents != 5000 {
		t.Fatalf("the actual edit (max_events) was lost: got %d", applied.Dashboard.MaxEvents)
	}
	if applied.Dashboard.AdminPassword != "REAL-ADMIN-PASSWORD" {
		t.Fatalf("omitted admin_password was NOT preserved, got %q", applied.Dashboard.AdminPassword)
	}
}

func TestConfigAPI_PUTPassesAdminPasswordThrough(t *testing.T) {
	h, _ := newTestHandler(t, oracleTime())
	fk := &fakePanel{cfg: cfgWithSecrets()}
	h.panel = fk
	session := loginCookie(t, h)

	getReq := httptest.NewRequest(http.MethodGet, "/-/api/config", nil)
	getReq.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	var asMap map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &asMap); err != nil {
		t.Fatal(err)
	}
	asMap["dashboard"].(map[string]any)["admin_password"] = "brand-new-plaintext-pw"
	buf, _ := json.Marshal(asMap)

	putReq := httptest.NewRequest(http.MethodPut, "/-/api/config", bytes.NewReader(buf))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, putReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if fk.applied.Dashboard.AdminPassword != "brand-new-plaintext-pw" {
		t.Fatalf("dashboard layer transformed admin_password itself (should pass through to Apply untouched): got %q", fk.applied.Dashboard.AdminPassword)
	}
}

func TestLoginBruteForceThrottle(t *testing.T) {
	now := oracleTime()
	h, _ := newTestHandler(t, now)
	const testMax = 3
	h.throttle = newLoginThrottle(testMax, time.Minute, func() time.Time { return now })

	attempt := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"user": "admin", "password": "wrong"})
		req := httptest.NewRequest(http.MethodPost, "/-/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.5.5.5:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	var last *httptest.ResponseRecorder
	for i := 0; i < testMax; i++ {
		last = attempt()
		if last.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, last.Code)
		}
	}
	throttled := attempt()
	if throttled.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after %d failed attempts, got %d", testMax, throttled.Code)
	}
	if throttled.Header().Get("Retry-After") == "" {
		t.Fatal("429 response missing Retry-After")
	}
	if throttled.Body.String() != last.Body.String() {
		t.Fatalf("throttled response body differs from normal invalid-credentials body: %q vs %q", throttled.Body.String(), last.Body.String())
	}

	body, _ := json.Marshal(map[string]string{"user": "admin", "password": "adminpass"})
	req := httptest.NewRequest(http.MethodPost, "/-/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.5.5.5:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password during lockout: want 429, got %d", rr.Code)
	}
}

func TestPanelListMutationsMarkDirty(t *testing.T) {
	addIdx := strings.Index(panelHTML, "dataset.add !== undefined")
	delIdx := strings.Index(panelHTML, "dataset.del !== undefined")
	navIdx := strings.Index(panelHTML, "dataset.navup !== undefined")
	if addIdx < 0 || delIdx < 0 || navIdx < 0 {
		t.Fatal("panel click handler branches not found — panel_ui.go markup changed shape")
	}
	addBranch := panelHTML[addIdx:delIdx]
	delBranch := panelHTML[delIdx:navIdx]
	if !strings.Contains(addBranch, "setDirty(true)") {
		t.Fatal("data-add branch does not call setDirty(true) — added items won't be saveable")
	}
	if !strings.Contains(delBranch, "setDirty(true)") {
		t.Fatal("data-del branch does not call setDirty(true) — deletions (the reported bug) won't be saveable")
	}
}
