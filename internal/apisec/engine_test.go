package apisec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

func testEngine(t *testing.T, cfg *config.APISecurityConfig) *Engine {
	t.Helper()
	e, err := NewEngine(cfg, time.Now)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

var demoJWTSecret = "demo-secret"

func newDemoCfg(routes []config.APIRouteConfig, policy config.APIPolicyConfig) *config.APISecurityConfig {
	return &config.APISecurityConfig{
		Enabled: true,
		JWT: &config.JWTConfig{
			Algorithm: "HS256",
			Secret:    demoJWTSecret,
			Issuer:    "waap-demo",
		},
		Routes: routes,
		Policy: policy,
	}
}

func TestEngineJWTRequiredRoute(t *testing.T) {
	cfg := newDemoCfg(
		[]config.APIRouteConfig{{Path: "/api/v1/orders"}},
		config.APIPolicyConfig{AuthnRequired: true},
	)
	e := testEngine(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orders", nil)
	res := e.Evaluate(req, nil)
	if res.Action != config.ActionUnauthorized {
		t.Fatalf("want UNAUTHORIZED, got %s (matched=%v)", res.Action, res.Matched)
	}

	tok := issueHS256(t, demoJWTSecret, map[string]any{"iss": "waap-demo", "exp": time.Now().Add(time.Hour).Unix()})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orders?x=1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res = e.Evaluate(req, nil)
	if res.Action != config.ActionAllow {
		t.Fatalf("want ALLOW, got %s (%s)", res.Action, res.Reason)
	}
	if !res.Matched {
		t.Fatal("expected route matched")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/orders", nil)
	req.Header.Set("Authorization", "Bearer garbage.token.here")
	res = e.Evaluate(req, nil)
	if res.Action != config.ActionUnauthorized {
		t.Fatalf("want UNAUTHORIZED for bad token, got %s", res.Action)
	}
}

func TestEngineAuthNoneRoute(t *testing.T) {
	cfg := newDemoCfg(
		[]config.APIRouteConfig{
			{Path: "/api/v1/public", AuthNone: true},
			{Path: "/api/v1/private"},
		},
		config.APIPolicyConfig{AuthnRequired: true},
	)
	e := testEngine(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public", nil)
	if res := e.Evaluate(req, nil); res.Action != config.ActionAllow {
		t.Fatalf("auth_none route must not require token, got %s", res.Action)
	}
}

func TestEngineOptionalAuth(t *testing.T) {
	cfg := newDemoCfg(
		[]config.APIRouteConfig{{Path: "/api"}},
		config.APIPolicyConfig{},
	)
	e := testEngine(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	if res := e.Evaluate(req, nil); res.Action != config.ActionAllow {
		t.Fatalf("optional auth with no token must allow, got %s", res.Action)
	}

	cfg2 := newDemoCfg(
		[]config.APIRouteConfig{{Path: "/api"}},
		config.APIPolicyConfig{NoAuthAction: config.ActionBlock},
	)
	e2 := testEngine(t, cfg2)
	req = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer bad")
	if res := e2.Evaluate(req, nil); res.Action != config.ActionBlock {
		t.Fatalf("want BLOCK, got %s", res.Action)
	}
}

func TestEngineSchemaEnforcement(t *testing.T) {
	cfg := newDemoCfg(
		[]config.APIRouteConfig{{
			Path:          "/api/v1/orders",
			RequestSchema: `{"type":"object","properties":{"qty":{"type":"integer","minimum":1}},"required":["qty"]}`,
		}},
		config.APIPolicyConfig{AuthnRequired: true, ValidateSchema: true},
	)
	e := testEngine(t, cfg)
	tok := issueHS256(t, demoJWTSecret, map[string]any{"iss": "waap-demo", "exp": time.Now().Add(time.Hour).Unix()})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/orders", strings.NewReader(`{"qty":"many"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	res := e.Evaluate(req, []byte(`{"qty":"many"}`))
	if res.Action != config.ActionBlock {
		t.Fatalf("schema violation must block, got %s (%s)", res.Action, res.Reason)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/orders", strings.NewReader(`{"qty": 3}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	res = e.Evaluate(req, []byte(`{"qty": 3}`))
	if res.Action != config.ActionAllow {
		t.Fatalf("valid body rejected: %s (%s)", res.Action, res.Reason)
	}
}

func TestEngineUncoveredRequestNoPolicy(t *testing.T) {
	cfg := newDemoCfg(
		[]config.APIRouteConfig{{Path: "/api/v1/orders"}},
		config.APIPolicyConfig{},
	)
	e := testEngine(t, cfg)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	res := e.Evaluate(req, nil)
	if res.Action != config.ActionAllow || res.Matched {
		t.Fatalf("uncovered request must pass through, got %s matched=%v", res.Action, res.Matched)
	}
}

func TestEngineGlobalAuthnRequired(t *testing.T) {
	cfg := newDemoCfg(nil, config.APIPolicyConfig{AuthnRequired: true})
	e := testEngine(t, cfg)
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	if res := e.Evaluate(req, nil); res.Action != config.ActionUnauthorized {
		t.Fatalf("global authn required must 401, got %s", res.Action)
	}
}

func TestEngineDisabled(t *testing.T) {
	e, err := NewEngine(&config.APISecurityConfig{Enabled: false}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if e != nil {
		t.Fatal("disabled engine must be nil")
	}
}
