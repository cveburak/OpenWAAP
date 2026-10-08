package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
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
	testorigin "github.com/openwaap/openwaap/test/origin"
)

const phase4Secret = "e2e-api-secret"

func phase4Edge(t *testing.T, mutate func(*config.Config)) *httptest.Server {
	t.Helper()
	o, err := testorigin.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	_, port, ok := strings.Cut(o.ListenerAddr(), ":")
	if !ok {
		t.Fatalf("cannot extract port from %s", o.ListenerAddr())
	}
	en := true
	dc := config.DomainConfig{
		Hostname: "example.com",
		Enabled:  &en,
		Origin:   config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: port},
		WAF: config.WAFPolicy{
			Mode:    config.WAFModeDetection,
			Managed: config.ManagedPolicy{RulesetVersion: "1", ParanoiaLevel: 1},
		},
	}
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{ListenHTTPS: ":0", ListenHTTP: ":0"},
		Security: config.SecurityConfig{
			EngineFailMode:  config.FailOpen,
		},
		Domains: []config.DomainConfig{dc},
	}
	mutate(cfg)

	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 1024})
	t.Cleanup(emit.Close)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	handler, err := proxy.New(cfg, proxy.Options{Logger: log, Emit: emit})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func apiReq(method, path string, headers map[string]string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, path, body)
	req.Host = "example.com"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func doAPI(client *http.Client, req *http.Request) (*http.Response, string) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func jwtHS256(secret string, claims map[string]any) string {
	head, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(head)
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return h + "." + p + "." + sig
}

func TestAPIJWTGate(t *testing.T) {
	srv := phase4Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].APISecurity = &config.APISecurityConfig{
			Enabled: true,
			JWT:     &config.JWTConfig{Algorithm: "HS256", Secret: phase4Secret},
			Policy:  config.APIPolicyConfig{AuthnRequired: true},
		}
	})
	client := &http.Client{Timeout: 10 * time.Second}
	full := srv.URL

	resp, body := doAPI(client, apiReq(http.MethodGet, full, map[string]string{
		"Accept": "text/html", "User-Agent": "Mozilla/5.0", "Accept-Language": "en",
	}, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d (%s)", resp.StatusCode, body)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate header")
	}

	tok := jwtHS256(phase4Secret, map[string]any{"sub": "svc", "exp": time.Now().Add(time.Hour).Unix()})
	resp, body = doAPI(client, apiReq(http.MethodGet, full, map[string]string{
		"Authorization": "Bearer " + tok,
		"User-Agent":    "Mozilla/5.0", "Accept-Language": "en",
	}, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 from origin, got %d (%s)", resp.StatusCode, body)
	}

	badTok := jwtHS256("wrong-secret", map[string]any{"sub": "svc"})
	resp, _ = doAPI(client, apiReq(http.MethodGet, full, map[string]string{
		"Authorization": "Bearer " + badTok,
	}, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 for bad signature, got %d", resp.StatusCode)
	}
}

func TestAPISchemaBlocking(t *testing.T) {
	srv := phase4Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].APISecurity = &config.APISecurityConfig{
			Enabled: true,
			JWT:     &config.JWTConfig{Algorithm: "HS256", Secret: phase4Secret},
			Routes: []config.APIRouteConfig{{
				Path:          "orders",
				RequestSchema: `{"type":"object","properties":{"qty":{"type":"integer","minimum":1}},"required":["qty"]}`,
			}},
			Policy: config.APIPolicyConfig{AuthnRequired: true, ValidateSchema: true},
		}
	})
	client := &http.Client{Timeout: 10 * time.Second}
	tok := jwtHS256(phase4Secret, map[string]any{"sub": "svc", "exp": time.Now().Add(time.Hour).Unix()})

	resp, _ := doAPI(client, apiReq(http.MethodPost, srv.URL+"/orders", map[string]string{
		"Authorization": "Bearer " + tok,
		"Content-Type":  "application/json",
	}, strings.NewReader(`{"qty":"a lot"}`)))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 schema violation, got %d", resp.StatusCode)
	}

	resp, _ = doAPI(client, apiReq(http.MethodPost, srv.URL+"/orders", map[string]string{
		"Authorization": "Bearer " + tok,
		"Content-Type":  "application/json",
	}, strings.NewReader(`{"qty": 4}`)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 from origin for valid body, got %d", resp.StatusCode)
	}
}

func TestAPISecurityDisabledPassesThrough(t *testing.T) {
	srv := phase4Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].APISecurity = &config.APISecurityConfig{Enabled: false}
	})
	client := &http.Client{Timeout: 10 * time.Second}
	resp, _ := doAPI(client, apiReq(http.MethodGet, srv.URL+"/orders", map[string]string{
		"User-Agent": "Mozilla/5.0", "Accept-Language": "en",
	}, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disabled api_security must pass through, got %d", resp.StatusCode)
	}
}
