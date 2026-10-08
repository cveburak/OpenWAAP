package proxy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/openwaap/openwaap/internal/config"
)

func TestHostnameNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"Example.COM", "Example.COM"},
		{"sub.example.com:8080", "sub.example.com"},
		{"127.0.0.1", "127.0.0.1"},
		{"[::1]:443", "::1"},
	}
	for _, c := range cases {
		if got := hostname(c.in); got != c.want {
			t.Errorf("hostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAllCategoriesEnabled(t *testing.T) {
	m := allCategoriesEnabled()
	if len(m) != 5 {
		t.Fatalf("expected 5 categories, got %d", len(m))
	}
	for k, v := range m {
		if !v {
			t.Fatalf("expected %s enabled", k)
		}
	}
}

func TestNewOriginProxy(t *testing.T) {
	rp, err := newOriginProxy(config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: "8080"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rp == nil {
		t.Fatal("nil reverse proxy")
	}
}

func TestNewOriginProxyOriginValidation(t *testing.T) {
	cases := []struct {
		name    string
		origin  config.OriginConfig
		wantErr bool
	}{
		{"valid ipv4", config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: "8080"}, false},
		{"valid ipv6 unbracketed", config.OriginConfig{Scheme: "http", Host: "::1", Port: "8080"}, false},
		{"host with space", config.OriginConfig{Scheme: "http", Host: "bad host", Port: "8080"}, true},
		{"host with escape sequence", config.OriginConfig{Scheme: "http", Host: "%zz", Port: "8080"}, true},
		{"empty host", config.OriginConfig{Scheme: "http", Host: "", Port: "8080"}, true},
		{"host with stray bracket", config.OriginConfig{Scheme: "http", Host: "[::1", Port: "8080"}, true},
		{"empty port", config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: ""}, true},
		{"non-numeric port", config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: "notaport"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newOriginProxy(c.origin, 0)
			if c.wantErr && err == nil {
				t.Fatalf("origin %+v: expected an error, got nil", c.origin)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("origin %+v: unexpected error: %v", c.origin, err)
			}
		})
	}
}

func TestReloadSwapsDomainRoutes(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	h, err := New(cfg, Options{Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	has := func(host string) bool {
		h.mu.RLock()
		defer h.mu.RUnlock()
		_, ok := h.domains[host]
		return ok
	}
	if !has(cfg.Domains[0].Hostname) {
		t.Fatal("initial domain not routed")
	}

	cfg2 := config.Default()
	cfg2.Domains[0].Hostname = "other.test"
	if err := h.Reload(cfg2); err != nil {
		t.Fatal(err)
	}
	if !has("other.test") || has("example.com") {
		t.Fatal("reload did not atomically swap routes")
	}

	cfg3 := config.Default()
	cfg3.Domains[0].Hostname = "broken.test"
	cfg3.Domains[0].APISecurity = &config.APISecurityConfig{
		Enabled: true,
		Routes:  []config.APIRouteConfig{{Path: "/api", RequestSchema: "not json"}},
	}
	if err := h.Reload(cfg3); err == nil {
		t.Fatal("expected reload error for invalid api_security schema")
	}
	if !has("other.test") {
		t.Fatal("failed reload clobbered the previous route table")
	}
}
