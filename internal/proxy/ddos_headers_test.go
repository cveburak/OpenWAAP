package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openwaap/openwaap/internal/config"
)

func TestDDoSAndHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-ok")
	}))
	defer origin.Close()

	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	tru := true
	cfg := config.Default()
	cfg.Domains = []config.DomainConfig{{
		Hostname: "hit.test",
		Origin:   config.OriginConfig{Scheme: "http", Host: host, Port: port},
		WAF:      config.WAFPolicy{Mode: config.WAFModeDisabled},
		Enabled:  &tru,
		Headers: &config.SecurityHeadersConfig{
			HSTS:           true,
			FrameOption:    "DENY",
			NoSniff:        true,
			ReferrerPolicy: "no-referrer",
		},
	}}
	cfg.Security.DDOS = &config.DDoSConfig{
		Enabled:     true,
		PerIPRate:   1,
		PerIPAction: "block",
	}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := New(cfg, Options{Logger: discard})
	if err != nil {
		t.Fatal(err)
	}

	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://hit.test/x", nil)
		r.RemoteAddr = "203.0.113.7:1234"
		return r
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req())
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status=%d want 200", rr.Code)
	}
	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS header missing on proxied response")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("X-Frame-Options=%q want DENY", rr.Header().Get("X-Frame-Options"))
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff missing")
	}
	if rr.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("referrer-policy missing")
	}

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req())
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("second request status=%d want 403", rr2.Code)
	}
	if rr2.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing on denied response")
	}
}

func TestHeadersOriginCannotOverride(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=0")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	tru := true
	cfg := config.Default()
	cfg.Domains = []config.DomainConfig{{
		Hostname: "origin.test",
		Origin:   config.OriginConfig{Scheme: "http", Host: host, Port: port},
		WAF:      config.WAFPolicy{Mode: config.WAFModeDisabled},
		Enabled:  &tru,
	}}
	cfg.Security.Headers = &config.SecurityHeadersConfig{
		HSTS:           true,
		FrameOption:    "SAMEORIGIN",
		NoSniff:        true,
		ReferrerPolicy: "strict-origin-when-cross-origin",
	}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := New(cfg, Options{Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://origin.test/", nil)
	r.RemoteAddr = "203.0.113.9:4321"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Header().Get("Strict-Transport-Security") != "max-age=31536000; includeSubDomains" {
		t.Fatalf("edge must override origin HSTS, got %q", rr.Header().Get("Strict-Transport-Security"))
	}
	if rr.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatal("global frame option missing")
	}
}

func TestDDoSDefenseModeBlock(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	tru := true
	cfg := config.Default()
	cfg.Domains = []config.DomainConfig{{
		Hostname: "flood.test",
		Origin:   config.OriginConfig{Scheme: "http", Host: host, Port: port},
		WAF:      config.WAFPolicy{Mode: config.WAFModeDisabled},
		Enabled:  &tru,
	}}
	cfg.Security.DDOS = &config.DDoSConfig{
		Enabled:       true,
		SiteBurstRPS:  2,
		DefenseAction: "block",
		DefenseTTL:    config.Duration(2),
	}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := New(cfg, Options{Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodGet, "http://flood.test/", nil)
		r.RemoteAddr = "198.51.100.7:99"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if i < 2 {
			if rr.Code != http.StatusOK {
				t.Fatalf("req %d status=%d want 200", i, rr.Code)
			}
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://flood.test/", nil)
	r.RemoteAddr = "198.51.100.8:99"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("defense mode: expected 403, got %d", rr.Code)
	}
}
