package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

func makeWizardConfig() *config.Config {
	tru := true
	return &config.Config{
		Version: "1",
		Server: config.ServerConfig{
			ListenHTTPS: ":8443",
			ListenHTTP:  ":8080",
		},
		Security: config.SecurityConfig{
			EngineFailMode:  config.FailOpen,
			HMACSecret:      strings.Repeat("a", 32),
			Headers: &config.SecurityHeadersConfig{
				HSTS: true, FrameOption: "SAMEORIGIN", NoSniff: true,
				ReferrerPolicy: "strict-origin-when-cross-origin",
			},
			DDOS: &config.DDoSConfig{Enabled: true, PerIPRate: 20, PerIPAction: "challenge"},
		},
		Dashboard: config.DashboardConfig{
			Enabled: true, AdminUser: "admin", AdminPassword: "s3cretpassw0rd!",
			SessionTTL: config.Duration(12 * time.Hour), MaxEvents: 10000,
		},
		Domains: []config.DomainConfig{{
			Hostname: "example.com",
			Origin:   config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: "8080"},
			WAF:      config.WAFPolicy{Mode: config.WAFModeBlock, Managed: config.ManagedPolicy{ParanoiaLevel: 1}},
			Enabled:  &tru,
			RateLimit: &config.RateLimitConfig{
				Enabled: true,
				Limits:  []config.RateLimitRule{{ID: "global", Enabled: true, Scope: config.ScopeIP, Max: 60, Window: config.Duration(time.Minute), Action: config.ActionRateLimit}},
			},
		}},
		Log: config.LogConfig{RotationKeep: 5},
	}
}

func setupHandler(t *testing.T, pending bool) (*Handler, *fakePanel) {
	t.Helper()
	now := time.Now()
	store := NewStore(64, func() time.Time { return now })
	signer := NewSigner("secret")
	h := NewHandler(HandlerConfig{
		Store: store, Signer: signer,
		Panel:        &fakePanel{cfg: config.Default()},
		Admin:        true,
		SessionTTL:   time.Hour,
		SetupPending: pending,
		ConfigPath:   filepath.Join(t.TempDir(), "waap.yaml"),
		Now:          func() time.Time { return now },
	})
	return h, h.panel.(*fakePanel)
}

func TestSetupPageServedOnlyWhilePending(t *testing.T) {
	h, _ := setupHandler(t, true)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/-/setup", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup page status=%d want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Installer") {
		t.Fatal("setup wizard text missing")
	}

	h2, _ := setupHandler(t, false)
	rr2 := httptest.NewRecorder()
	h2.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/-/setup", nil))
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("setup must be 404 once installed, got %d", rr2.Code)
	}
}

func TestSetupInstallFlow(t *testing.T) {
	h, panel := setupHandler(t, true)
	cfg := makeWizardConfig()
	cfg.Server.TLSCertFile = ""
	cfg.Server.TLSKeyFile = ""
	body, _ := json.Marshal(map[string]any{
		"config":        cfg,
		"generate_cert": true,
		"hosts":         []string{"example.com"},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/-/api/setup", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("install status=%d body=%s", rr.Code, rr.Body.String())
	}
	if panel.applied == nil {
		t.Fatal("panel.Apply not called")
	}
	if panel.applied.SetupPending {
		t.Fatal("SetupPending must be cleared on install")
	}
	if panel.applied.Dashboard.AdminPassword == "" {
		t.Fatal("admin password missing")
	}
	if !panel.restarted {
		t.Fatal("edge must restart after install")
	}
	if !exists(panel.applied.Server.TLSCertFile) {
		t.Fatal("generated certificate file missing")
	}
	if !exists(panel.applied.Server.TLSKeyFile) {
		t.Fatal("generated key file missing")
	}
}

func exists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func TestSetupRejectsMissingCredentials(t *testing.T) {
	h, _ := setupHandler(t, true)
	cfg := makeWizardConfig()
	cfg.Dashboard.AdminPassword = ""
	body, _ := json.Marshal(map[string]any{"config": cfg, "generate_cert": true})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/-/api/setup", bytes.NewReader(body)))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for missing admin password, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetupRejectsUnknownFields(t *testing.T) {
	h, _ := setupHandler(t, true)
	body := []byte(`{"config":{"version":"1","totally_bogus":123}}`)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/-/api/setup", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", rr.Code)
	}
}
