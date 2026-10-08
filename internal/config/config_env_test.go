package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func writeCfgFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "waap.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("WAAP_ADMIN_PASSWORD", "s3cret")
	t.Setenv("WAAP_HMAC", "hmac-secret")
	path := writeCfgFile(t, `
version: "1"
security:
  engine_fail_mode: fail_open
  hmac_secret: ${WAAP_HMAC}
dashboard:
  enabled: true
  admin_user: admin
  admin_password: ${WAAP_ADMIN_PASSWORD}
  session_ttl: 1h
server:
  listen_https: ":443"
domains:
  - hostname: x.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block, managed: {ruleset_version: "1.0.0"}}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.HMACSecret != "hmac-secret" {
		t.Fatalf("hmac not expanded: %q", cfg.Security.HMACSecret)
	}
	if !IsBcryptHash(cfg.Dashboard.AdminPassword) {
		t.Fatalf("admin_password was not hashed by Load: %q", cfg.Dashboard.AdminPassword)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.Dashboard.AdminPassword), []byte("s3cret")); err != nil {
		t.Fatalf("admin_password hash does not match the expanded env value %q: %v", "s3cret", err)
	}
}

func TestDashboardRequiresCreds(t *testing.T) {
	path := writeCfgFile(t, `
version: "1"
server: {listen_https: ":443"}
security: {engine_fail_mode: fail_open}
dashboard: {enabled: true, session_ttl: 1h}
domains:
  - hostname: x.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error without admin creds")
	}
}

func TestChallengeDefaultsApplied(t *testing.T) {
	cfg := Default()
	if cfg.Security.Challenge.Enabled {
		t.Fatal("challenge should default disabled")
	}
	if cfg.Security.Challenge.Difficulty != 4 {
		t.Fatalf("expected default difficulty 4, got %d", cfg.Security.Challenge.Difficulty)
	}
	if cfg.Security.Challenge.TTL.D() != 10*time.Minute {
		t.Fatalf("unexpected ttl: %v", cfg.Security.Challenge.TTL.D())
	}
}
