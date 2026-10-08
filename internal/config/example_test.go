package config

import "testing"

func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("WAAP_JWT_SECRET", "change-me-hmac-secret")
	cfg, err := Load("../../config/openwaap.example.yaml")
	if err != nil {
		t.Fatalf("example config must load: %v", err)
	}
	if len(cfg.Domains) == 0 {
		t.Fatal("example config should have domains")
	}
	if cfg.Security.Challenge.Enabled || cfg.Security.Challenge.Difficulty != 4 {
		t.Fatalf("challenge settings mismatch: %+v", cfg.Security.Challenge)
	}
	if cfg.Dashboard.MaxEvents != 10000 {
		t.Fatalf("max_events mismatch: %d", cfg.Dashboard.MaxEvents)
	}
	if cfg.Domains[0].APISecurity == nil || !cfg.Domains[0].APISecurity.Enabled {
		t.Fatal("example config should enable api_security")
	}
	if cfg.Domains[0].APISecurity.JWT == nil || cfg.Domains[0].APISecurity.JWT.Algorithm != "HS256" {
		t.Fatal("example config should define a HS256 jwt section")
	}
	if cfg.Domains[0].APISecurity.JWT.Secret != "change-me-hmac-secret" {
		t.Fatalf("jwt secret should be env-expanded, got %q", cfg.Domains[0].APISecurity.JWT.Secret)
	}
	if cfg.Domains[0].Behavior == nil || !cfg.Domains[0].Behavior.Enabled {
		t.Fatal("example config should enable behavior")
	}
	if cfg.Domains[0].Behavior.BlockAbove != 85 || cfg.Domains[0].Behavior.ChallengeAbove != 60 {
		t.Fatalf("behavior bands mismatch: %+v", cfg.Domains[0].Behavior)
	}
	if cfg.Security.GeoIP == nil || cfg.Security.GeoIP.Enabled {
		t.Fatal("example config geoip should stay disabled")
	}
	if cfg.Security.SIEM == nil || cfg.Security.SIEM.Enabled {
		t.Fatal("example config siem should stay disabled")
	}
	if cfg.Security.Store.Type != "memory" {
		t.Fatalf("example config store type: %s", cfg.Security.Store.Type)
	}
}
