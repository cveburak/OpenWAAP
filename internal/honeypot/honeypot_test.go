package honeypot

import (
	"testing"
)

func TestRegistryMatchesConfiguredAndAuto(t *testing.T) {
	r := NewRegistry([]string{"/custom-decoy"}, true, 0)
	if !r.IsDecoy("/wp-admin") {
		t.Fatal("expected auto-generated /wp-admin to be a decoy")
	}
	if !r.IsDecoy("/custom-decoy") {
		t.Fatal("expected configured decoy to be matched")
	}
	if r.IsDecoy("/home") {
		t.Fatal("expected /home NOT to be a decoy")
	}
}

func TestRegistryNoAuto(t *testing.T) {
	r := NewRegistry([]string{"/custom"}, false, 0)
	if r.IsDecoy("/wp-admin") {
		t.Fatal("expected no auto decoys when autoGenerate=false")
	}
	if !r.IsDecoy("/custom") {
		t.Fatal("expected configured decoy match")
	}
}

func TestNormalizeLeadingSlash(t *testing.T) {
	r := NewRegistry([]string{"custom-no-slash"}, true, 0)
	if !r.IsDecoy("/custom-no-slash") {
		t.Fatal("expected leading slash normalization")
	}
}

func TestPathsListed(t *testing.T) {
	r := NewRegistry([]string{"/only-path"}, false, 0)
	ps := r.Paths()
	found := false
	for _, p := range ps {
		if p == "/only-path" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected /only-path in paths, got %v", ps)
	}
}

func TestExplainNonEmpty(t *testing.T) {
	if Explain("/wp-admin") == "" {
		t.Fatal("expected non-empty explanation")
	}
}

func TestDefaultPointsHigh(t *testing.T) {
	if DefaultPoints < 90 {
		t.Fatalf("expected high default points, got %d", DefaultPoints)
	}
	r := NewRegistry(nil, true, 0)
	if r.Points() != DefaultPoints {
		t.Fatalf("unset points should fall back to DefaultPoints, got %d", r.Points())
	}
}

func TestConfiguredPointsOverrideDefault(t *testing.T) {
	r := NewRegistry(nil, true, 50)
	if r.Points() != 50 {
		t.Fatalf("configured points not honored: got %d, want 50", r.Points())
	}
}

func TestNilRegistryIsSafe(t *testing.T) {
	var r *Registry
	if r.IsDecoy("/wp-admin") {
		t.Fatal("nil Registry must report every path as a non-decoy")
	}
	if r.Points() != DefaultPoints {
		t.Fatalf("nil Registry.Points() = %d, want DefaultPoints", r.Points())
	}
	if got := r.Paths(); got != nil {
		t.Fatalf("nil Registry.Paths() = %v, want nil", got)
	}
}
