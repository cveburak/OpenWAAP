package dashboard

import (
	"strings"
	"testing"
	"time"
)

func TestSignerRoundTrip(t *testing.T) {
	s := NewSigner("sekret")
	payload := s.Issue("10.0.0.1", "admin", time.Hour, time.Unix(1_700_000_000, 0))

	v, ok := s.ValueOk(payload, "10.0.0.1", time.Unix(1_700_000_100, 0))
	if !ok || v != "admin" {
		t.Fatalf("expected admin payload, got %q ok=%v", v, ok)
	}
}

func TestSignerRejectsTamper(t *testing.T) {
	s := NewSigner("sekret")
	payload := s.Issue("10.0.0.1", "admin", time.Hour, time.Unix(1_700_000_000, 0))

	tampered := flipBit(payload)
	if s.Valid(tampered) {
		t.Fatal("tampered payload must be invalid")
	}
}

func TestSignerRejectsWrongIP(t *testing.T) {
	s := NewSigner("sekret")
	payload := s.Issue("10.0.0.1", "admin", time.Hour, time.Unix(1_700_000_000, 0))
	if _, ok := s.ValueOk(payload, "10.0.0.2", time.Unix(1_700_000_100, 0)); ok {
		t.Fatal("IP-bound payload accepted for another IP")
	}
}

func TestSignerRejectsExpired(t *testing.T) {
	s := NewSigner("sekret")
	payload := s.Issue("10.0.0.1", "admin", time.Hour, time.Unix(1_700_000_000, 0))
	if _, ok := s.ValueOk(payload, "10.0.0.1", time.Unix(1_700_003_601, 0)); ok {
		t.Fatal("expired payload must be rejected")
	}
}

func TestSignerEmptySecretStillWorks(t *testing.T) {
	s := NewSigner("")
	p := s.Sign("x")
	if !s.Valid(p) {
		t.Fatal("random-secret signer should verify its own payloads")
	}
}

func flipBit(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] == 'a' {
			b[i] = 'b'
			break
		}
	}
	return string(b)
}

func TestSignerValueLooksStructured(t *testing.T) {
	s := NewSigner("k")
	p := s.Issue("ip", "pv", time.Minute, time.Unix(1_700_000_000, 0))
	if strings.Count(s.Value(p), "|") != 2 {
		t.Fatalf("expected 3-part cleartext, got %q", s.Value(p))
	}
}
