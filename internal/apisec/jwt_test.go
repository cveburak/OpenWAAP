package apisec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func issueHS256(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	head, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(head)
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return h + "." + p + "." + sig
}

func mustCfg(t *testing.T, alg, secret string) *JWTConfig {
	t.Helper()
	c, err := NewJWTConfig(alg, secret, "", "", nil, nil, 0, "")
	if err != nil {
		t.Fatalf("NewJWTConfig: %v", err)
	}
	return c
}

func TestVerifyValidToken(t *testing.T) {
	c := mustCfg(t, "HS256", "s3cret")
	tok := issueHS256(t, "s3cret", map[string]any{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()})
	claims, err := c.Verify(tok, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims["sub"] != "u1" {
		t.Fatalf("sub = %v", claims["sub"])
	}
}

func TestVerifyFailures(t *testing.T) {
	c := mustCfg(t, "HS256", "s3cret")
	now := time.Now()

	cases := []struct {
		name  string
		token string
	}{
		{"missing", ""},
		{"bad-part-count", "a.b"},
		{"wrong-signature", issueHS256(t, "other", map[string]any{"sub": "u1"})},
		{"expired", issueHS256(t, "s3cret", map[string]any{"exp": now.Add(-time.Hour).Unix()})},
		{"not-yet-valid", issueHS256(t, "s3cret", map[string]any{"nbf": now.Add(time.Hour).Unix()})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Verify(tc.token, now); err == nil {
				t.Fatalf("expected error for %q", tc.name)
			}
		})
	}
}

func TestVerifyIssuerAndAudience(t *testing.T) {
	c, err := NewJWTConfig("HS256", "s3cret", "", "issuer-a", []string{"api"}, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	good := issueHS256(t, "s3cret", map[string]any{
		"iss": "issuer-a", "aud": []any{"web", "api"},
	})
	if _, err := c.Verify(good, time.Now()); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	badIss := issueHS256(t, "s3cret", map[string]any{"iss": "issuer-b", "aud": "api"})
	if _, err := c.Verify(badIss, time.Now()); err == nil {
		t.Fatal("expected issuer mismatch")
	}
	badAud := issueHS256(t, "s3cret", map[string]any{"aud": "other"})
	if _, err := c.Verify(badAud, time.Now()); err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestVerifyRequiredClaimsAndLeeway(t *testing.T) {
	c, err := NewJWTConfig("HS256", "s3cret", "", "", nil, []string{"sub", "role"}, 30, "")
	if err != nil {
		t.Fatal(err)
	}
	missing := issueHS256(t, "s3cret", map[string]any{"sub": "u1"})
	if _, err := c.Verify(missing, time.Now()); err == nil {
		t.Fatal("expected missing required claim error")
	}

	lc, _ := NewJWTConfig("HS256", "s3cret", "", "", nil, nil, 30, "")
	expired := issueHS256(t, "s3cret", map[string]any{"exp": time.Now().Add(-10 * time.Second).Unix()})
	if _, err := lc.Verify(expired, time.Now()); err != nil {
		t.Fatalf("leeway should accept: %v", err)
	}
}

func TestNewJWTConfigErrors(t *testing.T) {
	if _, err := NewJWTConfig("HS256", "", "", "", nil, nil, 0, ""); err == nil {
		t.Fatal("expected missing-secret error")
	}
	if _, err := NewJWTConfig("RS256", "", "", "", nil, nil, 0, ""); err == nil {
		t.Fatal("expected missing RSA key error")
	}
	if _, err := NewJWTConfig("ES256", "x", "", "", nil, nil, 0, ""); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestTokenFromHeader(t *testing.T) {
	if got := tokenFromHeader("Bearer abc.def"); got != "abc.def" {
		t.Fatalf("got %q", got)
	}
	if got := tokenFromHeader("rawtoken"); got != "rawtoken" {
		t.Fatalf("got %q", got)
	}
	if got := tokenFromHeader(strings.Repeat(" ", 10)); got != "" {
		t.Fatalf("got %q", got)
	}
}
