package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

func itoa(n int) string { return strconv.Itoa(n) }

func buildCookieHeader(raw string) http.Header {
	h := http.Header{}
	h.Set("Cookie", raw)
	return h
}

func chCfg(difficulty int) config.ChallengeConfig {
	return config.ChallengeConfig{
		Difficulty: difficulty,
		TTL:        config.Duration(10 * time.Minute),
		ProofTTL:   config.Duration(3 * time.Minute),
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := NewSigner("secret")
	m := NewChallengeManager(signer, chCfg(4), func() time.Time { return now })

	cd, err := m.Issue("10.0.0.9", "/app")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := SolveProof(cd.Cleartext, cd.Difficulty)
	if err != nil {
		t.Fatalf("solve failed: %v", err)
	}

	cookie, err := m.VerifyChallenge(cd, "10.0.0.9", itoa(nonce), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if v, ok := signer.ValueOk(cookie, "10.0.0.9", now.Add(time.Minute)); !ok || !strings.HasPrefix(v, "challenge_ok") {
		t.Fatalf("access cookie invalid: %q", cookie)
	}
}

func TestChallengeRejectsWrongNonce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := NewChallengeManager(NewSigner("secret"), chCfg(4), func() time.Time { return now })
	cd, err := m.Issue("10.0.0.9", "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyChallenge(cd, "10.0.0.9", "0", now.Add(time.Minute)); err == nil {
		t.Fatal("nonce of all-zero proof must be rejected for difficulty>=4")
	}
}

func TestChallengeRejectsForeignIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := NewChallengeManager(NewSigner("secret"), chCfg(2), func() time.Time { return now })
	cd, err := m.Issue("10.0.0.9", "/")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := SolveProof(cd.Cleartext, cd.Difficulty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyChallenge(cd, "10.0.0.99", itoa(nonce), now.Add(time.Minute)); err == nil {
		t.Fatal("challenge issued for another IP must fail")
	}
}

func TestChallengeExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := NewChallengeManager(NewSigner("secret"), chCfg(2), func() time.Time { return now })
	cd, err := m.Issue("10.0.0.9", "/")
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := SolveProof(cd.Cleartext, cd.Difficulty)
	if _, err := m.VerifyChallenge(cd, "10.0.0.9", itoa(nonce), now.Add(10*time.Minute)); err == nil {
		t.Fatal("expired challenge must fail")
	}
}

func TestValidProofMatchesJS(t *testing.T) {
	salt := "pow:abc|10.0.0.9|1700000060"
	for _, difficulty := range []int{2, 3, 4} {
		nonce, err := SolveProof(salt, difficulty)
		if err != nil {
			t.Fatalf("solve d=%d: %v", difficulty, err)
		}
		sum := sha256.Sum256([]byte(salt + ":" + itoa(nonce)))
		h := hex.EncodeToString(sum[:])
		if !strings.HasPrefix(h, strings.Repeat("0", difficulty)) {
			t.Fatalf("proof d=%d does not satisfy prefix", difficulty)
		}
		if !ValidProof(salt, itoa(nonce), difficulty) {
			t.Fatalf("ValidProof disagrees for d=%d", difficulty)
		}
	}
}

func TestVerifyAccessCookie(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := NewSigner("secret")
	m := NewChallengeManager(signer, chCfg(2), func() time.Time { return now })

	cd, _ := m.Issue("1.2.3.4", "/")
	nonce, _ := SolveProof(cd.Cleartext, cd.Difficulty)
	cookie, _ := m.VerifyChallenge(cd, "1.2.3.4", itoa(nonce), now)

	hdr := buildCookieHeader(ChallengeCookie + "=" + cookie)
	if !m.VerifyAccess("1.2.3.4", hdr, now.Add(time.Minute)) {
		t.Fatal("valid cookie must verify")
	}
	if m.VerifyAccess("1.2.3.5", hdr, now.Add(time.Minute)) {
		t.Fatal("cookie must be IP-bound")
	}
	if m.VerifyAccess("1.2.3.4", hdr, now.Add(2*time.Hour)) {
		t.Fatal("expired access cookie must fail")
	}
}
