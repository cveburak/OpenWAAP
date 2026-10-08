package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

const ChallengeCookie = "waap_challenge"

type ChallengeManager struct {
	signer     *Signer
	difficulty int
	ttl        time.Duration
	proofTTL   time.Duration
	now        func() time.Time
}

func NewChallengeManager(signer *Signer, cfg config.ChallengeConfig, now func() time.Time) *ChallengeManager {
	difficulty := cfg.Difficulty
	if difficulty <= 0 {
		difficulty = 4
	}
	ttl := cfg.TTL.D()
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	proofTTL := cfg.ProofTTL.D()
	if proofTTL <= 0 {
		proofTTL = 3 * time.Minute
	}
	nt := time.Now
	if now != nil {
		nt = now
	}
	return &ChallengeManager{signer: signer, difficulty: difficulty, ttl: ttl, proofTTL: proofTTL, now: nt}
}

func NewFromDefaults(signer *Signer, difficulty int) *ChallengeManager {
	return NewChallengeManager(signer, config.ChallengeConfig{Difficulty: difficulty, TTL: config.Duration(10 * time.Minute), ProofTTL: config.Duration(3 * time.Minute)}, nil)
}

type ChallengeData struct {
	Cleartext  string `json:"cleartext"`
	Signature  string `json:"signature"`
	Difficulty int    `json:"difficulty"`
	Next       string `json:"next"`
}

func (m *ChallengeManager) Issue(ip, next string) (ChallengeData, error) {
	token, err := NewToken()
	if err != nil {
		return ChallengeData{}, err
	}
	cleartext := "pow:" + token + "|" + ip + "|" + strconv.FormatInt(m.now().Add(m.proofTTL).Unix(), 10)
	return ChallengeData{
		Cleartext:  cleartext,
		Signature:  m.signer.Sign(cleartext),
		Difficulty: m.difficulty,
		Next:       next,
	}, nil
}

func (m *ChallengeManager) VerifyChallenge(cd ChallengeData, ip, nonce string, now time.Time) (string, error) {
	if !m.signer.Valid(cd.Signature) || m.signer.Value(cd.Signature) != cd.Cleartext {
		return "", errors.New("bad challenge signature")
	}
	parts := strings.Split(cd.Cleartext, "|")
	if len(parts) != 3 {
		return "", errors.New("malformed challenge")
	}
	value, wantIP, expStr := parts[0], parts[1], parts[2]
	if !strings.HasPrefix(value, "pow:") {
		return "", errors.New("wrong challenge type")
	}
	if wantIP != ip {
		return "", errors.New("challenge bound to another IP")
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || now.Unix() > exp {
		return "", errors.New("challenge expired")
	}
	if _, err := randomNonce(nonce, 1<<32); err != nil {
		return "", err
	}
	if !ValidProof(cd.Cleartext, nonce, m.difficulty) {
		return "", errors.New("proof-of-work invalid")
	}
	return m.signer.Issue(ip, "challenge_ok", m.ttl, now), nil
}

func ValidProof(salt, nonce string, difficulty int) bool {
	sum := sha256.Sum256([]byte(salt + ":" + nonce))
	h := hex.EncodeToString(sum[:])
	return strings.HasPrefix(h, strings.Repeat("0", difficulty))
}

func SolveProof(salt string, difficulty int) (int, error) {
	if difficulty > 8 {
		return 0, errors.New("difficulty too high for test solve")
	}
	for n := 0; n < 1<<22; n++ {
		if ValidProof(salt, strconv.Itoa(n), difficulty) {
			return n, nil
		}
	}
	return 0, errors.New("no proof found")
}

func (m *ChallengeManager) ValidateAccessCookie(r *http.Request) bool {
	return m.VerifyAccess(ClientIP(r), r.Header, m.now())
}

func (m *ChallengeManager) VerifyAccess(ip string, headers http.Header, now time.Time) bool {
	var raw string
	for _, line := range headers.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 && kv[0] == ChallengeCookie {
				raw = kv[1]
			}
		}
	}
	if raw == "" {
		return false
	}
	v, ok := m.signer.ValueOk(raw, ip, now)
	return ok && v == "challenge_ok"
}

func (m *ChallengeManager) Difficulty() int { return m.difficulty }

func ClientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func pagePath(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}
