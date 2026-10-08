package dashboard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Signer struct {
	secret []byte
}

func NewSigner(secret string) *Signer {
	if secret != "" {
		return &Signer{secret: []byte(secret)}
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &Signer{secret: key}
}

func (s *Signer) Sign(value string) string {
	mac := s.mac(value)
	return value + "." + mac
}

func (s *Signer) Valid(payload string) bool {
	value, sig, ok := s.split(payload)
	if !ok {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(s.mac(value)))
}

func (s *Signer) Value(payload string) string {
	v, _, _ := s.split(payload)
	return v
}

func (s *Signer) mac(value string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Signer) split(payload string) (string, string, bool) {
	i := strings.LastIndexByte(payload, '.')
	if i <= 0 || i == len(payload)-1 {
		return "", "", false
	}
	return payload[:i], payload[i+1:], true
}

func (s *Signer) Issue(ip, value string, ttl time.Duration, now time.Time) string {
	expiry := now.Add(ttl).Unix()
	cleartext := value + "|" + ip + "|" + strconv.FormatInt(expiry, 10)
	return s.Sign(cleartext)
}

func (s *Signer) Verify(payload, ip string, now time.Time) (string, error) {
	value, ok := s.ValueOk(payload, ip, now)
	if !ok {
		return "", errors.New("invalid or expired signature")
	}
	return value, nil
}

func (s *Signer) ValueOk(payload, ip string, now time.Time) (string, bool) {
	if !s.Valid(payload) {
		return "", false
	}
	clean := s.Value(payload)
	parts := strings.Split(clean, "|")
	if len(parts) != 3 {
		return "", false
	}
	value, wantIP, expStr := parts[0], parts[1], parts[2]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", false
	}
	if now.Unix() > exp {
		return "", false
	}
	if wantIP != ip {
		return "", false
	}
	return value, true
}

func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dashboard: rng: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomNonce(nonce string, max int64) (int64, error) {
	n, err := strconv.ParseInt(nonce, 10, 64)
	if err != nil || n < 0 || n > max {
		return 0, errors.New("invalid nonce")
	}
	return n, nil
}
