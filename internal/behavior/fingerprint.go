package behavior

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const CookieName = "waap_client"

type Fingerprinter struct {
	secret []byte
	ttl    time.Duration
}

func NewFingerprinter(secret string, ttl time.Duration) (*Fingerprinter, error) {
	if secret == "" {
		s, err := randomHex(32)
		if err != nil {
			return nil, err
		}
		secret = s
	}
	return &Fingerprinter{secret: []byte(secret), ttl: ttl}, nil
}

func (f *Fingerprinter) Issue(ip string, now time.Time) (id, cookie string, err error) {
	id, err = randomHex(8)
	if err != nil {
		return "", "", err
	}
	cleartext := fmt.Sprintf("fp:%s:%d:%s", id, now.Add(f.ttl).Unix(), ip)
	cookie = base64.RawURLEncoding.EncodeToString([]byte(cleartext + "." + f.mac(cleartext)))
	return id, cookie, nil
}

func (f *Fingerprinter) Validate(cookie, ip string, now time.Time) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cookie))
	if err != nil {
		return "", false
	}
	s := string(raw)
	mid := strings.LastIndex(s, ".")
	if mid <= 1 {
		return "", false
	}
	cleartext, mac := s[:mid], s[mid+1:]
	if !hmac.Equal([]byte(mac), []byte(f.mac(cleartext))) {
		return "", false
	}
	parts := strings.SplitN(cleartext, ":", 4)
	if len(parts) != 4 || parts[0] != "fp" {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", false
	}
	if now.Unix() > exp {
		return "", false
	}
	if parts[3] != ip {
		return "", false
	}
	return parts[1], true
}

func (f *Fingerprinter) mac(v string) string {
	h := hmac.New(sha256.New, f.secret)
	h.Write([]byte(v))
	return hex.EncodeToString(h.Sum(nil))
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("behavior: crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
