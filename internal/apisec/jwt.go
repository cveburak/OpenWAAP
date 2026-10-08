package apisec

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type JWTConfig struct {
	Algorithm      string
	Issuer         string
	Audiences      []string
	RequiredClaims []string
	LeewaySeconds  int
	Header string

	secret []byte
	pubKey any
}

func NewJWTConfig(alg, secret, publicPEM, issuer string, audiences, required []string, leeway int, header string) (*JWTConfig, error) {
	c := &JWTConfig{
		Algorithm:      alg,
		Issuer:         issuer,
		Audiences:      audiences,
		RequiredClaims: required,
		LeewaySeconds:  leeway,
		Header:         header,
	}
	switch strings.ToUpper(alg) {
	case "", "HS256":
		c.Algorithm = "HS256"
		if secret == "" {
			return nil, errors.New("apisec: HS256 requires a secret")
		}
		c.secret = []byte(secret)
	case "RS256":
		if publicPEM == "" {
			return nil, errors.New("apisec: RS256 requires public_key_pem")
		}
		key, err := parsePublicKeyPEM(publicPEM)
		if err != nil {
			return nil, fmt.Errorf("apisec: rs256 public key: %w", err)
		}
		c.pubKey = key
	default:
		return nil, fmt.Errorf("apisec: unsupported JWT algorithm %q (HS256, RS256)", alg)
	}
	return c, nil
}

func parsePublicKeyPEM(pemData string) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		if key, err := x509.ParsePKIXPublicKey([]byte(pemData)); err == nil {
			return key, nil
		}
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

type JWTVerificationError struct {
	Reason string
}

func (e *JWTVerificationError) Error() string { return "jwt: " + e.Reason }

func jwtErr(reason string) error { return &JWTVerificationError{Reason: reason} }

func tokenFromHeader(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	if strings.EqualFold(v[:min(7, len(v))], "Bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return v
}

func (c *JWTConfig) Verify(token string, now time.Time) (map[string]any, error) {
	if token == "" {
		return nil, jwtErr("missing token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, jwtErr("token not a compact JWS")
	}
	headB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ,omitempty"`
	}
	if err := decodeJSON(headB64, &header); err != nil {
		return nil, jwtErr("malformed header")
	}
	if !strings.EqualFold(header.Alg, c.Algorithm) {
		return nil, jwtErr(fmt.Sprintf("alg mismatch: %s", header.Alg))
	}

	if err := c.checkSignature(headB64, payloadB64, sigB64); err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := decodeJSON(payloadB64, &claims); err != nil {
		return nil, jwtErr("malformed payload")
	}
	leeway := time.Duration(c.LeewaySeconds) * time.Second

	if exp, ok := claims["exp"].(float64); ok {
		if now.Unix() > int64(exp)+int64(leeway.Seconds()) {
			return nil, jwtErr("token expired")
		}
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if now.Unix()+int64(leeway.Seconds()) < int64(nbf) {
			return nil, jwtErr("token not yet valid")
		}
	}
	if c.Issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != c.Issuer {
			return nil, jwtErr("issuer mismatch")
		}
	}
	if len(c.Audiences) > 0 {
		aud := audiencesOf(claims)
		if len(intersect(aud, c.Audiences)) == 0 {
			return nil, jwtErr("audience mismatch")
		}
	}
	for _, claim := range c.RequiredClaims {
		if v, ok := claims[claim]; !ok || isEmpty(v) {
			return nil, jwtErr(fmt.Sprintf("missing required claim %q", claim))
		}
	}
	return claims, nil
}

func (c *JWTConfig) checkSignature(headB64, payloadB64, sigB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return jwtErr("malformed signature")
	}
	signingInput := headB64 + "." + payloadB64
	switch c.Algorithm {
	case "HS256":
		mac := hmac.New(sha256.New, c.secret)
		mac.Write([]byte(signingInput))
		want := mac.Sum(nil)
		if !hmac.Equal(sig, want) {
			return jwtErr("signature mismatch")
		}
		return nil
	case "RS256":
		key, ok := c.pubKey.(*rsa.PublicKey)
		if !ok {
			return jwtErr("unsupported key type")
		}
		hash := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(key, 0, hash[:], sig); err != nil {
			return jwtErr("rsa signature mismatch")
		}
		return nil
	}
	return jwtErr("unsupported algorithm")
}

func decodeJSON(part string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func audiencesOf(claims map[string]any) []string {
	aud, ok := claims["aud"]
	if !ok {
		return nil
	}
	switch t := aud.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, v := range t {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func intersect(a, b []string) []string {
	want := map[string]bool{}
	for _, v := range b {
		want[v] = true
	}
	var out []string
	for _, v := range a {
		if want[v] {
			out = append(out, v)
		}
	}
	return out
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	default:
		return false
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
