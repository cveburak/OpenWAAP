package logging

import (
	"strings"
)

const MaskedValue = "***MASKED***"

var sensitiveHeaderPrefixes = []string{
	"authorization",
	"proxy-authorization",
	"x-api-key",
	"x-auth-token",
	"cookie",
	"set-cookie",
	"api-key",
}

var sensitiveQueryParams = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"access_token",
	"jwt",
	"signature",
	"key",
}

func RedactHeaderValue(name, value string) string {
	ln := strings.ToLower(name)
	for _, s := range sensitiveHeaderPrefixes {
		if ln == s || strings.HasPrefix(ln, s) {
			return MaskedValue
		}
	}
	return value
}

func RedactQueryString(rawQuery string) string {
	if rawQuery == "" {
		return rawQuery
	}
	parts := strings.Split(rawQuery, "&")
	for i, kv := range parts {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			continue
		}
		name := kv[:idx]
		if isSensitiveParam(name) {
			parts[i] = name + "=" + MaskedValue
		}
	}
	return strings.Join(parts, "&")
}

func isSensitiveParam(name string) bool {
	ln := strings.ToLower(name)
	if sensitiveParamSet[ln] {
		return true
	}
	for _, seg := range strings.FieldsFunc(ln, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		if sensitiveParamSet[seg] {
			return true
		}
	}
	return false
}

var sensitiveParamSet = func() map[string]bool {
	m := make(map[string]bool, len(sensitiveQueryParams))
	for _, s := range sensitiveQueryParams {
		m[s] = true
	}
	return m
}()

func RedactBody() string {
	return MaskedValue
}
