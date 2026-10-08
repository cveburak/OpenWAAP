package logging

import (
	"strings"
	"testing"
)

func TestRedactHeader(t *testing.T) {
	cases := []struct {
		name, value, want string
	}{
		{"authorization", "Bearer abc.def.ghi", MaskedValue},
		{"Authorization", "Basic dXNlcjpwYXNz", MaskedValue},
		{"x-api-key", "sk-12345", MaskedValue},
		{"cookie", "session=abc123", MaskedValue},
		{"user-agent", "curl/8.0", "curl/8.0"},
		{"x-app-version", "1.0", "1.0"},
	}
	for _, c := range cases {
		got := RedactHeaderValue(c.name, c.value)
		if got != c.want {
			t.Errorf("RedactHeaderValue(%q): got %q want %q", c.name, got, c.want)
		}
	}
}

func TestRedactQueryString(t *testing.T) {
	orig := "user=alice&password=hunter2&token=abc&id=5&secret=s3"
	got := RedactQueryString(orig)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("password leaked: %s", got)
	}
	if strings.Contains(got, "abc") {
		t.Fatalf("token leaked: %s", got)
	}
	if strings.Contains(got, "s3") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !strings.Contains(got, "token="+MaskedValue) {
		t.Fatalf("expected masked token param: %s", got)
	}
	if !strings.Contains(got, "user=alice") {
		t.Fatalf("expected innocuous param preserved: %s", got)
	}
}

func TestRedactQueryStringEmpty(t *testing.T) {
	if got := RedactQueryString(""); got != "" {
		t.Fatalf("expected empty input unchanged, got %q", got)
	}
}

func TestRedactBody(t *testing.T) {
	if RedactBody() != MaskedValue {
		t.Fatal("bodies should be masked by default in phase 1")
	}
}
