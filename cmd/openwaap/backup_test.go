package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openwaap/openwaap/internal/selfsigned"
)

func minimalConfigYAML(certPath, keyPath string, setupPending bool) string {
	sp := ""
	if setupPending {
		sp = "setup_pending: true\n"
	}
	return sp + `version: "1"
server:
  listen_https: ":8443"
  tls_cert_file: "` + certPath + `"
  tls_key_file: "` + keyPath + `"
security:
  engine_fail_mode: fail_open
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "openwaap.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunValidateAcceptsExistingTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "edge.pem"), filepath.Join(dir, "edge.key")
	if err := selfsigned.Generate(cert, key, []string{"localhost"}); err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	p := writeConfig(t, minimalConfigYAML(cert, key, false))
	if err := runValidate(p); err != nil {
		t.Fatalf("runValidate with existing TLS material: %v", err)
	}
}

func TestRunValidateRejectsMissingTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "does-not-exist.pem")
	key := filepath.Join(dir, "does-not-exist.key")
	p := writeConfig(t, minimalConfigYAML(cert, key, false))
	err := runValidate(p)
	if err == nil {
		t.Fatal("runValidate should have rejected a config pointing at missing TLS material")
	}
}

func TestRunValidateSkipsTLSCheckWhenSetupPending(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "does-not-exist.pem")
	key := filepath.Join(dir, "does-not-exist.key")
	p := writeConfig(t, minimalConfigYAML(cert, key, true))
	if err := runValidate(p); err != nil {
		t.Fatalf("runValidate with setup_pending should skip the TLS check: %v", err)
	}
}
