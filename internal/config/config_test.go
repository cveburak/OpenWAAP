package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "waap.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
  listen_http: ":80"
security:
  engine_fail_mode: fail_open
domains:
  - hostname: example.com
    origin:
      scheme: http
      host: 127.0.0.1
      port: "8080"
    waf:
      mode: block
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if len(cfg.Domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(cfg.Domains))
	}
	if !cfg.Domains[0].EnabledBool() {
		t.Fatal("expected domain enabled by default")
	}
	if cfg.Security.EngineFailMode != FailOpen {
		t.Fatalf("expected fail_open, got %s", cfg.Security.EngineFailMode)
	}
}

func TestLoadInvalidFailMode(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
security:
  engine_fail_mode: sometimes
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for invalid fail mode")
	}
}

func TestLoadDuplicateDomain(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
domains:
  - hostname: a.com
    origin: {scheme: http, host: h, port: "1"}
    waf: {mode: block}
  - hostname: a.com
    origin: {scheme: http, host: h, port: "1"}
    waf: {mode: block}
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for duplicate domain")
	}
}

func TestLoadMissingOrigin(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
domains:
  - hostname: a.com
    waf: {mode: block}
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for missing origin")
	}
}

func TestActionValid(t *testing.T) {
	if !ActionBlock.Valid() || !ActionAllow.Valid() || !ActionChallenge.Valid() || !ActionLog.Valid() {
		t.Fatal("expected valid actions to be valid")
	}
	if !ActionUnauthorized.Valid() {
		t.Fatal("expected UNAUTHORIZED to be valid")
	}
	if Action("BOGUS").Valid() {
		t.Fatal("expected bogus action to be invalid")
	}
}

func TestDomainAPISecurityMissingJWTSkip(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
domains:
  - hostname: a.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`)
	if _, err := Load(p); err != nil {
		t.Fatalf("api_security absent must not fail validation: %v", err)
	}
}

func TestDomainAPISecurityValidations(t *testing.T) {
	write := func(block string) string {
		return writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
domains:
  - hostname: a.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
    api_security:
      enabled: true
      `+block)
	}

	tests := []struct {
		name  string
		block string
		want  string
	}{
		{"missing-secret", "jwt: {algorithm: HS256}", "secret is required"},
		{"unsupported-alg", "jwt: {algorithm: ES256, secret: x}", "unsupported"},
		{"missing-rsa-key", "jwt: {algorithm: RS256}", "public_key_pem is required"},
		{"bad-no_auth_action", "policy: {no_auth_action: NOPE}", "must be a valid action"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(write(tc.block)); err == nil {
				t.Fatalf("expected validation error for %q", tc.name)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestDomainBehaviorValidations(t *testing.T) {
	write := func(block string) string {
		return writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
domains:
  - hostname: a.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
    behavior:
      enabled: true
      `+block)
	}

	tests := []struct {
		name  string
		block string
		want  string
	}{
		{"disabled-ok", "challenge_above: 99", ""},
		{"bands-crossed", "challenge_above: 60\n      block_above: 50", "block_above must be above"},
		{"band-out-of-range", "block_above: 101", "within 0-100"},
		{"negative-ttl", "cookie_ttl: -1h", "must not be negative"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(tc.block))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("expected valid config, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected validation error for %q", tc.name)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestDomainAddress(t *testing.T) {
	o := OriginConfig{Host: "127.0.0.1", Port: "8080"}
	if got := o.Address(); got != "127.0.0.1:8080" {
		t.Fatalf("expected address, got %s", got)
	}
}

func TestSecurityGeoIPValidations(t *testing.T) {
	base := `version: "1"
server: {listen_https: ":443"}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
security:
  geoip:
    enabled: true
`

	if _, err := Load(writeTemp(t, base)); err == nil {
		t.Fatal("expected error when geoip enabled without db_path")
	}

	ok := strings.ReplaceAll(base, "enabled: true", "enabled: true\n    db_path: /tmp/GeoLite2.mmdb")
	if _, err := Load(writeTemp(t, ok)); err != nil {
		t.Fatalf("valid geoip config rejected: %v", err)
	}
}

func TestSecuritySIEMValidations(t *testing.T) {
	base := `version: "1"
server: {listen_https: ":443"}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`
	enabled := base + `security:
  siem:
    enabled: true
`
	if _, err := Load(writeTemp(t, enabled)); err == nil {
		t.Fatal("expected error when siem enabled without endpoints")
	}

	httpOK := enabled + `    batch_interval: 2s
    endpoints:
      - type: http
        url: https://siem.example.com/ingest
`
	if _, err := Load(writeTemp(t, httpOK)); err != nil {
		t.Fatalf("valid http siem rejected: %v", err)
	}

	badNetwork := enabled + `    endpoints:
      - type: syslog
        network: sctp
        address: 10.0.0.1:514
`
	if _, err := Load(writeTemp(t, badNetwork)); err == nil {
		t.Fatal("expected error for invalid syslog network")
	}
}

func TestSecurityStoreValidations(t *testing.T) {
	base := `version: "1"
server: {listen_https: ":443"}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`
	badType := base + `security:
  store:
    type: etcd
`
	if _, err := Load(writeTemp(t, badType)); err == nil {
		t.Fatal("expected error for unsupported store type")
	}

	noAddr := base + `security:
  store:
    type: redis
`
	if _, err := Load(writeTemp(t, noAddr)); err == nil {
		t.Fatal("expected error for redis store without address")
	}

	okRedis := base + `security:
  store:
    type: redis
    redis:
      address: 127.0.0.1:6379
      db: 2
      prefix: "waap:edge1:"
`
	if _, err := Load(writeTemp(t, okRedis)); err != nil {
		t.Fatalf("valid redis store rejected: %v", err)
	}
}

func TestSaveAndJSONRoundTrip(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server:
  listen_https: ":443"
  listen_http: ":80"
security:
  engine_fail_mode: fail_open
  hmac_secret: supersecret
  challenge:
    enabled: true
    difficulty: 4
    ttl: 600s
    proof_ttl: 180s
  geoip:
    enabled: true
    db_path: /tmp/geo.mmdb
  siem:
    enabled: false
  store:
    type: memory
  ddos:
    enabled: true
    per_ip_rate: 30
    site_burst_rps: 1500
    defense_ttl: 60s
    allowlist:
      - 10.0.0.0/8
  headers:
    hsts: true
    frame_options: SAMEORIGIN
    no_sniff: true
    referrer_policy: strict-origin-when-cross-origin
    csp: "default-src 'self'"
log:
  rotation_max_mb: 128
  rotation_keep: 10
dashboard:
  enabled: true
  admin_user: admin
  admin_password: changeme
  session_ttl: 12h
setup_pending: true
domains:
  - hostname: example.com
    origin:
      scheme: http
      host: 127.0.0.1
      port: "8080"
    waf:
      mode: block
    headers:
      frame_options: DENY
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "out.yaml")
	if err := cfg.Save(dst); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(dst)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Security.HMACSecret != "supersecret" {
		t.Fatalf("hmac not persisted: %q", cfg2.Security.HMACSecret)
	}
	if cfg2.Security.Challenge.TTL.D() != 600*time.Second {
		t.Fatalf("challenge ttl roundtrip mismatch: %v", cfg2.Security.Challenge.TTL.D())
	}
	if cfg2.Log.RotationMaxMB != 128 {
		t.Fatalf("rotation_max_mb mismatch: %d", cfg2.Log.RotationMaxMB)
	}
	if cfg2.Server.ListenHTTPS != ":443" {
		t.Fatalf("server listener mismatch: %q", cfg2.Server.ListenHTTPS)
	}
	if !cfg2.SetupPending {
		t.Fatal("setup_pending roundtrip lost")
	}
	if cfg2.Security.DDOS == nil || !cfg2.Security.DDOS.Enabled || cfg2.Security.DDOS.PerIPRate != 30 {
		t.Fatalf("ddos roundtrip mismatch: %+v", cfg2.Security.DDOS)
	}
	if cfg2.Security.DDOS.DefenseTTL.D() != 60*time.Second {
		t.Fatalf("ddos defense_ttl mismatch: %v", cfg2.Security.DDOS.DefenseTTL.D())
	}
	if cfg2.Security.DDOS.Allowlist[0] != "10.0.0.0/8" {
		t.Fatalf("ddos allowlist mismatch: %v", cfg2.Security.DDOS.Allowlist)
	}
	if cfg2.Security.Headers == nil || !cfg2.Security.Headers.NoSniff || cfg2.Security.Headers.CSP != "default-src 'self'" {
		t.Fatalf("security.headers roundtrip mismatch: %+v", cfg2.Security.Headers)
	}
	if cfg2.Domains[0].Headers == nil || cfg2.Domains[0].Headers.FrameOption != "DENY" {
		t.Fatalf("domain headers roundtrip mismatch: %+v", cfg2.Domains[0].Headers)
	}
}

func TestDurationJSON(t *testing.T) {
	type wrap struct {
		TTL Duration `json:"ttl"`
	}
	in := []byte(`{"ttl":600}`)
	var w wrap
	if err := json.Unmarshal(in, &w); err != nil {
		t.Fatal(err)
	}
	if w.TTL.D() != 600*time.Second {
		t.Fatalf("want 600s, got %v", w.TTL.D())
	}
	in2 := []byte(`{"ttl":"90s"}`)
	var w2 wrap
	if err := json.Unmarshal(in2, &w2); err != nil {
		t.Fatal(err)
	}
	if w2.TTL.D() != 90*time.Second {
		t.Fatalf("want 90s, got %v", w2.TTL.D())
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ttl":600}` {
		t.Fatalf("marshal want seconds int, got %s", b)
	}
}

func TestDDoSValidations(t *testing.T) {
	base := func() *Config {
		c := Default()
		c.SetupPending = true
		return c
	}
	c1 := base()
	c1.Security.DDOS = &DDoSConfig{Enabled: true, PerIPAction: "banana"}
	if err := c1.Validate(); err == nil {
		t.Fatal("expected error for invalid ddos action")
	}
	c2 := base()
	c2.Security.DDOS = &DDoSConfig{Enabled: true, DefenseAction: "block", Allowlist: []string{"not-a-cidr!!"}}
	if err := c2.Validate(); err == nil {
		t.Fatal("expected error for invalid allowlist")
	}
	c3 := base()
	c3.Security.DDOS = &DDoSConfig{Enabled: true, PerIPRate: 10, SiteBurstRPS: 500, Allowlist: []string{"10.0.0.0/8"}}
	if err := c3.Validate(); err != nil {
		t.Fatalf("valid ddos config rejected: %v", err)
	}
	c4 := base()
	c4.Security.Headers = &SecurityHeadersConfig{FrameOption: "ALWAYS"}
	if err := c4.Validate(); err == nil {
		t.Fatal("expected error for invalid frame_options")
	}
}

func TestSetupPendingAllowsEmptyInstaller(t *testing.T) {
	c := Config{Version: "1", SetupPending: true, Security: SecurityConfig{EngineFailMode: FailOpen}, Server: ServerConfig{ListenHTTPS: ":8443"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("setup-pending config should validate: %v", err)
	}
	c.SetupPending = false
	if err := c.Validate(); err == nil {
		t.Fatal("same config must fail once install completes")
	}
}

func TestAdminAllowlistValidation(t *testing.T) {
	base := func() Config {
		tru := true
		c := Config{Version: "1", Server: ServerConfig{ListenHTTPS: ":8443"}}
		c.Security.EngineFailMode = FailOpen
		c.Dashboard = DashboardConfig{Enabled: true, AdminUser: "admin", AdminPassword: "pw", SessionTTL: Duration(3600), MaxEvents: 1000}
		c.Domains = []DomainConfig{{Hostname: "example.com", Origin: OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: "8080"}, Enabled: &tru, WAF: WAFPolicy{Mode: WAFModeBlock}}}
		return c
	}
	empty := base()
	if err := empty.Validate(); err != nil {
		t.Fatalf("valid admin allowlist-free config rejected: %v", err)
	}
	ok := base()
	ok.Dashboard.AdminAllowlist = []string{"10.0.0.0/8", "2001:db8::/32"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid allowlist rejected: %v", err)
	}
	bare := base()
	bare.Dashboard.AdminAllowlist = []string{"203.0.113.10"}
	if err := bare.Validate(); err != nil {
		t.Fatalf("bare IP in allowlist rejected: %v", err)
	}
	bad := base()
	bad.Dashboard.AdminAllowlist = []string{"not-an-ip"}
	c := &bad
	if err := c.Validate(); err == nil {
		t.Fatal("invalid allowlist entry accepted")
	}
}

func TestConsolePathValidation(t *testing.T) {
	base := func() Config {
		tru := true
		c := Config{Version: "1", Server: ServerConfig{ListenHTTPS: ":8443"}}
		c.Security.EngineFailMode = FailOpen
		c.Dashboard = DashboardConfig{Enabled: true, AdminUser: "admin", AdminPassword: "pw", SessionTTL: Duration(3600), MaxEvents: 1000}
		c.Domains = []DomainConfig{{Hostname: "example.com", Origin: OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: "8080"}, Enabled: &tru, WAF: WAFPolicy{Mode: WAFModeBlock}}}
		return c
	}
	for _, path := range []string{"/ops-8x3h", "/secret_panel-2", "", "/ops/x", "/-"} {
		c := base()
		c.Dashboard.ConsolePath = path
		if err := c.Validate(); err != nil {
			t.Fatalf("valid console_path %q rejected: %v", path, err)
		}
	}
	for _, bad := range []string{"ops-no-slash", "/weird space", "/quo\"te", "/"} {
		c := base()
		c.Dashboard.ConsolePath = bad
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid console_path %q accepted", bad)
		}
	}
}


func TestLoadHashesPlaintextAdminPassword(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server: {listen_https: ":8443"}
security: {engine_fail_mode: fail_open}
dashboard: {enabled: true, admin_user: admin, admin_password: plaintextpw, session_ttl: 1h}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !IsBcryptHash(cfg.Dashboard.AdminPassword) {
		t.Fatalf("Load did not hash plaintext admin_password: %q", cfg.Dashboard.AdminPassword)
	}
	if bcrypt.CompareHashAndPassword([]byte(cfg.Dashboard.AdminPassword), []byte("plaintextpw")) != nil {
		t.Fatal("hashed admin_password does not verify against the original plaintext")
	}
}

func TestLoadIsIdempotentAcrossReload(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server: {listen_https: ":8443"}
security: {engine_fail_mode: fail_open}
dashboard: {enabled: true, admin_user: admin, admin_password: plaintextpw, session_ttl: 1h}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`)
	cfg1, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg1.Save(p); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Dashboard.AdminPassword != cfg1.Dashboard.AdminPassword {
		t.Fatalf("admin_password hash changed across Save->Load with no edit:\nfirst:  %q\nsecond: %q",
			cfg1.Dashboard.AdminPassword, cfg2.Dashboard.AdminPassword)
	}
	if err := cfg2.Save(p); err != nil {
		t.Fatal(err)
	}
	cfg3, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg3.Dashboard.AdminPassword != cfg1.Dashboard.AdminPassword {
		t.Fatalf("admin_password hash changed on a second Save->Load round trip")
	}
}

func TestLoadLeavesAlreadyHashedPasswordAlone(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("whatever"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	p := writeTemp(t, `
version: "1"
server: {listen_https: ":8443"}
security: {engine_fail_mode: fail_open}
dashboard: {enabled: true, admin_user: admin, admin_password: "`+string(hash)+`", session_ttl: 1h}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dashboard.AdminPassword != string(hash) {
		t.Fatalf("Load touched an already-bcrypt admin_password:\nwant: %q\ngot:  %q", hash, cfg.Dashboard.AdminPassword)
	}
}

func TestNormalizeAdminPasswordEmptyIsNoop(t *testing.T) {
	c := &Config{}
	if err := c.NormalizeAdminPassword(); err != nil {
		t.Fatal(err)
	}
	if c.Dashboard.AdminPassword != "" {
		t.Fatalf("empty admin_password should stay empty, got %q", c.Dashboard.AdminPassword)
	}
}


func TestUnmaskSecretsRestoresMaskedFieldsOnly(t *testing.T) {
	old := Default()
	old.Security.HMACSecret = "real-hmac"
	old.Dashboard.AdminPassword = "real-pw"
	old.Security.Store.Redis.Password = "real-redis-pw"
	old.Domains[0].Behavior = &BehaviorConfig{Enabled: true, Secret: "real-behavior-secret"}

	const masked = "***MASKED***"
	submitted := Default()
	submitted.Security.HMACSecret = masked
	submitted.Dashboard.AdminPassword = "new-real-password"
	submitted.Security.Store.Redis.Password = masked
	submitted.Domains[0].Behavior = &BehaviorConfig{Enabled: true, Secret: masked}

	touched := UnmaskSecrets(submitted, old)

	if submitted.Security.HMACSecret != "real-hmac" {
		t.Fatalf("masked hmac_secret not restored: %q", submitted.Security.HMACSecret)
	}
	if submitted.Security.Store.Redis.Password != "real-redis-pw" {
		t.Fatalf("masked redis password not restored: %q", submitted.Security.Store.Redis.Password)
	}
	if submitted.Domains[0].Behavior.Secret != "real-behavior-secret" {
		t.Fatalf("masked behavior.secret not restored: %q", submitted.Domains[0].Behavior.Secret)
	}
	if submitted.Dashboard.AdminPassword != "new-real-password" {
		t.Fatalf("UnmaskSecrets touched a field that wasn't masked: %q", submitted.Dashboard.AdminPassword)
	}
	if len(touched) != 3 {
		t.Fatalf("expected 3 restored fields logged, got %d: %v", len(touched), touched)
	}
}


func TestSaveWritesFileMode0600(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server: {listen_https: ":8443"}
security: {engine_fail_mode: fail_open}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode = %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("temp file left behind after Save")
	}
}


func TestValidateRejectsMalformedOrigin(t *testing.T) {
	base := func(host, port string) *Config {
		c := Default()
		c.Domains[0].Origin = OriginConfig{Scheme: "http", Host: host, Port: port}
		return c
	}
	cases := []struct {
		name       string
		host, port string
	}{
		{"non-numeric port", "127.0.0.1", "notaport"},
		{"port zero", "127.0.0.1", "0"},
		{"port out of range", "127.0.0.1", "65536"},
		{"bracketed ipv6 host", "[::1]", "8080"},
		{"host with whitespace", "bad host", "8080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := base(c.host, c.port).Validate(); err == nil {
				t.Fatalf("origin host=%q port=%q should have been rejected", c.host, c.port)
			}
		})
	}
}

func TestValidateAcceptsUnbracketedIPv6Origin(t *testing.T) {
	c := Default()
	c.Domains[0].Origin = OriginConfig{Scheme: "http", Host: "::1", Port: "8080"}
	if err := c.Validate(); err != nil {
		t.Fatalf("unbracketed IPv6 origin host should be accepted: %v", err)
	}
}

func TestSaveNormalizesLooseExistingPermissions(t *testing.T) {
	p := writeTemp(t, `
version: "1"
server: {listen_https: ":8443"}
security: {engine_fail_mode: fail_open}
domains:
  - hostname: example.com
    origin: {scheme: http, host: 127.0.0.1, port: "8080"}
    waf: {mode: block}
`)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pre-existing 0644 config not normalized to 0600 on Save, got %v", info.Mode().Perm())
	}
}
