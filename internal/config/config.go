package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/openwaap/openwaap/internal/logging"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"60s\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.D().String(), nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(int64(d.D().Seconds()))
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var n int64
	if err := json.Unmarshal(b, &n); err == nil {
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be seconds (number) or \"60s\" string: %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type FailMode string

const (
	FailOpen   FailMode = "fail_open"
	FailClosed FailMode = "fail_closed"
)

func (f FailMode) Valid() bool {
	return f == FailOpen || f == FailClosed
}

type Action string

const (
	ActionAllow        Action = "ALLOW"
	ActionBlock        Action = "BLOCK"
	ActionChallenge    Action = "CHALLENGE"
	ActionLog          Action = "LOG"
	ActionRateLimit    Action = "RATE_LIMIT"
	ActionThrottle     Action = "THROTTLE"
	ActionUnauthorized Action = "UNAUTHORIZED"
)

func (a Action) Valid() bool {
	switch a {
	case ActionAllow, ActionBlock, ActionChallenge, ActionLog, ActionRateLimit, ActionThrottle, ActionUnauthorized:
		return true
	}
	return false
}

type Config struct {
	Version   string          `yaml:"version" json:"version"`
	Server    ServerConfig    `yaml:"server" json:"server"`
	Security  SecurityConfig  `yaml:"security" json:"security"`
	Log       LogConfig       `yaml:"log" json:"log"`
	Dashboard DashboardConfig `yaml:"dashboard" json:"dashboard"`
	UI        UIConfig        `yaml:"ui" json:"ui,omitempty"`
	Domains   []DomainConfig  `yaml:"domains" json:"domains"`
	SetupPending bool `yaml:"setup_pending,omitempty" json:"setup_pending,omitempty"`
}

type UIConfig struct {
	Theme string `yaml:"theme" json:"theme"`
	Accent string `yaml:"accent" json:"accent"`
	Density string `yaml:"density" json:"density"`
	TimeRange int `yaml:"time_range" json:"time_range"`
	ChartBucket int `yaml:"chart_bucket" json:"chart_bucket"`
	AutoRefresh *bool `yaml:"auto_refresh" json:"auto_refresh"`
	HiddenPages []string `yaml:"hidden_pages" json:"hidden_pages"`
	PagesOrder []string `yaml:"pages_order" json:"pages_order"`
	Language string `yaml:"language" json:"language"`
}

type LogConfig struct {
	RotationMaxMB int `yaml:"rotation_max_mb" json:"rotation_max_mb"`
	RotationKeep int `yaml:"rotation_keep" json:"rotation_keep"`
}

type ServerConfig struct {
	ListenHTTPS string `yaml:"listen_https" json:"listen_https"`
	ListenHTTP string `yaml:"listen_http" json:"listen_http"`
	TLSCertFile string `yaml:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file" json:"tls_key_file"`
}

type SecurityConfig struct {
	EngineFailMode FailMode `yaml:"engine_fail_mode" json:"engine_fail_mode"`
	HMACSecret string `yaml:"hmac_secret" json:"hmac_secret"`
	Challenge ChallengeConfig `yaml:"challenge" json:"challenge"`
	GeoIP *GeoIPConfig `yaml:"geoip" json:"geoip"`
	SIEM *SIEMConfig `yaml:"siem" json:"siem"`
	Store StoreConfig `yaml:"store" json:"store"`
	DDOS *DDoSConfig `yaml:"ddos" json:"ddos"`
	Headers *SecurityHeadersConfig `yaml:"headers" json:"headers"`
}

type SecurityHeadersConfig struct {
	HSTS bool `yaml:"hsts" json:"hsts"`
	FrameOption string `yaml:"frame_options" json:"frame_options"`
	NoSniff bool `yaml:"no_sniff" json:"no_sniff"`
	CSP string `yaml:"csp" json:"csp"`
	ReferrerPolicy string `yaml:"referrer_policy" json:"referrer_policy"`
}

type DDoSConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	PerIPRate int `yaml:"per_ip_rate" json:"per_ip_rate"`
	PerIPAction string `yaml:"per_ip_action" json:"per_ip_action"`
	SiteBurstRPS int `yaml:"site_burst_rps" json:"site_burst_rps"`
	DefenseAction string `yaml:"defense_action" json:"defense_action"`
	DefenseTTL Duration `yaml:"defense_ttl" json:"defense_ttl"`
	Allowlist []string `yaml:"allowlist" json:"allowlist"`
}

type GeoIPConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	DBPath string `yaml:"db_path" json:"db_path"`
}

type StoreConfig struct {
	Type string `yaml:"type" json:"type"`
	Redis RedisConfig `yaml:"redis" json:"redis"`
}

type RedisConfig struct {
	Address string `yaml:"address" json:"address"`
	Password string `yaml:"password" json:"password"`
	DB       int    `yaml:"db" json:"db"`
	Prefix string `yaml:"prefix" json:"prefix"`
}

type SIEMConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	BatchInterval Duration `yaml:"batch_interval" json:"batch_interval"`
	BatchSize int `yaml:"batch_size" json:"batch_size"`
	MaxBuffer int `yaml:"max_buffer" json:"max_buffer"`
	Endpoints []SIEMEndpoint `yaml:"endpoints" json:"endpoints"`
}

type SIEMEndpoint struct {
	Type string `yaml:"type" json:"type"`
	URL string `yaml:"url" json:"url"`
	Token string `yaml:"token" json:"token"`
	HMACSecret string `yaml:"hmac_secret" json:"hmac_secret"`
	Network string `yaml:"network" json:"network"`
	Address string `yaml:"address" json:"address"`
}

type ChallengeConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Difficulty int `yaml:"difficulty" json:"difficulty"`
	TTL Duration `yaml:"ttl" json:"ttl"`
	ProofTTL Duration `yaml:"proof_ttl" json:"proof_ttl"`
}

type DashboardConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Listen string `yaml:"listen" json:"listen"`
	ConsolePath string `yaml:"console_path" json:"console_path"`
	AdminUser     string `yaml:"admin_user" json:"admin_user"`
	AdminPassword string `yaml:"admin_password" json:"admin_password"`
	SessionTTL Duration `yaml:"session_ttl" json:"session_ttl"`
	MaxEvents int `yaml:"max_events" json:"max_events"`
	AdminAllowlist []string `yaml:"admin_allowlist" json:"admin_allowlist"`
	LoginRateLimitAttempts int      `yaml:"login_rate_limit_attempts" json:"login_rate_limit_attempts"`
	LoginRateLimitWindow   Duration `yaml:"login_rate_limit_window" json:"login_rate_limit_window"`
}

const (
	DefaultLoginRateLimitAttempts = 10
	DefaultLoginRateLimitWindow   = 5 * time.Minute
)

type DomainConfig struct {
	Hostname string `yaml:"hostname" json:"hostname"`
	Origin OriginConfig `yaml:"origin" json:"origin"`
	TLS *TLSDomainConfig `yaml:"tls" json:"tls"`
	WAF WAFPolicy `yaml:"waf" json:"waf"`
	Honeypot *HoneypotConfig `yaml:"honeypot" json:"honeypot"`
	RateLimit *RateLimitConfig `yaml:"rate_limits" json:"rate_limits"`
	Bot *BotConfig `yaml:"bot" json:"bot"`
	Reputation *ReputationConfig `yaml:"reputation" json:"reputation"`
	APISecurity *APISecurityConfig `yaml:"api_security" json:"api_security"`
	Behavior *BehaviorConfig `yaml:"behavior" json:"behavior"`
	Headers *SecurityHeadersConfig `yaml:"headers" json:"headers"`
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

type BehaviorConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	CookieName string `yaml:"cookie_name" json:"cookie_name"`
	Secret string `yaml:"secret" json:"secret"`
	CookieTTL Duration `yaml:"cookie_ttl" json:"cookie_ttl"`
	IdleTTL Duration `yaml:"idle_ttl" json:"idle_ttl"`
	MaxClients int `yaml:"max_clients" json:"max_clients"`
	ChallengeAbove int `yaml:"challenge_above" json:"challenge_above"`
	BlockAbove int `yaml:"block_above" json:"block_above"`
}

type APISecurityConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	JWT *JWTConfig `yaml:"jwt" json:"jwt"`
	Routes []APIRouteConfig `yaml:"routes" json:"routes"`
	Policy APIPolicyConfig `yaml:"policy" json:"policy"`
}

type APIRouteConfig struct {
	Path string `yaml:"path" json:"path"`
	Method string `yaml:"method" json:"method"`
	AuthNone bool `yaml:"auth_none" json:"auth_none"`
	RequestSchema string `yaml:"request_schema" json:"request_schema"`
}

type APIPolicyConfig struct {
	AuthnRequired bool `yaml:"authn_required" json:"authn_required"`
	NoAuthAction Action `yaml:"no_auth_action" json:"no_auth_action"`
	ValidateSchema bool `yaml:"validate_schema" json:"validate_schema"`
	Override *Action `yaml:"override" json:"override"`
}

type JWTConfig struct {
	Algorithm string `yaml:"algorithm" json:"algorithm"`
	Secret string `yaml:"secret" json:"secret"`
	PublicKeyPEM string `yaml:"public_key_pem" json:"public_key_pem"`
	Issuer string `yaml:"issuer" json:"issuer"`
	Audiences []string `yaml:"audiences" json:"audiences"`
	Header string `yaml:"header" json:"header"`
	RequiredClaims []string `yaml:"required_claims" json:"required_claims"`
	LeewaySeconds int `yaml:"leeway_seconds" json:"leeway_seconds"`
}

type OriginConfig struct {
	Scheme string `yaml:"scheme" json:"scheme"`
	Host string `yaml:"host" json:"host"`
	Port string `yaml:"port" json:"port"`
}

func (o OriginConfig) Address() string {
	return net.JoinHostPort(o.Host, o.Port)
}

type TLSDomainConfig struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

type WAFPolicy struct {
	Mode WAFMode `yaml:"mode" json:"mode"`
	Managed ManagedPolicy    `yaml:"managed" json:"managed"`
	Custom  []CustomRuleConf `yaml:"custom_rules" json:"custom_rules"`
}

type WAFMode string

const (
	WAFModeDetection WAFMode = "detection"
	WAFModeBlock     WAFMode = "block"
	WAFModeDisabled  WAFMode = "disabled"
)

func (m WAFMode) Valid() bool {
	switch m {
	case WAFModeDetection, WAFModeBlock, WAFModeDisabled:
		return true
	}
	return false
}

type ManagedPolicy struct {
	RulesetVersion string `yaml:"ruleset_version" json:"ruleset_version"`
	Categories map[string]bool `yaml:"categories" json:"categories"`
	ParanoiaLevel int `yaml:"paranoia_level" json:"paranoia_level"`
}

type CustomRuleConf struct {
	ID      string `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	DSL string `yaml:"dsl" json:"dsl"`
}

type HoneypotConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	Paths        []string `yaml:"paths" json:"paths"`
	AutoGenerate bool     `yaml:"auto_generate" json:"auto_generate"`
	Points int `yaml:"points" json:"points"`
}

type RateLimitConfig struct {
	Enabled bool            `yaml:"enabled" json:"enabled"`
	Limits  []RateLimitRule `yaml:"limits" json:"limits"`
}

type RateLimitScope string

const (
	ScopeIP       RateLimitScope = "ip"
	ScopePath     RateLimitScope = "path"
	ScopeIPPath   RateLimitScope = "ip_path"
	ScopeIPMethod RateLimitScope = "ip_method"
	ScopeHeader   RateLimitScope = "header"
)

func (s RateLimitScope) Valid() bool {
	switch s {
	case ScopeIP, ScopePath, ScopeIPPath, ScopeIPMethod, ScopeHeader:
		return true
	}
	return false
}

type RateLimitRule struct {
	ID          string         `yaml:"id" json:"id"`
	Name        string         `yaml:"name" json:"name"`
	Enabled     bool           `yaml:"enabled" json:"enabled"`
	Scope       RateLimitScope `yaml:"scope" json:"scope"`
	Path        string         `yaml:"path" json:"path"`
	Method      string         `yaml:"method" json:"method"`
	Header      string         `yaml:"header" json:"header"`
	Max         int            `yaml:"max" json:"max"`
	ThrottleMax *int           `yaml:"throttle_max" json:"throttle_max"`
	Window      Duration       `yaml:"window" json:"window"`
	Action      Action         `yaml:"action" json:"action"`
}

func (r RateLimitRule) RetryAfter() int {
	return int(r.Window.D().Seconds())
}

func (r RateLimitRule) Active() bool {
	return r.Enabled && r.Max > 0 && r.Window.D() > 0
}

type BotConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	ChallengeBelow int `yaml:"challenge_below" json:"challenge_below"`
	BlockBelow int `yaml:"block_below" json:"block_below"`
	VerifiedBots []string `yaml:"verified_bots" json:"verified_bots"`
}

type ReputationConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	HoneypotPoints int `yaml:"honeypot_points" json:"honeypot_points"`
	BlockedRequestPoints int `yaml:"blocked_request_points" json:"blocked_request_points"`
	BlockScore int `yaml:"block_score" json:"block_score"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := Default()
	if err := yaml.Unmarshal([]byte(expandEnv(string(data))), cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.NormalizeAdminPassword(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) NormalizeAdminPassword() error {
	if c.Dashboard.AdminPassword == "" || IsBcryptHash(c.Dashboard.AdminPassword) {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(c.Dashboard.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash admin_password: %w", err)
	}
	c.Dashboard.AdminPassword = string(hash)
	return nil
}

func UnmaskSecrets(cfg, old *Config) []string {
	var touched []string
	restore := func(path string, dst *string, src string) {
		if *dst == logging.MaskedValue {
			*dst = src
			touched = append(touched, path)
		}
	}
	restore("security.hmac_secret", &cfg.Security.HMACSecret, old.Security.HMACSecret)
	restore("dashboard.admin_password", &cfg.Dashboard.AdminPassword, old.Dashboard.AdminPassword)
	restore("security.store.redis.password", &cfg.Security.Store.Redis.Password, old.Security.Store.Redis.Password)
	if cfg.Security.SIEM != nil && old.Security.SIEM != nil {
		for i := range cfg.Security.SIEM.Endpoints {
			if i >= len(old.Security.SIEM.Endpoints) {
				break
			}
			restore(fmt.Sprintf("security.siem.endpoints[%d].token", i),
				&cfg.Security.SIEM.Endpoints[i].Token, old.Security.SIEM.Endpoints[i].Token)
			restore(fmt.Sprintf("security.siem.endpoints[%d].hmac_secret", i),
				&cfg.Security.SIEM.Endpoints[i].HMACSecret, old.Security.SIEM.Endpoints[i].HMACSecret)
		}
	}
	for di := range cfg.Domains {
		if di >= len(old.Domains) {
			break
		}
		if cfg.Domains[di].Behavior != nil && old.Domains[di].Behavior != nil {
			restore(fmt.Sprintf("domains[%d].behavior.secret", di),
				&cfg.Domains[di].Behavior.Secret, old.Domains[di].Behavior.Secret)
		}
		if cfg.Domains[di].APISecurity != nil && cfg.Domains[di].APISecurity.JWT != nil &&
			old.Domains[di].APISecurity != nil && old.Domains[di].APISecurity.JWT != nil {
			restore(fmt.Sprintf("domains[%d].api_security.jwt.secret", di),
				&cfg.Domains[di].APISecurity.JWT.Secret, old.Domains[di].APISecurity.JWT.Secret)
		}
	}
	return touched
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnv(in string) string {
	return envRef.ReplaceAllStringFunc(in, func(m string) string {
		name := envRef.FindStringSubmatch(m)[1]
		return os.Getenv(name)
	})
}

func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	out, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm() != 0o600 {
		if chErr := os.Chmod(path, 0o600); chErr != nil {
			return fmt.Errorf("config: normalize permissions on %s: %w", path, chErr)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: replace %s: %w", path, err)
	}
	return nil
}

var bcryptPrefixes = []string{"$2a$", "$2b$", "$2y$"}

func IsBcryptHash(s string) bool {
	for _, p := range bcryptPrefixes {
		if strings.HasPrefix(s, p) {
			return len(s) >= 59
		}
	}
	return false
}

func Default() *Config {
	t := true
	return &Config{
		Version: "1",
		Server: ServerConfig{
			ListenHTTP:  ":80",
			ListenHTTPS: ":443",
		},
		Security: SecurityConfig{
			EngineFailMode: FailOpen,
			Challenge: ChallengeConfig{
				Difficulty: 4,
				TTL:        Duration(10 * time.Minute),
				ProofTTL:   Duration(3 * time.Minute),
			},
		},
		Log: LogConfig{
			RotationKeep: 5,
		},
		Dashboard: DashboardConfig{
			SessionTTL:             Duration(12 * time.Hour),
			MaxEvents:              10000,
			LoginRateLimitAttempts: DefaultLoginRateLimitAttempts,
			LoginRateLimitWindow:   Duration(DefaultLoginRateLimitWindow),
		},
		Domains: []DomainConfig{
			{
				Hostname: "example.com",
				Origin:   OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: "8080"},
				WAF: WAFPolicy{
					Mode: WAFModeBlock,
					Managed: ManagedPolicy{
						RulesetVersion: "1.0.0",
						ParanoiaLevel:  1,
						Categories:     map[string]bool{},
					},
				},
				Enabled: &t,
			},
		},
	}
}

func validateOriginHostPort(host, port string) error {
	if strings.ContainsAny(host, " \t[]") {
		return fmt.Errorf("origin host %q must not contain whitespace or brackets (write an IPv6 address unbracketed, e.g. \"::1\")", host)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("origin port %q is not numeric", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("origin port %d is out of range (1-65535)", n)
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("missing 'version'")
	}
	if !c.Security.EngineFailMode.Valid() {
		return fmt.Errorf("security.engine_fail_mode must be %q or %q", FailOpen, FailClosed)
	}
	if err := c.validateChallenge(); err != nil {
		return err
	}
	if err := c.validateGeoIP(); err != nil {
		return err
	}
	if err := c.validateSIEM(); err != nil {
		return err
	}
	if err := c.validateLog(); err != nil {
		return err
	}
	if err := c.validateStore(); err != nil {
		return err
	}
	if err := c.validateDDOS(); err != nil {
		return err
	}
	if err := c.validateHeaders(); err != nil {
		return err
	}
	if err := c.validateDashboard(); err != nil {
		return err
	}
	if c.Server.ListenHTTPS == "" {
		return fmt.Errorf("server.listen_https is required")
	}
	if len(c.Domains) == 0 {
		if !c.SetupPending {
			return fmt.Errorf("at least one domain is required")
		}
	} else {
		seen := map[string]bool{}
		for i, d := range c.Domains {
			if d.Hostname == "" {
				return fmt.Errorf("domains[%d].hostname is required", i)
			}
			if seen[d.Hostname] {
				return fmt.Errorf("duplicate domain hostname %q", d.Hostname)
			}
			seen[d.Hostname] = true
			if d.Origin.Host == "" || d.Origin.Port == "" || d.Origin.Scheme == "" {
				return fmt.Errorf("domain %q: origin.host/port/scheme are required", d.Hostname)
			}
			if d.Origin.Scheme != "http" && d.Origin.Scheme != "https" {
				return fmt.Errorf("domain %q: origin.scheme must be http or https", d.Hostname)
			}
			if err := validateOriginHostPort(d.Origin.Host, d.Origin.Port); err != nil {
				return fmt.Errorf("domain %q: %w", d.Hostname, err)
			}
			if !d.WAF.Mode.Valid() {
				return fmt.Errorf("domain %q: waf.mode must be one of %q", d.Hostname, []WAFMode{WAFModeDetection, WAFModeBlock, WAFModeDisabled})
			}
			if d.Honeypot != nil && d.Honeypot.Points != 0 && (d.Honeypot.Points < 1 || d.Honeypot.Points > 99) {
				return fmt.Errorf("domain %q: honeypot.points must be between 1 and 99 (0/unset uses the default)", d.Hostname)
			}
			if d.TLS != nil && (d.TLS.CertFile != "" || d.TLS.KeyFile != "") {
				if d.TLS.CertFile == "" || d.TLS.KeyFile == "" {
					return fmt.Errorf("domain %q: tls requires cert_file and key_file", d.Hostname)
				}
			}
			if err := d.validateRateLimits(); err != nil {
				return err
			}
			if err := d.validateBot(); err != nil {
				return err
			}
			if err := d.validateReputation(); err != nil {
				return err
			}
			if err := d.validateAPISecurity(); err != nil {
				return err
			}
			if err := d.validateBehavior(); err != nil {
				return err
			}
			if err := validateHeadersConfig(fmt.Sprintf("domain %q: headers", d.Hostname), d.Headers); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) validateChallenge() error {
	ch := c.Security.Challenge
	if !ch.Enabled {
		return nil
	}
	if ch.Difficulty <= 0 {
		return fmt.Errorf("security.challenge.difficulty must be > 0")
	}
	if ch.TTL.D() <= 0 {
		return fmt.Errorf("security.challenge.ttl must be a positive duration")
	}
	if ch.ProofTTL.D() <= 0 {
		return fmt.Errorf("security.challenge.proof_ttl must be a positive duration")
	}
	return nil
}

func (c *Config) validateGeoIP() error {
	geo := c.Security.GeoIP
	if geo == nil || !geo.Enabled {
		return nil
	}
	if geo.DBPath == "" {
		return fmt.Errorf("security.geoip.db_path is required when geoip is enabled")
	}
	return nil
}

func (c *Config) validateSIEM() error {
	s := c.Security.SIEM
	if s == nil || !s.Enabled {
		return nil
	}
	if len(s.Endpoints) == 0 {
		return fmt.Errorf("security.siem.endpoints must be non-empty when siem is enabled")
	}
	for i, e := range s.Endpoints {
		where := fmt.Sprintf("security.siem.endpoints[%d]", i)
		switch e.Type {
		case "http":
			if e.URL == "" {
				return fmt.Errorf("%s: url is required for http type", where)
			}
		case "syslog":
			if e.Network != "udp" && e.Network != "tcp" {
				return fmt.Errorf("%s: syslog network must be udp or tcp", where)
			}
			if e.Address == "" {
				return fmt.Errorf("%s: address is required for syslog type", where)
			}
		default:
			return fmt.Errorf("%s: type must be http or syslog", where)
		}
	}
	if s.BatchInterval.D() < 0 || s.BatchSize < 0 || s.MaxBuffer < 0 {
		return fmt.Errorf("security.siem batch_interval/batch_size/max_buffer must not be negative")
	}
	return nil
}

func (c *Config) validateLog() error {
	l := c.Log
	if l.RotationMaxMB < 0 {
		return fmt.Errorf("log.rotation_max_mb must not be negative")
	}
	if l.RotationKeep < 0 {
		return fmt.Errorf("log.rotation_keep must not be negative")
	}
	return nil
}

func (c *Config) validateStore() error {
	st := c.Security.Store
	if st.Type == "" {
		return nil
	}
	if st.Type != "memory" && st.Type != "redis" {
		return fmt.Errorf("security.store.type must be memory or redis")
	}
	if st.Type == "redis" {
		if st.Redis.Address == "" {
			return fmt.Errorf("security.store.redis.address is required when store.type is redis")
		}
		if st.Redis.DB < 0 {
			return fmt.Errorf("security.store.redis.db must not be negative")
		}
	}
	return nil
}

func (c *Config) validateDDOS() error {
	d := c.Security.DDOS
	if d == nil {
		return nil
	}
	where := "security.ddos"
	if !d.Enabled {
		return nil
	}
	if d.PerIPRate < 0 {
		return fmt.Errorf("%s.per_ip_rate must not be negative", where)
	}
	if d.SiteBurstRPS < 0 {
		return fmt.Errorf("%s.site_burst_rps must not be negative", where)
	}
	if d.DefenseTTL.D() < 0 {
		return fmt.Errorf("%s.defense_ttl must not be negative", where)
	}
	if d.PerIPAction != "" && d.PerIPAction != "challenge" && d.PerIPAction != "block" {
		return fmt.Errorf("%s.per_ip_action must be %q or %q", where, "challenge", "block")
	}
	if d.DefenseAction != "" && d.DefenseAction != "challenge" && d.DefenseAction != "block" {
		return fmt.Errorf("%s.defense_action must be %q or %q", where, "challenge", "block")
	}
	for _, raw := range d.Allowlist {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, err := netip.ParsePrefix(raw); err != nil {
			if _, aerr := netip.ParseAddr(raw); aerr != nil {
				return fmt.Errorf("%s: invalid allowlist %q: %w", where, raw, err)
			}
		}
	}
	return nil
}

func (c *Config) validateHeaders() error {
	return validateHeadersConfig("security.headers", c.Security.Headers)
}

func validateHeadersConfig(where string, h *SecurityHeadersConfig) error {
	if h == nil {
		return nil
	}
	switch h.FrameOption {
	case "", "DENY", "SAMEORIGIN":
	default:
		return fmt.Errorf("%s.frame_options must be %q, %q or empty", where, "DENY", "SAMEORIGIN")
	}
	return nil
}

func (c *Config) validateDashboard() error {
	d := c.Dashboard
	if !d.Enabled {
		return nil
	}
	if d.AdminUser == "" {
		if c.SetupPending {
			return nil
		}
		return fmt.Errorf("dashboard.admin_user is required when dashboard is enabled")
	}
	if d.AdminPassword == "" {
		if c.SetupPending {
			return nil
		}
		return fmt.Errorf("dashboard.admin_password is required when dashboard is enabled (reference an env var: ${WAAP_ADMIN_PASSWORD})")
	}
	if d.SessionTTL.D() <= 0 {
		return fmt.Errorf("dashboard.session_ttl must be a positive duration")
	}
	if p := strings.TrimSpace(d.ConsolePath); p != "" {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("dashboard.console_path must start with \"/\"")
		}
		if p == "/" {
			return fmt.Errorf("dashboard.console_path must not be \"/\" (it would shadow every proxied site)")
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '-' || c == '_') {
				return fmt.Errorf("dashboard.console_path may only contain letters, digits, \"/\", \"-\" and \"_\"")
			}
		}
	}
	for _, raw := range d.AdminAllowlist {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, err := netip.ParsePrefix(raw); err != nil {
			if _, aerr := netip.ParseAddr(raw); aerr != nil {
				return fmt.Errorf("dashboard.admin_allowlist: invalid entry %q: %w", raw, err)
			}
		}
	}
	return nil
}

func (d DomainConfig) validateRateLimits() error {
	if d.RateLimit == nil {
		return nil
	}
	if !d.RateLimit.Enabled {
		return nil
	}
	seen := map[string]bool{}
	for i, r := range d.RateLimit.Limits {
		where := fmt.Sprintf("domain %q: rate_limits.limits[%d]", d.Hostname, i)
		if r.ID == "" {
			return fmt.Errorf("%s: id is required", where)
		}
		if seen[r.ID] {
			return fmt.Errorf("domain %q: duplicate rate limit id %q", d.Hostname, r.ID)
		}
		seen[r.ID] = true
		if !r.Scope.Valid() {
			return fmt.Errorf("%s: scope must be one of %q", where, []RateLimitScope{ScopeIP, ScopePath, ScopeIPPath, ScopeIPMethod, ScopeHeader})
		}
		if r.Scope == ScopeIPMethod && r.Method == "" {
			return fmt.Errorf("%s: scope ip_method requires method", where)
		}
		if r.Scope == ScopeHeader && r.Header == "" {
			return fmt.Errorf("%s: scope header requires header", where)
		}
		if r.Max <= 0 {
			return fmt.Errorf("%s: max must be > 0", where)
		}
		if r.Window.D() <= 0 {
			return fmt.Errorf("%s: window must be a positive duration", where)
		}
		if !r.Action.Valid() {
			return fmt.Errorf("%s: invalid action %q", where, r.Action)
		}
		if r.ThrottleMax != nil {
			if *r.ThrottleMax <= r.Max {
				return fmt.Errorf("%s: throttle_max must be greater than max", where)
			}
		}
	}
	return nil
}

func (d DomainConfig) validateBot() error {
	if d.Bot == nil || !d.Bot.Enabled {
		return nil
	}
	if d.Bot.ChallengeBelow < 0 {
		return fmt.Errorf("domain %q: bot.challenge_below must be >= 0", d.Hostname)
	}
	if d.Bot.BlockBelow < 0 {
		return fmt.Errorf("domain %q: bot.block_below must be >= 0", d.Hostname)
	}
	if d.Bot.BlockBelow >= d.Bot.ChallengeBelow {
		return fmt.Errorf("domain %q: bot.block_below must be lower than challenge_below (lower score = more bot-like)", d.Hostname)
	}
	return nil
}

func (d DomainConfig) validateReputation() error {
	if d.Reputation == nil || !d.Reputation.Enabled {
		return nil
	}
	r := d.Reputation
	if r.BlockScore <= 0 {
		return fmt.Errorf("domain %q: reputation.block_score must be > 0", d.Hostname)
	}
	if r.HoneypotPoints <= 0 {
		return fmt.Errorf("domain %q: reputation.honeypot_points must be > 0", d.Hostname)
	}
	if r.BlockedRequestPoints <= 0 {
		return fmt.Errorf("domain %q: reputation.blocked_request_points must be > 0", d.Hostname)
	}
	return nil
}

func (d DomainConfig) validateBehavior() error {
	b := d.Behavior
	if b == nil || !b.Enabled {
		return nil
	}
	if b.CookieTTL.D() < 0 || b.IdleTTL.D() < 0 {
		return fmt.Errorf("domain %q: behavior.cookie_ttl and behavior.idle_ttl must not be negative", d.Hostname)
	}
	if b.MaxClients < 0 {
		return fmt.Errorf("domain %q: behavior.max_clients must not be negative", d.Hostname)
	}
	ch, blk := b.ChallengeAbove, b.BlockAbove
	if ch < 0 || ch > 100 || blk < 0 || blk > 100 {
		return fmt.Errorf("domain %q: behavior challenge_above/block_above must be within 0-100", d.Hostname)
	}
	if ch > 0 && blk > 0 && ch >= blk {
		return fmt.Errorf("domain %q: behavior.block_above must be above challenge_above", d.Hostname)
	}
	return nil
}

func (d DomainConfig) validateAPISecurity() error {
	a := d.APISecurity
	if a == nil || !a.Enabled {
		return nil
	}
	if a.JWT != nil {
		j := a.JWT
		switch j.Algorithm {
		case "HS256":
			if j.Secret == "" {
				return fmt.Errorf("domain %q: api_security.jwt.secret is required for HS256 (reference an env var: ${JWT_SECRET})", d.Hostname)
			}
		case "RS256":
			if j.PublicKeyPEM == "" {
				return fmt.Errorf("domain %q: api_security.jwt.public_key_pem is required for RS256", d.Hostname)
			}
		case "":
			return fmt.Errorf("domain %q: api_security.jwt.algorithm must be HS256 or RS256", d.Hostname)
		default:
			return fmt.Errorf("domain %q: api_security.jwt.algorithm %q unsupported (HS256, RS256)", d.Hostname, j.Algorithm)
		}
	}
	if a.Policy.NoAuthAction != "" && !a.Policy.NoAuthAction.Valid() {
		return fmt.Errorf("domain %q: api_security.policy.no_auth_action must be a valid action", d.Hostname)
	}
	if a.Policy.Override != nil && !a.Policy.Override.Valid() {
		return fmt.Errorf("domain %q: api_security.policy.override must be a valid action", d.Hostname)
	}
	return nil
}

func (d DomainConfig) EnabledBool() bool {
	if d.Enabled == nil {
		return true
	}
	return *d.Enabled
}
