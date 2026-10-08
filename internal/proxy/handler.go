package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openwaap/openwaap/internal/apisec"
	"github.com/openwaap/openwaap/internal/behavior"
	"github.com/openwaap/openwaap/internal/bot"
	"github.com/openwaap/openwaap/internal/config"
	reqctx "github.com/openwaap/openwaap/internal/context"
	"github.com/openwaap/openwaap/internal/ddos"
	"github.com/openwaap/openwaap/internal/decision"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/geo"
	"github.com/openwaap/openwaap/internal/honeypot"
	"github.com/openwaap/openwaap/internal/metrics"
	"github.com/openwaap/openwaap/internal/pipeline"
	"github.com/openwaap/openwaap/internal/ratelimit"
	"github.com/openwaap/openwaap/internal/reputation"
	custom "github.com/openwaap/openwaap/internal/rules/custom"
	"github.com/openwaap/openwaap/internal/rules/managed"
)

type Handler struct {
	mu sync.RWMutex
	domains map[string]*domainRoute
	defaultRuleset *managed.Ruleset
	internal       http.Handler
	ChallengePage func(w http.ResponseWriter, r *http.Request)
	ChallengePassed func(c *reqctx.RequestContext) bool
	log             *slog.Logger
	emit            *events.Emitter
	geo             *geo.Provider
	metrics         *metrics.Edge
	rateBackend     ratelimit.Backend
	originTimeout   time.Duration
	dashPath string
}

type domainRoute struct {
	hostname string
	proc     *pipeline.Processor
	proxy    *httputil.ReverseProxy
	enabled  bool
	headers []headerKV
}

type headerKV struct{ k, v string }

type Options struct {
	Logger *slog.Logger
	Emit   *events.Emitter
	OriginTimeout time.Duration
	Internal http.Handler
	DashPath string
	ChallengePage func(w http.ResponseWriter, r *http.Request)
	ChallengePassed func(c *reqctx.RequestContext) bool
	Geo *geo.Provider
	RateLimitBackend ratelimit.Backend
	Metrics *metrics.Edge
}

func New(cfg *config.Config, opts Options) (*Handler, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	defaultRuleset, err := managed.LoadDefault()
	if err != nil {
		return nil, fmt.Errorf("proxy: load default managed ruleset: %w", err)
	}

	h := &Handler{
		domains:         map[string]*domainRoute{},
		defaultRuleset:  defaultRuleset,
		internal:        opts.Internal,
		ChallengePage:   opts.ChallengePage,
		ChallengePassed: opts.ChallengePassed,
		log:             log,
		emit:            opts.Emit,
		geo:             opts.Geo,
		metrics:         opts.Metrics,
		rateBackend:     opts.RateLimitBackend,
		originTimeout:   opts.OriginTimeout,
		dashPath:        strings.TrimRight(opts.DashPath, "/"),
	}

	if err := h.buildDomains(cfg); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Handler) Reload(cfg *config.Config) error {
	newDomains, err := h.buildRoutes(cfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.domains = newDomains
	h.mu.Unlock()
	h.log.Info("edge configuration reloaded", "domains", len(newDomains))
	return nil
}

func (h *Handler) buildDomains(cfg *config.Config) error {
	routes, err := h.buildRoutes(cfg)
	if err != nil {
		return err
	}
	h.domains = routes
	return nil
}

func (h *Handler) buildRoutes(cfg *config.Config) (map[string]*domainRoute, error) {
	routes := map[string]*domainRoute{}

	var guard *ddos.Shield
	if cfg.Security.DDOS != nil && cfg.Security.DDOS.Enabled {
		var err error
		if guard, err = ddos.New(*cfg.Security.DDOS); err != nil {
			return nil, fmt.Errorf("ddos: %w", err)
		}
	}

	var err error
	for _, dc := range cfg.Domains {
		if !dc.EnabledBool() {
			continue
		}
		activeCat := map[string]bool{}
		if len(dc.WAF.Managed.Categories) == 0 {
			activeCat = allCategoriesEnabled()
		} else {
			activeCat = dc.WAF.Managed.Categories
		}
		rs := h.defaultRuleset.FilterCategories(activeCat)
		if v := dc.WAF.Managed.RulesetVersion; v != "" && v != h.defaultRuleset.Version {
			h.log.Warn("domain's configured waf.managed.ruleset_version does not match the embedded ruleset actually in use",
				"domain", dc.Hostname, "configured", v, "embedded", h.defaultRuleset.Version)
		}
		paranoia := dc.WAF.Managed.ParanoiaLevel
		if paranoia == 0 {
			paranoia = 1
		}

		var customRules []*custom.Rule
		for _, cr := range dc.WAF.Custom {
			if cr.Enabled && cr.DSL != "" {
				r, err := custom.Parse(cr.ID, cr.Name, cr.DSL)
				if err != nil {
					h.log.Error("invalid custom rule skipped", "domain", dc.Hostname, "rule", cr.ID, "err", err)
					continue
				}
				customRules = append(customRules, r)
			}
		}

		wafEnabled := dc.WAF.Mode == config.WAFModeBlock
		failOpen := cfg.Security.EngineFailMode == config.FailOpen

		var hp *honeypot.Registry
		if dc.Honeypot != nil && dc.Honeypot.Enabled {
			hp = honeypot.NewRegistry(dc.Honeypot.Paths, dc.Honeypot.AutoGenerate, dc.Honeypot.Points)
		}

		var rl *ratelimit.Engine
		if dc.RateLimit != nil && dc.RateLimit.Enabled {
			rl = ratelimit.NewWithBackend(dc.RateLimit.Limits, nil, h.rateBackend)
			if h.metrics != nil {
				rl.SetDegradedCounter(
					h.metrics.Registry().Counter("waap_ratelimit_backend_degraded_total",
						"Rate-limit Observe calls that fell back to in-memory counting because the distributed backend failed, by domain.", "domain"),
					dc.Hostname,
				)
			}
		}

		var det *bot.Detector
		if dc.Bot != nil && dc.Bot.Enabled {
			det = bot.New(dc.Bot.VerifiedBots, nil)
		}

		var rep *reputation.Store
		if dc.Reputation != nil && dc.Reputation.Enabled {
			rep = reputation.New(nil)
		}

		var apiEngine *apisec.Engine
		if dc.APISecurity != nil {
			if apiEngine, err = apisec.NewEngine(dc.APISecurity, time.Now); err != nil {
				return nil, fmt.Errorf("domain %q: api_security: %w", dc.Hostname, err)
			}
		}

		var behaviorEngine *behavior.Engine
		if dc.Behavior != nil {
			if behaviorEngine, err = behavior.New(dc.Behavior); err != nil {
				return nil, fmt.Errorf("domain %q: behavior: %w", dc.Hostname, err)
			}
		}

		procCfg := pipeline.Config{
			Ruleset:            rs,
			CustomRules:        customRules,
			FailOpen:           failOpen,
			WAFEnabled:         wafEnabled,
			ManagedMaxParanoia: paranoia,
			RateLimit:          rl,
			BotDetector:        det,
			RepBlockScore:      repScore(dc),
			RepHoneypotPoints:  repPoints(dc, repHoneypot),
			RepBlockedPoints:   repPoints(dc, repBlocked),
			ChallengePassed:    h.ChallengePassed,
			APISecEngine:       apiEngine,
			Behavior:           behaviorEngine,
			DDoS:               guard,
		}
		if det != nil {
			procCfg.BotChallengeBelow = dc.Bot.ChallengeBelow
			procCfg.BotBlockBelow = dc.Bot.BlockBelow
		}
		if rep != nil {
			procCfg.Reputation = rep
		}
		if hp != nil {
			procCfg.Honeypot = hp
		}
		proc := pipeline.New(procCfg, h.emit, h.log)

		originProxy, err := newOriginProxy(dc.Origin, h.originTimeout)
		if err != nil {
			return nil, fmt.Errorf("domain %q: origin %q: %w", dc.Hostname, dc.Origin.Address(), err)
		}
		route := &domainRoute{
			hostname: dc.Hostname,
			proc:     proc,
			enabled:  dc.EnabledBool(),
			proxy:    originProxy,
			headers:  headersForDomain(cfg.Security.Headers, dc.Headers),
		}
		routes[dc.Hostname] = route
	}
	return routes, nil
}

func allCategoriesEnabled() map[string]bool {
	return map[string]bool{
		string(managed.CatSQLi):          true,
		string(managed.CatXSS):           true,
		string(managed.CatRCE):           true,
		string(managed.CatLFI):           true,
		string(managed.CatPathTraversal): true,
	}
}

func headersForDomain(global, dom *config.SecurityHeadersConfig) []headerKV {
	h := config.SecurityHeadersConfig{}
	if global != nil {
		h = *global
	}
	if dom != nil {
		if dom.HSTS {
			h.HSTS = true
		}
		if dom.FrameOption != "" {
			h.FrameOption = dom.FrameOption
		}
		if dom.NoSniff {
			h.NoSniff = true
		}
		if dom.CSP != "" {
			h.CSP = dom.CSP
		}
		if dom.ReferrerPolicy != "" {
			h.ReferrerPolicy = dom.ReferrerPolicy
		}
	}
	var out []headerKV
	if h.HSTS {
		out = append(out, headerKV{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"})
	}
	if h.FrameOption != "" {
		out = append(out, headerKV{"X-Frame-Options", h.FrameOption})
	}
	if h.NoSniff {
		out = append(out, headerKV{"X-Content-Type-Options", "nosniff"})
	}
	if h.CSP != "" {
		out = append(out, headerKV{"Content-Security-Policy", h.CSP})
	}
	if h.ReferrerPolicy != "" {
		out = append(out, headerKV{"Referrer-Policy", h.ReferrerPolicy})
	}
	return out
}

type repKind int

const (
	repHoneypot repKind = iota
	repBlocked
)

func repScore(dc config.DomainConfig) int {
	if dc.Reputation != nil && dc.Reputation.BlockScore > 0 {
		return dc.Reputation.BlockScore
	}
	return 60
}

func repPoints(dc config.DomainConfig, kind repKind) int {
	if dc.Reputation == nil {
		if kind == repHoneypot {
			return 50
		}
		return 25
	}
	if kind == repHoneypot && dc.Reputation.HoneypotPoints > 0 {
		return dc.Reputation.HoneypotPoints
	}
	if kind == repBlocked && dc.Reputation.BlockedRequestPoints > 0 {
		return dc.Reputation.BlockedRequestPoints
	}
	return 25
}

func newOriginProxy(origin config.OriginConfig, timeout time.Duration) (*httputil.ReverseProxy, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	target, err := url.Parse(origin.Scheme + "://" + origin.Address())
	if err != nil {
		return nil, fmt.Errorf("parse origin url: %w", err)
	}
	host := target.Hostname()
	if target.Host == "" || host == "" {
		return nil, fmt.Errorf("origin host %q is empty or invalid", origin.Host)
	}
	if strings.ContainsAny(host, " \t[]") {
		return nil, fmt.Errorf("origin host %q is not a valid hostname", origin.Host)
	}
	portStr := target.Port()
	if portStr == "" {
		return nil, fmt.Errorf("origin port %q is missing or not numeric", origin.Port)
	}
	if port, perr := strconv.Atoi(portStr); perr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("origin port %q is not a valid port number", origin.Port)
	}
	rev := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			ResponseHeaderTimeout: timeout,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Default().Error("origin proxy error", "host", r.Host, "path", r.URL.Path, "err", err)
			http.Error(w, "origin unavailable", http.StatusBadGateway)
		},
	}
	return rev, nil
}

func (h *Handler) isInternalPath(path string) bool {
	if strings.HasPrefix(path, "/-/") {
		return true
	}
	dp := h.dashPath
	if dp == "" || dp == "/-" {
		return false
	}
	return path == dp || strings.HasPrefix(path, dp+"/")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tw := &trackingWriter{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()

	if h.internal != nil && h.isInternalPath(r.URL.Path) {
		h.internal.ServeHTTP(tw, r)
		tw.flushStatus()
		h.accessLog(tw.status, r, time.Since(start), "internal")
		return
	}

	if h.metrics != nil {
		h.metrics.Active.Add(1)
	}

	host := hostname(r.Host)
	h.mu.RLock()
	route := h.domains[host]
	h.mu.RUnlock()
	if route == nil || !route.enabled {
		tw.status = http.StatusNotFound
		tw.WriteHeader(http.StatusNotFound)
		if h.metrics != nil {
			h.metrics.Active.Add(-1)
		}
		h.accessLog(tw.status, r, time.Since(start), actionLabel("NOT_FOUND"))
		return
	}

	requestID := uuid.NewString()
	w.Header().Set("X-WAAP-Request-Id", requestID)

	tw.hdrs = route.headers

	c := reqctx.New(r, requestID)
	c.Domain = route.hostname

	if h.geo != nil {
		info := h.geo.Lookup(c.RemoteIP)
		c.Country = info.Country
		c.ASN = int(info.ASN)
	}

	var bodyPayload []byte
	bodyReader := func() ([]byte, error) {
		if bodyPayload != nil {
			return bodyPayload, nil
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			return nil, err
		}
		bodyPayload = b
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return b, nil
	}

	res := route.proc.Inspect(c, bodyReader)

	if res.FingerprintCookie != nil {
		http.SetCookie(tw, res.FingerprintCookie)
	}

	if res.Decision == decision.Log {
		res.Denied = false
	}
	if !res.Denied {
		route.proxy.ServeHTTP(tw, r)
	} else {
		h.writeDenied(tw, r, c, res)
	}
	tw.flushStatus()

	if res.Event != nil {
		res.Event.StatusCode = tw.status
		if h.emit != nil {
			h.emit.Emit(*res.Event)
		}
	}

	if h.metrics != nil {
		label := actionLabel(string(res.Decision))
		h.metrics.RequestsTotal.Incr(label)
		if res.Denied {
			h.metrics.RequestsDenied.Incr(label, route.hostname)
			for id := range h.ruleIDsFor(res) {
				h.metrics.RuleTriggers.Incr(id)
			}
		}
		h.metrics.Latency.Observe(time.Since(start).Seconds())
		h.metrics.Active.Add(-1)
	}
	h.accessLog(tw.status, r, time.Since(start), string(res.Decision))
}

func (h *Handler) writeDenied(w http.ResponseWriter, r *http.Request, c *reqctx.RequestContext, res pipeline.Result) {
	switch res.Decision {
	case decision.Block:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintln(w, "403 Forbidden — request blocked by security policy")
	case decision.Unauthorized:
		w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintln(w, "401 Unauthorized — a valid API token is required")
	case decision.Challenge:
		if h.ChallengePage != nil {
			h.ChallengePage(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooEarly)
		_, _ = fmt.Fprintln(w, "Request challenged — please verify you are human")
	case decision.RateLimit, decision.Throttle:
		if res.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(res.RetryAfter))
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprintln(w, "429 Too Many Requests — rate limit exceeded")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

type trackingWriter struct {
	http.ResponseWriter
	status  int
	flushed bool
	hdrs []headerKV
}

func (t *trackingWriter) WriteHeader(code int) {
	if t.flushed {
		return
	}
	t.applyHeaders()
	t.status = code
}

func (t *trackingWriter) Write(b []byte) (int, error) {
	if !t.flushed {
		t.applyHeaders()
		t.flushed = true
		t.ResponseWriter.WriteHeader(t.status)
	}
	return t.ResponseWriter.Write(b)
}

func (t *trackingWriter) flushStatus() {
	if t.flushed {
		return
	}
	t.applyHeaders()
	t.flushed = true
	t.ResponseWriter.WriteHeader(t.status)
}

func (t *trackingWriter) applyHeaders() {
	if len(t.hdrs) == 0 {
		return
	}
	for _, h := range t.hdrs {
		t.Header().Set(h.k, h.v)
	}
}

func (t *trackingWriter) Flush() {
	t.flushStatus()
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *Handler) accessLog(status int, r *http.Request, d time.Duration, action string) {
	if h.log == nil {
		return
	}
	h.log.Info("access",
		"method", r.Method,
		"host", hostname(r.Host),
		"path", r.URL.Path,
		"status", status,
		"duration_ms", d.Milliseconds(),
		"action", action,
		"remote", r.RemoteAddr,
	)
}

func actionLabel(decision string) string {
	switch decision {
	case "ALLOW":
		return "ALLOW"
	case "BLOCK":
		return "BLOCK"
	case "CHALLENGE":
		return "CHALLENGE"
	case "RATE_LIMIT":
		return "RATE_LIMIT"
	case "THROTTLE":
		return "THROTTLE"
	case "UNAUTHORIZED":
		return "UNAUTHORIZED"
	case "LOG":
		return "LOG"
	case "NOT_FOUND":
		return "NOT_FOUND"
	default:
		return "UNKNOWN"
	}
}

func (h *Handler) ruleIDsFor(res pipeline.Result) map[string]struct{} {
	ids := map[string]struct{}{}
	for _, r := range res.Reasons {
		if r.RuleID != "" {
			ids[r.RuleID] = struct{}{}
		}
	}
	return ids
}

func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func TLSCertProvider(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &serverCert, nil
		},
	}
}
