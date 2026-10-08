package dashboard

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
)

const (
	SessionCookie = "waap_session"
)

type HandlerConfig struct {
	Store     *Store
	Signer    *Signer
	Challenge *ChallengeManager
	Panel             PanelController
	Admin             bool
	AdminUser         string
	AdminPassword     string
	SessionTTL        time.Duration
	DashboardAssetTag string
	AdminAllowlist []netip.Prefix
	ConsolePath string
	RootConsole bool
	SetupPending bool
	ConfigPath string
	Now        func() time.Time
	LoginRateLimitAttempts int
	LoginRateLimitWindow   time.Duration
}

type Handler struct {
	store      *Store
	signer     *Signer
	chlg       *ChallengeManager
	panel      PanelController
	admin      bool
	adminUser  string
	adminPass  string
	cfgPath    string
	sessionTTL time.Duration
	version    string
	setup      bool
	now        func() time.Time
	adminAllow []netip.Prefix
	base       string
	throttle *loginThrottle
}

const (
	loginBruteForceMax    = config.DefaultLoginRateLimitAttempts
	loginBruteForceWindow = config.DefaultLoginRateLimitWindow
)

func NewHandler(c HandlerConfig) *Handler {
	nt := time.Now
	if c.Now != nil {
		nt = c.Now
	}
	ttl := c.SessionTTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	base := strings.TrimRight(c.ConsolePath, "/")
	switch {
	case c.RootConsole:
		base = "/"
	case base == "":
		base = "/-"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	var throttle *loginThrottle
	if c.Admin {
		max := c.LoginRateLimitAttempts
		if max <= 0 {
			max = loginBruteForceMax
		}
		window := c.LoginRateLimitWindow
		if window <= 0 {
			window = loginBruteForceWindow
		}
		throttle = newLoginThrottle(max, window, nt)
	}
	return &Handler{
		store: c.Store, signer: c.Signer, chlg: c.Challenge,
		panel: c.Panel, admin: c.Admin, adminUser: c.AdminUser, adminPass: c.AdminPassword,
		cfgPath: c.ConfigPath, sessionTTL: ttl, version: c.DashboardAssetTag, setup: c.SetupPending, now: nt,
		adminAllow: c.AdminAllowlist, base: base, throttle: throttle,
	}
}

func (h *Handler) Config() *config.Config {
	if h.panel == nil {
		return nil
	}
	return h.panel.Config()
}

func (h *Handler) rel(path string) string {
	if path == h.base {
		return "/"
	}
	base := strings.TrimRight(h.base, "/")
	if base == "" {
		return path
	}
	if strings.HasPrefix(path, base+"/") {
		rel := path[len(base):]
		if rel == "" {
			return "/"
		}
		return rel
	}
	return ""
}

func (h *Handler) sub(p string) string {
	return strings.TrimRight(h.base, "/") + p
}

func (h *Handler) page(s string) string {
	return strings.ReplaceAll(s, "/-/", strings.TrimRight(h.base, "/")+"/")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	rel := h.rel(path)
	if rel != "" && rel != "/health" && !h.allowAdmin(r) {
		http.NotFound(w, r)
		return
	}
	switch {
	case h.setup && rel == "/setup" && r.Method == http.MethodGet:
		h.writeHTML(w, http.StatusOK, h.page(setupHTML))
	case h.setup && rel == "/api/setup" && r.Method == http.MethodPost:
		h.handleSetup(w, r)
	case h.setup && (rel == "/" || rel == "/login" || rel == "/index" || rel == "/index.html"):
		http.Redirect(w, r, h.sub("/setup"), http.StatusFound)
	case rel == "/login":
		h.handleLogin(w, r)
	case rel == "/logout":
		h.handleLogout(w, r)
	case h.admin && (rel == "/" || rel == "/index" || rel == "/index.html"):
		if !h.authed(r) {
			http.Redirect(w, r, h.sub("/login"), http.StatusFound)
			return
		}
		h.writeHTML(w, http.StatusOK, h.page(panelHTML))
	case h.admin && strings.HasPrefix(rel, "/api/"):
		if !h.authed(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h.handleAPI(w, r, rel)
	case path == "/-/health":
		h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": h.version})
	case rel == "/health":
		h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": h.version})
	case path == "/-/challenge" && r.Method == http.MethodGet:
		h.ServeChallengePage(w, r, r.URL.Query().Get("next"))
	case path == "/-/challenge/verify" && r.Method == http.MethodPost:
		h.handleChallengeVerify(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) allowAdmin(r *http.Request) bool {
	if len(h.adminAllow) == 0 {
		return true
	}
	ip := ClientIP(r)
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range h.adminAllow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (h *Handler) authed(r *http.Request) bool {
	ck, err := r.Cookie(SessionCookie)
	if err != nil {
		return false
	}
	ip := ClientIP(r)
	v, ok := h.signer.ValueOk(ck.Value, ip, h.now())
	return ok && v == "admin"
}

func (h *Handler) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: r.TLS != nil,
		MaxAge: int(ttl.Seconds()),
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		if h.admin {
			h.writeHTML(w, http.StatusOK, h.page(loginHTML))
		} else {
			http.NotFound(w, r)
		}
		return
	}
	user, pass := h.creds(r)

	jsonCall := strings.Contains(r.Header.Get("Accept"), "json") ||
		r.Header.Get("X-Requested-With") == "fetch" ||
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")

	ip := ClientIP(r)
	if h.throttle != nil {
		if ok, retryAfter := h.throttle.allow(ip); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			if jsonCall {
				h.writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "invalid credentials"})
			} else {
				h.writeHTML(w, http.StatusTooManyRequests, h.page(loginHTML))
			}
			return
		}
	}

	userOK := user == h.adminUser
	passOK := bcrypt.CompareHashAndPassword([]byte(h.adminPass), []byte(pass)) == nil
	authOK := userOK && passOK

	if !authOK {
		if h.throttle != nil {
			h.throttle.record(ip)
		}
		if jsonCall {
			h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		} else {
			h.writeHTML(w, http.StatusUnauthorized, h.page(loginHTML))
		}
		return
	}
	if h.throttle != nil {
		h.throttle.reset(ip)
	}

	cookie := h.signer.Issue(ClientIP(r), "admin", h.sessionTTL, h.now())
	h.setCookie(w, r, SessionCookie, cookie, h.sessionTTL)

	if jsonCall {
		h.writeJSON(w, http.StatusOK, map[string]string{"ok": "true", "redirect": h.sub("/")})
	} else {
		http.Redirect(w, r, h.sub("/"), http.StatusFound)
	}
}

func (h *Handler) creds(r *http.Request) (string, string) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			return strings.TrimSpace(body.User), body.Password
		}
	}
	return strings.TrimSpace(r.PostFormValue("user")), r.PostFormValue("password")
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, h.sub("/login"), http.StatusFound)
}

func (h *Handler) writeHTML(w http.ResponseWriter, code int, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(html))
}

func (h *Handler) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}


func (h *Handler) ServeChallengePage(w http.ResponseWriter, r *http.Request, next string) {
	if h.chlg == nil {
		http.NotFound(w, r)
		return
	}
	cd, err := h.chlg.Issue(ClientIP(r), pagePath(next))
	if err != nil {
		http.Error(w, "challenge unavailable", http.StatusInternalServerError)
		return
	}
	raw, err := json.Marshal(cd)
	if err != nil {
		http.Error(w, "challenge unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	_ = challengePageTemplate.Execute(w, struct{ Data string }{Data: string(raw)})
}

func (h *Handler) handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if h.chlg == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	cd := ChallengeData{
		Cleartext: r.PostFormValue("cleartext"),
		Signature: r.PostFormValue("signature"),
	}
	nonce := r.PostFormValue("nonce")
	cookie, err := h.chlg.VerifyChallenge(cd, ClientIP(r), nonce, h.now())
	if err != nil {
		h.ServeChallengePage(w, r, pagePath(r.PostFormValue("next")))
		return
	}
	h.setCookie(w, r, ChallengeCookie, cookie, h.chlg.ttl)
	next := pagePath(r.PostFormValue("next"))
	if strings.Contains(r.Header.Get("Accept"), "json") {
		h.writeJSON(w, http.StatusOK, map[string]string{"ok": "true", "next": next})
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}


func (h *Handler) handleAPI(w http.ResponseWriter, r *http.Request, path string) {
	q := r.URL.Query()

	window := func(name string, def time.Duration) time.Duration {
		s := q.Get(name)
		if s == "" {
			return def
		}
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		return def
	}
	since := window("since", 5*time.Minute)

	switch path {
	case "/api/summary":
		h.writeJSON(w, http.StatusOK, SummaryOf(h.store.snapshot(since)))

	case "/api/events":
		limit := 50
		if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
			limit = min(n, 200)
		}
		offset := 0
		if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
			offset = n
		}
		h.writeJSON(w, http.StatusOK, h.store.Recent(limit, offset, q.Get("action"), q.Get("ip"), q.Get("rule"), q.Get("category")))

	case "/api/topips":
		h.writeJSON(w, http.StatusOK, Top(h.store.snapshot(since), func(ev events.Event) string {
			return ev.SourceIP
		}, atoiN(q.Get("n"), 10)))

	case "/api/toppaths":
		h.writeJSON(w, http.StatusOK, Top(h.store.snapshot(since), func(ev events.Event) string {
			return ev.Path
		}, atoiN(q.Get("n"), 10)))

	case "/api/topcountries":
		h.writeJSON(w, http.StatusOK, TopStrict(h.store.snapshot(since), func(ev events.Event) string {
			return ev.Country
		}, atoiN(q.Get("n"), 10)))

	case "/api/toprules":
		h.writeJSON(w, http.StatusOK, TopStrict(h.store.snapshot(since), func(ev events.Event) string {
			return ev.RuleID
		}, atoiN(q.Get("n"), 10)))

	case "/api/topcategories":
		h.writeJSON(w, http.StatusOK, TopStrict(h.store.snapshot(since), func(ev events.Event) string {
			return ev.Category
		}, atoiN(q.Get("n"), 10)))

	case "/api/series":
		bucket := window("bucket", 15*time.Second)
		h.writeJSON(w, http.StatusOK, Series(h.store.snapshot(since), since, bucket, h.now()))

	case "/api/config":
		h.handleConfigAPI(w, r)

	case "/api/restart":
		if h.panel == nil {
			http.NotFound(w, r)
			return
		}
		if err := h.panel.Restart(); err != nil {
			h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]string{"ok": "true", "note": "restarting"})

	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleConfigAPI(w http.ResponseWriter, r *http.Request) {
	if h.panel == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		redacted, err := redactConfig(h.panel.Config())
		if err != nil {
			h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot render config"})
			return
		}
		h.writeJSON(w, http.StatusOK, redacted)
		return
	}
	if r.Method != http.MethodPut {
		h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	nc, err := cloneConfig(h.panel.Config())
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot prepare config"})
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(nc); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config json: " + err.Error()})
		return
	}
	restart, err := h.panel.Apply(nc)
	if err != nil {
		h.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	redacted, err := redactConfig(h.panel.Config())
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot render config"})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"restart_required": restart,
		"config":           redacted,
	})
}

func atoiN(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}
