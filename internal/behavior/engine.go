package behavior

import (
	"net/http"
	"strings"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	reqctx "github.com/openwaap/openwaap/internal/context"
)

const (
	DefaultCookieTTL      = 24 * time.Hour
	DefaultMaxClients     = 10000
	DefaultChallengeAbove = 60
	DefaultBlockAbove     = 85
	DefaultIdleTTL        = 2 * time.Hour
)

type Engine struct {
	cp             *Fingerprinter
	store          *Store
	cookieName     string
	cookieTTL      time.Duration
	challengeAbove int
	blockAbove     int
}

func New(cfg *config.BehaviorConfig) (*Engine, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	cookie := cfg.CookieName
	if cookie == "" {
		cookie = CookieName
	}
	ttl := cfg.CookieTTL.D()
	if ttl <= 0 {
		ttl = DefaultCookieTTL
	}
	idle := cfg.IdleTTL.D()
	if idle <= 0 {
		idle = DefaultIdleTTL
	}
	max := cfg.MaxClients
	if max <= 0 {
		max = DefaultMaxClients
	}
	ch := cfg.ChallengeAbove
	if ch <= 0 {
		ch = DefaultChallengeAbove
	}
	blk := cfg.BlockAbove
	if blk <= 0 {
		blk = DefaultBlockAbove
	}
	fp, err := NewFingerprinter(cfg.Secret, ttl)
	if err != nil {
		return nil, err
	}
	return &Engine{
		cp:             fp,
		store:          NewStore(idle, max),
		cookieName:     cookie,
		cookieTTL:      ttl,
		challengeAbove: ch,
		blockAbove:     blk,
	}, nil
}

func (e *Engine) CookieTTL() time.Duration { return e.cookieTTL }

type Result struct {
	Score int
	Action config.Action
	Label string
	NewClient bool
	Cookie string
	ClientID string
}

var assetSuffixes = []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".ico", ".woff", ".woff2", ".ttf", ".webp", ".avif", ".webmanifest", ".json", ".xml", ".map"}

func isDocumentRequest(path, accept, xrw, method string) bool {
	low := strings.ToLower(path)
	for _, s := range assetSuffixes {
		if strings.HasSuffix(low, s) {
			return false
		}
	}
	if xrw != "" {
		return false
	}
	if strings.Contains(strings.ToLower(accept), "text/html") ||
		strings.Contains(strings.ToLower(accept), "xhtml+xml") {
		return true
	}
	return method == http.MethodGet && strings.Contains(strings.ToLower(accept), "text/html")
}

func (e *Engine) Inspect(c *reqctx.RequestContext, cookie string, verifiedUA bool, now time.Time) Result {
	if verifiedUA {
		return Result{Score: 0, Action: config.ActionAllow, Label: "verified_bot"}
	}

	ip := c.RemoteIP.String()
	validCookie := false
	key := "ip:" + ip
	if cookie != "" {
		if id, ok := e.cp.Validate(cookie, ip, now); ok {
			validCookie = true
			key = "fp:" + id
			if e.store.get(key) == nil {
				e.store.adopt("ip:"+ip, key)
			}
		}
	}

	st := e.store.touch(key, now)
	st.requests++
	if st.revoked {
		return Result{Score: 100, Action: config.ActionBlock, Label: "revoked", ClientID: key}
	}

	ua := c.UA
	accept := c.Headers.Get("Accept")
	lang := c.Headers.Get("Accept-Language")
	xrw := c.Headers.Get("X-Requested-With")
	isDoc := isDocumentRequest(c.Path, accept, xrw, c.Method)

	if st.ua != "" && ua != "" && st.ua != ua {
		st.uaChange++
	}
	st.ua = ua

	browserAccept := strings.Contains(strings.ToLower(accept), "text/html") ||
		strings.Contains(strings.ToLower(accept), "xhtml+xml")
	if !browserAccept && lang == "" && !isDoc {
		st.scripted++
	}

	if !isDoc && !st.docSeen {
		st.assetDirect++
	}
	if isDoc {
		st.docSeen = true
	}

	gap := now.Sub(st.lastSeen)
	if st.requests > 1 && gap < 90*time.Millisecond && (st.scripted > 0 || !st.docSeen) {
		st.consecGapCD++
		if st.consecGapCD >= 3 {
			st.bursts++
			st.consecGapCD = 0
		}
	} else {
		st.consecGapCD = 0
	}

	if validCookie {
		st.cookieIssued = true
	} else if st.cookieIssued {
		st.noCookie++
	}

	res := Result{ClientID: key}
	reasons := []string{}
	score := 0

	if !st.docSeen && st.requests >= 2 {
		score += 10
		reasons = append(reasons, "no_document_navigation")
	}
	if st.assetDirect > 0 {
		score += 20
		reasons = append(reasons, "asset_before_document")
	}
	if st.scripted > 0 {
		score += 15
		reasons = append(reasons, "incomplete_headers")
	}
	if st.uaChange > 0 {
		score += 15
		reasons = append(reasons, "ua_changed")
	}
	if st.noCookie >= 3 {
		score += 20
		reasons = append(reasons, "cookie_refusal")
	}
	if st.bursts > 0 {
		score += 25
		reasons = append(reasons, "request_burst")
	}
	if st.cookieIssued {
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	res.Score = score
	res.Label = strings.Join(reasons, ",")
	if len(reasons) == 0 {
		res.Label = "clean"
	}

	switch {
	case score >= e.blockAbove:
		res.Action = config.ActionBlock
	case score >= e.challengeAbove:
		res.Action = config.ActionChallenge
	default:
		res.Action = config.ActionAllow
	}

	if cookie == "" && !st.cookieIssued && res.Action != config.ActionBlock {
		if id, cv, err := e.cp.Issue(ip, now); err == nil {
			res.Cookie = cv
			res.NewClient = true
			res.ClientID = "fp:" + id
			st.cookieIssued = true
		}
	}
	return res
}

func (e *Engine) CookieName() string { return e.cookieName }
