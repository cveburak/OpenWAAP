package pipeline

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openwaap/openwaap/internal/apisec"
	"github.com/openwaap/openwaap/internal/behavior"
	"github.com/openwaap/openwaap/internal/bot"
	"github.com/openwaap/openwaap/internal/config"
	reqctx "github.com/openwaap/openwaap/internal/context"
	"github.com/openwaap/openwaap/internal/ddos"
	"github.com/openwaap/openwaap/internal/decision"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/honeypot"
	"github.com/openwaap/openwaap/internal/ratelimit"
	"github.com/openwaap/openwaap/internal/reputation"
	custom "github.com/openwaap/openwaap/internal/rules/custom"
	"github.com/openwaap/openwaap/internal/rules/managed"
	"github.com/openwaap/openwaap/internal/scoring"
)

type Config struct {
	Ruleset *managed.Ruleset
	CustomRules []*custom.Rule
	Honeypot *honeypot.Registry
	FailOpen bool
	WAFEnabled bool
	ManagedMaxParanoia int

	RateLimit         *ratelimit.Engine
	BotDetector       *bot.Detector
	BotChallengeBelow int
	BotBlockBelow     int
	Reputation        *reputation.Store
	RepBlockScore     int
	RepHoneypotPoints int
	RepBlockedPoints  int

	ChallengePassed func(c *reqctx.RequestContext) bool

	APISecEngine *apisec.Engine

	Behavior *behavior.Engine

	DDoS *ddos.Shield
}

type Processor struct {
	cfg  Config
	dec  *decision.Engine
	emit *events.Emitter
	log  *slog.Logger
}

func New(cfg Config, emit *events.Emitter, log *slog.Logger) *Processor {
	decEng := decision.NewEngine(decision.DefaultThresholds(), cfg.FailOpen, cfg.WAFEnabled)
	if log == nil {
		log = slog.Default()
	}
	return &Processor{cfg: cfg, dec: decEng, emit: emit, log: log}
}

type Result struct {
	Decision decision.Action
	Score int
	Event *events.Event
	Reasons []reqctx.Reason
	Denied bool
	RetryAfter int
	FingerprintCookie *http.Cookie
}

func (p *Processor) Inspect(c *reqctx.RequestContext, bodyReader func() ([]byte, error)) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("pipeline panic", "err", r, "request_id", c.RequestID, "component", "pipeline")
			act := decision.Allow
			denied := false
			if !p.cfg.FailOpen {
				act = decision.Block
				denied = true
			}
			c.Decision = string(act)
			ev := events.FromContext(c, mapAction(act), "")
			res = Result{Decision: act, Score: c.AttackScore, Event: &ev, Denied: denied, Reasons: c.DecisionReasons}
		}
	}()

	start := time.Now()
	res = p.inspect(c, bodyReader)
	c.Processing = time.Since(start)
	return res
}

func (p *Processor) inspect(c *reqctx.RequestContext, bodyReader func() ([]byte, error)) Result {
	var preAction *string
	var preRuleID string

	if p.cfg.DDoS != nil {
		if act, rule := p.cfg.DDoS.Check(c.RemoteIP.String()); act != config.ActionAllow {
			setPre(&preAction, &preRuleID, string(act), rule)
		}
	}

	if p.cfg.Honeypot != nil && p.cfg.Honeypot.IsDecoy(c.Path) {
		c.HoneypotHit = true
		scoring.AddSignalThatExplains(c, "honeypot", "honeypot-decoy", "HONEYPOT",
			honeypot.Explain(c.Path), p.cfg.Honeypot.Points(), decision.DefaultThresholds().High)
	}

	if p.cfg.Reputation != nil {
		ip := c.RemoteIP.String()
		if c.HoneypotHit {
			p.cfg.Reputation.Observe(ip, p.cfg.RepHoneypotPoints)
		}
		if rep := p.cfg.Reputation.Score(ip); rep > 0 {
			scoring.AddSignalThatExplains(c, "reputation", "reputation-ip",
				"REPUTATION", "IP reputation "+strconv.Itoa(rep), min(20, rep/5),
				decision.DefaultThresholds().High)
			if rep >= p.cfg.RepBlockScore {
				setPre(&preAction, &preRuleID, "BLOCK", "reputation:block")
			}
		}
	}

	verifiedBot := false
	if p.cfg.BotDetector != nil {
		det := p.cfg.BotDetector.Scan(c.UA,
			c.Headers.Get("Accept"), c.Headers.Get("Accept-Language"))
		c.BotScore = det.Score
		verifiedBot = det.Verified
		if !det.Verified {
			switch {
			case p.cfg.BotBlockBelow > 0 && det.Score < p.cfg.BotBlockBelow:
				setPre(&preAction, &preRuleID, "BLOCK", "bot:block")
			case p.cfg.BotChallengeBelow > 0 && det.Score < p.cfg.BotChallengeBelow:
				setPre(&preAction, &preRuleID, "CHALLENGE", "bot:challenge")
			}
		}
	}

	if p.cfg.Behavior != nil {
		bres := p.cfg.Behavior.Inspect(
			c, cookieValue(c.Headers.Get("Cookie"), p.cfg.Behavior.CookieName()),
			verifiedBot, time.Now())
		c.BehaviorScore = bres.Score
		if bres.NewClient {
			c.BehaviorNewClient = true
			c.BehaviorCookie = bres.Cookie
		}
		switch bres.Action {
		case config.ActionBlock:
			setPre(&preAction, &preRuleID, "BLOCK", "behavior:block")
		case config.ActionChallenge:
			setPre(&preAction, &preRuleID, "CHALLENGE", "behavior:challenge")
		}
		if bres.Score > 0 {
			scoring.AddSignalThatExplains(c, "behavior", "behavior-signal",
				"BEHAVIOR", bres.Label, min(15, bres.Score/8), decision.DefaultThresholds().High)
		}
	}

	var retryAfter int
	if p.cfg.RateLimit != nil {
		oc := p.cfg.RateLimit.Check(ratelimit.Request{
			Domain:  c.Domain,
			IP:      c.RemoteIP.String(),
			Path:    c.Path,
			Method:  c.Method,
			Headers: c.Headers,
		})
		if oc.Action != config.ActionAllow {
			if oc.Rule != nil {
				retryAfter = oc.Rule.RetryAfter()
			}
			setPre(&preAction, &preRuleID, string(oc.Action), "ratelimit:"+oc.Rule.ID)
		}
	}

	if p.cfg.APISecEngine != nil {
		var apiBody []byte
		if c.Method == http.MethodPost || c.Method == http.MethodPut || c.Method == http.MethodPatch {
			if bodyReader != nil {
				if b, err := bodyReader(); err == nil {
					apiBody = b
				}
			}
		}
		apiReq, err := http.NewRequest(c.Method, "http://x"+c.Path, nil)
		if err == nil {
			apiReq.Header = c.Headers
			apiURL := apiReq.URL
			apiURL.RawQuery = c.RawQuery
			apiRes := p.cfg.APISecEngine.Evaluate(apiReq, apiBody)
			switch {
			case apiRes.Action == config.ActionUnauthorized:
				c.Decision = string(decision.Unauthorized)
				ev := events.FromContext(c, events.ActionUnauthorized, apiRes.RuleID)
				return Result{
					Decision:   decision.Unauthorized,
					Score:      c.AttackScore,
					Event:      &ev,
					Reasons:    append(c.DecisionReasons, reqctx.Reason{Label: apiRes.Reason, Points: 0, RuleID: apiRes.RuleID}),
					Denied:     true,
					RetryAfter: 0,
				}
			case apiRes.Action != config.ActionAllow && apiRes.Action != "":
				setPre(&preAction, &preRuleID,
					string(apiRes.Action), apiRes.RuleID)
			}
		}
	}

	headers := c.Headers
	args := reduceArgs(c)
	var body []byte
	if c.Method == http.MethodPost || c.Method == http.MethodPut || c.Method == http.MethodPatch {
		if bodyReader != nil {
			b, err := bodyReader()
			if err == nil {
				body = b
			}
		}
	}
	for k, v := range decodeBodyArgs(c, body) {
		args[k] = v
	}

	values := managed.Values{
		URI:     c.Path + "?" + c.RawQuery,
		Args:    args,
		Headers: headers,
		Body:    body,
	}

	matches := p.cfg.Ruleset.MatchAll(values, p.cfg.ManagedMaxParanoia, 0)
	for _, m := range matches {
		scoring.AddSignalThatExplains(c, "waf", m.Rule.ID, string(m.Rule.Category),
			m.Detail, m.Rule.Points, decision.DefaultThresholds().High)
	}

	var customOverride *string
	var customRuleID string
	if len(p.cfg.CustomRules) > 0 {
		for _, rule := range p.cfg.CustomRules {
			if rule == nil {
				continue
			}
			act, fired, reasons := rule.Match(c)
			if fired {
				customOverride = ptr(string(act))
				customRuleID = rule.ID
				for _, r := range reasons {
					p.log.Debug("custom rule match", "rule", rule.ID, "condition", r, "request_id", c.RequestID)
				}
				break
			}
		}
	}

	score := scoring.Evaluate(c)
	dec, err := p.dec.EvaluateWithOverrides(c, score, customOverride, customRuleID, preAction, preRuleID)
	if err != nil {
		act := decision.Allow
		if !p.cfg.FailOpen {
			act = decision.Block
		}
		p.log.Error("decision error", "err", err, "request_id", c.RequestID)
		dec = decision.Decision{Action: act, Score: score, Source: "engine_error"}
	}
	c.Decision = string(dec.Action)
	c.DecisionReasons = dec.Reasons

	if dec.Action == decision.Challenge && p.cfg.ChallengePassed != nil && p.cfg.ChallengePassed(c) {
		dec.Action = decision.Allow
		dec.RuleID = "challenge_passed"
		dec.Source = "challenge"
		dec.Reasons = append(dec.Reasons, reqctx.Reason{Label: "challenge_passed", Points: 0, RuleID: "challenge_passed"})
	}

	if p.cfg.Reputation != nil && dec.Action == decision.Block {
		p.cfg.Reputation.Observe(c.RemoteIP.String(), p.cfg.RepBlockedPoints)
	}
	ev := events.FromContext(c, mapAction(dec.Action), string(dec.RuleID))
	res := Result{
		Decision:   dec.Action,
		Score:      dec.Score,
		Event:      &ev,
		Reasons:    dec.Reasons,
		Denied:     dec.Action != decision.Allow,
		RetryAfter: retryAfter,
	}
	if c.BehaviorNewClient {
		name := behavior.CookieName
		ttl := behavior.DefaultCookieTTL
		if p.cfg.Behavior != nil {
			name = p.cfg.Behavior.CookieName()
			ttl = p.cfg.Behavior.CookieTTL()
		}
		res.FingerprintCookie = &http.Cookie{
			Name:     name,
			Value:    c.BehaviorCookie,
			MaxAge:   int(ttl.Seconds()),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
	}
	return res
}

func mapAction(a decision.Action) events.Action {
	switch a {
	case decision.Block:
		return events.ActionBlock
	case decision.Challenge:
		return events.ActionChallenge
	case decision.RateLimit:
		return events.ActionRateLimit
	case decision.Throttle:
		return events.ActionThrottle
	case decision.Log:
		return events.ActionLog
	case decision.Unauthorized:
		return events.ActionUnauthorized
	default:
		return events.ActionAllow
	}
}

func setPre(preAction **string, preRuleID *string, action, ruleID string) {
	if *preAction == nil || severityOf(action) > severityOf(**preAction) {
		*preAction = ptr(action)
		*preRuleID = ruleID
	}
}

func severityOf(a string) int {
	switch a {
	case "BLOCK":
		return 5
	case "RATE_LIMIT":
		return 4
	case "CHALLENGE":
		return 3
	case "THROTTLE":
		return 2
	default:
		return 1
	}
}

func ptr[T any](v T) *T { return &v }

func reduceArgs(c *reqctx.RequestContext) map[string]string {
	if c.RawQuery == "" {
		return map[string]string{}
	}
	args := map[string]string{}
	values, err := url.ParseQuery(c.RawQuery)
	if err != nil {
		return managed.QueryStringArgs(c.RawQuery)
	}
	for k, vs := range values {
		if len(vs) > 0 {
			args[k] = vs[0]
		} else {
			args[k] = ""
		}
	}
	return args
}

func decodeBodyArgs(c *reqctx.RequestContext, body []byte) map[string]string {
	if len(body) == 0 {
		return nil
	}
	ct := strings.ToLower(c.Headers.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil
		}
		out := map[string]string{}
		for k, vs := range values {
			if len(vs) > 0 {
				out[k] = vs[0]
			} else {
				out[k] = ""
			}
		}
		return out
	case strings.Contains(ct, "application/json"):
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		out := map[string]string{}
		for k, v := range m {
			out[k] = jsonScalar(v)
		}
		return out
	}
	return nil
}

func jsonScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return ""
	}
}

func cookieValue(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if key, val, ok := strings.Cut(part, "="); ok && key == name {
			return val
		}
	}
	return ""
}
