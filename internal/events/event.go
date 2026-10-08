package events

import (
	"encoding/json"
	"time"

	reqctx "github.com/openwaap/openwaap/internal/context"
)

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

type Event struct {
	Timestamp   time.Time       `json:"timestamp"`
	RequestID   string          `json:"request_id"`
	SourceIP    string          `json:"source_ip"`
	Country     string          `json:"country,omitempty"`
	ASN         uint32          `json:"asn,omitempty"`
	Hostname    string          `json:"hostname"`
	Path        string          `json:"path"`
	Method      string          `json:"method"`
	Action      Action          `json:"action"`
	RuleID      string          `json:"rule_id,omitempty"`
	AttackScore int             `json:"attack_score"`
	BotScore    int             `json:"bot_score"`
	Category    string          `json:"category,omitempty"`
	Reasons     []reqctx.Reason `json:"reasons,omitempty"`
	HoneypotHit bool            `json:"honeypot_hit,omitempty"`
	MatchCount  int             `json:"match_count"`
	DurationMs int `json:"duration_ms,omitempty"`
	StatusCode int `json:"status_code,omitempty"`
	Code EventCode `json:"code,omitempty"`
}

type EventCode string

const (
	CodeAllowed     EventCode = "REQUEST_ALLOWED"
	CodeBlocked     EventCode = "REQUEST_BLOCKED"
	CodeChallenged  EventCode = "REQUEST_CHALLENGED"
	CodeRateLimited EventCode = "REQUEST_RATE_LIMITED"
	CodeWAFDetected EventCode = "WAF_DETECTED"
	CodeHoneypotHit EventCode = "HONEYPOT_HIT"
)

func FromContext(c *reqctx.RequestContext, action Action, ruleID string) Event {
	cat := ""
	if len(c.Matches) > 0 {
		cat = string(c.Matches[0].Category)
	}
	return Event{
		Timestamp:   c.Timestamp,
		RequestID:   c.RequestID,
		SourceIP:    c.RemoteIP.String(),
		Country:     c.Country,
		ASN:         uint32(c.ASN),
		Hostname:    c.Host,
		Path:        c.Path,
		Method:      c.Method,
		Action:      action,
		RuleID:      ruleID,
		AttackScore: c.AttackScore,
		BotScore:    c.BotScore,
		Category:    cat,
		Reasons:     c.DecisionReasons,
		HoneypotHit: c.HoneypotHit,
		MatchCount:  len(c.Matches),
		DurationMs:  int(c.Processing.Nanoseconds() / 1e6),
		Code:        codeFor(action, c.HoneypotHit),
	}
}

func codeFor(action Action, honeypotHit bool) EventCode {
	if honeypotHit {
		return CodeHoneypotHit
	}
	switch action {
	case ActionBlock, ActionUnauthorized:
		return CodeBlocked
	case ActionChallenge:
		return CodeChallenged
	case ActionRateLimit, ActionThrottle:
		return CodeRateLimited
	case ActionLog:
		return CodeWAFDetected
	default:
		return CodeAllowed
	}
}

func (e *Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}
