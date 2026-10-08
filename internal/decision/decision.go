package decision

import (
	"fmt"

	reqctx "github.com/openwaap/openwaap/internal/context"
	"github.com/openwaap/openwaap/internal/scoring"
)

type Action string

const (
	Allow     Action = "ALLOW"
	Block     Action = "BLOCK"
	Challenge Action = "CHALLENGE"
	Log       Action = "LOG"
	RateLimit Action = "RATE_LIMIT"
	Throttle  Action = "THROTTLE"
	Unauthorized Action = "UNAUTHORIZED"
)

type Thresholds struct {
	Low int
	High int
}

func DefaultThresholds() Thresholds {
	return Thresholds{Low: scoring.LowRiskCeiling, High: scoring.HighRiskFloor}
}

type Engine struct {
	Thresholds Thresholds
	FailOpen bool
	WAFEnabled bool
}

type Decision struct {
	Action  Action          `json:"action"`
	Score   int             `json:"score"`
	Reasons []reqctx.Reason `json:"reasons"`
	Source string `json:"source"`
	RuleID string `json:"rule_id,omitempty"`
}

func (d Decision) String() string {
	return fmt.Sprintf("%s (score=%d, reasons=%d)", d.Action, d.Score, len(d.Reasons))
}

func NewEngine(th Thresholds, failOpen, wafEnabled bool) *Engine {
	return &Engine{Thresholds: th, FailOpen: failOpen, WAFEnabled: wafEnabled}
}

func (e *Engine) Evaluate(c *reqctx.RequestContext) (Decision, error) {
	score := scoring.Evaluate(c)
	return e.decide(c, score), nil
}

func (e *Engine) decide(c *reqctx.RequestContext, score int) Decision {
	d := Decision{Score: score, Reasons: c.DecisionReasons}

	if !e.WAFEnabled {
		d.Action = Allow
		d.Source = "waf_disabled"
		if score > 0 {
			d.Reasons = c.DecisionReasons
		}
		return d
	}

	switch {
	case score <= e.Thresholds.Low:
		d.Action = Allow
		d.Source = "low_risk"
	case score < e.Thresholds.High:
		d.Action = Challenge
		d.Source = "score_challenge"
	default:
		d.Action = Block
		d.Source = "score_block"
	}

	if len(d.Reasons) == 0 {
		for _, m := range c.Matches {
			d.Reasons = append(d.Reasons, reqctx.Reason{
				Label: m.Category, Points: m.Points, RuleID: m.RuleID,
			})
		}
	}
	return d
}

func (e *Engine) EvaluateWithCustom(c *reqctx.RequestContext, score int, customAction *string, customRuleID string) (Decision, error) {
	return e.EvaluateWithOverrides(c, score, customAction, customRuleID, nil, "")
}

func (e *Engine) EvaluateWithOverrides(c *reqctx.RequestContext, score int, customAction *string, customRuleID string, preAction *string, preRuleID string) (Decision, error) {
	d := e.decide(c, score)

	switch {
	case customAction != nil:
		d.Action = toAction(*customAction)
		if d.Action == Block {
			d.Source = "custom_rule"
			d.RuleID = customRuleID
			d.Reasons = append(d.Reasons, reqctx.Reason{
				Label: "custom_rule", RuleID: customRuleID, Points: score,
			})
		}
	case preAction != nil:
		act := toAction(*preAction)
		if act != Allow {
			d.Action = act
			d.Source = "early_security"
			d.RuleID = preRuleID
			d.Reasons = append(d.Reasons, reqctx.Reason{
				Label: preRuleID, RuleID: preRuleID, Points: score,
			})
		}
	}
	return d, nil
}

func toAction(a string) Action {
	switch a {
	case "BLOCK":
		return Block
	case "CHALLENGE":
		return Challenge
	case "RATE_LIMIT":
		return RateLimit
	case "THROTTLE":
		return Throttle
	case "LOG":
		return Log
	default:
		return Allow
	}
}
