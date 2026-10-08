package scoring

import (
	reqctx "github.com/openwaap/openwaap/internal/context"
)

const (
	LowRiskCeiling = 40
	ChallengeFloor = 41
	HighRiskFloor = 80
)

func Evaluate(c *reqctx.RequestContext) int {
	total := 0
	for _, m := range c.Matches {
		total += m.Points
	}
	if total > 99 {
		total = 99
	}
	if total < 0 {
		total = 0
	}
	c.AttackScore = total
	return total
}

func AddSignalThatExplains(c *reqctx.RequestContext, source, ruleID, category, detail string, points int, threshold int) {
	c.AddSignal(reqctx.SignalMatch{
		Source:   source,
		RuleID:   ruleID,
		Category: category,
		Points:   points,
		Detail:   detail,
	})
	c.DecisionReasons = append(c.DecisionReasons, reqctx.Reason{
		Label:     category,
		Points:    points,
		Threshold: threshold,
		RuleID:    ruleID,
	})
}
