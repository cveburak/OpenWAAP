package scoring

import (
	"testing"

	reqctx "github.com/openwaap/openwaap/internal/context"
)

func TestEvaluateEmpty(t *testing.T) {
	c := &reqctx.RequestContext{}
	if got := Evaluate(c); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestEvaluateSumAndClamp(t *testing.T) {
	c := &reqctx.RequestContext{}
	c.AddSignal(reqctx.SignalMatch{Source: "waf", Points: 30})
	c.AddSignal(reqctx.SignalMatch{Source: "bot", Points: 25})
	if got := Evaluate(c); got != 55 {
		t.Fatalf("expected 55, got %d", got)
	}

	c2 := &reqctx.RequestContext{}
	c2.AddSignal(reqctx.SignalMatch{Points: 60})
	c2.AddSignal(reqctx.SignalMatch{Points: 60})
	if got := Evaluate(c2); got != 99 {
		t.Fatalf("expected clamp to 99, got %d", got)
	}
}

func TestAddSignalThatExplains(t *testing.T) {
	c := &reqctx.RequestContext{}
	AddSignalThatExplains(c, "waf", "sqli-001", "SQL_INJECTION", "union select", 40, 80)
	if got := Evaluate(c); got != 40 {
		t.Fatalf("expected 40, got %d", got)
	}
	if len(c.Matches) != 1 || len(c.DecisionReasons) != 1 {
		t.Fatalf("expected 1 match and 1 reason, got %d/%d", len(c.Matches), len(c.DecisionReasons))
	}
	if c.DecisionReasons[0].RuleID != "sqli-001" {
		t.Fatalf("expected rule id, got %s", c.DecisionReasons[0].RuleID)
	}
}

func TestThresholds(t *testing.T) {
	if !(LowRiskCeiling < ChallengeFloor && ChallengeFloor <= HighRiskFloor) {
		t.Fatalf("threshold ordering violated")
	}
}
