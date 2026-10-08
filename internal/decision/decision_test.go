package decision

import (
	"testing"

	reqctx "github.com/openwaap/openwaap/internal/context"
)

func TestLowRiskAllows(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	c.AddSignal(reqctx.SignalMatch{Source: "waf", Category: "SCANNER", Points: 10, RuleID: "s-1"})
	d, err := e.Evaluate(c)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != Allow {
		t.Fatalf("expected allow for low score, got %s (score=%d)", d.Action, d.Score)
	}
}

func TestHighRiskBlocks(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	c.AddSignal(reqctx.SignalMatch{Source: "waf", Category: "SQL_INJECTION", Points: 60, RuleID: "sqli-1"})
	c.AddSignal(reqctx.SignalMatch{Source: "bot", Category: "BOT", Points: 30, RuleID: "bot-1"})
	d, _ := e.Evaluate(c)
	if d.Score != 90 {
		t.Fatalf("expected score 90, got %d", d.Score)
	}
	if d.Action != Block {
		t.Fatalf("expected block for high score, got %s", d.Action)
	}
}

func TestMidRiskChallenges(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	c.AddSignal(reqctx.SignalMatch{Source: "waf", Category: "PATH_TRAVERSAL", Points: 45, RuleID: "pt"})
	d, _ := e.Evaluate(c)
	if d.Action != Challenge {
		t.Fatalf("expected challenge for mid score, got %s", d.Action)
	}
}

func TestExplanableReasons(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	c.AddSignal(reqctx.SignalMatch{Source: "waf", Category: "SQL_INJECTION", Points: 60, RuleID: "sqli-1"})
	c.AddSignal(reqctx.SignalMatch{Source: "bot", Category: "BOT", Points: 25, RuleID: "bot-1"})
	d, _ := e.Evaluate(c)
	if d.Score != 85 {
		t.Fatalf("expected 85, got %d", d.Score)
	}
	if len(d.Reasons) == 0 {
		t.Fatal("expected reasons for explainable blocking")
	}
	if d.Source != "score_block" {
		t.Fatalf("expected source score_block, got %s", d.Source)
	}
}

func TestWAFDisabledAllows(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, false)
	c := &reqctx.RequestContext{}
	c.AddSignal(reqctx.SignalMatch{Source: "waf", Category: "SQL_INJECTION", Points: 90, RuleID: "x"})
	d, _ := e.Evaluate(c)
	if d.Action != Allow {
		t.Fatalf("expected allow when WAF disabled, got %s", d.Action)
	}
}

func TestCustomRuleOverride(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	var block = "BLOCK"
	d, err := e.EvaluateWithCustom(c, 5, &block, "myrule")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != Block {
		t.Fatalf("expected custom override to block, got %s", d.Action)
	}
	if d.RuleID != "myrule" || d.Source != "custom_rule" {
		t.Fatalf("expected custom_rule source, got %s/%s", d.Source, d.RuleID)
	}
}

func TestString(t *testing.T) {
	d := Decision{Action: Block, Score: 80}
	if d.String() == "" {
		t.Fatal("expected non-empty string")
	}
}
func TestPreOverrideRateLimit(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	rate := "RATE_LIMIT"
	d, err := e.EvaluateWithOverrides(c, 0, nil, "", &rate, "rl:login-ip")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != RateLimit {
		t.Fatalf("expected RATE_LIMIT override, got %s", d.Action)
	}
	if d.Source != "early_security" {
		t.Fatalf("expected early_security source, got %s", d.Source)
	}
	if len(d.Reasons) != 1 || d.Reasons[0].RuleID != "rl:login-ip" {
		t.Fatalf("expected explainable reason, got %+v", d.Reasons)
	}
}

func TestCustomWinsOverPreOverride(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	rate := "RATE_LIMIT"
	allow := "ALLOW"
	d, err := e.EvaluateWithOverrides(c, 0, &allow, "custom-allow", &rate, "rl:x")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != Allow {
		t.Fatalf("custom ALLOW must beat rate override, got %s", d.Action)
	}
}

func TestThrottleAction(t *testing.T) {
	e := NewEngine(DefaultThresholds(), true, true)
	c := &reqctx.RequestContext{}
	th := "THROTTLE"
	d, _ := e.EvaluateWithOverrides(c, 0, nil, "", &th, "rl:throttle")
	if d.Action != Throttle {
		t.Fatalf("expected THROTTLE, got %s", d.Action)
	}
}
