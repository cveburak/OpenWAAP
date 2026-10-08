package custom

import (
	"net"
	"testing"

	reqctx "github.com/openwaap/openwaap/internal/context"
)

func makeCtx() *reqctx.RequestContext {
	c := &reqctx.RequestContext{
		RemoteIP: net.ParseIP("203.0.113.7"),
		Host:     "example.com",
		Path:     "/admin/settings",
		Method:   "GET",
		Country:  "TR",
		ASN:      64512,
		UA:       "curl/8.0",
		BotScore: 90,
	}
	c.Headers = map[string][]string{"X-Api-Key": {"secret123"}}
	return c
}

func mustParse(t *testing.T, id, input string) *Rule {
	t.Helper()
	r, err := Parse(id, "name", input)
	if err != nil {
		t.Fatalf("parse %q: %v", input, err)
	}
	return r
}

func TestParseBasicHostnameMatch(t *testing.T) {
	r := mustParse(t, "r1", `IF hostname == "example.com" THEN BLOCK`)
	c := makeCtx()
	act, fired, _ := r.Match(c)
	if !fired || act != ActionBlock {
		t.Fatalf("expected block fired, got %s/%v", act, fired)
	}
}

func TestParseCountryNotMatch(t *testing.T) {
	r := mustParse(t, "r2", `IF country != "US" THEN LOG`)
	c := makeCtx()
	act, fired, _ := r.Match(c)
	if !fired || act != ActionLog {
		t.Fatalf("expected log, got %s/%v", act, fired)
	}
}

func TestStartsWithAdmin(t *testing.T) {
	r := mustParse(t, "r3", `IF path starts_with "/admin" THEN BLOCK`)
	c := makeCtx()
	act, fired, _ := r.Match(c)
	if !fired || act != ActionBlock {
		t.Fatalf("expected block, got %s/%v", act, fired)
	}
}

func TestAndComposition(t *testing.T) {
	r := mustParse(t, "r4", `IF path starts_with "/admin" AND country == "TR" THEN BLOCK`)
	c := makeCtx()
	act, fired, _ := r.Match(c)
	if !fired || act != ActionBlock {
		t.Fatalf("expected both conds match → block, got %s/%v", act, fired)
	}

	c2 := makeCtx()
	c2.Country = "US"
	_, fired2, _ := r.Match(c2)
	if fired2 {
		t.Fatal("expected not fired when country is US")
	}
}

func TestOrGroup(t *testing.T) {
	r := mustParse(t, "r5", `IF path starts_with "/admin" OR path starts_with "/login" THEN CHALLENGE`)
	c := makeCtx()
	act, fired, _ := r.Match(c)
	if !fired || act != ActionChallenge {
		t.Fatalf("expected challenge fired, got %s/%v", act, fired)
	}
	c2 := makeCtx()
	c2.Path = "/home"
	_, fired2, _ := r.Match(c2)
	if fired2 {
		t.Fatal("expected not fired on /home")
	}
}

func TestMatchesRegex(t *testing.T) {
	r := mustParse(t, "r6", `IF user_agent matches "^curl" THEN LOG`)
	c := makeCtx()
	act, fired, _ := r.Match(c)
	if !fired || act != ActionLog {
		t.Fatalf("expected log for curl UA, got %s/%v", act, fired)
	}
}

func TestInCIDR(t *testing.T) {
	r := mustParse(t, "r7", `IF ip in_cidr "203.0.113.0/24" THEN ALLOW`)
	c := makeCtx()
	act, fired, _ := r.Match(c)
	if !fired || act != ActionAllow {
		t.Fatalf("expected allow, got %s/%v", act, fired)
	}
}

func TestQueryParam(t *testing.T) {
	r := mustParse(t, "r8", `IF query:act == "delete" THEN BLOCK`)
	c := makeCtx()
	c.RawQuery = "act=delete&id=5"
	act, fired, _ := r.Match(c)
	if !fired || act != ActionBlock {
		t.Fatalf("expected block on query act=delete, got %s/%v", act, fired)
	}
}

func TestHeaderField(t *testing.T) {
	r := mustParse(t, "r9", `IF header:x-api-key != "secret123" THEN BLOCK`)
	c := makeCtx()
	_, fired, _ := r.Match(c)
	if fired {
		t.Fatal("expected not fired when header matches expected value")
	}
}

func TestAttackScoreComparison(t *testing.T) {
	r := mustParse(t, "r10", `IF attack_score > 80 THEN BLOCK`)
	c := makeCtx()
	c.AttackScore = 95
	act, fired, _ := r.Match(c)
	if !fired || act != ActionBlock {
		t.Fatalf("expected block, got %s/%v", act, fired)
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`hostname == "x" THEN BLOCK`,
		`IF hostname "x" THEN BLOCK`,
		`IF hostname == x THEN BLOCK`,
		`IF bogus == "x" THEN BLOCK`,
		`IF path starts_with "/x"`,
		`IF path starts_with "/x" THEN LET`,
		`IF path starts_with "/x" BANDAID`,
	}
	for _, s := range bad {
		if _, err := Parse("r", "n", s); err == nil {
			t.Fatalf("expected parse error for %q", s)
		}
	}
}

func TestParseBadRegex(t *testing.T) {
	if _, err := Parse("r", "n", `IF path matches "[unclosed" THEN BLOCK`); err == nil {
		t.Fatal("expected error for bad regex")
	}
}

func TestParseBadCIDR(t *testing.T) {
	if _, err := Parse("r", "n", `IF ip in_cidr "999.1.1.1/x" THEN BLOCK`); err == nil {
		t.Fatal("expected error for bad CIDR")
	}
}

func TestStartsWithTwoWords(t *testing.T) {
	r := mustParse(t, "r11", `IF path starts with "/admin" THEN LOG`)
	c := makeCtx()
	_, fired, _ := r.Match(c)
	if !fired {
		t.Fatal("expected fired for 'starts with'")
	}
}

func TestTrailingTokensRejected(t *testing.T) {
	if _, err := Parse("r", "n", `IF path starts_with "/x" THEN BLOCK extra`); err == nil {
		t.Fatal("expected error for trailing tokens")
	}
}
