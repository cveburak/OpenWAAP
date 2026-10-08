package custom

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	reqctx "github.com/openwaap/openwaap/internal/context"
)

type Action string

const (
	ActionAllow     Action = "ALLOW"
	ActionBlock     Action = "BLOCK"
	ActionChallenge Action = "CHALLENGE"
	ActionLog       Action = "LOG"
)

type Op string

const (
	OpEq       Op = "=="
	OpNeq      Op = "!="
	OpStarts   Op = "starts_with"
	OpContains Op = "contains"
	OpMatches  Op = "matches"
	OpInCIDR   Op = "in_cidr"
	OpGt       Op = ">"
	OpLt       Op = "<"
)

type Field string

const (
	FieldIP          Field = "ip"
	FieldCountry     Field = "country"
	FieldASN         Field = "asn"
	FieldHostname    Field = "hostname"
	FieldPath        Field = "path"
	FieldMethod      Field = "method"
	FieldHeader      Field = "header"
	FieldQuery       Field = "query"
	FieldUserAgent   Field = "user_agent"
	FieldBotScore    Field = "bot_score"
	FieldAttackScore Field = "attack_score"
)

type Rule struct {
	ID     string
	Name   string
	Groups []Group
	Then   Action
}

type Group struct {
	Conds []Condition
}

type Condition struct {
	Field Field
	Arg  string
	Op   Op
	Val  string
	re   *regexp.Regexp
	cidr *net.IPNet
	num  int
}

func (r *Rule) Match(c *reqctx.RequestContext) (Action, bool, []string) {
	var matchedReasons []string
	for _, g := range r.Groups {
		gMatch, reasons := g.eval(c)
		if !gMatch {
			return "", false, nil
		}
		matchedReasons = append(matchedReasons, reasons...)
	}
	return r.Then, true, matchedReasons
}

func (g *Group) eval(c *reqctx.RequestContext) (bool, []string) {
	var reasons []string
	for i := range g.Conds {
		if g.Conds[i].eval(c) {
			reasons = append(reasons, g.Conds[i].describe())
		}
	}
	if len(g.Conds) == 0 {
		return true, nil
	}
	return len(reasons) > 0, reasons
}

func (cond *Condition) eval(c *reqctx.RequestContext) bool {
	actual, ok := cond.resolve(c)
	if !ok {
		return false
	}
	switch cond.Op {
	case OpEq:
		return actual == cond.Val
	case OpNeq:
		return actual != cond.Val
	case OpStarts:
		return strings.HasPrefix(actual, cond.Val)
	case OpContains:
		return strings.Contains(actual, cond.Val)
	case OpMatches:
		return cond.re.MatchString(actual)
	case OpInCIDR:
		ip := net.ParseIP(actual)
		if ip == nil {
			return false
		}
		return cond.cidr != nil && cond.cidr.Contains(ip)
	case OpGt, OpLt:
		n, err := strconv.Atoi(actual)
		if err != nil {
			return false
		}
		if cond.Op == OpGt {
			return n > cond.num
		}
		return n < cond.num
	}
	return false
}

func (cond *Condition) resolve(c *reqctx.RequestContext) (string, bool) {
	switch cond.Field {
	case FieldIP:
		if c.RemoteIP == nil {
			return "", false
		}
		return c.RemoteIP.String(), true
	case FieldCountry:
		return c.Country, c.Country != ""
	case FieldASN:
		return strconv.Itoa(c.ASN), true
	case FieldHostname:
		return c.Host, c.Host != ""
	case FieldPath:
		return c.Path, true
	case FieldMethod:
		return c.Method, true
	case FieldHeader:
		v := c.Headers.Get(cond.Arg)
		return v, v != ""
	case FieldQuery:
		v := c.QueryParam(cond.Arg)
		return v, true
	case FieldUserAgent:
		return c.UA, true
	case FieldBotScore:
		return strconv.Itoa(c.BotScore), true
	case FieldAttackScore:
		return strconv.Itoa(c.AttackScore), true
	}
	return "", false
}

func (cond *Condition) describe() string {
	name := string(cond.Field)
	if cond.Arg != "" {
		name += ":" + cond.Arg
	}
	return fmt.Sprintf("%s %s %s", name, cond.Op, cond.Val)
}

func (cond *Condition) validate() error {
	switch cond.Op {
	case OpMatches:
		if cond.re == nil {
			return fmt.Errorf("matches operator requires a valid regex")
		}
	case OpInCIDR:
		if cond.cidr == nil {
			return fmt.Errorf("in_cidr operator requires a valid CIDR")
		}
	}
	switch cond.Field {
	case FieldHeader, FieldQuery:
		if cond.Arg == "" {
			return fmt.Errorf("field %q requires a selector (e.g. header:user-agent)", cond.Field)
		}
	}
	return nil
}

