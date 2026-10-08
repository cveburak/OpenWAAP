package custom

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type tokType int

const (
	tokEOF tokType = iota
	tokIdent
	tokString
	tokOp
)

type token struct {
	typ tokType
	val string
}

func lex(input string) ([]token, error) {
	var toks []token
	i := 0
	n := len(input)
	for i < n {
		ch := input[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			i++
		case ch == '"':
			j := i + 1
			var sb strings.Builder
			closed := false
			for j < n {
				if input[j] == '\\' && j+1 < n {
					sb.WriteByte(input[j+1])
					j += 2
					continue
				}
				if input[j] == '"' {
					closed = true
					j++
					break
				}
				sb.WriteByte(input[j])
				j++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, token{tokString, sb.String()})
			i = j
		case strings.ContainsRune("=!<>", rune(ch)):
			if i+1 < n && (input[i+1] == '=') {
				toks = append(toks, token{tokOp, input[i : i+2]})
				i += 2
			} else if ch == '>' || ch == '<' {
				toks = append(toks, token{tokOp, string(ch)})
				i++
			} else {
				return nil, fmt.Errorf("unexpected character %q", ch)
			}
		case isIdentChar(ch):
			j := i
			for j < n && isIdentChar(input[j]) {
				j++
			}
			word := input[i:j]
			toks = append(toks, token{tokIdent, word})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q at %d", ch, i)
		}
	}
	return toks, nil
}

func isIdentChar(c byte) bool {
	return c == '_' || c == ':' || c == '-' || c == '.' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

var keyword = map[string]string{
	"if": "IF", "and": "AND", "or": "OR", "then": "THEN",
	"allow": "ALLOW", "block": "BLOCK", "challenge": "CHALLENGE", "log": "LOG",
	"matches": "matches", "contains": "contains", "in_cidr": "in_cidr",
	"starts_with": "starts_with", "==": "==", "!=": "!=", ">": ">", "<": "<",
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return &token{tokEOF, ""}
}

func (p *parser) next() *token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) expectIdent(upper string) error {
	t := p.next()
	if t.typ != tokIdent || strings.ToUpper(t.val) != upper {
		return fmt.Errorf("expected %q, got %q", upper, t.val)
	}
	return nil
}

func (p *parser) parseCondition() (Condition, error) {
	ft := p.next()
	if ft.typ != tokIdent {
		return Condition{}, fmt.Errorf("expected field name, got %q", ft.val)
	}
	fieldStr := strings.ToLower(ft.val)
	var cond Condition

	opTok := p.next()
	if opTok.typ == tokOp {
		switch opTok.val {
		case "==":
			cond.Op = OpEq
		case "!=":
			cond.Op = OpNeq
		case ">":
			cond.Op = OpGt
		case "<":
			cond.Op = OpLt
		default:
			return Condition{}, fmt.Errorf("unknown operator %q", opTok.val)
		}
	} else if opTok.typ == tokIdent {
		l := strings.ToLower(opTok.val)
		switch keyword[l] {
		case "matches":
			cond.Op = OpMatches
		case "contains":
			cond.Op = OpContains
		case "in_cidr":
			cond.Op = OpInCIDR
		case "starts_with":
			cond.Op = OpStarts
		default:
			return Condition{}, fmt.Errorf("unknown operator %q", opTok.val)
		}
	} else {
		return Condition{}, fmt.Errorf("expected operator after %q", fieldStr)
	}

	valTok := p.next()
	if valTok.typ == tokString {
		cond.Val = valTok.val
	} else if valTok.typ == tokIdent && (cond.Op == OpGt || cond.Op == OpLt) {
		if _, err := strconv.Atoi(valTok.val); err != nil {
			return Condition{}, fmt.Errorf("expected numeric value, got %q", valTok.val)
		}
		cond.Val = valTok.val
	} else {
		return Condition{}, fmt.Errorf("expected quoted value, got %q", valTok.val)
	}

	if idx := strings.IndexByte(fieldStr, ':'); idx >= 0 {
		cond.Arg = fieldStr[idx+1:]
		fieldStr = fieldStr[:idx]
	}
	if err := setField(&cond, fieldStr); err != nil {
		return Condition{}, err
	}

	switch cond.Op {
	case OpMatches:
		re, err := regexp.Compile(cond.Val)
		if err != nil {
			return Condition{}, fmt.Errorf("bad regex %q: %v", cond.Val, err)
		}
		cond.re = re
	case OpInCIDR:
		_, ipnet, err := net.ParseCIDR(cond.Val)
		if err != nil {
			return Condition{}, fmt.Errorf("bad CIDR %q: %v", cond.Val, err)
		}
		cond.cidr = ipnet
	case OpGt, OpLt:
		n, err := strconv.Atoi(cond.Val)
		if err != nil {
			return Condition{}, fmt.Errorf("numeric operand required for %q", cond.Op)
		}
		cond.num = n
	}
	if err := cond.validate(); err != nil {
		return Condition{}, err
	}
	return cond, nil
}

func setField(cond *Condition, field string) error {
	switch field {
	case "ip":
		cond.Field = FieldIP
	case "country":
		cond.Field = FieldCountry
	case "asn":
		cond.Field = FieldASN
	case "hostname", "host":
		cond.Field = FieldHostname
	case "path":
		cond.Field = FieldPath
	case "method":
		cond.Field = FieldMethod
	case "header":
		cond.Field = FieldHeader
	case "query":
		cond.Field = FieldQuery
	case "user_agent", "ua":
		cond.Field = FieldUserAgent
	case "bot_score":
		cond.Field = FieldBotScore
	case "attack_score":
		cond.Field = FieldAttackScore
	default:
		return fmt.Errorf("unknown condition field %q", field)
	}
	return nil
}

func Parse(id, name, input string) (*Rule, error) {
	toks, err := lex(input)
	if err != nil {
		return nil, fmt.Errorf("dsl parse %q: %w", input, err)
	}
	toks = normalizeStartsWith(toks)
	p := &parser{toks: toks}
	if err := p.expectIdent("IF"); err != nil {
		return nil, fmt.Errorf("dsl: %w", err)
	}

	rule := &Rule{ID: id, Name: name}
	for {
		cond, err := p.parseCondition()
		if err != nil {
			return nil, err
		}
		group := Group{Conds: []Condition{cond}}
		for p.peek().typ == tokIdent && strings.EqualFold(p.peek().val, "or") {
			p.next()
			c, err := p.parseCondition()
			if err != nil {
				return nil, err
			}
			group.Conds = append(group.Conds, c)
		}
		rule.Groups = append(rule.Groups, group)

		nt := p.peek()
		if nt.typ == tokIdent && strings.EqualFold(nt.val, "then") {
			break
		}
		if nt.typ == tokIdent && strings.EqualFold(nt.val, "and") {
			p.next()
			continue
		}
		return nil, fmt.Errorf("expected AND or THEN, got %q", nt.val)
	}

	if err := p.expectIdent("THEN"); err != nil {
		return nil, err
	}
	act := p.next()
	if act.typ != tokIdent {
		return nil, fmt.Errorf("expected action after THEN")
	}
	switch strings.ToUpper(act.val) {
	case "ALLOW":
		rule.Then = ActionAllow
	case "BLOCK":
		rule.Then = ActionBlock
	case "CHALLENGE":
		rule.Then = ActionChallenge
	case "LOG":
		rule.Then = ActionLog
	default:
		return nil, fmt.Errorf("unknown action %q", act.val)
	}

	if p.peek().typ != tokEOF {
		return nil, fmt.Errorf("unexpected trailing tokens after %q", act.val)
	}
	if len(rule.Groups) == 0 {
		return nil, fmt.Errorf("rule requires at least one condition")
	}
	return rule, nil
}

func normalizeStartsWith(toks []token) []token {
	var out []token
	for i := 0; i < len(toks); i++ {
		if strings.EqualFold(toks[i].val, "starts") && i+1 < len(toks) &&
			strings.EqualFold(toks[i+1].val, "with") {
			out = append(out, token{tokIdent, "starts_with"})
			i++
			continue
		}
		out = append(out, toks[i])
	}
	return out
}
