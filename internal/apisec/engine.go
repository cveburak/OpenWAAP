package apisec

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

type Route struct {
	Path          string
	Method        string
	AuthNone      bool
	RequestSchema *schema
	SchemaJSON    string
}

type Engine struct {
	jwt    *JWTConfig
	routes []*Route
	policy config.APIPolicyConfig
	now    func() time.Time
}

func NewEngine(cfg *config.APISecurityConfig, now func() time.Time) (*Engine, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	e := &Engine{policy: cfg.Policy}
	if cfg.JWT != nil {
		jwt, err := NewJWTConfig(
			cfg.JWT.Algorithm,
			cfg.JWT.Secret,
			cfg.JWT.PublicKeyPEM,
			cfg.JWT.Issuer,
			cfg.JWT.Audiences,
			cfg.JWT.RequiredClaims,
			cfg.JWT.LeewaySeconds,
			cfg.JWT.Header,
		)
		if err != nil {
			return nil, err
		}
		e.jwt = jwt
	}
	for _, r := range cfg.Routes {
		route := &Route{Path: r.Path, Method: strings.ToUpper(r.Method), AuthNone: r.AuthNone, SchemaJSON: r.RequestSchema}
		if r.RequestSchema != "" {
			s, err := compileSchema([]byte(r.RequestSchema))
			if err != nil {
				return nil, fmt.Errorf("route %q: %w", r.Path, err)
			}
			route.RequestSchema = s
		}
		e.routes = append(e.routes, route)
	}
	if now != nil {
		e.now = now
	} else {
		e.now = time.Now
	}
	return e, nil
}

type Result struct {
	Action config.Action
	StatusHint int
	Reason string
	RuleID string
	Matched bool
}

func (e *Engine) Evaluate(r *http.Request, body []byte) Result {
	var route *Route
	path := r.URL.Path
	for _, rt := range e.routes {
		if !pathMatches(rt.Path, path) {
			continue
		}
		if rt.Method != "" && rt.Method != strings.ToUpper(r.Method) {
			continue
		}
		route = rt
		break
	}

	action := config.ActionAllow
	var reason, ruleID string
	statusHint := 0

	if route != nil {
		if !route.AuthNone && e.jwt != nil {
			token, presented := e.extractToken(r)
			ruleID = "api.jwt:" + route.Path
			if _, err := e.jwt.Verify(token, e.now()); !presented || err != nil {
				reason = authFailureReason(presented, err)
				if e.policy.AuthnRequired {
					action = config.ActionUnauthorized
					statusHint = http.StatusUnauthorized
				} else {
					action = noAuthFallback(e.policy)
				}
				return Result{Action: action, StatusHint: statusHint, Reason: reason, RuleID: ruleID, Matched: true}
			}
		}

		if e.policy.ValidateSchema && route.RequestSchema != nil && len(body) > 0 {
			ruleID = "api.schema:" + route.Path
			var doc any
			dec := json.NewDecoder(strings.NewReader(string(body)))
			dec.UseNumber()
			if err := dec.Decode(&doc); err != nil {
				reason = "invalid JSON body: " + err.Error()
				return Result{Action: config.ActionBlock, Reason: reason, RuleID: ruleID, Matched: true}
			} else if err := route.RequestSchema.Validate(doc, "body"); err != nil {
				reason = err.Error()
				return Result{Action: config.ActionBlock, Reason: reason, RuleID: ruleID, Matched: true}
			}
		}

		if ov := e.policy.Override; ov != nil {
			action = *ov
			reason = "api.policy.override:" + route.Path
			return Result{Action: action, StatusHint: statusHint, Reason: reason, RuleID: "api.override:" + route.Path, Matched: true}
		}
		return Result{Action: config.ActionAllow, Reason: "api route matched, validated", RuleID: "api." + route.Path, Matched: true}
	}

	if e.jwt != nil && e.policy.AuthnRequired {
		token, presented := e.extractToken(r)
		if _, err := e.jwt.Verify(token, e.now()); !presented || err != nil {
			reason = "api.jwt:uncovered:" + authFailureReason(presented, err)
			return Result{Action: config.ActionUnauthorized, StatusHint: http.StatusUnauthorized, Reason: reason, RuleID: "api.jwt:uncovered", Matched: true}
		}
	}
	return Result{Action: config.ActionAllow, Matched: false}
}

func (e *Engine) extractToken(r *http.Request) (string, bool) {
	if e.jwt == nil {
		return "", false
	}
	header := e.jwt.Header
	if header == "" {
		header = "Authorization"
	}
	raw := r.Header.Get(header)
	if raw == "" {
		return "", false
	}
	t := tokenFromHeader(raw)
	return t, t != ""
}

func authFailureReason(presented bool, err error) string {
	if !presented {
		return "missing token"
	}
	return err.Error()
}

func pathMatches(prefix, path string) bool {
	if prefix == "" {
		return true
	}
	p := strings.TrimPrefix(path, "/")
	pr := strings.Trim(prefix, "/")
	return p == pr || strings.HasPrefix(p, pr+"/")
}

func noAuthFallback(p config.APIPolicyConfig) config.Action {
	if p.NoAuthAction != "" {
		return p.NoAuthAction
	}
	return config.ActionAllow
}

