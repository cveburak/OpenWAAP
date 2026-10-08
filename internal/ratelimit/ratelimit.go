package ratelimit

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/metrics"
)

type Backend interface {
	Observe(ctx context.Context, ruleKey string, window time.Duration, now time.Time) (int, error)
}

type Engine struct {
	limits []config.RateLimitRule

	backend Backend

	mu sync.Mutex
	counts map[string]*counter

	MaxCountKeys int

	now func() time.Time

	degradedCounter *metrics.Counter
	degradedDomain  string
}

type counter struct {
	mu sync.Mutex
	at []time.Time
}

func (e *Engine) SetDegradedCounter(c *metrics.Counter, domain string) {
	e.degradedCounter = c
	e.degradedDomain = domain
}

type Outcome struct {
	Action config.Action
	Rule *config.RateLimitRule
	Count int
	RetryAfter int
}

type Request struct {
	Domain  string
	IP      string
	Path    string
	Method  string
	Headers http.Header
}

func New(limits []config.RateLimitRule, now func() time.Time) *Engine {
	return NewWithBackend(limits, now, nil)
}

func NewWithBackend(limits []config.RateLimitRule, now func() time.Time, backend Backend) *Engine {
	active := make([]config.RateLimitRule, 0, len(limits))
	for _, l := range limits {
		if l.Active() {
			active = append(active, l)
		}
	}
	nt := time.Now
	if now != nil {
		nt = now
	}
	return &Engine{limits: active, backend: backend, counts: map[string]*counter{}, now: nt}
}

func (e *Engine) Check(req Request) Outcome {
	var worst Outcome
	worst.Action = config.ActionAllow
	for i := range e.limits {
		rule := &e.limits[i]
		if !ScopeMatches(*rule, req) {
			continue
		}
		count := e.observe(rule, keyFor(rule, req))
		oc := e.outcome(rule, count)
		if worst.Rule == nil || severity(oc.Action) > severity(worst.Action) {
			worst = oc
		}
	}
	return worst
}

func (e *Engine) outcome(rule *config.RateLimitRule, count int) Outcome {
	out := Outcome{Action: config.ActionAllow, Rule: rule, Count: count, RetryAfter: rule.RetryAfter()}
	if count <= rule.Max {
		return out
	}
	if rule.ThrottleMax != nil && count <= *rule.ThrottleMax {
		out.Action = config.ActionThrottle
		return out
	}
	out.Action = rule.Action
	if out.Action == "" || !out.Action.Valid() {
		out.Action = config.ActionBlock
	}
	return out
}

func (e *Engine) observe(rule *config.RateLimitRule, key string) int {
	ck := rule.ID + "\x00" + key
	if e.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), e.backendTimeout())
		n, err := e.backend.Observe(ctx, ck, rule.Window.D(), e.now())
		cancel()
		if err == nil {
			return n
		}
		if e.degradedCounter != nil {
			e.degradedCounter.Incr(e.degradedDomain)
		}
	}
	return e.memoryObserve(ck, rule.Window.D())
}

func (e *Engine) backendTimeout() time.Duration { return 250 * time.Millisecond }

func (e *Engine) memoryObserve(ck string, window time.Duration) int {
	now := e.now()
	e.mu.Lock()
	c := e.counts[ck]
	if c == nil {
		if len(e.counts) >= e.maxKeys() {
			e.evictLocked()
		}
		c = &counter{}
		e.counts[ck] = c
	}
	e.mu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = prune(c.at, now, window)
	c.at = append(c.at, now)
	return len(c.at)
}

const defaultMaxCountKeys = 100000

func (e *Engine) maxKeys() int {
	if e.MaxCountKeys > 0 {
		return e.MaxCountKeys
	}
	return defaultMaxCountKeys
}

func (e *Engine) evictLocked() {
	target := e.maxKeys() * 9 / 10
	for k := range e.counts {
		if len(e.counts) <= target {
			return
		}
		delete(e.counts, k)
	}
}

func keyFor(r *config.RateLimitRule, req Request) string {
	switch r.Scope {
	case config.ScopeIP:
		return req.IP
	case config.ScopePath:
		return req.Path
	case config.ScopeIPPath:
		return req.IP + "|" + req.Path
	case config.ScopeIPMethod:
		return req.IP + "|" + strings.ToUpper(req.Method)
	case config.ScopeHeader:
		return strings.ToLower(r.Header) + "=" + req.Headers.Get(r.Header)
	default:
		return "?"
	}
}

func prune(at []time.Time, now time.Time, window time.Duration) []time.Time {
	if len(at) == 0 {
		return at
	}
	cutoff := now.Add(-window)
	i := 0
	for i < len(at) && at[i].Before(cutoff) {
		i++
	}
	return at[i:]
}

func severity(a config.Action) int {
	switch a {
	case config.ActionBlock:
		return 5
	case config.ActionRateLimit:
		return 4
	case config.ActionChallenge:
		return 3
	case config.ActionThrottle:
		return 2
	default:
		return 1
	}
}

func ScopeMatches(r config.RateLimitRule, req Request) bool {
	switch r.Scope {
	case config.ScopeIP:
		return req.IP != ""
	case config.ScopePath:
		return r.Path == "" || r.Path == "*" || r.Path == req.Path
	case config.ScopeIPPath:
		if !(r.Path == "" || r.Path == "*" || r.Path == req.Path) {
			return false
		}
		return req.IP != ""
	case config.ScopeIPMethod:
		m := r.Method
		return m == "" || strings.EqualFold(m, req.Method)
	case config.ScopeHeader:
		return r.Header != "" && req.Headers.Get(r.Header) != ""
	default:
		return false
	}
}
