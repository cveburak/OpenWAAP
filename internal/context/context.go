package context

import (
	"net"
	"net/http"
	"net/url"
	"time"
)

type RequestContext struct {
	RequestID string
	Timestamp time.Time

	RemoteIP net.IP
	Port     int
	ASN      int
	Country  string

	BotScore      int
	BehaviorScore int

	BehaviorNewClient bool
	BehaviorCookie    string

	Method   string
	Path     string
	RawQuery string
	Host     string
	Headers  http.Header
	UA string

	Body []byte

	Domain string

	Matches []SignalMatch

	AttackScore int

	Decision string

	DecisionReasons []Reason

	HoneypotHit bool

	Processing time.Duration
}

type SignalMatch struct {
	Source string
	RuleID string
	Category string
	Points int
	Detail string
}

type Reason struct {
	Label     string `json:"label"`
	Points    int    `json:"points"`
	Threshold int    `json:"threshold,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
}

func (c *RequestContext) AddSignal(s SignalMatch) {
	c.Matches = append(c.Matches, s)
}

func (c *RequestContext) QueryParam(key string) string {
	values, err := url.ParseQuery(c.RawQuery)
	if err != nil {
		return ""
	}
	vs := values[key]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

func New(req *http.Request, requestID string) *RequestContext {
	remoteIP := net.ParseIP("0.0.0.0")
	if req.RemoteAddr != "" {
		if h, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			if ip := net.ParseIP(h); ip != nil {
				remoteIP = ip
			}
		} else if ip := net.ParseIP(req.RemoteAddr); ip != nil {
			remoteIP = ip
		}
	}
	return &RequestContext{
		RequestID: requestID,
		Timestamp: time.Now(),
		RemoteIP:  remoteIP,
		Method:    req.Method,
		Path:      req.URL.Path,
		RawQuery:  req.URL.RawQuery,
		Host:      req.Host,
		Headers:   req.Header.Clone(),
		UA:        req.UserAgent(),
	}
}
