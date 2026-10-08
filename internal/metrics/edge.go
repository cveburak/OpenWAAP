package metrics

type Edge struct {
	registry *Registry

	RequestsTotal  *Counter
	RequestsDenied *Counter
	Latency        *Histogram
	Active         *Gauge
	RuleTriggers   *Counter
}

func (e *Edge) Registry() *Registry { return e.registry }

func NewEdge(r *Registry) *Edge {
	return &Edge{
		registry:       r,
		RequestsTotal:  r.Counter("waap_requests_total", "Requests evaluated by the edge, by final action.", "action"),
		RequestsDenied: r.Counter("waap_requests_denied_total", "Requests denied (not proxied to origin), by action and domain.", "action", "domain"),
		Latency:        r.Histogram("waap_request_latency_seconds", "Edge request latency (decision + origin round-trip), seconds."),
		Active:         r.Gauge("waap_active_requests", "Requests currently being handled by the edge."),
		RuleTriggers:   r.Counter("waap_rule_triggers_total", "Rules that fired, by rule id.", "rule_id"),
	}
}
