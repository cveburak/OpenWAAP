package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Registry struct {
	mu         sync.RWMutex
	counters   []*Counter
	gauges     []*Gauge
	histograms []*Histogram
}

func NewRegistry() *Registry { return &Registry{} }

type Counter struct {
	name      string
	help      string
	labelKeys []string
	mu        sync.RWMutex
	values    map[string]uint64
}

type Gauge struct {
	name      string
	help      string
	labelKeys []string
	mu        sync.RWMutex
	values    map[string]int64
}

type Histogram struct {
	name      string
	help      string
	labelKeys []string
	mu        sync.Mutex
	values    map[string]*histValue
}

type histValue struct {
	buckets []uint64
	count   uint64
	sum     float64
}

func (r *Registry) Counter(name, help string, labelKeys ...string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.counters {
		if c.name == name && sameLabels(c.labelKeys, labelKeys) {
			return c
		}
	}
	c := &Counter{name: name, help: help, labelKeys: labelKeys, values: map[string]uint64{}}
	r.counters = append(r.counters, c)
	return c
}

func (r *Registry) Gauge(name, help string, labelKeys ...string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, g := range r.gauges {
		if g.name == name && sameLabels(g.labelKeys, labelKeys) {
			return g
		}
	}
	g := &Gauge{name: name, help: help, labelKeys: labelKeys, values: map[string]int64{}}
	r.gauges = append(r.gauges, g)
	return g
}

func (r *Registry) Histogram(name, help string, labelKeys ...string) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range r.histograms {
		if h.name == name && sameLabels(h.labelKeys, labelKeys) {
			return h
		}
	}
	h := &Histogram{name: name, help: help, labelKeys: labelKeys, values: map[string]*histValue{}}
	r.histograms = append(r.histograms, h)
	return h
}

func sameLabels(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *Counter) Incr(labelValues ...string) { c.Incrby(1, labelValues...) }

func (c *Counter) Incrby(delta uint64, labelValues ...string) {
	if c == nil {
		return
	}
	key := encode(c.labelKeys, labelValues)
	c.mu.Lock()
	c.values[key] += delta
	c.mu.Unlock()
}

func (c *Counter) Get() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var total uint64
	for _, v := range c.values {
		total += v
	}
	return total
}

func (g *Gauge) Set(value int64, labelValues ...string) {
	if g == nil {
		return
	}
	key := encode(g.labelKeys, labelValues)
	g.mu.Lock()
	g.values[key] = value
	g.mu.Unlock()
}

func (g *Gauge) Add(delta int64, labelValues ...string) {
	if g == nil {
		return
	}
	key := encode(g.labelKeys, labelValues)
	g.mu.Lock()
	g.values[key] += delta
	g.mu.Unlock()
}

var bucketBounds = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func (h *Histogram) Observe(value float64, labelValues ...string) {
	if h == nil || value < 0 {
		return
	}
	key := encode(h.labelKeys, labelValues)
	h.mu.Lock()
	hv := h.values[key]
	if hv == nil {
		hv = &histValue{buckets: make([]uint64, len(bucketBounds))}
		h.values[key] = hv
	}
	hv.sum += value
	hv.count++
	for i, b := range bucketBounds {
		if value <= b {
			hv.buckets[i]++
		}
	}
	h.mu.Unlock()
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		r.write(w)
	})
}

func (r *Registry) write(w io.Writer) {
	r.mu.RLock()
	counters := append([]*Counter(nil), r.counters...)
	gauges := append([]*Gauge(nil), r.gauges...)
	histograms := append([]*Histogram(nil), r.histograms...)
	r.mu.RUnlock()

	sort.Slice(counters, func(i, j int) bool { return counters[i].name < counters[j].name })
	sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })
	sort.Slice(histograms, func(i, j int) bool { return histograms[i].name < histograms[j].name })

	for _, c := range counters {
		r.meta(w, c.name, c.help, "counter")
		c.writeSeries(w)
	}
	for _, g := range gauges {
		r.meta(w, g.name, g.help, "gauge")
		g.writeSeries(w)
	}
	for _, h := range histograms {
		r.meta(w, h.name, h.help, "histogram")
		h.writeSeries(w)
	}
}

func (r *Registry) meta(w io.Writer, name, help, typ string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

func (c *Counter) writeSeries(w io.Writer) {
	c.mu.RLock()
	rows := make([]string, 0, len(c.values))
	for k, v := range c.values {
		rows = append(rows, c.name+render(c.labelKeys, k)+" "+strconv.FormatUint(v, 10))
	}
	c.mu.RUnlock()
	sort.Strings(rows)
	for _, r := range rows {
		fmt.Fprintln(w, r)
	}
}

func (g *Gauge) writeSeries(w io.Writer) {
	g.mu.RLock()
	rows := make([]string, 0, len(g.values))
	for k, v := range g.values {
		rows = append(rows, g.name+render(g.labelKeys, k)+" "+strconv.FormatInt(v, 10))
	}
	g.mu.RUnlock()
	sort.Strings(rows)
	for _, r := range rows {
		fmt.Fprintln(w, r)
	}
}

func (h *Histogram) writeSeries(w io.Writer) {
	h.mu.Lock()
	type kv struct {
		labels string
		val    *histValue
	}
	rows := make([]kv, 0, len(h.values))
	for k, v := range h.values {
		rows = append(rows, kv{labels: render(h.labelKeys, k), val: v})
	}
	h.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].labels < rows[j].labels })

	for _, rv := range rows {
		labels := rv.labels
		var running uint64
		for i, b := range bucketBounds {
			running += rv.val.buckets[i]
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, withLe(labels, b), running)
		}
		fmt.Fprintf(w, "%s_count%s %d\n", h.name, labels, rv.val.count)
		fmt.Fprintf(w, "%s_sum%s %g\n", h.name, labels, rv.val.sum)
	}
}

func encode(keys, vals []string) string {
	switch len(keys) {
	case 0:
		return ""
	case 1:
		if len(vals) > 0 {
			return vals[0]
		}
		return ""
	default:
		var sb strings.Builder
		for i := range keys {
			if i > 0 {
				sb.WriteByte('\x1f')
			}
			if i < len(vals) {
				sb.WriteString(vals[i])
			}
		}
		return sb.String()
	}
}

func render(keys []string, key string) string {
	if len(keys) == 0 {
		return ""
	}
	vals := strings.Split(key, "\x1f")
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		v := ""
		if i < len(vals) {
			v = vals[i]
		}
		sb.WriteString(k)
		sb.WriteString("=\"")
		sb.WriteString(v)
		sb.WriteByte('"')
	}
	sb.WriteByte('}')
	return sb.String()
}

func withLe(labels string, le float64) string {
	leS := strconv.FormatFloat(le, 'f', -1, 64)
	if labels == "" {
		return "{le=\"" + leS + "\"}"
	}
	return strings.TrimSuffix(labels, "}") + ", le=\"" + leS + "\"}"
}
