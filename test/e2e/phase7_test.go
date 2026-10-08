package e2e

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/metrics"
	"github.com/openwaap/openwaap/internal/ops"
	"github.com/openwaap/openwaap/internal/proxy"
	testorigin "github.com/openwaap/openwaap/test/origin"
)

func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(b)
}

func phase7Edge(t *testing.T, addOpts func(*proxy.Options)) (*httptest.Server, *events.Emitter) {
	t.Helper()
	o, err := testorigin.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	_, port, ok := strings.Cut(o.ListenerAddr(), ":")
	if !ok {
		t.Fatalf("cannot extract port from %s", o.ListenerAddr())
	}
	en := true
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{ListenHTTPS: ":0", ListenHTTP: ":0"},
		Security: config.SecurityConfig{
			EngineFailMode: config.FailOpen,
		},
		Domains: []config.DomainConfig{{
			Hostname: "example.com",
			Enabled:  &en,
			Origin:   config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: port},
			WAF: config.WAFPolicy{
				Mode:    config.WAFModeBlock,
				Managed: config.ManagedPolicy{RulesetVersion: "1", ParanoiaLevel: 1},
			},
		}},
	}

	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 1024})
	t.Cleanup(emit.Close)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	reg := metrics.NewRegistry()
	edge := metrics.NewEdge(reg)
	opsHandler := ops.New(reg, "phase7-test", nil)

	opts := proxy.Options{Logger: log, Emit: emit, Internal: opsHandler, Metrics: edge}
	if addOpts != nil {
		addOpts(&opts)
	}
	handler, err := proxy.New(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, emit
}

func TestOpsNamespaceAlwaysMounted(t *testing.T) {
	srv, _ := phase7Edge(t, nil)

	resp, err := http.Get(srv.URL + "/-/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("healthz: code=%d body=%s", resp.StatusCode, body)
	}

	resp, err = http.Get(srv.URL + "/-/readyz")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("readyz: code=%d body=%s", resp.StatusCode, body)
	}

	resp, err = http.Get(srv.URL + "/-/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(resp)
	for _, want := range []string{"waap_requests_total", "waap_request_latency_seconds", "waap_active_requests"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}

	resp, err = getWithHost("example.com", srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("origin pass-through: want 200 got %d", resp.StatusCode)
	}
}

func TestRequestMetricsAndEventEnrichment(t *testing.T) {
	srv, emit := phase7Edge(t, nil)

	sink := newCapturingSink()
	emit.AddSink(sink)

	resp, err := getWithHost("example.com", srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-WAAP-Request-Id") == "" {
		t.Fatal("missing X-WAAP-Request-Id header")
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("benign: want 200 got %d", resp.StatusCode)
	}

	resp, err = getWithHost("example.com", srv.URL+"/products?id=1+UNION+SELECT+1,2,3")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("block mode should reject the SQLi, got %d", resp.StatusCode)
	}

	var blocked, allowed *events.Event
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ev := sink.next()
		if ev == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if ev.Action == events.ActionBlock && blocked == nil {
			blocked = ev
		} else if ev.Action == events.ActionAllow && allowed == nil {
			allowed = ev
		}
		if blocked != nil && allowed != nil {
			break
		}
	}
	if blocked == nil {
		t.Fatal("no BLOCK event captured")
	}
	if allowed == nil {
		t.Fatal("no ALLOW event captured")
	}
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked event status_code: want 403 got %d", blocked.StatusCode)
	}
	if blocked.DurationMs < 0 {
		t.Fatalf("blocked event duration_ms must be >= 0: %+v", blocked)
	}
	if allowed.RequestID == "" {
		t.Fatal("allowed event missing request id")
	}

	resp, err = http.Get(srv.URL + "/-/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(resp)
	for _, want := range []string{
		`waap_requests_total{action="ALLOW"}`,
		`waap_requests_total{action="BLOCK"}`,
		`waap_requests_denied_total{action="BLOCK",domain="example.com"}`,
		`waap_rule_triggers_total`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
}
