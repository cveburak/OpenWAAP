package e2e

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/proxy"
	"github.com/openwaap/openwaap/internal/rules/managed"
	testorigin "github.com/openwaap/openwaap/test/origin"
	"github.com/openwaap/openwaap/test/simulate"
)

type captureSink struct {
	ch chan events.Event
}

func (c *captureSink) Name() string { return "e2e-capture" }
func (c *captureSink) Emit(_ context.Context, ev events.Event) error {
	select {
	case c.ch <- ev:
	default:
	}
	return nil
}

func TestFullEdgeIntegration(t *testing.T) {
	o, err := testorigin.New()
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()

	_, port, ok := strings.Cut(o.ListenerAddr(), ":")
	if !ok {
		t.Fatalf("cannot extract port from %s", o.ListenerAddr())
	}

	en := true
	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{ListenHTTPS: ":0"},
		Security: config.SecurityConfig{
			EngineFailMode:  config.FailOpen,
		},
		Domains: []config.DomainConfig{
			{
				Hostname: "example.com",
				Origin:   config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: port},
				Enabled:  &en,
				Honeypot: &config.HoneypotConfig{Enabled: true, AutoGenerate: true},
				WAF: config.WAFPolicy{
					Mode: config.WAFModeBlock,
					Managed: config.ManagedPolicy{
						RulesetVersion: managed.DefaultRulesetVersion,
						ParanoiaLevel:  1,
					},
				},
			},
		},
	}

	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 128})
	defer emit.Close()
	cap := &captureSink{ch: make(chan events.Event, 1024)}
	emit.AddSink(cap)

	handler, err := proxy.New(cfg, proxy.Options{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		Emit:   emit,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	res := simulate.RunWithHost(srv.URL, simulate.DefaultCases(), 15*time.Second, "example.com")

	t.Log(simulate.Report(res))

	failed := 0
	for _, r := range res {
		if !r.Passed {
			failed++
			t.Logf("case failure: %s -> %s", r.Case.Name, r.Reason)
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d simulator cases failed:\n%s", failed, len(res), simulate.Report(res))
	}

	if o.Requests() < 3 {
		t.Fatalf("expected benign requests to reach origin, got %d", o.Requests())
	}
	if o.Requests() >= int64(len(res)) {
		t.Fatalf("expected some requests to be blocked before origin, origin saw %d/%d",
			o.Requests(), len(res))
	}

	blocked := 0
	for {
		select {
		case ev := <-cap.ch:
			if ev.Action == events.ActionBlock {
				blocked++
			}
		case <-time.After(500 * time.Millisecond):
			goto drained
		}
	}
drained:
	if blocked == 0 {
		t.Fatal("expected blocked security events in the pipeline")
	}
}

func TestExplainableReasonsInEvent(t *testing.T) {
	o, err := testorigin.New()
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	_, port, ok := strings.Cut(o.ListenerAddr(), ":")
	if !ok {
		t.Fatalf("cannot extract port")
	}
	en := true
	cfg := &config.Config{
		Version:  "1",
		Server:   config.ServerConfig{ListenHTTPS: ":0"},
		Security: config.SecurityConfig{EngineFailMode: config.FailOpen},
		Domains: []config.DomainConfig{
			{
				Hostname: "example.com",
				Origin:   config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: port},
				Enabled:  &en,
				WAF: config.WAFPolicy{
					Mode:    config.WAFModeBlock,
					Managed: config.ManagedPolicy{RulesetVersion: managed.DefaultRulesetVersion, ParanoiaLevel: 1},
				},
			},
		},
	}
	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 64})
	defer emit.Close()
	cap := &captureSink{ch: make(chan events.Event, 8)}
	emit.AddSink(cap)
	handler, err := proxy.New(cfg, proxy.Options{Emit: emit})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	cases := []simulate.Case{{
		Name: "sqli union select", Path: "/products", Query: "id=1 UNION SELECT 1,2,3",
		Method: "GET", BlockedOK: true,
	}}
	res := simulate.RunWithHost(srv.URL, cases, 10*time.Second, "example.com")
	if len(res) != 1 || !res[0].Passed {
		t.Fatalf("expected the union-select case to be blocked: %+v", res)
	}

	select {
	case ev := <-cap.ch:
		if ev.Action != events.ActionBlock {
			t.Fatalf("expected BLOCK, got %s", ev.Action)
		}
		if len(ev.Reasons) == 0 {
			t.Fatal("expected explainable reasons on the blocked event")
		}
		found := false
		for _, r := range ev.Reasons {
			if strings.Contains(strings.ToUpper(r.Label), "SQL_INJECTION") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a SQL_INJECTION reason, got %+v", ev.Reasons)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected blocked event emission")
	}
}
