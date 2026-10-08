package e2e

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/geo"
	"github.com/openwaap/openwaap/internal/proxy"
	"github.com/openwaap/openwaap/internal/ratelimit"
	testorigin "github.com/openwaap/openwaap/test/origin"
)

func writeGeoFixture(t *testing.T) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "GeoLite2-Country",
		RecordSize:              24,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	if err := w.Insert(lo, mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("LO"),
		},
		"autonomous_system_number":       mmdbtype.Uint32(1337),
		"autonomous_system_organization": mmdbtype.String("TestLoopbackNet"),
	}); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/fixture.mmdb"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}

func phase6Edge(t *testing.T, mutate func(*config.Config), addOpts func(*proxy.Options)) (*httptest.Server, *events.Emitter) {
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
	dc := config.DomainConfig{
		Hostname: "example.com",
		Enabled:  &en,
		Origin:   config.OriginConfig{Scheme: "http", Host: "127.0.0.1", Port: port},
		WAF: config.WAFPolicy{
			Mode:    config.WAFModeDetection,
			Managed: config.ManagedPolicy{RulesetVersion: "1", ParanoiaLevel: 1},
		},
	}
	cfg := &config.Config{
		Version:  "1",
		Server:   config.ServerConfig{ListenHTTPS: ":0", ListenHTTP: ":0"},
		Security: config.SecurityConfig{EngineFailMode: config.FailOpen},
		Domains:  []config.DomainConfig{dc},
	}
	mutate(cfg)

	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 1024})
	t.Cleanup(emit.Close)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	opts := proxy.Options{Logger: log, Emit: emit}
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

func TestGeoEnrichesCustomRuleAndEvents(t *testing.T) {
	geoProvider, err := geo.Open(writeGeoFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer geoProvider.Close()

	srv, emit := phase6Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].WAF.Custom = []config.CustomRuleConf{{
			ID: "block-lo", Name: "Block test country", Enabled: true,
			DSL: `IF country == "LO" THEN BLOCK`,
		}}
	}, func(opts *proxy.Options) { opts.Geo = geoProvider })

	resp, err := getWithHost("example.com", srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("custom country rule must block, got %d", resp.StatusCode)
	}

	sink := newCapturingSink()
	emit.AddSink(sink)
	resp, err = getWithHost("example.com", srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ev := sink.next()
		if ev == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if ev.Country != "LO" || ev.ASN != 1337 {
			t.Fatalf("event must carry geo enrichment, got country=%q asn=%d", ev.Country, ev.ASN)
		}
		return
	}
	t.Fatal("no event captured")
}

func TestRedisRateLimitSharedAcrossEdges(t *testing.T) {
	mr := miniredis.RunT(t)
	backend, client, err := ratelimit.NewRedisBackendFromConfig(config.RedisConfig{Address: mr.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer backend.Close()

	attach := func(opts *proxy.Options) { opts.RateLimitBackend = backend }
	srv1, _ := phase6Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].RateLimit = &config.RateLimitConfig{
			Enabled: true,
			Limits: []config.RateLimitRule{{
				ID: "shared-ip", Enabled: true, Scope: config.ScopeIP,
				Max: 2, Window: config.Duration(60 * time.Second),
				Action: config.ActionRateLimit,
			}},
		}
	}, attach)
	srv2, _ := phase6Edge(t, func(cfg *config.Config) {
		cfg.Domains[0].RateLimit = &config.RateLimitConfig{
			Enabled: true,
			Limits: []config.RateLimitRule{{
				ID: "shared-ip", Enabled: true, Scope: config.ScopeIP,
				Max: 2, Window: config.Duration(60 * time.Second),
				Action: config.ActionRateLimit,
			}},
		}
	}, attach)

	code := func(u string) int {
		resp, err := getWithHost("example.com", u+"/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if got := code(srv1.URL); got != http.StatusOK {
		t.Fatalf("edge1 hit1: want 200 got %d", got)
	}
	if got := code(srv1.URL); got != http.StatusOK {
		t.Fatalf("edge1 hit2: want 200 got %d", got)
	}
	if got := code(srv2.URL); got != http.StatusTooManyRequests {
		t.Fatalf("edge2 hit3 must hit the shared limit: want 429 got %d", got)
	}
}

type capturingSink struct {
	ch chan events.Event
}

func newCapturingSink() *capturingSink {
	return &capturingSink{ch: make(chan events.Event, 128)}
}

func (c *capturingSink) Name() string { return "e2e-capture" }

func (c *capturingSink) Emit(_ context.Context, ev events.Event) error {
	select {
	case c.ch <- ev:
	default:
	}
	return nil
}

func (c *capturingSink) next() *events.Event {
	select {
	case ev := <-c.ch:
		return &ev
	default:
		return nil
	}
}

func getWithHost(host, u string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	return http.DefaultClient.Do(req)
}
