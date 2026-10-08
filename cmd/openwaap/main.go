package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/openwaap/openwaap/internal/config"
	reqctx "github.com/openwaap/openwaap/internal/context"
	"github.com/openwaap/openwaap/internal/dashboard"
	"github.com/openwaap/openwaap/internal/events"
	"github.com/openwaap/openwaap/internal/geo"
	"github.com/openwaap/openwaap/internal/logging"
	"github.com/openwaap/openwaap/internal/metrics"
	"github.com/openwaap/openwaap/internal/ops"
	"github.com/openwaap/openwaap/internal/proxy"
	"github.com/openwaap/openwaap/internal/ratelimit"
	"github.com/openwaap/openwaap/internal/selfsigned"
	"github.com/openwaap/openwaap/internal/siem"
)

var version = "1.0"

func main() {
	var (
		configPath = flag.String("config", "config/openwaap.yaml", "path to configuration file")
		logPath    = flag.String("log", "logs/openwaap-events.jsonl", "security event log output (JSONL)")
		showVer    = flag.Bool("version", false, "print version and exit")
		justCheck  = flag.Bool("validate", false, "validate configuration and exit")
		doBackup   = flag.Bool("backup", false, "snapshot config, logs and certs to a tar.gz")
		backupOut  = flag.String("out", "", "backup output path (default backups/openwaap-backup-<ts>.tar.gz)")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("openwaap %s\n", version)
		return
	}

	if *justCheck {
		if err := runValidate(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *doBackup {
		if err := runBackup(*configPath, *logPath, *backupOut); err != nil {
			fmt.Fprintf(os.Stderr, "backup failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, setupMode, err := loadForStart(*configPath, log)
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}

	if setupMode {
		cp := cfg.Dashboard.ConsolePath
		if cp == "" {
			cp = "/-"
		}
		log.Warn("first-run setup mode: guided installer at https://<host>" + cfg.Server.ListenHTTPS + strings.TrimRight(cp, "/") + "/setup")
		log.Info("setup: default listeners", "https", cfg.Server.ListenHTTPS, "http", cfg.Server.ListenHTTP)
		if !selfsigned.Exists(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile) {
			certDir := selfsigned.DefaultDir(*configPath)
			cert, key := filepath.Join(certDir, "edge.pem"), filepath.Join(certDir, "edge.key")
			san := []string{"localhost", "openwaap-edge"}
			if hn, hErr := os.Hostname(); hErr == nil && hn != "" {
				san = append(san, hn)
			}
			if err := selfsigned.Generate(cert, key, san); err != nil {
				log.Error("setup: cannot provision boot TLS certificate", "err", err)
				os.Exit(1)
			}
			cfg.Server.TLSCertFile = cert
			cfg.Server.TLSKeyFile = key
			log.Info("setup: boot TLS certificate generated", "cert", cert)
		}
	}

	emit := events.NewEmitter(events.EmitterOptions{BufferSize: 4096, FailOpen: true})
	defer emit.Close()
	jsonl, err := logging.NewJSONLSinkWithOptions(*logPath, logging.JSONLOptions{
		MaxBytes: int64(cfg.Log.RotationMaxMB) * 1024 * 1024,
		Keep:     cfg.Log.RotationKeep,
	})
	if err != nil {
		log.Error("cannot open event log", "path", *logPath, "err", err)
		os.Exit(1)
	}
	defer jsonl.Close()
	emit.AddSink(jsonl)

	var geoProvider *geo.Provider
	if cfg.Security.GeoIP != nil && cfg.Security.GeoIP.Enabled {
		geoProvider, err = geo.Open(cfg.Security.GeoIP.DBPath)
		if err != nil {
			log.Error("geoip: cannot open database", "path", cfg.Security.GeoIP.DBPath, "err", err)
			os.Exit(1)
		}
		defer geoProvider.Close()
		log.Info("geoip enrichment enabled", "db", cfg.Security.GeoIP.DBPath)
	}

	var rateBackend ratelimit.Backend
	var redisClient *redis.Client
	if cfg.Security.Store.Type == "redis" {
		var err error
		rateBackend, redisClient, err = ratelimit.NewRedisBackendFromConfig(cfg.Security.Store.Redis)
		if err != nil {
			log.Error("store: cannot connect to redis", "addr", cfg.Security.Store.Redis.Address, "err", err)
			os.Exit(1)
		}
		defer redisClient.Close()
		log.Info("distributed rate-limit store enabled", "addr", cfg.Security.Store.Redis.Address)
	}

	siemSinks, siemClosers, err := siem.NewSinks(cfg.Security.SIEM, log)
	if err != nil {
		log.Error("siem: configuration error", "err", err)
		os.Exit(1)
	}
	for _, s := range siemSinks {
		emit.AddSink(s)
	}
	defer func() {
		for _, stop := range siemClosers {
			stop()
		}
	}()

	metricRegistry := metrics.NewRegistry()
	edgeMetrics := metrics.NewEdge(metricRegistry)
	emit.AttachMetrics(
		metricRegistry.Counter("waap_events_dropped_total", "Events dropped because the emitter buffer was full."),
		metricRegistry.Counter("waap_event_sink_errors_total", "Event sink errors surfaced when fail-open is disabled."),
	)

	var readyChecks []ops.NamedCheck
	if redisClient != nil {
		checkRedis := func(ctx context.Context) error {
			if err := redisClient.Ping(ctx).Err(); err != nil {
				return fmt.Errorf("redis: %w", err)
			}
			return nil
		}
		readyChecks = append(readyChecks, ops.Named("redis", checkRedis))
	}
	if geoProvider != nil {
		readyChecks = append(readyChecks, ops.Named("geoip", func(ctx context.Context) error {
			if _, err := os.Stat(cfg.Security.GeoIP.DBPath); err != nil {
				return fmt.Errorf("geoip db: %w", err)
			}
			return nil
		}))
	}

	releasedCh := make(chan struct{})
	ctrl := &edgeController{cfgPath: *configPath, cfg: cfg, log: log, released: releasedCh, spawned: make(chan struct{})}
	innerHandler, rootConsoleHandler, challengePage, challengePassed := buildInternal(cfg, emit, ctrl, log)
	opsHandler := ops.New(metricRegistry, version, innerHandler, readyChecks...)

	handler, err := proxy.New(cfg, proxy.Options{
		Logger:           log,
		Emit:             emit,
		Internal:         opsHandler,
		ChallengePage:    challengePage,
		ChallengePassed:  challengePassed,
		Geo:              geoProvider,
		RateLimitBackend: rateBackend,
		Metrics:          edgeMetrics,
		DashPath:         cfg.Dashboard.ConsolePath,
	})
	if err != nil {
		log.Error("cannot build edge handler", "err", err)
		os.Exit(1)
	}
	ctrl.edge = handler

	server := proxy.NewServer(
		handler,
		cfg.Server.ListenHTTPS,
		cfg.Server.ListenHTTP,
		cfg.Server.TLSCertFile,
		cfg.Server.TLSKeyFile,
		log,
	)

	var adminSrv *http.Server
	if cfg.Dashboard.Enabled && cfg.Dashboard.Listen != "" {
		adminHandler := innerHandler
		if rootConsoleHandler != nil {
			adminHandler = rootConsoleHandler
		}
		if adminHandler != nil {
			adminSrv = &http.Server{
				Addr:              cfg.Dashboard.Listen,
				Handler:           adminHandler,
				ReadHeaderTimeout: 10 * time.Second,
			}
			go func() {
				log.Info("dashboard listener starting", "listen", cfg.Dashboard.Listen)
				if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Error("dashboard listener stopped", "err", err)
				}
			}()
		} else {
			log.Warn("dashboard.listen configured but dashboard disabled", "listen", cfg.Dashboard.Listen)
		}
	}

	log.Info("openwaap starting", "version", version, "domains", len(cfg.Domains),
		"fail_mode", cfg.Security.EngineFailMode,
		"challenge_enabled", cfg.Security.Challenge.Enabled,
		"dashboard_enabled", cfg.Dashboard.Enabled)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctrl.stop = stop

	runErr := server.Run(ctx)
	if runErr != nil {
		log.Error("edge server stopped", "err", runErr)
		os.Exit(1)
	}

	if adminSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := adminSrv.Shutdown(shutdownCtx); err != nil {
			log.Warn("admin listener shutdown", "err", err)
		}
		cancel()
	}

	close(releasedCh)
	if geoProvider != nil {
		geoProvider.Close()
	}
	if emit != nil {
		emit.Close()
	}
	ctrl.waitForRestart()
	log.Info("openwaap stopped gracefully")
}

func loadForStart(path string, log *slog.Logger) (*config.Config, bool, error) {
	cfg, err := config.Load(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, false, err
		}
		log.Warn("no configuration file found; entering guided setup",
			"path", path, "installer", "/-/setup")
		first := setupDefaultConfig()
		return first, true, nil
	}
	if cfg.SetupPending {
		log.Warn("configuration is marked setup_pending; resuming guided setup",
			"path", path, "installer", "/-/setup")
		return cfg, true, nil
	}
	return cfg, false, nil
}

func setupDefaultConfig() *config.Config {
	cfg := config.Default()
	cfg.SetupPending = true
	cfg.Server.ListenHTTPS = ":8443"
	cfg.Server.ListenHTTP = ":8080"
	cfg.Server.TLSCertFile = ""
	cfg.Server.TLSKeyFile = ""
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.AdminUser = ""
	cfg.Dashboard.AdminPassword = ""
	cfg.Domains = nil
	return cfg
}

func buildInternal(cfg *config.Config, emit *events.Emitter, ctrl *edgeController, log *slog.Logger) (http.Handler, http.Handler, func(http.ResponseWriter, *http.Request), func(*reqctx.RequestContext) bool) {
	panel := cfg.Dashboard.Enabled || cfg.Security.Challenge.Enabled
	if !panel {
		return nil, nil, nil, nil
	}
	signer := dashboard.NewSigner(cfg.Security.HMACSecret)

	var store *dashboard.Store
	if cfg.Dashboard.Enabled {
		store = dashboard.NewStore(cfg.Dashboard.MaxEvents, nil)
		emit.AddSink(store)
	}

	chlg := dashboard.NewChallengeManager(signer, cfg.Security.Challenge, nil)
	hc := dashboard.HandlerConfig{
		Store:             store,
		Signer:            signer,
		Challenge:         chlg,
		Panel:             ctrl,
		Admin:             cfg.Dashboard.Enabled,
		AdminUser:         cfg.Dashboard.AdminUser,
		AdminPassword:     cfg.Dashboard.AdminPassword,
		SessionTTL:        cfg.Dashboard.SessionTTL.D(),
		DashboardAssetTag: version,
		SetupPending:      cfg.SetupPending,
		ConfigPath:        ctrl.cfgPath,
		AdminAllowlist:    parseAdminAllowlist(cfg.Dashboard.AdminAllowlist),
		ConsolePath:       cfg.Dashboard.ConsolePath,
		LoginRateLimitAttempts: cfg.Dashboard.LoginRateLimitAttempts,
		LoginRateLimitWindow:   cfg.Dashboard.LoginRateLimitWindow.D(),
	}
	inner := dashboard.NewHandler(hc)
	rootHc := hc
	rootHc.RootConsole = true
	root := dashboard.NewHandler(rootHc)
	page := func(w http.ResponseWriter, r *http.Request) {
		inner.ServeChallengePage(w, r, r.URL.EscapedPath())
	}
	passed := func(c *reqctx.RequestContext) bool {
		return chlg.VerifyAccess(c.RemoteIP.String(), c.Headers, time.Now())
	}
	if !cfg.Security.Challenge.Enabled {
		page, passed = nil, nil
	}
	log.Info("internal endpoints enabled", "dashboard", cfg.Dashboard.Enabled,
		"challenge", cfg.Security.Challenge.Enabled)
	return inner, root, page, passed
}

func parseAdminAllowlist(entries []string) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p)
			continue
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

type edgeController struct {
	cfgPath    string
	log        *slog.Logger
	edge       *proxy.Handler
	stop       context.CancelFunc
	released   chan struct{}
	spawned    chan struct{}
	restarting bool

	mu  sync.RWMutex
	cfg *config.Config
}

func (c *edgeController) Config() *config.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

func (c *edgeController) Apply(cfg *config.Config) ([]string, error) {
	old := c.Config()
	if touched := config.UnmaskSecrets(cfg, old); len(touched) > 0 {
		c.log.Info("panel: restored masked secret fields from live config", "fields", touched)
	}
	if err := cfg.NormalizeAdminPassword(); err != nil {
		return nil, fmt.Errorf("normalize admin password: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Save(c.cfgPath); err != nil {
		return nil, fmt.Errorf("persist config: %w", err)
	}
	saved, err := config.Load(c.cfgPath)
	if err != nil {
		return nil, fmt.Errorf("reload saved config: %w", err)
	}
	restart := restartRequired(old, saved)
	if c.edge != nil {
		if err := c.edge.Reload(saved); err != nil {
			return nil, fmt.Errorf("live apply: %w", err)
		}
	}
	c.mu.Lock()
	c.cfg = saved
	c.mu.Unlock()
	c.log.Info("panel: configuration applied", "restart_required", restart)
	return restart, nil
}

func (c *edgeController) Restart() error {
	if c.stop == nil || c.released == nil {
		return fmt.Errorf("edge not running")
	}
	c.mu.Lock()
	c.restarting = true
	c.mu.Unlock()
	go func() {
		time.Sleep(500 * time.Millisecond)
		c.log.Info("restarting edge")
		c.stop()
		<-c.released
		cmd := exec.Command(mustExecutable(), os.Args[1:]...)
		cmd.Env = os.Environ()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			c.log.Error("restart: spawn failed", "err", err)
		} else {
			c.log.Info("restart: successor spawned", "pid", cmd.Process.Pid)
		}
		close(c.spawned)
	}()
	return nil
}

func (c *edgeController) waitForRestart() {
	c.mu.Lock()
	restarting := c.restarting
	c.mu.Unlock()
	if !restarting {
		return
	}
	select {
	case <-c.spawned:
	case <-time.After(5 * time.Second):
		c.log.Warn("restart: successor spawn not confirmed within 5s")
	}
}

func mustExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	return exe
}

func restartRequired(old, neu *config.Config) []string {
	var sections []string
	if !reflect.DeepEqual(old.Server, neu.Server) {
		sections = append(sections, "server")
	}
	if !reflect.DeepEqual(old.Security.Store, neu.Security.Store) {
		sections = append(sections, "store")
	}
	if !reflect.DeepEqual(old.Security.SIEM, neu.Security.SIEM) {
		sections = append(sections, "siem")
	}
	if !reflect.DeepEqual(old.Security.GeoIP, neu.Security.GeoIP) {
		sections = append(sections, "geoip")
	}
	if !reflect.DeepEqual(old.Security.Challenge, neu.Security.Challenge) {
		sections = append(sections, "challenge")
	}
	if old.Security.HMACSecret != neu.Security.HMACSecret {
		sections = append(sections, "hmac_secret")
	}
	if !reflect.DeepEqual(old.Dashboard, neu.Dashboard) {
		sections = append(sections, "dashboard")
	}
	if !reflect.DeepEqual(old.Log, neu.Log) {
		sections = append(sections, "log")
	}
	return sections
}
