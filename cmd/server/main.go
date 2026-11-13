// Command server runs the guardrails gateway.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/experiment"
	"github.com/VicoAritonang/guard-rails-engine/internal/gateway"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards/runtime"
	"github.com/VicoAritonang/guard-rails-engine/internal/mcp"
	"github.com/VicoAritonang/guard-rails-engine/internal/server"
	"github.com/VicoAritonang/guard-rails-engine/internal/telemetry"
)

var version = "dev" // set via -ldflags at build time

func main() {
	if err := run(); err != nil {
		slog.Default().Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	if err := cfg.CheckExposure(); err != nil {
		return err
	}

	logger, closeLog, err := newLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()
	slog.SetDefault(logger)

	if cfg.WeakSecret() {
		logger.Warn("GUARDRAILS_SECRET is a published example value: anyone can forge approvals until it is replaced",
			"hint", "openssl rand -hex 32")
	}
	if cfg.SecretGenerated {
		logger.Warn("GUARDRAILS_SECRET is unset, using a random one for this process",
			"hint", "set it when running more than one replica, or approvals and vault tokens fail across them")
	}

	// Tracing first, so every tracer created below resolves to the exporting
	// provider rather than OTel's no-op default.
	if cfg.TracingEnabled || cfg.OTLPEndpoint != "" {
		shutdown, err := telemetry.SetupTracing(context.Background(), telemetry.TracingOptions{
			ServiceName: "guardrails-engine", Version: version,
			Endpoint: cfg.OTLPEndpoint, Insecure: cfg.OTLPInsecure,
		})
		if err != nil {
			logger.Warn("tracing disabled", "error", err)
		} else {
			cfg.TracingEnabled = true
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = shutdown(ctx)
			}()
			logger.Info("tracing enabled", "otlp_endpoint", orNone(cfg.OTLPEndpoint))
		}
	}

	pol, err := loadPolicy(cfg)
	if err != nil {
		return err
	}
	logger.Info("policy loaded",
		"name", pol.Name, "version", pol.Version, "source", pol.Path(),
		"guards_enabled", len(pol.EnabledGuards()))

	pricing, err := telemetry.LoadPricing(cfg.PricingPath)
	if err != nil {
		return err
	}

	registry := prometheus.NewRegistry()
	metrics, err := telemetry.NewMetrics(telemetry.MetricsOptions{
		Namespace:   "guardrails",
		TenantLabel: cfg.TenantMetrics,
		Registry:    registry,
		Logger:      logger,
	})
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}

	auditor := telemetry.NewAuditor(telemetry.AuditOptions{
		Logger:     logger,
		Enabled:    cfg.AuditEnabled,
		LogAllowed: cfg.AuditLogAllowed,
	})

	var tracer core.Tracer
	if cfg.TracingEnabled {
		tracer = telemetry.NewTracer("guardrails-engine")
	}

	engine, err := guards.Build(pol,
		guards.Deps{Secret: cfg.Secret, Pricing: pricing},
		core.WithObserver(metrics),
		core.WithTracer(tracer),
	)
	if err != nil {
		return fmt.Errorf("build engine: %w", err)
	}
	// Every stage is logged, including an empty one. "Which rails are actually
	// loaded" is the first question during an incident, and a stage that is
	// silently absent from this line is a stage nobody notices is missing.
	logger.Info("engine ready",
		"inbound", engine.Inbound.Guards(),
		"runtime", engine.Runtime.Guards(),
		"tool_result", engine.ToolResult.Guards(),
		"outbound", engine.Outbound.Guards())
	if ev := engine.ToolEvaluator(); ev != nil {
		o := ev.Options()
		logger.Info("tool control plane ready",
			"tools", len(ev.Catalog().Names()),
			"max_tier", o.MaxTier.String(),
			"egress_allowlist", len(o.EgressAllowlist),
			"approvals", o.Approver != nil)
		for _, w := range ev.Lint() {
			logger.Warn("tool policy", "warning", w)
		}
	}

	router, err := gateway.BuildRouter(cfg, logger, metrics)
	if err != nil {
		return err
	}
	warnMissingKey(cfg, logger)
	exact, semantic := gateway.BuildCaches(cfg, logger)
	tier, err := gateway.BuildTier(cfg, router, pricing, gateway.JudgeObserver{Metrics: metrics, Logger: logger}, logger)
	if err != nil {
		return err
	}
	logger.Info("efficiency and semantic tier",
		"cache_entries", cfg.CacheSize, "semantic_cache", semantic != nil,
		"semantic_tier", string(tier.Mode()), "classifiers", cfg.JudgeClassifiers)

	bus := server.NewBus()
	var mcpGW *mcp.Gateway
	if cfg.MCPPath != "" {
		mcfg, err := mcp.LoadConfig(cfg.MCPPath)
		if err != nil {
			return err
		}
		argPolicy, err := runtime.NewToolPolicy(pol.Guard(config.GuardToolPolicy))
		if err != nil {
			return err
		}
		mcpGW, err = mcp.NewGateway(context.Background(), mcp.Options{Config: mcfg, Base: engine.ToolEvaluator(),
			ToolResult: engine.ToolResult, ArgPolicy: argPolicy, Secret: cfg.Secret,
			Events: toolEvents{bus: bus, metrics: metrics, log: logger}, Logger: logger})
		if err != nil {
			return fmt.Errorf("mcp gateway: %w", err)
		}
		exposed, quarantined := mcpGW.Inventory()
		logger.Info("mcp gateway ready", "servers", len(mcfg.Servers), "tools", len(exposed), "quarantined", len(quarantined))
	}

	var lab *server.Lab
	if cfg.ExperimentsDir != "" && cfg.ExperimentsRun {
		// A separate router with SDK retries off: the experiment recorder
		// retries rate limits itself, outside the latency measurement.
		labCfg := *cfg
		labCfg.UpstreamMaxRetries = -1
		labRouter, err := gateway.BuildRouter(&labCfg, logger, nil)
		if err != nil {
			return fmt.Errorf("experiment lab: %w", err)
		}
		root := cfg.ExperimentsDir
		lab = &server.Lab{
			Root: root,
			Run: func(ctx context.Context, name string, quick bool, log io.Writer) (*experiment.Result, string, error) {
				rc := experiment.DefaultRunConfig(root)
				rc.Corpus, rc.Version = cfg.EvalCorpus, version
				if quick {
					rc = rc.Quickened()
				}
				return experiment.RunNamed(ctx, &labCfg, labRouter, pricing, rc, name, log)
			},
			Fetch: func(ctx context.Context, log io.Writer) error {
				_, err := experiment.FetchBenchmarks(ctx, filepath.Join(root, "benchmarks"), log)
				return err
			},
		}
		logger.Info("experiment lab enabled", "root", root, "corpus", cfg.EvalCorpus)
	}

	srv, err := server.New(server.Options{
		Engine:          engine,
		Policy:          pol,
		Provider:        router,
		Router:          router,
		Exact:           exact,
		Semantic:        semantic,
		Tier:            tier,
		MCP:             mcpGW,
		Bus:             bus,
		ExperimentsDir:  cfg.ExperimentsDir,
		Lab:             lab,
		Pricing:         pricing,
		Metrics:         metrics,
		Auditor:         auditor,
		Logger:          logger,
		Secret:          cfg.Secret,
		APIKeys:         cfg.APIKeys,
		AdminKeys:       cfg.AdminKeys,
		RequestTimeout:  cfg.RequestTimeout,
		MaxBodyBytes:    cfg.MaxBodyBytes,
		EnableDashboard: cfg.Dashboard,
		Version:         version,
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
		// Generous read/write timeouts: the upstream model call dominates and
		// is bounded separately by RequestTimeout. Aggressive values here
		// truncate long completions rather than protecting anything.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.RequestTimeout + 10*time.Second,
		WriteTimeout:      cfg.RequestTimeout + 10*time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening",
			"addr", cfg.Addr, "provider", cfg.Provider,
			"model", cfg.DefaultModel, "env_file", orNone(cfg.EnvFile),
			"dashboard", cfg.Dashboard, "version", version)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// Drain before shutting down: flipping readiness first lets a load
	// balancer stop sending new work while in-flight requests finish. Skipping
	// this step is why "zero-downtime" deploys drop requests.
	logger.Info("shutdown signal received, draining")
	srv.SetReady(false)
	time.Sleep(cfg.DrainDelay)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("stopped cleanly")
	return nil
}

func loadPolicy(cfg *config.Config) (*config.Policy, error) {
	if cfg.PolicyPath != "" {
		return config.LoadPolicy(cfg.PolicyPath)
	}
	pol := config.DefaultPolicy()
	if cfg.StrictPolicy {
		pol = config.StrictPolicy()
	}
	return pol, pol.Validate()
}

// warnMissingKey makes a missing default-provider key a warning, not an
// error: the SDKs resolve credentials from sources this process cannot see (an
// ambient env var in the container, an auth profile on disk, workload identity
// federation). What would be unhelpful is discovering it only on the first 401.
func warnMissingKey(cfg *config.Config, logger *slog.Logger) {
	switch {
	case cfg.Provider == "openai" && cfg.OpenAIAPIKey == "":
		logger.Warn("OPENAI_API_KEY is unset",
			"hint", "put it in .env or export it; the SDK will also read it from the ambient environment",
			"env_file", orNone(cfg.EnvFile))
	case cfg.Provider == "anthropic" && cfg.AnthropicAPIKey == "":
		logger.Warn("ANTHROPIC_API_KEY is unset; relying on the SDK's other credential sources")
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none found)"
	}
	return s
}

// newLogger writes JSON (or text) to stdout and, when GUARDRAILS_LOG_FILE is
// set, an identical JSON copy to that file for a log shipper to tail. Stdout
// stays primary: a full disk must not be able to silence the process's logs.
func newLogger(cfg *config.Config) (*slog.Logger, func(), error) {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.LogFormat == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	if cfg.LogFile == "" {
		return slog.New(h), func() {}, nil
	}
	f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, nil, fmt.Errorf("open GUARDRAILS_LOG_FILE: %w", err)
	}
	fileH := slog.NewJSONHandler(f, opts)
	return slog.New(fanout{h, fileH}), func() { _ = f.Close() }, nil
}

// fanout sends every record to each handler.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (f fanout) WithAttrs(a []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(a)
	}
	return out
}

func (f fanout) WithGroup(n string) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(n)
	}
	return out
}

// toolEvents fans MCP gateway events out to the live console, Prometheus and
// the audit log, so a refused tool call is visible in all three.
type toolEvents struct {
	bus     *server.Bus
	metrics *telemetry.Metrics
	log     *slog.Logger
}

func (t toolEvents) Publish(kind string, data any) {
	t.bus.Publish(kind, data)
	switch v := data.(type) {
	case *mcp.CallOutcome:
		t.metrics.ToolCallObserved(v.Server, v.Tier, v.Status)
		level := slog.LevelInfo
		if v.Status != "executed" && v.Status != "dry_run" {
			level = slog.LevelWarn
		}
		var cats []string
		for _, f := range v.Findings {
			cats = append(cats, f.Category)
		}
		t.log.Log(context.Background(), level, "tool call", "event", "guardrail.tool_call", "tool", v.Tool,
			"server", v.Server, "tier", v.Tier, "status", v.Status, "findings", cats, "trace", v.Trace,
			"receipt", v.Receipt, "duration_ms", v.DurationMS)
	case mcp.Quarantined:
		t.metrics.QuarantineObserved(v.Server, v.Reason)
	}
}
