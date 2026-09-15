package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Evr1kys/HydraFlow/bypass"
	"github.com/Evr1kys/HydraFlow/config"
	"github.com/Evr1kys/HydraFlow/integrations"
	"github.com/Evr1kys/HydraFlow/smartsub"
	"github.com/Evr1kys/HydraFlow/xray"
	"github.com/google/uuid"
)

// cmdServe starts the smart subscription server.
func cmdServe() {
	cfgPath := getConfigPath()
	modeOverride := getFlagValue("--mode")
	listenOverride := getFlagValue("--listen")

	cfg, err := loadCLIConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// Apply overrides.
	if modeOverride != "" {
		cfg.Mode = config.Mode(modeOverride)
	}
	if listenOverride != "" {
		cfg.Listen = listenOverride
	}

	// Setup logger.
	level := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	logger.Info("starting HydraFlow",
		"version", version,
		"mode", cfg.Mode,
		"listen", cfg.Listen,
	)

	// Create the smart subscription engine.
	engine := smartsub.NewEngine(smartsub.EngineConfig{
		Token:    cfg.AdminToken,
		ServerIP: serverAddress(cfg),
		Logger:   logger,
	})

	// Initialize bypass engine for ISP-specific optimizations.
	// The bypass presets are used to enhance subscription configs.
	bypassCfg := bypass.BypassConfig{
		FragmentEnabled:  true,
		FragmentPackets:  "tlshello",
		FragmentSize:     "1-5",
		FragmentInterval: "1-5",
	}
	bypassEngine, err := bypass.NewBypassEngine(bypassCfg, logger)
	if err != nil {
		logger.Warn("bypass engine init failed, continuing without bypass", "error", err)
	} else {
		logger.Info("bypass engine initialized",
			"techniques", len(bypassEngine.Techniques()),
		)
	}

	// Setup context with signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Initialize based on mode.
	switch cfg.Mode {
	case config.ModeStandalone:
		if err := serveStandalone(ctx, cfg, engine, logger); err != nil {
			logger.Error("standalone mode error", "error", err)
			os.Exit(1)
		}
	case config.Mode3XUI:
		if err := serve3XUI(ctx, cfg, engine, logger); err != nil {
			logger.Error("3x-ui mode error", "error", err)
			os.Exit(1)
		}
	case config.ModeMarzban:
		if err := serveMarzban(ctx, cfg, engine, logger); err != nil {
			logger.Error("marzban mode error", "error", err)
			os.Exit(1)
		}
	case config.ModeRemnawave:
		if err := serveRemnawave(ctx, cfg, engine, logger); err != nil {
			logger.Error("remnawave mode error", "error", err)
			os.Exit(1)
		}
	case config.ModeHiddify:
		if err := serveHiddify(ctx, cfg, engine, logger); err != nil {
			logger.Error("hiddify mode error", "error", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", cfg.Mode)
		os.Exit(1)
	}
}

// serveStandalone runs in standalone mode with built-in xray management.
func serveStandalone(ctx context.Context, cfg *config.Config, engine *smartsub.Engine, logger *slog.Logger) error {
	// Load users from JSON.
	users, err := loadUsers(cfg.Standalone.UsersFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("load users: %w", err)
	}

	// Setup xray manager.
	mgr := xray.NewManager(xray.ManagerConfig{
		XrayPath:   cfg.Standalone.XrayBinary,
		ConfigPath: cfg.Standalone.XrayConfig,
	}, logger)

	if err := ensureReality(cfg, getConfigPath()); err != nil {
		return err
	}
	nodes := configureStandalone(cfg, users, mgr.Builder())
	engine.SetNodes(nodes)

	// Start xray.
	if err := mgr.Start(); err != nil {
		return fmt.Errorf("start xray: %w", err)
	} else {
		defer mgr.Close()
	}

	// Start health checks.
	engine.StartHealthChecks(ctx, 5*time.Minute)

	// Watch for user file changes (simple poll).
	go watchUsersFile(ctx, cfg, engine, mgr, logger)

	// Start HTTP server.
	return startHTTPServer(ctx, cfg, engine, logger)
}

// serve3XUI runs in 3x-ui integration mode.
func serve3XUI(ctx context.Context, cfg *config.Config, engine *smartsub.Engine, logger *slog.Logger) error {
	provider, err := integrations.NewXUIProvider(integrations.XUIConfig{
		DatabasePath: cfg.XUI.Database,
		PollInterval: time.Duration(cfg.XUI.PollInterval) * time.Second,
		ServerIP:     serverAddress(cfg),
		Logger:       logger,
		OnChange: func(nodes []smartsub.Node) {
			engine.SetNodes(nodes)
		},
	})
	if err != nil {
		return fmt.Errorf("init 3x-ui provider: %w", err)
	}

	if err := provider.Start(); err != nil {
		return fmt.Errorf("start 3x-ui provider: %w", err)
	}
	defer provider.Stop()

	// Set initial nodes.
	engine.SetNodes(provider.Nodes())

	// Start health checks.
	engine.StartHealthChecks(ctx, 5*time.Minute)

	// Start HTTP server.
	return startHTTPServer(ctx, cfg, engine, logger)
}

// serveMarzban runs in Marzban integration mode.
func serveMarzban(ctx context.Context, cfg *config.Config, engine *smartsub.Engine, logger *slog.Logger) error {
	provider, err := integrations.NewMarzbanProvider(integrations.MarzbanConfig{
		APIURL:       cfg.Marzban.APIURL,
		APIToken:     cfg.Marzban.APIToken,
		PollInterval: 30 * time.Second,
		ServerIP:     serverAddress(cfg),
		Logger:       logger,
		OnChange: func(nodes []smartsub.Node) {
			engine.SetNodes(nodes)
		},
	})
	if err != nil {
		return fmt.Errorf("init Marzban provider: %w", err)
	}

	if err := provider.Start(); err != nil {
		return fmt.Errorf("start Marzban provider: %w", err)
	}
	defer provider.Stop()

	engine.SetNodes(provider.Nodes())
	engine.StartHealthChecks(ctx, 5*time.Minute)

	return startHTTPServer(ctx, cfg, engine, logger)
}

// serveRemnawave runs in Remnawave integration mode.
func serveRemnawave(ctx context.Context, cfg *config.Config, engine *smartsub.Engine, logger *slog.Logger) error {
	provider, err := integrations.NewRemnawaveProvider(integrations.RemnawaveConfig{
		APIURL:       cfg.Remnawave.APIURL,
		APIToken:     cfg.Remnawave.APIToken,
		PollInterval: 30 * time.Second,
		ServerIP:     serverAddress(cfg),
		Logger:       logger,
		OnChange: func(nodes []smartsub.Node) {
			engine.SetNodes(nodes)
		},
	})
	if err != nil {
		return fmt.Errorf("init Remnawave provider: %w", err)
	}

	if err := provider.Start(); err != nil {
		return fmt.Errorf("start Remnawave provider: %w", err)
	}
	defer provider.Stop()

	engine.SetNodes(provider.Nodes())
	engine.StartHealthChecks(ctx, 5*time.Minute)

	return startHTTPServer(ctx, cfg, engine, logger)
}

// serveHiddify runs in Hiddify Manager integration mode.
func serveHiddify(ctx context.Context, cfg *config.Config, engine *smartsub.Engine, logger *slog.Logger) error {
	provider, err := integrations.NewHiddifyProvider(integrations.HiddifyConfig{
		APIURL:       cfg.Hiddify.APIURL,
		APIToken:     cfg.Hiddify.APIToken,
		PollInterval: 30 * time.Second,
		ServerIP:     serverAddress(cfg),
		Logger:       logger,
		OnChange: func(nodes []smartsub.Node) {
			engine.SetNodes(nodes)
		},
	})
	if err != nil {
		return fmt.Errorf("init Hiddify provider: %w", err)
	}

	if err := provider.Start(); err != nil {
		return fmt.Errorf("start Hiddify provider: %w", err)
	}
	defer provider.Stop()

	engine.SetNodes(provider.Nodes())
	engine.StartHealthChecks(ctx, 5*time.Minute)

	return startHTTPServer(ctx, cfg, engine, logger)
}

// startHTTPServer starts the main subscription HTTP server.
func startHTTPServer(ctx context.Context, cfg *config.Config, engine *smartsub.Engine, logger *slog.Logger) error {
	handler := engine.Handler()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	logger.Info("smart subscription server started",
		"addr", cfg.Listen,
		"mode", cfg.Mode,
		"subscriptions", "use hydraflow user sub <email> to issue a user link",
	)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down HTTP server")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}

// watchUsersFile polls the users file for changes and updates the engine.
func watchUsersFile(ctx context.Context, cfg *config.Config, engine *smartsub.Engine, mgr *xray.XrayManager, logger *slog.Logger) {
	var lastMod time.Time
	// Initialize lastMod from the file's current ModTime so we don't
	// trigger a spurious reload on the first tick.
	if info, err := os.Stat(cfg.Standalone.UsersFile); err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(cfg.Standalone.UsersFile)
			if err != nil {
				continue
			}
			if info.ModTime().After(lastMod) {
				users, err := loadUsers(cfg.Standalone.UsersFile)
				if err != nil {
					logger.Error("reload users failed", "error", err)
					continue
				}

				nodes := configureStandalone(cfg, users, mgr.Builder())
				if err := mgr.Reload(); err != nil {
					logger.Error("xray reload failed", "error", err)
					continue
				}
				engine.SetNodes(nodes)
				lastMod = info.ModTime()

				logger.Info("users reloaded", "count", len(users))
			}
		}
	}
}

// --- User JSON file management ---

// User represents a user in the standalone users file.
type User struct {
	Email       string    `json:"email"`
	UUID        string    `json:"uuid"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	TrafficUp   int64     `json:"traffic_up"`
	TrafficDown int64     `json:"traffic_down"`
}

// loadUsers reads the users JSON file.
func loadUsers(path string) ([]User, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("parse users %s: %w", path, err)
	}

	return users, nil
}

// saveUsers writes the users JSON file atomically (write-to-temp-then-rename).
func saveUsers(users []User, path string) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal users: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	// Atomic write: create a temp file in the same directory, write, then rename.
	tmp, err := os.CreateTemp(dir, ".users-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0640); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}

	return nil
}

// addUser adds a new user to the users file.
func addUser(path, email string) (*User, error) {
	users, err := loadUsers(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// Check for duplicate.
	for _, u := range users {
		if u.Email == email {
			return nil, fmt.Errorf("user %q already exists", email)
		}
	}

	user := User{
		Email:     email,
		UUID:      uuid.New().String(),
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	users = append(users, user)

	if err := saveUsers(users, path); err != nil {
		return nil, err
	}

	return &user, nil
}

// deleteUser removes a user from the users file.
func deleteUser(path, email string) error {
	users, err := loadUsers(path)
	if err != nil {
		return err
	}

	found := false
	var remaining []User
	for _, u := range users {
		if u.Email == email {
			found = true
			continue
		}
		remaining = append(remaining, u)
	}

	if !found {
		return fmt.Errorf("user %q not found", email)
	}

	return saveUsers(remaining, path)
}

// --- Config loading helper ---

func loadCLIConfig(path string) (*config.Config, error) {
	return config.Load(path)
}

// --- Helpers ---

// getFlagValue returns the value of a --flag from os.Args.
func getFlagValue(flag string) string {
	for i, arg := range os.Args {
		if arg == flag && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

// detectServerIP returns the server's public IP.
func detectServerIP(listen string) string {
	// If listen has a specific non-zero IP, use it.
	host, _, err := net.SplitHostPort(listen)
	if err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		return host
	}

	// Try to detect from network interfaces.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil && !ipnet.IP.IsPrivate() {
				return ipnet.IP.String()
			}
		}
	}

	// Fallback to first non-loopback.
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return "127.0.0.1"
}

// parseLogLevel converts a string to slog.Level.
func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
