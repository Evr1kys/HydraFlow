package xray

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ManagerConfig configures the XrayManager.
type ManagerConfig struct {
	// XrayPath is the path to the xray-core binary.
	XrayPath string

	// ConfigPath is the path where generated xray configs are written.
	ConfigPath string

	// AssetPath is the directory containing geoip.dat and geosite.dat.
	AssetPath string

	// APIPort is the port for the xray stats API (dokodemo-door).
	APIPort int
}

// DefaultManagerConfig returns a ManagerConfig with standard defaults.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		XrayPath:   "/usr/local/bin/xray",
		ConfigPath: "/etc/hydraflow/xray.json",
		AssetPath:  "/usr/local/share/xray",
		APIPort:    10085,
	}
}

// ProcessStatus contains information about the running xray process.
type ProcessStatus struct {
	Running   bool      `json:"running"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Uptime    string    `json:"uptime"`
	Version   string    `json:"version"`
}

// XrayManager manages the lifecycle of an xray-core subprocess.
type XrayManager struct {
	mu      sync.RWMutex
	config  ManagerConfig
	logger  *slog.Logger
	builder *ConfigBuilder

	cmd       *exec.Cmd
	process   *os.Process
	startedAt time.Time
	running   bool
	version   string

	ctx    context.Context
	cancel context.CancelFunc

	// waitDone is closed when cmd.Wait() has been called exactly once by monitor().
	// Stop() selects on this channel instead of calling Wait() a second time.
	waitDone chan struct{}
	waitErr  error
}

// NewManager creates a new XrayManager.
func NewManager(cfg ManagerConfig, logger *slog.Logger) *XrayManager {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.XrayPath == "" {
		cfg.XrayPath = DefaultManagerConfig().XrayPath
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = DefaultManagerConfig().ConfigPath
	}
	if cfg.APIPort == 0 {
		cfg.APIPort = DefaultManagerConfig().APIPort
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &XrayManager{
		config:  cfg,
		logger:  logger,
		builder: NewConfigBuilder(),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Builder returns the ConfigBuilder for modifying xray configuration.
func (m *XrayManager) Builder() *ConfigBuilder {
	return m.builder
}

// GenerateConfig builds the xray JSON config from the builder and writes
// it to ConfigPath. Returns the generated JSON bytes.
func (m *XrayManager) GenerateConfig() ([]byte, error) {
	m.builder.APIPort = m.config.APIPort

	data, err := m.builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build xray config: %w", err)
	}

	// Ensure config directory exists.
	dir := filepath.Dir(m.config.ConfigPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create config dir %s: %w", dir, err)
	}

	// Validate a private temporary file before replacing the live configuration.
	tmp, err := os.CreateTemp(dir, ".xray-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
	defer cancel()
	check := exec.CommandContext(ctx, m.config.XrayPath, "run", "-test", "-c", tmp.Name())
	if m.config.AssetPath != "" {
		check.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+m.config.AssetPath)
	}
	if output, err := check.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("validate xray config: %w: %s", err, output)
	}
	if err := os.Rename(tmp.Name(), m.config.ConfigPath); err != nil {
		return nil, fmt.Errorf("save xray config: %w", err)
	}

	m.logger.Info("xray config generated", "path", m.config.ConfigPath, "size", len(data))
	return data, nil
}

// Start launches the xray-core process with the current configuration.
func (m *XrayManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("xray is already running")
	}

	// Generate config before starting.
	if _, err := m.GenerateConfig(); err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	// Detect xray version.
	m.detectVersion()

	// Build command.
	args := []string{"run", "-c", m.config.ConfigPath}

	cmd := exec.CommandContext(m.ctx, m.config.XrayPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set environment for geo assets.
	if m.config.AssetPath != "" {
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("XRAY_LOCATION_ASSET=%s", m.config.AssetPath),
		)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start xray: %w", err)
	}

	m.cmd = cmd
	m.process = cmd.Process
	m.startedAt = time.Now()
	m.running = true
	m.waitDone = make(chan struct{})

	m.logger.Info("xray-core started",
		"pid", cmd.Process.Pid,
		"config", m.config.ConfigPath,
		"version", m.version,
	)

	// Monitor process in background.
	go m.monitor()

	return nil
}

// Stop gracefully stops the xray-core process.
func (m *XrayManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running || m.process == nil {
		return nil
	}

	m.logger.Info("stopping xray-core", "pid", m.process.Pid)

	// Send SIGTERM first for graceful shutdown.
	if err := m.process.Signal(syscall.SIGTERM); err != nil {
		m.logger.Warn("SIGTERM failed, sending SIGKILL", "error", err)
		if killErr := m.process.Kill(); killErr != nil {
			return fmt.Errorf("kill xray: %w", killErr)
		}
	}

	// Wait for monitor() to observe the process exit (it calls cmd.Wait()
	// exactly once). We do NOT call cmd.Wait() here to avoid a double-wait panic.
	select {
	case <-m.waitDone:
		if m.waitErr != nil {
			m.logger.Debug("xray exited with error", "error", m.waitErr)
		}
	case <-time.After(10 * time.Second):
		m.logger.Warn("xray did not stop gracefully, killing")
		m.process.Kill()
		<-m.waitDone // wait for monitor to finish after kill
	}

	m.running = false
	m.process = nil
	m.cmd = nil
	m.logger.Info("xray-core stopped")

	return nil
}

// Restart stops and starts the xray-core process.
func (m *XrayManager) Restart() error {
	if err := m.Stop(); err != nil {
		m.logger.Warn("error stopping xray during restart", "error", err)
	}
	return m.Start()
}

// Reload triggers a hot-reload of the xray configuration by sending
// SIGUSR1 to the xray process, which causes it to re-read its config.
// If the process is not running, it starts it instead.
func (m *XrayManager) Reload() error {
	m.mu.RLock()
	running := m.running
	process := m.process
	m.mu.RUnlock()

	if !running || process == nil {
		m.logger.Info("xray not running, starting instead of reloading")
		return m.Start()
	}

	// Regenerate config first.
	if _, err := m.GenerateConfig(); err != nil {
		return fmt.Errorf("regenerate config for reload: %w", err)
	}

	// xray-core does not support SIGUSR1 for reload; perform restart.
	m.logger.Info("reloading xray-core (restart)", "pid", process.Pid)
	return m.Restart()
}

// Status returns the current status of the xray process.
func (m *XrayManager) Status() ProcessStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := ProcessStatus{
		Running: m.running,
		Version: m.version,
	}

	if m.running && m.process != nil {
		status.PID = m.process.Pid
		status.StartedAt = m.startedAt
		status.Uptime = time.Since(m.startedAt).Round(time.Second).String()
	}

	return status
}

// Close shuts down the manager and stops the xray process.
func (m *XrayManager) Close() error {
	m.cancel()
	return m.Stop()
}

// monitor watches the xray subprocess and logs if it exits unexpectedly.
// It is the only goroutine that calls cmd.Wait(), and it signals completion
// via m.waitDone so that Stop() never double-waits.
func (m *XrayManager) monitor() {
	if m.cmd == nil {
		return
	}

	err := m.cmd.Wait()

	m.mu.Lock()
	m.running = false
	m.waitErr = err
	m.mu.Unlock()

	// Signal that Wait() has returned.
	close(m.waitDone)

	select {
	case <-m.ctx.Done():
		// Normal shutdown.
		return
	default:
	}

	if err != nil {
		m.logger.Error("xray-core exited unexpectedly",
			"error", err,
			"uptime", time.Since(m.startedAt).Round(time.Second),
		)
	} else {
		m.logger.Warn("xray-core exited",
			"uptime", time.Since(m.startedAt).Round(time.Second),
		)
	}

	// Auto-restart after unexpected exit.
	m.logger.Info("auto-restarting xray-core in 3 seconds")
	select {
	case <-time.After(3 * time.Second):
		if err := m.Start(); err != nil {
			m.logger.Error("auto-restart failed", "error", err)
		}
	case <-m.ctx.Done():
		return
	}
}

// detectVersion runs `xray version` to capture the installed version.
func (m *XrayManager) detectVersion() {
	out, err := exec.Command(m.config.XrayPath, "version").Output()
	if err != nil {
		m.logger.Debug("could not detect xray version", "error", err)
		m.version = "unknown"
		return
	}
	// First line typically: "Xray 1.8.x (Xray, Penetrates Everything) ..."
	version := string(out)
	for i, c := range version {
		if c == '\n' || c == '\r' {
			version = version[:i]
			break
		}
	}
	m.version = version
}
