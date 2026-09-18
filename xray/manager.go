package xray

import (
	"context"
	"errors"
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

	cmd         *exec.Cmd
	process     *os.Process
	startedAt   time.Time
	running     bool
	wantRunning bool
	version     string

	ctx    context.Context
	cancel context.CancelFunc

	// waitDone is closed when cmd.Wait() has been called exactly once by monitor().
	// Stop waits on this channel without holding mu.
	waitDone chan struct{}
	waitErr  error

	// Kept configurable inside the package so lifecycle tests do not need to
	// sleep for the production restart interval.
	restartDelay time.Duration
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
		config:       cfg,
		logger:       logger,
		builder:      NewConfigBuilder(),
		ctx:          ctx,
		cancel:       cancel,
		restartDelay: 3 * time.Second,
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
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("secure temporary xray config: %w", err)
	}
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

	m.wantRunning = true
	if m.running {
		return fmt.Errorf("xray is already running")
	}
	if err := m.startLocked(); err != nil {
		m.wantRunning = false
		return err
	}
	return nil
}

// startIfWanted is used by the crash monitor. It never overrides a concurrent
// Stop request, because wantRunning is checked while holding mu.
func (m *XrayManager) startIfWanted() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.wantRunning || m.ctx.Err() != nil || m.running {
		return nil
	}
	return m.startLocked()
}

// startLocked starts xray while mu is held.
func (m *XrayManager) startLocked() error {
	if m.ctx.Err() != nil {
		return fmt.Errorf("xray manager is closed")
	}

	// Generate config before starting.
	if _, err := m.GenerateConfig(); err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	// Detect xray version.
	m.detectVersion()

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

	startedAt := time.Now()
	done := make(chan struct{})
	m.cmd = cmd
	m.process = cmd.Process
	m.startedAt = startedAt
	m.running = true
	m.waitDone = done
	m.waitErr = nil

	m.logger.Info("xray-core started",
		"pid", cmd.Process.Pid,
		"config", m.config.ConfigPath,
		"version", m.version,
	)

	// Pass process-specific values so an old monitor cannot affect a newer run.
	go m.monitor(cmd, done, startedAt)

	return nil
}

// Stop gracefully stops the xray-core process.
func (m *XrayManager) Stop() error {
	m.mu.Lock()
	m.wantRunning = false
	if !m.running || m.process == nil {
		m.mu.Unlock()
		return nil
	}
	process := m.process
	done := m.waitDone
	pid := process.Pid
	m.mu.Unlock()

	m.logger.Info("stopping xray-core", "pid", pid)

	// Never hold mu while waiting: monitor needs it before it can close done.
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		m.logger.Warn("SIGTERM failed, sending SIGKILL", "error", err)
		if killErr := process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			return fmt.Errorf("kill xray: %w", killErr)
		}
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		m.logger.Warn("xray did not stop gracefully, killing", "pid", pid)
		if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill unresponsive xray: %w", err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("xray process %d did not exit after SIGKILL", pid)
		}
	}

	m.mu.RLock()
	waitErr := m.waitErr
	m.mu.RUnlock()
	if waitErr != nil {
		m.logger.Debug("xray exited while stopping", "error", waitErr)
	}
	m.logger.Info("xray-core stopped", "pid", pid)
	return nil
}

// Restart stops and starts the xray-core process.
func (m *XrayManager) Restart() error {
	if err := m.Stop(); err != nil {
		m.logger.Warn("error stopping xray during restart", "error", err)
	}
	return m.Start()
}

// Reload validates and writes the new configuration, then restarts xray.
// If the process is not running, it starts it instead.
func (m *XrayManager) Reload() error {
	m.mu.RLock()
	running := m.running
	m.mu.RUnlock()

	if !running {
		m.logger.Info("xray not running, starting instead of reloading")
		return m.Start()
	}

	// Validate the candidate before interrupting the working process.
	if _, err := m.GenerateConfig(); err != nil {
		return fmt.Errorf("regenerate config for reload: %w", err)
	}

	// xray-core does not support a reliable in-process config reload.
	m.logger.Info("reloading xray-core (restart)")
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
	err := m.Stop()
	m.cancel()
	return err
}

// monitor watches one xray subprocess. It is the only goroutine that calls
// cmd.Wait(), and it always closes the matching done channel exactly once.
func (m *XrayManager) monitor(cmd *exec.Cmd, done chan struct{}, startedAt time.Time) {
	err := cmd.Wait()

	m.mu.Lock()
	isCurrent := m.cmd == cmd
	intentional := !m.wantRunning || m.ctx.Err() != nil
	if isCurrent {
		m.running = false
		m.process = nil
		m.cmd = nil
		m.waitErr = err
	}
	m.mu.Unlock()
	close(done)

	// A stale monitor must never modify or restart a newer process.
	if !isCurrent || intentional {
		return
	}

	if err != nil {
		m.logger.Error("xray-core exited unexpectedly",
			"error", err,
			"uptime", time.Since(startedAt).Round(time.Second),
		)
	} else {
		m.logger.Warn("xray-core exited",
			"uptime", time.Since(startedAt).Round(time.Second),
		)
	}

	m.logger.Info("auto-restarting xray-core", "delay", m.restartDelay)
	timer := time.NewTimer(m.restartDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		if err := m.startIfWanted(); err != nil {
			m.logger.Error("auto-restart failed", "error", err)
		}
	case <-m.ctx.Done():
		return
	}
}

// detectVersion runs `xray version` to capture the installed version.
// The caller holds mu.
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
