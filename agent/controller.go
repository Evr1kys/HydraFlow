package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Controller abstracts Xray validation and service management for tests and
// for alternative supervisors.
type Controller interface {
	Validate(ctx context.Context, configPath string) error
	Restart(ctx context.Context) error
	Status(ctx context.Context) (ProcessStatus, error)
}

// SystemdController manages a dedicated Xray systemd unit without a shell.
type SystemdController struct {
	XrayBinary string
	AssetPath  string
	Service    string
}

func (c *SystemdController) Validate(ctx context.Context, configPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, c.XrayBinary, "run", "-test", "-c", configPath)
	if c.AssetPath != "" {
		command.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+c.AssetPath)
	}
	var output limitedBuffer
	output.limit = 32 << 10
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("xray validation timed out: %w", ctx.Err())
		}
		return fmt.Errorf("xray rejected candidate: %w: %s", err, output.String())
	}
	return nil
}

func (c *SystemdController) Restart(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	service := c.Service
	if service == "" {
		service = "hydraflow-xray.service"
	}
	command := exec.CommandContext(ctx, "systemctl", "restart", service)
	var output limitedBuffer
	output.limit = 32 << 10
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("xray restart timed out: %w", ctx.Err())
		}
		return fmt.Errorf("restart %s: %w: %s", service, err, output.String())
	}
	return nil
}

func (c *SystemdController) Status(ctx context.Context) (ProcessStatus, error) {
	status := ProcessStatus{CheckedAt: time.Now().UTC()}
	service := c.Service
	if service == "" {
		service = "hydraflow-xray.service"
	}

	activeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	activeCommand := exec.CommandContext(activeCtx, "systemctl", "is-active", "--quiet", service)
	if err := activeCommand.Run(); err == nil {
		status.Active = true
	} else if activeCtx.Err() != nil {
		return status, fmt.Errorf("query service state: %w", activeCtx.Err())
	}

	if status.Active {
		pidCtx, pidCancel := context.WithTimeout(ctx, 5*time.Second)
		defer pidCancel()
		pidOut, err := exec.CommandContext(pidCtx, "systemctl", "show", service, "--property=MainPID", "--value").Output()
		if err == nil {
			status.PID, _ = strconv.Atoi(strings.TrimSpace(string(pidOut)))
		}
	}

	versionCtx, versionCancel := context.WithTimeout(ctx, 5*time.Second)
	defer versionCancel()
	versionOut, err := exec.CommandContext(versionCtx, c.XrayBinary, "version").Output()
	if err == nil {
		line := strings.SplitN(strings.TrimSpace(string(versionOut)), "\n", 2)[0]
		status.Version = line
	}
	return status, nil
}

type limitedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return original, nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(b.buf.String())
}
