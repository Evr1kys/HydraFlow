package xray

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGenerateConfigRejectsInvalidCandidateWithoutReplacingLiveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX test executable")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "reject-xray")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho invalid configuration >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "xray.json")
	original := []byte("previous working config")
	if err := os.WriteFile(live, original, 0600); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(ManagerConfig{XrayPath: binary, ConfigPath: live}, nil)
	defer mgr.Close()
	if _, err := mgr.GenerateConfig(); err == nil {
		t.Fatal("invalid config was accepted")
	}
	got, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatal("live config overwritten after validation failure")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".xray-*.json"))
	if err != nil || len(matches) != 0 {
		t.Fatal("candidate file leaked")
	}
}

func TestStopDoesNotDeadlockOrRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX signals and a shell test executable")
	}
	binary, runs := writeFakeXray(t, "stay")
	mgr := NewManager(ManagerConfig{
		XrayPath:   binary,
		ConfigPath: filepath.Join(t.TempDir(), "xray.json"),
	}, nil)
	mgr.restartDelay = 25 * time.Millisecond
	t.Cleanup(func() { _ = mgr.Close() })

	if err := mgr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return runCount(runs) == 1 }, "first xray process start")

	stopped := make(chan error, 1)
	go func() { stopped <- mgr.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop deadlocked waiting for monitor")
	}

	time.Sleep(100 * time.Millisecond)
	if mgr.Status().Running {
		t.Fatal("xray is still running after Stop")
	}
	if got := runCount(runs); got != 1 {
		t.Fatalf("manual Stop triggered an unexpected restart: runs=%d", got)
	}
}

func TestUnexpectedExitAutoRestarts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell test executable")
	}
	binary, runs := writeFakeXray(t, "crash-once")
	mgr := NewManager(ManagerConfig{
		XrayPath:   binary,
		ConfigPath: filepath.Join(t.TempDir(), "xray.json"),
	}, nil)
	mgr.restartDelay = 25 * time.Millisecond
	t.Cleanup(func() { _ = mgr.Close() })

	if err := mgr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return runCount(runs) >= 2 && mgr.Status().Running
	}, "automatic restart after unexpected exit")

	if err := mgr.Stop(); err != nil {
		t.Fatalf("stop after restart: %v", err)
	}
}

func TestStopCancelsPendingAutoRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell test executable")
	}
	binary, runs := writeFakeXray(t, "always-crash")
	mgr := NewManager(ManagerConfig{
		XrayPath:   binary,
		ConfigPath: filepath.Join(t.TempDir(), "xray.json"),
	}, nil)
	mgr.restartDelay = 250 * time.Millisecond
	t.Cleanup(func() { _ = mgr.Close() })

	if err := mgr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		return runCount(runs) == 1 && !mgr.Status().Running
	}, "first process crash")

	// Stop must cancel restart intent even though the child already exited.
	if err := mgr.Stop(); err != nil {
		t.Fatalf("stop during restart delay: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if got := runCount(runs); got != 1 {
		t.Fatalf("xray restarted after manual Stop: runs=%d", got)
	}
}

func writeFakeXray(t *testing.T, mode string) (binary, runs string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "fake-xray")
	runs = filepath.Join(dir, "runs")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
runs_file=%q
mode=%q

if [ "${1:-}" = "version" ]; then
  echo "Xray test"
  exit 0
fi

if [ "${1:-}" = "run" ] && [ "${2:-}" = "-test" ]; then
  exit 0
fi

if [ "${1:-}" != "run" ]; then
  exit 2
fi

echo run >> "$runs_file"
count=$(wc -l < "$runs_file")
case "$mode" in
  crash-once)
    if [ "$count" -eq 1 ]; then exit 23; fi
    ;;
  always-crash)
    exit 23
    ;;
esac

trap 'exit 0' TERM INT
while :; do sleep 0.1; done
`, runs, mode)
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return binary, runs
}

func runCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n") + 1
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
