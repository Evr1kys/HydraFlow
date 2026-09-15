package xray

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
