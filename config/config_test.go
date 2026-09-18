package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig_HasCorrectDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Mode != ModeStandalone {
		t.Fatalf("expected mode 'standalone', got %q", cfg.Mode)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("expected listen %q, got %q", DefaultListen, cfg.Listen)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected log level 'info', got %q", cfg.LogLevel)
	}
	if cfg.Standalone.XrayBinary != "/usr/local/bin/xray" {
		t.Fatalf("unexpected xray binary: %q", cfg.Standalone.XrayBinary)
	}
	if cfg.Standalone.XrayConfig != "/etc/hydraflow/xray-config.json" {
		t.Fatalf("unexpected xray config path: %q", cfg.Standalone.XrayConfig)
	}
	if cfg.Standalone.UsersFile != DefaultUsersFile {
		t.Fatalf("unexpected users file: %q", cfg.Standalone.UsersFile)
	}
	if cfg.XUI.Database != "/etc/x-ui/x-ui.db" {
		t.Fatalf("unexpected xui database: %q", cfg.XUI.Database)
	}
	if cfg.XUI.PollInterval != 30 {
		t.Fatalf("expected poll interval 30, got %d", cfg.XUI.PollInterval)
	}
	if cfg.Marzban.APIURL != "http://localhost:8000" {
		t.Fatalf("unexpected marzban API URL: %q", cfg.Marzban.APIURL)
	}
	if cfg.Remnawave.APIURL != "http://localhost:3000" {
		t.Fatalf("unexpected remnawave API URL: %q", cfg.Remnawave.APIURL)
	}
	if cfg.Hiddify.APIURL != "http://localhost:8001" {
		t.Fatalf("unexpected hiddify API URL: %q", cfg.Hiddify.APIURL)
	}
}

func TestLoad_MissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "new", "config.yaml"))
	if err != nil {
		t.Fatalf("Load should not error on missing file: %v", err)
	}
	if cfg.Mode != ModeStandalone {
		t.Fatalf("expected default mode, got %q", cfg.Mode)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("expected default listen, got %q", cfg.Listen)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "hydraflow.yaml")

	yamlContent := `
mode: 3xui
listen: "0.0.0.0:9999"
admin_token: "my-secret-token"
log_level: debug
xui:
  database: "/tmp/test.db"
  poll_interval: 60
cdn:
  enabled: true
  domain: "cdn.example.com"
  provider: cloudflare
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0640); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Mode != Mode3XUI {
		t.Fatalf("expected mode '3xui', got %q", cfg.Mode)
	}
	if cfg.Listen != "0.0.0.0:9999" {
		t.Fatalf("expected listen '0.0.0.0:9999', got %q", cfg.Listen)
	}
	if cfg.AdminToken != "my-secret-token" {
		t.Fatalf("expected admin token 'my-secret-token', got %q", cfg.AdminToken)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected log level 'debug', got %q", cfg.LogLevel)
	}
	if cfg.XUI.Database != "/tmp/test.db" {
		t.Fatalf("expected xui database '/tmp/test.db', got %q", cfg.XUI.Database)
	}
	if cfg.XUI.PollInterval != 60 {
		t.Fatalf("expected poll interval 60, got %d", cfg.XUI.PollInterval)
	}
	if !cfg.CDN.Enabled {
		t.Fatal("expected CDN enabled")
	}
	if cfg.CDN.Domain != "cdn.example.com" {
		t.Fatalf("expected CDN domain 'cdn.example.com', got %q", cfg.CDN.Domain)
	}
}

func TestLoad_InvalidModeReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad.yaml")

	yamlContent := `mode: invalid_mode`
	os.WriteFile(cfgPath, []byte(yamlContent), 0640)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestLoad_EmptyModeDefaultsToStandalone(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "empty-mode.yaml")

	yamlContent := `listen: "0.0.0.0:8080"`
	os.WriteFile(cfgPath, []byte(yamlContent), 0640)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != ModeStandalone {
		t.Fatalf("expected mode 'standalone', got %q", cfg.Mode)
	}
}

func TestLoad_EmptyListenDefaultsToDefaultListen(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "no-listen.yaml")

	yamlContent := `mode: standalone`
	os.WriteFile(cfgPath, []byte(yamlContent), 0640)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("expected default listen %q, got %q", DefaultListen, cfg.Listen)
	}
}

func TestLoad_EmptyAdminTokenIsGenerated(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "no-token.yaml")

	yamlContent := `mode: standalone`
	os.WriteFile(cfgPath, []byte(yamlContent), 0640)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminToken == "" {
		t.Fatal("admin token should be auto-generated when empty")
	}
	// Generated token is 32 hex chars (16 bytes).
	if len(cfg.AdminToken) != 32 {
		t.Fatalf("expected 32-char hex token, got len=%d (%q)", len(cfg.AdminToken), cfg.AdminToken)
	}
}

func TestLoad_AllValidModes(t *testing.T) {
	modes := []struct {
		yaml string
		mode Mode
	}{
		{"mode: standalone", ModeStandalone},
		{"mode: 3xui", Mode3XUI},
		{"mode: marzban", ModeMarzban},
		{"mode: remnawave", ModeRemnawave},
		{"mode: hiddify", ModeHiddify},
	}

	for _, tc := range modes {
		t.Run(string(tc.mode), func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgPath := filepath.Join(tmpDir, "config.yaml")
			os.WriteFile(cfgPath, []byte(tc.yaml), 0640)

			cfg, err := Load(cfgPath)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Mode != tc.mode {
				t.Fatalf("expected mode %q, got %q", tc.mode, cfg.Mode)
			}
		})
	}
}

func TestLoad_InvalidYAMLReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad.yaml")

	os.WriteFile(cfgPath, []byte(":::invalid yaml[[["), 0640)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestSave_Roundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "saved.yaml")

	original := DefaultConfig()
	original.Mode = Mode3XUI
	original.Listen = "0.0.0.0:7777"
	original.AdminToken = "test-token"
	original.CDN.Enabled = true
	original.CDN.Domain = "test.example.com"

	if err := Save(original, cfgPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}

	if loaded.Mode != original.Mode {
		t.Fatalf("mode mismatch: %q vs %q", loaded.Mode, original.Mode)
	}
	if loaded.Listen != original.Listen {
		t.Fatalf("listen mismatch: %q vs %q", loaded.Listen, original.Listen)
	}
	if loaded.AdminToken != original.AdminToken {
		t.Fatalf("admin token mismatch")
	}
	if loaded.CDN.Domain != original.CDN.Domain {
		t.Fatalf("CDN domain mismatch")
	}
}

func TestLoad_CannotPersistToken(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(parent, "config.yaml")); err == nil {
		t.Fatal("must fail when the secret cannot be persisted")
	}
}

func TestDirOf(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/etc/hydraflow/config.yaml", "/etc/hydraflow"},
		{"/config.yaml", "/"},
		{"config.yaml", "."},
	}

	for _, tc := range tests {
		got := dirOf(tc.path)
		if got != tc.want {
			t.Fatalf("dirOf(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestLoad_WithServersConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "servers.yaml")

	yamlContent := `
mode: standalone
servers:
  - name: server-1
    ip: "1.2.3.4"
    api_key: "key-1"
    protocols:
      - vless-reality
      - vless-ws
  - name: server-2
    ip: "5.6.7.8"
    api_key: "key-2"
    protocols:
      - shadowsocks-2022
`
	os.WriteFile(cfgPath, []byte(yamlContent), 0640)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(cfg.Servers))
	}
	if cfg.Servers[0].Name != "server-1" {
		t.Fatalf("expected server name 'server-1', got %q", cfg.Servers[0].Name)
	}
	if cfg.Servers[0].IP != "1.2.3.4" {
		t.Fatalf("expected IP '1.2.3.4', got %q", cfg.Servers[0].IP)
	}
	if len(cfg.Servers[0].Protocols) != 2 {
		t.Fatalf("expected 2 protocols, got %d", len(cfg.Servers[0].Protocols))
	}
}

func TestLoad_PersistsTokenAndPrivatePermissions(t *testing.T) {
	for _, contents := range []string{"", "mode: standalone\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if contents != "" {
			if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
				t.Fatal(err)
			}
		}
		first, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		second, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if first.AdminToken == "" || first.AdminToken != second.AdminToken {
			t.Fatal("secret changed on reload")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("secret file mode = %o", info.Mode().Perm())
		}
	}
}
