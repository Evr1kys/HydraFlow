// Package config provides the central configuration for HydraFlow.
// It reads YAML config from /etc/hydraflow/hydraflow.yaml and provides
// typed access to all settings across modes (standalone, 3xui, marzban).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath  = "/etc/hydraflow/hydraflow.yaml"
	DefaultUsersFile   = "/etc/hydraflow/users.json"
	DefaultServersFile = "/etc/hydraflow/servers.json"
	DefaultListen      = "0.0.0.0:10086"
)

// Mode represents the operating mode of HydraFlow.
type Mode string

const (
	ModeStandalone Mode = "standalone"
	Mode3XUI       Mode = "3xui"
	ModeMarzban    Mode = "marzban"
	ModeRemnawave  Mode = "remnawave"
	ModeHiddify    Mode = "hiddify"
)

// Config is the top-level HydraFlow configuration.
type Config struct {
	Mode          Mode   `yaml:"mode"`
	Listen        string `yaml:"listen"`
	AdminToken    string `yaml:"admin_token"`
	LogLevel      string `yaml:"log_level"`
	ServerAddress string `yaml:"server_address,omitempty"`

	Standalone StandaloneConfig `yaml:"standalone"`
	XUI        XUIConfig        `yaml:"xui"`
	Marzban    MarzbanConfig    `yaml:"marzban"`
	Remnawave  RemnawaveConfig  `yaml:"remnawave"`
	Hiddify    HiddifyConfig    `yaml:"hiddify"`

	Servers []ServerEntry `yaml:"servers"`
	CDN     CDNConfig     `yaml:"cdn"`
}

// StandaloneConfig holds settings for standalone mode with built-in xray management.
type StandaloneConfig struct {
	XrayBinary        string `yaml:"xray_binary"`
	XrayConfig        string `yaml:"xray_config"`
	UsersFile         string `yaml:"users_file"`
	RealityPrivateKey string `yaml:"reality_private_key,omitempty"`
	RealityShortID    string `yaml:"reality_short_id,omitempty"`
}

// XUIConfig holds settings for 3x-ui integration mode.
type XUIConfig struct {
	Database     string `yaml:"database"`
	PollInterval int    `yaml:"poll_interval"` // seconds
}

// MarzbanConfig holds settings for Marzban integration mode.
type MarzbanConfig struct {
	APIURL   string `yaml:"api_url"`
	APIToken string `yaml:"api_token"`
}

// RemnawaveConfig holds settings for Remnawave integration mode.
type RemnawaveConfig struct {
	APIURL   string `yaml:"api_url"`
	APIToken string `yaml:"api_token"`
}

// HiddifyConfig holds settings for Hiddify Manager integration mode.
type HiddifyConfig struct {
	APIURL   string `yaml:"api_url"`
	APIToken string `yaml:"api_token"`
}

// ServerEntry represents a remote server in multi-server setup.
type ServerEntry struct {
	Name      string   `yaml:"name"`
	IP        string   `yaml:"ip"`
	APIKey    string   `yaml:"api_key"`
	Protocols []string `yaml:"protocols"`
}

// CDNConfig holds CDN-related settings.
type CDNConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Domain   string `yaml:"domain"`
	Provider string `yaml:"provider"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:     ModeStandalone,
		Listen:   DefaultListen,
		LogLevel: "info",
		Standalone: StandaloneConfig{
			XrayBinary: "/usr/local/bin/xray",
			XrayConfig: "/etc/hydraflow/xray-config.json",
			UsersFile:  DefaultUsersFile,
		},
		XUI: XUIConfig{
			Database:     "/etc/x-ui/x-ui.db",
			PollInterval: 30,
		},
		Marzban: MarzbanConfig{
			APIURL: "http://localhost:8000",
		},
		Remnawave: RemnawaveConfig{
			APIURL: "http://localhost:3000",
		},
		Hiddify: HiddifyConfig{
			APIURL: "http://localhost:8001",
		},
	}
}

// Load reads the configuration from a YAML file.
// If the file or admin token is missing, defaults and a generated secret are
// saved atomically before returning. The configuration directory must be writable.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			if err := ensureToken(cfg, path); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Validate mode.
	switch cfg.Mode {
	case ModeStandalone, Mode3XUI, ModeMarzban, ModeRemnawave, ModeHiddify:
		// valid
	case "":
		cfg.Mode = ModeStandalone
	default:
		return nil, fmt.Errorf("unknown mode %q (must be standalone, 3xui, marzban, remnawave, or hiddify)", cfg.Mode)
	}

	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}

	if err := ensureToken(cfg, path); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes the configuration to a YAML file.
func Save(cfg *Config, path string) error {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.MkdirAll(dirOf(path), 0750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dirOf(path), ".hydraflow-*.yaml")
	if err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	return nil
}

// ensureToken persists the secret before issuing any subscription URLs.
func ensureToken(cfg *Config, path string) error {
	if cfg.AdminToken != "" {
		return nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate admin token: %w", err)
	}
	cfg.AdminToken = hex.EncodeToString(b)
	return Save(cfg, path)
}

func dirOf(path string) string { return filepath.Dir(path) }
