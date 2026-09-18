package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Evr1kys/HydraFlow/smartsub"
)

// cmdExport reads the server config and outputs a ready-to-import config
// for V2Ray, Clash Meta, or sing-box client apps.
func cmdExport() {
	format := ""

	// Parse --format flag.
	for i, arg := range os.Args {
		if arg == "--format" && i+1 < len(os.Args) {
			format = os.Args[i+1]
			break
		}
	}

	if format == "" {
		fmt.Fprintf(os.Stderr, "usage: hydraflow export --format <v2ray|clash|singbox>\n\n")
		fmt.Fprintf(os.Stderr, "Reads server configuration and outputs a ready-to-import config.\n")
		fmt.Fprintf(os.Stderr, "Pipe to file:      hydraflow export --format clash > config.yaml\n")
		fmt.Fprintf(os.Stderr, "Copy to clipboard: hydraflow export --format v2ray | pbcopy\n")
		os.Exit(1)
	}

	// Load the sub-config.json which has all protocol details.
	subConfig, err := loadSubConfig("/etc/hydraflow/sub-config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read server config: %v\n", err)
		fmt.Fprintf(os.Stderr, "Make sure HydraFlow is installed and /etc/hydraflow/sub-config.json exists.\n")
		os.Exit(1)
	}

	switch strings.ToLower(format) {
	case "v2ray", "v2rayng":
		exportV2Ray(subConfig)
	case "clash", "clashmeta", "clash-meta":
		exportClash(subConfig)
	case "singbox", "sing-box":
		exportSingBox(subConfig)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q\n", format)
		fmt.Fprintf(os.Stderr, "Supported formats: v2ray, clash, singbox\n")
		os.Exit(1)
	}
}

// subConfigFile represents the sub-config.json structure.
type subConfigFile struct {
	ServerIP  string `json:"server_ip"`
	SubToken  string `json:"sub_token"`
	SubPort   int    `json:"sub_port"`
	Protocols struct {
		Reality struct {
			Port        int    `json:"port"`
			UUID        string `json:"uuid"`
			PublicKey   string `json:"public_key"`
			ShortID     string `json:"short_id"`
			SNI         string `json:"sni"`
			Flow        string `json:"flow"`
			Fingerprint string `json:"fingerprint"`
		} `json:"reality"`
		WS struct {
			Port int    `json:"port"`
			UUID string `json:"uuid"`
			Path string `json:"path"`
			Host string `json:"host"`
		} `json:"ws"`
		SS struct {
			Port     int    `json:"port"`
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"ss"`
	} `json:"protocols"`
}

func loadSubConfig(path string) (*subConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg subConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &cfg, nil
}

func exportV2Ray(cfg *subConfigFile)   { exportClientConfig(cfg, "v2ray") }
func exportClash(cfg *subConfigFile)   { exportClientConfig(cfg, "clash") }
func exportSingBox(cfg *subConfigFile) { exportClientConfig(cfg, "singbox") }

func exportClientConfig(cfg *subConfigFile, format string) {
	var nodes []smartsub.Node
	r := cfg.Protocols.Reality
	if r.UUID != "" {
		nodes = append(nodes, smartsub.Node{Name: "HydraFlow-Reality", Protocol: "reality", Server: cfg.ServerIP, Port: r.Port, UUID: r.UUID, PublicKey: r.PublicKey, ShortID: r.ShortID, SNI: r.SNI, Flow: r.Flow, Fingerprint: r.Fingerprint})
	}
	w := cfg.Protocols.WS
	if w.UUID != "" {
		nodes = append(nodes, smartsub.Node{Name: "HydraFlow-WS", Protocol: "ws", Server: cfg.ServerIP, Port: w.Port, UUID: w.UUID, Path: w.Path, Host: w.Host, Security: "none"})
	}
	ss := cfg.Protocols.SS
	if ss.Password != "" {
		nodes = append(nodes, smartsub.Node{Name: "HydraFlow-SS", Protocol: "ss", Server: cfg.ServerIP, Port: ss.Port, SSMethod: ss.Method, SSPassword: ss.Password})
	}
	data, _, err := smartsub.RenderSubscription(nodes, format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "export: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
