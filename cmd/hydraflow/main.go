// HydraFlow -- Smart anti-censorship subscription middleware.
//
// HydraFlow is NOT a panel. It's a smart layer that:
//   - Works standalone: manages xray + serves smart subscriptions
//   - Integrates with 3x-ui: reads its database, serves smart subscriptions
//   - Integrates with Marzban: reads its API, serves smart subscriptions
//
// Usage:
//
//	hydraflow serve                     Start smart subscription server
//	hydraflow serve --mode standalone   With built-in xray management
//	hydraflow serve --mode 3xui         Read from 3x-ui database
//	hydraflow serve --mode marzban      Read from Marzban API
//
//	hydraflow user add <email>          Add user (standalone mode)
//	hydraflow user list                 List users
//	hydraflow user del <email>          Remove user
//	hydraflow user sub <email>          Print subscription URL
//
//	hydraflow server add <ip> <key>     Add remote server
//	hydraflow server list               List servers
//	hydraflow server health             Check all servers health
//
//	hydraflow update                    Check for updates and upgrade
//	hydraflow test <vless-link>         Test VLESS link connectivity
//	hydraflow export --format <fmt>     Export config for client app
//	hydraflow backup [path]             Backup all configs
//	hydraflow restore <file>            Restore from backup
//
//	hydraflow status                    Show service status
//	hydraflow probe <host:port>         Run censorship probes
//	hydraflow version                   Version info
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Evr1kys/HydraFlow/discovery"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe()
	case "user":
		cmdUser()
	case "server":
		cmdServer()
	case "status":
		cmdStatus()
	case "probe":
		cmdProbe()
	case "update":
		cmdUpdate()
	case "test":
		cmdTest()
	case "export":
		cmdExport()
	case "backup":
		cmdBackup()
	case "restore":
		cmdRestore()
	case "version":
		fmt.Printf("hydraflow %s (built %s)\n", version, buildTime)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func cmdProbe() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow probe <host:port>\n")
		os.Exit(1)
	}

	target := os.Args[2]
	prober := discovery.NewProber(target)

	fmt.Printf("Probing %s for censorship...\n\n", target)

	results, err := prober.RunAll(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe error: %v\n", err)
		os.Exit(1)
	}

	for _, r := range results {
		status := "PASS"
		if !r.Success {
			status = "FAIL"
		}

		fmt.Printf("  %-20s [%s]", r.TestName, status)
		if r.Latency > 0 {
			fmt.Printf("  %v", r.Latency.Round(time.Millisecond))
		}
		fmt.Println()

		for k, v := range r.Details {
			fmt.Printf("    %s: %s\n", k, v)
		}
	}
}

func cmdStatus() {
	cfgPath := getConfigPath()
	cfg, err := loadCLIConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("HydraFlow %s\n\n", version)
	fmt.Printf("  Mode:    %s\n", cfg.Mode)
	fmt.Printf("  Listen:  %s\n", cfg.Listen)
	fmt.Printf("  Config:  %s\n", cfgPath)

	switch cfg.Mode {
	case "standalone":
		fmt.Printf("  Users:   %s\n", cfg.Standalone.UsersFile)
		fmt.Printf("  Xray:    %s\n", cfg.Standalone.XrayBinary)
	case "3xui":
		fmt.Printf("  3x-ui DB: %s\n", cfg.XUI.Database)
		fmt.Printf("  Poll:     %ds\n", cfg.XUI.PollInterval)
	case "marzban":
		fmt.Printf("  API URL: %s\n", cfg.Marzban.APIURL)
	}

	fmt.Println("\n  Issue a subscription: hydraflow user sub <email>")
}

func printUsage() {
	fmt.Printf(`HydraFlow %s -- Smart anti-censorship subscription middleware

Usage:
  hydraflow serve [flags]             Start smart subscription server
  hydraflow user <add|list|del|sub>   Manage users (standalone mode)
  hydraflow server <add|list|health>  Manage multi-server setup
  hydraflow status                    Show service status
  hydraflow probe <host:port>         Run censorship detection probes
  hydraflow update                    Check for updates and upgrade binary
  hydraflow test <vless-link>         Test if a VLESS link is reachable
  hydraflow export --format <fmt>     Export config for client app
  hydraflow backup [path]             Backup all configs to archive
  hydraflow restore <file>            Restore configs from backup
  hydraflow version                   Print version information

Serve flags:
  --mode <mode>       Mode: standalone, 3xui, marzban (default: from config)
  --config <path>     Config file (default: /etc/hydraflow/hydraflow.yaml)
  --listen <addr>     Override listen address

User commands:
  hydraflow user add <email>          Add user, generate UUID
  hydraflow user list                 List all users with traffic stats
  hydraflow user del <email>          Remove user
  hydraflow user sub <email>          Print subscription URL for user

Server commands:
  hydraflow server add <ip> <key>     Add remote server
  hydraflow server list               List all servers with status
  hydraflow server health             Check health of all servers

Export formats:
  hydraflow export --format v2ray     Base64-encoded V2Ray subscription links
  hydraflow export --format clash     Clash Meta YAML configuration
  hydraflow export --format singbox   sing-box JSON configuration

Backup & restore:
  hydraflow backup                    Save to /etc/hydraflow/backup.tar.gz
  hydraflow backup /tmp/hf.tar.gz    Save to custom path
  hydraflow restore backup.tar.gz    Restore from archive

Examples:
  hydraflow serve                     Start with config defaults
  hydraflow serve --mode 3xui         Read from 3x-ui database
  hydraflow user add user@example.com Add a user
  hydraflow probe server.com:443      Test for censorship
  hydraflow test "vless://uuid@host:443?security=reality&..."
  hydraflow export --format clash > clash-config.yaml
  hydraflow update                    Self-update to latest release
`, version)
}

// getConfigPath returns the config path from --config flag or default.
func getConfigPath() string {
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return "/etc/hydraflow/hydraflow.yaml"
}

// portFromListen extracts the port from a listen address.
func portFromListen(listen string) string {
	for i := len(listen) - 1; i >= 0; i-- {
		if listen[i] == ':' {
			return listen[i+1:]
		}
	}
	return listen
}
