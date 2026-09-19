package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Evr1kys/HydraFlow/agent"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "version":
		fmt.Printf("hydraflow-agent %s (built %s)\n", version, buildTime)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hydraflow-agent:", err)
		os.Exit(1)
	}
}

func runInit(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := flags.String("dir", "/etc/hydraflow/agent", "credential directory")
	hosts := flags.String("hosts", "", "comma-separated DNS names or IP addresses for the TLS certificate")
	force := flags.Bool("force", false, "replace existing credentials")
	if err := flags.Parse(args); err != nil {
		return err
	}
	var hostList []string
	for _, host := range strings.Split(*hosts, ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			hostList = append(hostList, host)
		}
	}
	result, err := agent.BootstrapCredentials(*dir, hostList, *force)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Store the registration secret securely; it is shown only in this output.")
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "0.0.0.0:8443", "HTTPS listen address")
	certFile := flags.String("tls-cert", "/etc/hydraflow/agent/server.crt", "TLS certificate")
	keyFile := flags.String("tls-key", "/etc/hydraflow/agent/server.key", "TLS private key")
	clientCA := flags.String("client-ca", "", "optional CA used to require mTLS client certificates")
	authKeys := flags.String("auth-keys", "/etc/hydraflow/agent/keys.json", "HMAC key store")
	xrayBinary := flags.String("xray-bin", "/usr/local/bin/xray", "Xray binary")
	xrayConfig := flags.String("xray-config", "/etc/hydraflow/xray-config.json", "managed Xray config")
	xrayAssets := flags.String("xray-assets", "/usr/local/share/xray", "Xray asset directory")
	service := flags.String("service", "hydraflow-xray.service", "systemd Xray service")
	stateDir := flags.String("state-dir", "/var/lib/hydraflow-agent", "Agent state directory")
	auditLog := flags.String("audit-log", "/var/log/hydraflow/agent-audit.jsonl", "append-only audit log")
	statsAddress := flags.String("stats-address", "127.0.0.1:10085", "Xray stats API address")
	maxBody := flags.Int64("max-body", 2<<20, "maximum API request body in bytes")
	maxHistory := flags.Int("max-history", 20, "number of config revisions to retain")
	if err := flags.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	controller := &agent.SystemdController{
		XrayBinary: *xrayBinary,
		AssetPath:  *xrayAssets,
		Service:    *service,
	}
	server, err := agent.NewServer(agent.ServerConfig{
		ListenAddress:  *listen,
		TLSCertFile:    *certFile,
		TLSKeyFile:     *keyFile,
		ClientCAFile:   *clientCA,
		KeyFile:        *authKeys,
		XrayConfig:     *xrayConfig,
		StateDir:       *stateDir,
		AuditLog:       *auditLog,
		StatsAddress:   *statsAddress,
		Version:        version,
		BuildTime:      buildTime,
		MaxBodyBytes:   *maxBody,
		MaxHistory:     *maxHistory,
		ReplayWindow:   5 * time.Minute,
		IdempotencyTTL: 24 * time.Hour,
	}, controller, logger)
	if err != nil {
		return err
	}
	defer server.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("HydraFlow Agent starting", "listen", *listen, "version", version)
	return server.Serve(ctx)
}

func usage() {
	fmt.Fprint(os.Stderr, `HydraFlow Agent

Usage:
  hydraflow-agent init --hosts <dns-or-ip>[,<dns-or-ip>]
  hydraflow-agent serve [flags]
  hydraflow-agent version

The Agent API is always served over TLS. Requests require HMAC-signed headers;
optionally provide --client-ca to require mutual TLS as well.
`)
}
