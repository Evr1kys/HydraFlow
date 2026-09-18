package main

import (
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/Evr1kys/HydraFlow/config"
	"github.com/Evr1kys/HydraFlow/smartsub"
	"github.com/Evr1kys/HydraFlow/xray"
)

// cmdUser handles all user management subcommands.
func cmdUser() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user <add|list|del|sub> [args]\n")
		os.Exit(1)
	}

	cfgPath := getConfigPath()
	cfg, err := loadCLIConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if cfg.Mode != config.ModeStandalone && os.Args[2] != "sub" {
		fmt.Fprintf(os.Stderr, "user management is only available in standalone mode (current: %s)\n", cfg.Mode)
		os.Exit(1)
	}

	switch os.Args[2] {
	case "add":
		cmdUserAdd(cfg)
	case "list":
		cmdUserList(cfg)
	case "del", "delete", "rm", "remove":
		cmdUserDel(cfg)
	case "sub":
		cmdUserSub(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown user command: %s\n", os.Args[2])
		fmt.Fprintf(os.Stderr, "usage: hydraflow user <add|list|del|sub> [args]\n")
		os.Exit(1)
	}
}

func cmdUserAdd(cfg *config.Config) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user add <email>\n")
		os.Exit(1)
	}

	email := os.Args[3]

	user, err := addUser(cfg.Standalone.UsersFile, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	serverIP := serverAddress(cfg)

	fmt.Printf("User added:\n")
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  UUID:  %s\n", user.UUID)
	fmt.Printf("\n")
	fmt.Printf("  Subscription URL: %s\n", userSubscriptionURL(cfg, serverIP, user.Email))
	fmt.Printf("\n")
	fmt.Printf("  Running HydraFlow reloads users automatically within 10 seconds.\n")
}

func cmdUserList(cfg *config.Config) {
	users, err := loadUsers(cfg.Standalone.UsersFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No users found. Add one with: hydraflow user add <email>")
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(users) == 0 {
		fmt.Println("No users found. Add one with: hydraflow user add <email>")
		return
	}

	// Try to get live traffic stats from xray.
	statsClient := xray.NewStatsClient("127.0.0.1:10085", nil)
	allTraffic, _ := statsClient.GetAllUserTraffic(false)

	fmt.Printf("%-30s %-8s %-12s %-12s %s\n", "EMAIL", "STATUS", "UPLOAD", "DOWNLOAD", "UUID")
	fmt.Printf("%-30s %-8s %-12s %-12s %s\n", "-----", "------", "------", "--------", "----")

	for _, u := range users {
		status := "active"
		if !u.Enabled {
			status = "disabled"
		}

		upStr := formatBytes(u.TrafficUp)
		downStr := formatBytes(u.TrafficDown)

		// Merge live stats if available.
		if allTraffic != nil {
			if t, ok := allTraffic[u.Email]; ok {
				upStr = formatBytes(t.Uplink + u.TrafficUp)
				downStr = formatBytes(t.Downlink + u.TrafficDown)
			}
		}

		fmt.Printf("%-30s %-8s %-12s %-12s %s\n", u.Email, status, upStr, downStr, u.UUID)
	}

	fmt.Printf("\nTotal: %d users\n", len(users))
}

func cmdUserDel(cfg *config.Config) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user del <email>\n")
		os.Exit(1)
	}

	email := os.Args[3]

	if err := deleteUser(cfg.Standalone.UsersFile, email); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("User %s removed.\n", email)
	fmt.Printf("Running HydraFlow reloads users automatically within 10 seconds.\n")
}

func cmdUserSub(cfg *config.Config) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user sub <email>\n")
		os.Exit(1)
	}

	email := os.Args[3]

	// Standalone users are local; panel-mode identities come from the provider.
	if cfg.Mode == config.ModeStandalone {
		users, err := loadUsers(cfg.Standalone.UsersFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		found := false
		for _, u := range users {
			if u.Email == email && u.Enabled {
				found = true
				break
			}
		}

		if !found {
			fmt.Fprintf(os.Stderr, "user %q not found\n", email)
			os.Exit(1)
		}

	}
	link := userSubscriptionURL(cfg, serverAddress(cfg), email)
	fmt.Printf("Subscription URLs for %s:\n\n", email)
	fmt.Printf("  Universal:  %s\n", link)
	fmt.Printf("  V2Ray:      %s?format=v2ray\n", link)
	fmt.Printf("  Clash:      %s?format=clash\n", link)
	fmt.Printf("  sing-box:   %s?format=singbox\n", link)
	fmt.Printf("\n")
	fmt.Printf("  The format is auto-detected from User-Agent if not specified.\n")
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(b int64) string {
	if b == 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"KB", "MB", "GB", "TB"}
	if exp >= len(suffix) {
		exp = len(suffix) - 1
	}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), suffix[exp])
}

func userSubscriptionURL(cfg *config.Config, host, email string) string {
	return "http://" + net.JoinHostPort(host, portFromListen(cfg.Listen)) + "/sub/" + smartsub.SubscriptionToken(cfg.AdminToken, email) + "/" + url.PathEscape(email)
}
