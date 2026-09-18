package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Evr1kys/HydraFlow/config"
	"github.com/Evr1kys/HydraFlow/smartsub"
	"github.com/Evr1kys/HydraFlow/xray"
)

func TestStandaloneCredentialsSurviveReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hydraflow.yaml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerAddress = "203.0.113.7"
	if err := ensureReality(cfg, path); err != nil {
		t.Fatal(err)
	}
	firstKey, firstID := cfg.Standalone.RealityPrivateKey, cfg.Standalone.RealityShortID
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureReality(loaded, path); err != nil {
		t.Fatal(err)
	}
	if loaded.Standalone.RealityPrivateKey != firstKey || loaded.Standalone.RealityShortID != firstID {
		t.Fatal("credentials rotated on restart")
	}
	users := []User{{Email: "alice", UUID: "11111111-1111-4111-8111-111111111111", Enabled: true}, {Email: "disabled", UUID: "other"}}
	builder := xray.NewConfigBuilder()
	nodes := configureStandalone(loaded, users, builder)
	if len(nodes) != 1 || nodes[0].PublicKey == "" || nodes[0].ShortID != firstID || nodes[0].Server != cfg.ServerAddress {
		t.Fatalf("bad subscription nodes: %+v", nodes)
	}
	data, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var inbound map[string]interface{}
	for _, raw := range doc["inbounds"].([]interface{}) {
		candidate := raw.(map[string]interface{})
		if candidate["tag"] == "vless-reality" {
			inbound = candidate
		}
	}
	if inbound == nil {
		t.Fatal("missing Reality inbound")
	}
	reality := inbound["streamSettings"].(map[string]interface{})["realitySettings"].(map[string]interface{})
	if reality["privateKey"] != firstKey {
		t.Fatal("server key differs from stored key")
	}
	again := configureStandalone(loaded, append(users, User{Email: "bob", UUID: "22222222-2222-4222-8222-222222222222", Enabled: true}), builder)
	if len(again) != 2 || again[0].PublicKey != nodes[0].PublicKey {
		t.Fatal("user update changed server identity")
	}
	// Optional integration check against an actual Xray binary and its geo assets.
	if binary := os.Getenv("HYDRAFLOW_TEST_XRAY"); binary != "" {
		output := filepath.Join(t.TempDir(), "xray.json")
		if err := os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-test", "-c", output)
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(binary))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Xray rejected generated config: %v\n%s", err, out)
		}
	}
	// Optional syntax validation of the generated sing-box configuration.
	if binary := os.Getenv("HYDRAFLOW_TEST_SINGBOX"); binary != "" {
		body, _, err := smartsub.RenderSubscription(nodes, "singbox")
		if err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(t.TempDir(), "singbox.json")
		if err := os.WriteFile(output, body, 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(binary, "check", "-c", output).CombinedOutput(); err != nil {
			t.Fatalf("sing-box rejected config: %v\n%s", err, out)
		}
	}
}

func TestStandaloneRejectsInvalidSavedKeys(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Standalone.RealityPrivateKey = "invalid"
	if err := ensureReality(cfg, filepath.Join(t.TempDir(), "config.yaml")); err == nil {
		t.Fatal("invalid key accepted")
	}
	cfg.Standalone.RealityPrivateKey = ""
	cfg.Standalone.RealityShortID = "xyz"
	if err := ensureReality(cfg, filepath.Join(t.TempDir(), "config.yaml")); err == nil {
		t.Fatal("invalid short ID accepted")
	}
}
