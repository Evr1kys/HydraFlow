package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/Evr1kys/HydraFlow/config"
	"github.com/Evr1kys/HydraFlow/smartsub"
	"github.com/Evr1kys/HydraFlow/xray"
)

func serverAddress(cfg *config.Config) string {
	if cfg.ServerAddress != "" {
		return cfg.ServerAddress
	}
	return detectServerIP(cfg.Listen)
}

// ensureReality generates credentials once and validates saved credentials.
// The same persisted private key supplies both Xray and client public keys.
func ensureReality(cfg *config.Config, path string) error {
	changed := false
	if cfg.Standalone.RealityPrivateKey == "" {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate Reality key: %w", err)
		}
		cfg.Standalone.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
		changed = true
	}
	if _, err := realityPublicKey(cfg.Standalone.RealityPrivateKey); err != nil {
		return err
	}
	if cfg.Standalone.RealityShortID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate Reality short ID: %w", err)
		}
		cfg.Standalone.RealityShortID = hex.EncodeToString(b)
		changed = true
	}
	id, err := hex.DecodeString(cfg.Standalone.RealityShortID)
	if err != nil || len(id) == 0 || len(id) > 8 {
		return fmt.Errorf("Reality short ID must be 2 to 16 hexadecimal characters, with even length")
	}
	if changed {
		return config.Save(cfg, path)
	}
	return nil
}

func realityPublicKey(encoded string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid Reality private key encoding: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(data)
	if err != nil {
		return "", fmt.Errorf("invalid Reality private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// configureStandalone is shared by startup and user reloads, preserving keys.
func configureStandalone(cfg *config.Config, users []User, builder *xray.ConfigBuilder) []smartsub.Node {
	publicKey, _ := realityPublicKey(cfg.Standalone.RealityPrivateKey) // validated at startup
	builder.Reset()
	builder.AddInbound(xray.InboundConfig{
		Tag: "vless-reality", Type: xray.InboundVLESSReality, Port: 443,
		RealityDest: "www.microsoft.com:443", RealityServerNames: []string{"www.microsoft.com"},
		RealityPrivateKey: cfg.Standalone.RealityPrivateKey,
		RealityPublicKey:  publicKey, RealityShortIDs: []string{cfg.Standalone.RealityShortID},
		Flow: "xtls-rprx-vision",
	})
	var nodes []smartsub.Node
	for _, u := range users {
		if !u.Enabled {
			continue
		}
		builder.AddUser("vless-reality", u.Email, u.UUID)
		nodes = append(nodes, smartsub.Node{
			Name: "HydraFlow-Reality", Server: serverAddress(cfg), Port: 443,
			Protocol: "reality", Security: "reality", UUID: u.UUID, Email: u.Email, Enabled: true,
			SNI: "www.microsoft.com", Flow: "xtls-rprx-vision", Fingerprint: "chrome",
			PublicKey: publicKey, ShortID: cfg.Standalone.RealityShortID, ServerName: "local",
		})
	}
	return nodes
}
