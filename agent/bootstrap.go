package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// BootstrapResult contains the one-time registration material printed by the
// CLI. Secret must be transferred to Panel over a trusted administrative path.
type BootstrapResult struct {
	KeyID        string `json:"key_id"`
	Secret       string `json:"secret"`
	CACertFile   string `json:"ca_cert_file"`
	TLSCertFile  string `json:"tls_cert_file"`
	TLSKeyFile   string `json:"tls_key_file"`
	KeyStoreFile string `json:"key_store_file"`
}

func BootstrapCredentials(dir string, hosts []string, force bool) (BootstrapResult, error) {
	if dir == "" {
		dir = "/etc/hydraflow/agent"
	}
	if len(hosts) == 0 {
		return BootstrapResult{}, fmt.Errorf("at least one DNS name or IP address is required")
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return BootstrapResult{}, err
	}

	paths := []string{
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "keys.json"),
	}
	if !force {
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return BootstrapResult{}, fmt.Errorf("credential file already exists: %s", path)
			} else if !os.IsNotExist(err) {
				return BootstrapResult{}, err
			}
		}
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return BootstrapResult{}, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return BootstrapResult{}, err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "HydraFlow Agent Local CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return BootstrapResult{}, err
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
		} else {
			serverTemplate.DNSNames = append(serverTemplate.DNSNames, host)
		}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return BootstrapResult{}, err
	}

	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return BootstrapResult{}, err
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return BootstrapResult{}, err
	}
	caCertPath := paths[0]
	caKeyPath := paths[1]
	serverCertPath := paths[2]
	serverKeyPath := paths[3]
	keyStorePath := paths[4]
	if err := atomicWriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644); err != nil {
		return BootstrapResult{}, err
	}
	if err := atomicWriteFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER}), 0600); err != nil {
		return BootstrapResult{}, err
	}
	if err := atomicWriteFile(serverCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0644); err != nil {
		return BootstrapResult{}, err
	}
	if err := atomicWriteFile(serverKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}), 0600); err != nil {
		return BootstrapResult{}, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return BootstrapResult{}, err
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return BootstrapResult{}, err
	}
	keyID := "agent-" + hex.EncodeToString(idBytes)
	encodedSecret := base64.RawStdEncoding.EncodeToString(secret)
	if err := writeKeyFileAtomic(keyStorePath, keyFile{
		Active: keyRecord{ID: keyID, Secret: encodedSecret},
	}); err != nil {
		return BootstrapResult{}, err
	}

	return BootstrapResult{
		KeyID:        keyID,
		Secret:       encodedSecret,
		CACertFile:   caCertPath,
		TLSCertFile:  serverCertPath,
		TLSKeyFile:   serverKeyPath,
		KeyStoreFile: keyStorePath,
	}, nil
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
