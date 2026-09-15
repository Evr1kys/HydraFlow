package smartsub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// RenderSubscription renders supported nodes using the requested client format.
// XHTTP is emitted only as a V2Ray link: the other clients have different
// transport support and must not receive a fabricated TCP replacement.
func RenderSubscription(nodes []Node, format string) ([]byte, string, error) {
	var links []string
	var proxies []map[string]interface{}
	var names []string
	for i, n := range nodes {
		// Prefix names to avoid duplicate tags and collisions with control outbounds.
		n.Name = fmt.Sprintf("%d-%s", i+1, n.Name)
		if format == "v2ray" {
			if link := nodeLink(n); link != "" {
				links = append(links, link)
			}
			continue
		}
		var proxy map[string]interface{}
		switch format {
		case "clash":
			proxy = clashProxy(n)
		case "singbox":
			proxy = singBoxOutbound(n)
		default:
			return nil, "", fmt.Errorf("unsupported subscription format %q", format)
		}
		if proxy != nil {
			proxies = append(proxies, proxy)
			names = append(names, n.Name)
		}
	}
	if format == "v2ray" {
		if len(links) == 0 {
			return nil, "", fmt.Errorf("no compatible nodes for %s", format)
		}
		return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))), "text/plain; charset=utf-8", nil
	}
	if len(proxies) == 0 {
		return nil, "", fmt.Errorf("no compatible nodes for %s", format)
	}
	if format == "clash" {
		doc := map[string]interface{}{
			"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "info",
			"proxies": proxies,
			"proxy-groups": []map[string]interface{}{
				{"name": "proxy", "type": "select", "proxies": append([]string{"auto"}, names...)},
				{"name": "auto", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300},
			},
			"rules": []string{"MATCH,proxy"},
		}
		b, err := yaml.Marshal(doc)
		return b, "application/yaml; charset=utf-8", err
	}
	outbounds := []map[string]interface{}{
		{"type": "selector", "tag": "proxy", "outbounds": append([]string{"auto"}, names...), "default": "auto"},
		{"type": "urltest", "tag": "auto", "outbounds": names, "url": "https://www.gstatic.com/generate_204", "interval": "3m"},
	}
	outbounds = append(outbounds, proxies...)
	doc := map[string]interface{}{
		"log":       map[string]interface{}{"level": "info"},
		"inbounds":  []map[string]interface{}{{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}},
		"outbounds": outbounds,
		"route":     map[string]interface{}{"final": "proxy", "auto_detect_interface": true},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	return b, "application/json; charset=utf-8", err
}

func nodeSecurity(n Node) string {
	if n.Security != "" {
		return n.Security
	}
	if n.Protocol == "reality" {
		return "reality"
	}
	if n.Protocol == "hysteria2" {
		return "tls"
	}
	return "none"
}

func nodeTransport(n Node) string {
	switch n.Protocol {
	case "ws", "grpc", "xhttp":
		return n.Protocol
	default:
		return "tcp"
	}
}

func nodeLink(n Node) string {
	u := &url.URL{Host: net.JoinHostPort(n.Server, strconv.Itoa(n.Port)), Fragment: n.Name}
	q := url.Values{}
	switch n.Protocol {
	case "", "vless", "reality", "ws", "grpc", "xhttp":
		u.Scheme = "vless"
		u.User = url.User(n.UUID)
		q.Set("encryption", "none")
		q.Set("type", nodeTransport(n))
		q.Set("security", nodeSecurity(n))
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		if n.Fingerprint != "" {
			q.Set("fp", n.Fingerprint)
		}
		if nodeSecurity(n) == "reality" {
			q.Set("pbk", n.PublicKey)
			q.Set("sid", n.ShortID)
		}
		if n.Flow != "" {
			q.Set("flow", n.Flow)
		}
		if n.Path != "" {
			q.Set("path", n.Path)
		}
		if n.Host != "" {
			q.Set("host", n.Host)
		}
		if n.ServiceName != "" {
			q.Set("serviceName", n.ServiceName)
		}
	case "ss":
		u.Scheme = "ss"
		// SIP002 requires plain, percent-encoded credentials for AEAD-2022.
		if strings.HasPrefix(n.SSMethod, "2022-") {
			u.User = url.UserPassword(n.SSMethod, n.SSPassword)
		} else {
			u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(n.SSMethod + ":" + n.SSPassword)))
		}
	case "hysteria2":
		u.Scheme = "hysteria2"
		u.User = url.User(n.UUID)
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		if n.Obfs != "" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", n.Obfs)
		}
	default:
		return ""
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func clashProxy(n Node) map[string]interface{} {
	p := map[string]interface{}{"name": n.Name, "server": n.Server, "port": n.Port, "udp": true}
	switch n.Protocol {
	case "", "vless", "reality", "ws", "grpc":
		p["type"] = "vless"
		p["uuid"] = n.UUID
		p["network"] = nodeTransport(n)
		if n.Flow != "" {
			p["flow"] = n.Flow
		}
		if nodeSecurity(n) != "none" {
			p["tls"] = true
			p["servername"] = n.SNI
			if n.Fingerprint != "" {
				p["client-fingerprint"] = n.Fingerprint
			}
		}
		if nodeSecurity(n) == "reality" {
			p["reality-opts"] = map[string]interface{}{"public-key": n.PublicKey, "short-id": n.ShortID}
		}
		if n.Protocol == "ws" {
			p["ws-opts"] = map[string]interface{}{"path": n.Path, "headers": map[string]string{"Host": n.Host}}
		}
		if n.Protocol == "grpc" {
			p["grpc-opts"] = map[string]interface{}{"grpc-service-name": n.ServiceName}
		}
	case "ss":
		p["type"] = "ss"
		p["cipher"] = n.SSMethod
		p["password"] = n.SSPassword
	case "hysteria2":
		p["type"] = "hysteria2"
		p["password"] = n.UUID
		p["sni"] = n.SNI
		if n.Obfs != "" {
			p["obfs"] = "salamander"
			p["obfs-password"] = n.Obfs
		}
	default:
		return nil
	}
	return p
}

func singBoxOutbound(n Node) map[string]interface{} {
	p := map[string]interface{}{"tag": n.Name, "server": n.Server, "server_port": n.Port}
	switch n.Protocol {
	case "", "vless", "reality", "ws", "grpc":
		p["type"] = "vless"
		p["uuid"] = n.UUID
		if n.Flow != "" {
			p["flow"] = n.Flow
		}
		if n.Protocol == "ws" {
			p["transport"] = map[string]interface{}{"type": "ws", "path": n.Path, "headers": map[string]string{"Host": n.Host}}
		}
		if n.Protocol == "grpc" {
			p["transport"] = map[string]interface{}{"type": "grpc", "service_name": n.ServiceName}
		}
	case "ss":
		p["type"] = "shadowsocks"
		p["method"] = n.SSMethod
		p["password"] = n.SSPassword
	case "hysteria2":
		p["type"] = "hysteria2"
		p["password"] = n.UUID
		if n.Obfs != "" {
			p["obfs"] = map[string]interface{}{"type": "salamander", "password": n.Obfs}
		}
	default:
		return nil
	}
	if nodeSecurity(n) != "none" && n.Protocol != "ss" {
		tls := map[string]interface{}{"enabled": true, "server_name": n.SNI}
		if n.Fingerprint != "" && n.Protocol != "hysteria2" {
			tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": n.Fingerprint}
		}
		if nodeSecurity(n) == "reality" {
			tls["reality"] = map[string]interface{}{"enabled": true, "public_key": n.PublicKey, "short_id": n.ShortID}
		}
		p["tls"] = tls
	}
	return p
}
