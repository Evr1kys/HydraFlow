package smartsub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSubscriptionIsolation(t *testing.T) {
	e := NewEngine(EngineConfig{Token: "admin-secret"})
	e.SetNodes([]Node{
		{Email: "alice@example.com", UUID: "alice-uuid", Protocol: "reality", Server: "127.0.0.1", Port: 443, Enabled: true},
		{Email: "bob@example.com", UUID: "bob-uuid", Protocol: "reality", Server: "127.0.0.1", Port: 443, Enabled: true},
	})
	token := SubscriptionToken("admin-secret", "alice@example.com")
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/sub/" + token + "/alice@example.com", 200},
		{"/sub/" + token + "/bob@example.com", 404},
		{"/sub/admin-secret/alice@example.com", 404},
		{"/sub/" + token + "?email=bob@example.com", 404},
		{"/admin/" + token + "/status", 404},
		{"/admin/admin-secret/status", 200},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rr := httptest.NewRecorder()
		e.Handler().ServeHTTP(rr, req)
		if rr.Code != tc.status {
			t.Fatalf("%s: got %d, want %d", tc.path, rr.Code, tc.status)
		}
		if rr.Code == 200 && strings.HasPrefix(tc.path, "/sub/") {
			data, err := base64.StdEncoding.DecodeString(rr.Body.String())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "bob-uuid") || !strings.Contains(string(data), "alice-uuid") {
				t.Fatalf("wrong credentials: %s", data)
			}
			if rr.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("credentials must not be cached")
			}
		}
	}
	e.SetNodes(nil)
	req := httptest.NewRequest("GET", "/sub/"+token+"/alice@example.com", nil)
	rr := httptest.NewRecorder()
	e.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatal("removed user still has a subscription")
	}
	if validSubscriptionToken("rotated-secret", "alice@example.com", token) {
		t.Fatal("old token survived rotation")
	}
	if validSubscriptionToken("", "alice@example.com", "") {
		t.Fatal("empty secret accepted")
	}
}

func TestSubscriptionFormatsAndEscaping(t *testing.T) {
	email := "alice+tag@example.com"
	e := NewEngine(EngineConfig{Token: "secret"})
	e.SetNodes([]Node{
		{Name: "same # name", Email: email, Enabled: true, Protocol: "reality", Server: "2001:db8::1", Port: 443, UUID: "11111111-1111-4111-8111-111111111111", SNI: "example.com", PublicKey: "public-key", ShortID: "ab", Flow: "xtls-rprx-vision", Fingerprint: "chrome"},
		{Name: "same # name", Email: email, Enabled: true, Protocol: "ws", Server: "127.0.0.1", Port: 8080, UUID: "22222222-2222-4222-8222-222222222222", Path: "/path?x=1&y=2", Host: "example.com", Security: "none"},
	})
	for _, format := range []string{"v2ray", "clash", "singbox"} {
		t.Run(format, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/sub/"+SubscriptionToken("secret", email)+"/"+url.PathEscape(email)+"?format="+format, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			rr := httptest.NewRecorder()
			e.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("%d: %s", rr.Code, rr.Body.String())
			}
			switch format {
			case "v2ray":
				b, err := base64.StdEncoding.DecodeString(rr.Body.String())
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(string(b), "\n")
				if len(lines) != 2 {
					t.Fatal("lost a transport")
				}
				u, err := url.Parse(lines[0])
				if err != nil {
					t.Fatal(err)
				}
				if u.Hostname() != "2001:db8::1" || u.Fragment != "1-same # name" || u.Query().Get("pbk") != "public-key" {
					t.Fatalf("bad Reality URL: %s", u)
				}
				u, err = url.Parse(lines[1])
				if err != nil {
					t.Fatal(err)
				}
				if u.Query().Get("path") != "/path?x=1&y=2" || u.Query().Get("security") != "none" {
					t.Fatal("transport parameters corrupted")
				}
			case "clash":
				var doc struct {
					Proxies []map[string]interface{} `yaml:"proxies"`
				}
				if err := yaml.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				if len(doc.Proxies) != 2 || doc.Proxies[0]["name"] == doc.Proxies[1]["name"] {
					t.Fatal("missing or duplicate proxies")
				}
				if doc.Proxies[1]["network"] != "ws" {
					t.Fatal("WS became TCP")
				}
			case "singbox":
				var doc struct {
					Outbounds []map[string]interface{} `json:"outbounds"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				if len(doc.Outbounds) != 4 {
					t.Fatal("missing selector, urltest or nodes")
				}
				if doc.Outbounds[2]["tls"] == nil {
					t.Fatal("missing Reality TLS")
				}
			}
		})
	}
}

func TestUnsupportedTransportIsNotRewrittenAsTCP(t *testing.T) {
	nodes := []Node{{Protocol: "xhttp", Server: "127.0.0.1", Port: 443, UUID: "id"}}
	if _, _, err := RenderSubscription(nodes, "v2ray"); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"clash", "singbox"} {
		if _, _, err := RenderSubscription(nodes, format); err == nil {
			t.Fatalf("unsupported XHTTP accepted as %s", format)
		}
	}
}
