package smartsub

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NewEngine
// ---------------------------------------------------------------------------

func TestNewEngine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cfg    EngineConfig
		token  string
		wantIP string
	}{
		{
			name:   "basic config",
			cfg:    EngineConfig{Token: "secret", ServerIP: "1.2.3.4"},
			token:  "secret",
			wantIP: "1.2.3.4",
		},
		{
			name:   "with logger",
			cfg:    EngineConfig{Token: "tok", ServerIP: "5.6.7.8", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
			token:  "tok",
			wantIP: "5.6.7.8",
		},
		{
			name:   "nil logger uses default",
			cfg:    EngineConfig{Token: "t"},
			token:  "t",
			wantIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := NewEngine(tt.cfg)
			if e == nil {
				t.Fatal("NewEngine returned nil")
			}
			if e.token != tt.token {
				t.Errorf("token = %q, want %q", e.token, tt.token)
			}
			if e.serverIP != tt.wantIP {
				t.Errorf("serverIP = %q, want %q", e.serverIP, tt.wantIP)
			}
			if e.logger == nil {
				t.Error("logger is nil")
			}
			if e.isp == nil {
				t.Error("isp is nil")
			}
			if e.health == nil {
				t.Error("health is nil")
			}
			if e.telemetry == nil {
				t.Error("telemetry is nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SetNodes / GetNodes
// ---------------------------------------------------------------------------

func TestSetGetNodes(t *testing.T) {
	t.Parallel()
	e := NewEngine(EngineConfig{Token: "t", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	// Initially empty.
	if got := e.GetNodes(); len(got) != 0 {
		t.Fatalf("expected 0 initial nodes, got %d", len(got))
	}

	nodes := []Node{
		{Name: "n1", Server: "1.1.1.1", Port: 443, Protocol: "reality", Email: "a@b.com", Enabled: true},
		{Name: "n2", Server: "2.2.2.2", Port: 8443, Protocol: "ws", Email: "c@d.com", Enabled: false},
	}

	e.SetNodes(nodes)

	got := e.GetNodes()
	if len(got) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(got))
	}

	// Verify it is a copy (modifying returned slice does not affect engine).
	got[0].Name = "MODIFIED"
	original := e.GetNodes()
	if original[0].Name == "MODIFIED" {
		t.Error("GetNodes did not return a copy")
	}

	// Verify content.
	for i, n := range e.GetNodes() {
		if n.Name != nodes[i].Name {
			t.Errorf("node[%d].Name = %q, want %q", i, n.Name, nodes[i].Name)
		}
	}
}

// ---------------------------------------------------------------------------
// NodesForUser
// ---------------------------------------------------------------------------

func TestNodesForUser(t *testing.T) {
	t.Parallel()
	e := NewEngine(EngineConfig{Token: "t", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	nodes := []Node{
		{Name: "r1", Server: "1.1.1.1", Port: 443, Protocol: "reality", Email: "alice@test.com", Enabled: true},
		{Name: "w1", Server: "1.1.1.1", Port: 8443, Protocol: "ws", Email: "alice@test.com", Enabled: true},
		{Name: "r2", Server: "2.2.2.2", Port: 443, Protocol: "reality", Email: "bob@test.com", Enabled: true},
		{Name: "disabled", Server: "3.3.3.3", Port: 443, Protocol: "reality", Email: "alice@test.com", Enabled: false},
	}
	e.SetNodes(nodes)

	tests := []struct {
		name      string
		email     string
		clientIP  string
		wantCount int
	}{
		{"alice gets her nodes", "alice@test.com", "127.0.0.1", 2},
		{"bob gets his node", "bob@test.com", "127.0.0.1", 1},
		{"unknown user gets nothing", "nobody@test.com", "127.0.0.1", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := e.NodesForUser(tt.email, tt.clientIP)
			if len(got) != tt.wantCount {
				t.Errorf("NodesForUser(%q, %q) returned %d nodes, want %d", tt.email, tt.clientIP, len(got), tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// fuzzyMatchISP
// ---------------------------------------------------------------------------

func TestFuzzyMatchISP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		isp  string
		org  string
		want string
	}{
		{"PJSC MegaFon", "", "megafon"},
		{"", "MegaFon Corp", "megafon"},
		{"MTS PJSC", "", "mts"},
		{"Mobile TeleSystems", "", "mts"},
		{"Beeline", "", "beeline"},
		{"PJSC VimpelCom", "", "beeline"},
		{"Tele2 AB", "", "tele2"},
		{"Rostelecom", "", "rostelecom"},
		{"LLC Dom.Ru", "", "domru"},
		{"ERTelecom", "", "domru"},
		{"Yota", "", "yota"},
		{"Scartel LLC", "", "yota"},
		{"TransTeleCom", "", "ttk"},
		{"China Telecom", "", "china-telecom"},
		{"ChinaNet", "", "china-telecom"},
		{"China Mobile", "", "china-mobile"},
		{"CMNET", "", "china-mobile"},
		{"China Unicom", "", "china-unicom"},
		{"Mobile Communication Company of Iran", "", "mci"},
		{"MTN Irancell", "", "irancell"},
		{"Unknown ISP", "Unknown Org", "default"},
		{"", "", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.isp+"_"+tt.org, func(t *testing.T) {
			t.Parallel()
			got := fuzzyMatchISP(tt.isp, tt.org)
			if got != tt.want {
				t.Errorf("fuzzyMatchISP(%q, %q) = %q, want %q", tt.isp, tt.org, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetISPPriority
// ---------------------------------------------------------------------------

func TestGetISPPriority(t *testing.T) {
	t.Parallel()
	tests := []struct {
		isp       string
		wantFirst string
	}{
		{"megafon", "ws-cdn"},
		{"beeline", "reality"},
		{"mts", "ws-cdn"},
		{"default", "reality"},
		{"unknown-isp", "reality"}, // falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.isp, func(t *testing.T) {
			t.Parallel()
			got := GetISPPriority(tt.isp)
			if len(got) == 0 {
				t.Fatal("empty priority list")
			}
			if got[0] != tt.wantFirst {
				t.Errorf("first priority for %q = %q, want %q", tt.isp, got[0], tt.wantFirst)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TelemetryStore — Record and IsBlocked
// ---------------------------------------------------------------------------

func TestTelemetryStore_RecordAndIsBlocked(t *testing.T) {
	t.Parallel()
	ts := NewTelemetryStore()

	// Not blocked with no data.
	if ts.IsBlocked("megafon", "reality") {
		t.Error("should not be blocked with no data")
	}

	// Record 5 blocked reports — not enough (need 10+ total).
	for i := 0; i < 5; i++ {
		ts.Record("megafon", TelemetryReport{Protocol: "reality", Status: "blocked"})
	}
	if ts.IsBlocked("megafon", "reality") {
		t.Error("should not be blocked with only 5 reports")
	}

	// Record 6 more blocked (total 11, all blocked = 100% > 60%).
	for i := 0; i < 6; i++ {
		ts.Record("megafon", TelemetryReport{Protocol: "reality", Status: "blocked"})
	}
	if !ts.IsBlocked("megafon", "reality") {
		t.Error("should be blocked with 11 blocked reports out of 11")
	}

	// A different ISP/protocol should not be blocked.
	if ts.IsBlocked("mts", "reality") {
		t.Error("mts/reality should not be blocked")
	}
	if ts.IsBlocked("megafon", "ws") {
		t.Error("megafon/ws should not be blocked")
	}
}

func TestTelemetryStore_NotBlockedWhenOKDominates(t *testing.T) {
	t.Parallel()
	ts := NewTelemetryStore()

	// 7 OK + 4 blocked = 11 total, blocked/total = 36% < 60%.
	for i := 0; i < 7; i++ {
		ts.Record("mts", TelemetryReport{Protocol: "ws", Status: "ok"})
	}
	for i := 0; i < 4; i++ {
		ts.Record("mts", TelemetryReport{Protocol: "ws", Status: "blocked"})
	}

	if ts.IsBlocked("mts", "ws") {
		t.Error("should not be blocked when OK dominates")
	}
}

func TestTelemetryStore_UnknownProtocolRejected(t *testing.T) {
	t.Parallel()
	ts := NewTelemetryStore()

	ts.Record("megafon", TelemetryReport{Protocol: "fake-proto", Status: "ok"})
	snap := ts.GetSnapshot()
	if _, ok := snap["megafon"]; ok {
		t.Error("unknown protocol should be silently rejected")
	}
}

func TestTelemetryStore_GetSnapshot(t *testing.T) {
	t.Parallel()
	ts := NewTelemetryStore()

	ts.Record("megafon", TelemetryReport{Protocol: "reality", Status: "ok"})
	ts.Record("megafon", TelemetryReport{Protocol: "reality", Status: "blocked"})
	ts.Record("megafon", TelemetryReport{Protocol: "ws", Status: "slow"})

	snap := ts.GetSnapshot()
	ispData, ok := snap["megafon"]
	if !ok {
		t.Fatal("expected megafon in snapshot")
	}

	realityData, ok := ispData.Protocols["reality"]
	if !ok {
		t.Fatal("expected reality in megafon protocols")
	}
	if realityData.OK != 1 || realityData.Blocked != 1 {
		t.Errorf("reality counters: OK=%d Blocked=%d, want 1/1", realityData.OK, realityData.Blocked)
	}

	wsData, ok := ispData.Protocols["ws"]
	if !ok {
		t.Fatal("expected ws in megafon protocols")
	}
	if wsData.Slow != 1 {
		t.Errorf("ws slow=%d, want 1", wsData.Slow)
	}
}

// ---------------------------------------------------------------------------
// extractClientIP
// ---------------------------------------------------------------------------

func TestExtractClientIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{
			name:       "localhost trusts XFF",
			remoteAddr: "127.0.0.1:12345",
			xff:        "203.0.113.5, 10.0.0.1",
			want:       "203.0.113.5",
		},
		{
			name:       "localhost trusts X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			xRealIP:    "198.51.100.7",
			want:       "198.51.100.7",
		},
		{
			name:       "localhost XFF takes priority over X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			xff:        "203.0.113.5",
			xRealIP:    "198.51.100.7",
			want:       "203.0.113.5",
		},
		{
			name:       "non-localhost ignores XFF",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.5",
			want:       "10.0.0.1",
		},
		{
			name:       "ipv6 localhost trusts XFF",
			remoteAddr: "[::1]:12345",
			xff:        "2001:db8::1",
			want:       "2001:db8::1",
		},
		{
			name:       "plain remote addr without port",
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			got := extractClientIP(r)
			if got != tt.want {
				t.Errorf("extractClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectFormat
// ---------------------------------------------------------------------------

func TestDetectFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		ua    string
		query string
		want  string
	}{
		{"query v2ray", "", "format=v2ray", "v2ray"},
		{"query clash", "", "format=clash", "clash"},
		{"query singbox", "", "format=singbox", "singbox"},
		{"query base64", "", "format=base64", "v2ray"},
		{"query sing-box", "", "format=sing-box", "singbox"},
		{"query clash-meta", "", "format=clash-meta", "clash"},
		{"ua v2rayng", "v2rayNG/1.8.5", "", "v2ray"},
		{"ua clash", "ClashMeta/1.0", "", "clash"},
		{"ua stash", "Stash/2.4", "", "clash"},
		{"ua mihomo", "mihomo/1.0", "", "clash"},
		{"ua singbox", "sing-box/1.5", "", "singbox"},
		{"ua sfa", "SFA/1.0", "", "singbox"},
		{"ua nekoray", "NekoRay/3.0", "", "v2ray"},
		{"ua hiddify", "Hiddify/1.0", "", "v2ray"},
		{"ua streisand", "Streisand/1.0", "", "v2ray"},
		{"ua unknown", "curl/7.0", "", "v2ray"},
		{"empty", "", "", "v2ray"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url := "/"
			if tt.query != "" {
				url = "/?" + tt.query
			}
			r := httptest.NewRequest(http.MethodGet, url, nil)
			if tt.ua != "" {
				r.Header.Set("User-Agent", tt.ua)
			}
			got := detectFormat(r)
			if got != tt.want {
				t.Errorf("detectFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hashIP
// ---------------------------------------------------------------------------

func TestHashIP(t *testing.T) {
	t.Parallel()
	// Deterministic.
	h1 := hashIP("192.168.1.1")
	h2 := hashIP("192.168.1.1")
	if h1 != h2 {
		t.Errorf("hashIP not deterministic: %q != %q", h1, h2)
	}
	// Different inputs give different outputs.
	h3 := hashIP("10.0.0.1")
	if h1 == h3 {
		t.Error("different IPs produced same hash")
	}
	// Length is 8 hex chars (4 bytes * 2).
	if len(h1) != 8 {
		t.Errorf("hash length = %d, want 8", len(h1))
	}
}

// ---------------------------------------------------------------------------
// formatProtocolName
// ---------------------------------------------------------------------------

func TestFormatProtocolName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"reality", "Reality"},
		{"ws", "WS-CDN"},
		{"grpc", "gRPC-CDN"},
		{"xhttp", "XHTTP"},
		{"ss", "SS-2022"},
		{"hysteria2", "Hysteria2"},
		{"shadowtls", "ShadowTLS"},
		{"custom", "Custom"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := formatProtocolName(tt.input)
			if got != tt.want {
				t.Errorf("formatProtocolName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HTTP handler — subscription
// ---------------------------------------------------------------------------

func TestHandler_SubscriptionOK(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := NewEngine(EngineConfig{Token: "test-token", ServerIP: "1.2.3.4", Logger: logger})

	nodes := []Node{
		{
			Name:      "n1",
			Server:    "1.2.3.4",
			Port:      443,
			Protocol:  "reality",
			UUID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Email:     "user@test.com",
			Enabled:   true,
			SNI:       "www.example.com",
			PublicKey: "pk123",
			ShortID:   "ab",
			Flow:      "xtls-rprx-vision",
		},
	}
	e.SetNodes(nodes)

	handler := e.Handler()

	req := httptest.NewRequest(http.MethodGet, "/sub/"+SubscriptionToken("test-token", "user@test.com")+"/user@test.com", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Body should be base64.
	body := rr.Body.String()
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("response is not valid base64: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") {
		t.Errorf("decoded body does not contain vless:// link: %s", string(decoded))
	}

	// Check subscription headers.
	if rr.Header().Get("Subscription-UserInfo") == "" {
		t.Error("missing Subscription-UserInfo header")
	}
	// X-HydraFlow-ISP header intentionally removed for security —
	// it would let observers fingerprint HydraFlow traffic.
}

func TestHandler_SubscriptionWrongToken(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := NewEngine(EngineConfig{Token: "real-token", ServerIP: "1.2.3.4", Logger: logger})
	e.SetNodes([]Node{{Name: "n", Protocol: "reality", Email: "u@t.com", Enabled: true}})

	handler := e.Handler()

	req := httptest.NewRequest(http.MethodGet, "/sub/wrong-token/u@t.com", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandler_SubscriptionEmptyPath(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := NewEngine(EngineConfig{Token: "tok", Logger: logger})
	handler := e.Handler()

	req := httptest.NewRequest(http.MethodGet, "/sub/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandler_HealthEndpoint(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := NewEngine(EngineConfig{Token: "tok", Logger: logger})
	handler := e.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Error("health response missing status:ok")
	}
}

// ---------------------------------------------------------------------------
// ProtocolHealth — mock TCP server
// ---------------------------------------------------------------------------

func TestProtocolHealth_MockServer(t *testing.T) {
	t.Parallel()

	// Start a mock TCP server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	ph := NewProtocolHealth(slog.New(slog.NewTextHandler(io.Discard, nil)))

	nodes := []Node{
		{Server: "127.0.0.1", Port: addr.Port, Protocol: "test"},
	}

	ph.CheckAll(nodes)

	// Give a moment for goroutines to complete.
	time.Sleep(100 * time.Millisecond)

	if !ph.IsUp("127.0.0.1", addr.Port) {
		t.Error("expected mock server to be UP")
	}
}

func TestProtocolHealth_UnreachableServer(t *testing.T) {
	t.Parallel()
	ph := NewProtocolHealth(slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Use a port that is almost certainly not listening.
	nodes := []Node{
		{Server: "127.0.0.1", Port: 19999, Protocol: "test"},
	}
	ph.CheckAll(nodes)
	time.Sleep(200 * time.Millisecond)

	// After checking, the unreachable port should be down.
	if ph.IsUp("127.0.0.1", 19999) {
		// IsUp returns true for never-checked, so only fail if we know it was checked.
		statuses := ph.GetAll()
		key := fmt.Sprintf("127.0.0.1:%d", 19999)
		if s, ok := statuses[key]; ok && s.Up {
			t.Error("expected unreachable server to be DOWN")
		}
	}
}

func TestProtocolHealth_NeverCheckedAssumesUp(t *testing.T) {
	t.Parallel()
	ph := NewProtocolHealth(slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Never checked = assume up.
	if !ph.IsUp("1.2.3.4", 443) {
		t.Error("never-checked should assume UP")
	}
}

// ---------------------------------------------------------------------------
// ISPLookup — direct cache test (no network calls)
// ---------------------------------------------------------------------------

func TestISPLookup_LoopbackReturnsDefault(t *testing.T) {
	t.Parallel()
	l := NewISPLookup(slog.New(slog.NewTextHandler(io.Discard, nil)))

	name, resp := l.Lookup("127.0.0.1")
	if name != "default" {
		t.Errorf("loopback ISP = %q, want %q", name, "default")
	}
	if resp != nil {
		t.Error("expected nil response for loopback")
	}
}

func TestISPLookup_PrivateReturnsDefault(t *testing.T) {
	t.Parallel()
	l := NewISPLookup(slog.New(slog.NewTextHandler(io.Discard, nil)))

	name, _ := l.Lookup("192.168.1.1")
	if name != "default" {
		t.Errorf("private IP ISP = %q, want %q", name, "default")
	}
}
