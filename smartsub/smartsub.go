// Package smartsub is the core smart subscription engine of HydraFlow.
// It detects the client's ISP, orders protocols by what works best for
// that ISP, health-checks all protocols, aggregates client telemetry,
// merges multi-server nodes, and outputs in V2Ray, Clash, and sing-box formats.
//
// This is the heart of HydraFlow -- the thing that makes it different
// from every other subscription server.
package smartsub

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// hashIP returns the first 8 characters of the SHA-256 hex digest of an IP,
// suitable for privacy-preserving log output.
func hashIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return fmt.Sprintf("%x", h[:4])
}

// Node represents a single proxy node (one protocol on one server).
type Node struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // reality, ws, grpc, xhttp, ss, hysteria2
	UUID     string `json:"uuid"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`

	// Reality-specific
	SNI       string `json:"sni,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
	SpiderX   string `json:"spider_x,omitempty"`
	Flow      string `json:"flow,omitempty"`

	// Transport-specific (WS, gRPC, XHTTP)
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	CDN         string `json:"cdn,omitempty"`

	// Hysteria2-specific
	Obfs  string `json:"obfs,omitempty"`
	Ports []int  `json:"ports,omitempty"`

	// TLS
	Fingerprint string `json:"fingerprint,omitempty"`
	Security    string `json:"security,omitempty"` // reality, tls, none

	// Shadowsocks
	SSMethod   string `json:"ss_method,omitempty"`
	SSPassword string `json:"ss_password,omitempty"`

	// Source metadata
	ServerName string `json:"server_name,omitempty"` // e.g., "NL-1"
}

// Engine is the smart subscription engine.
type Engine struct {
	mu        sync.RWMutex
	logger    *slog.Logger
	isp       *ISPLookup
	health    *ProtocolHealth
	telemetry *TelemetryStore
	nodes     []Node // all known nodes across all servers
	token     string // subscription access token
	serverIP  string // this server's public IP
	startTime time.Time
}

// EngineConfig configures the smart subscription engine.
type EngineConfig struct {
	Token    string
	ServerIP string
	Logger   *slog.Logger
}

// NewEngine creates a new smart subscription engine.
func NewEngine(cfg EngineConfig) *Engine {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Engine{
		logger:    logger,
		isp:       NewISPLookup(logger),
		health:    NewProtocolHealth(logger),
		telemetry: NewTelemetryStore(),
		token:     cfg.Token,
		serverIP:  cfg.ServerIP,
		startTime: time.Now(),
	}
}

// SetNodes replaces all known nodes. Called when providers (standalone, 3xui, marzban) refresh.
func (e *Engine) SetNodes(nodes []Node) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nodes = append([]Node(nil), nodes...)
	e.logger.Info("nodes updated", "count", len(nodes))
}

// GetNodes returns a copy of all current nodes.
func (e *Engine) GetNodes() []Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Node, len(e.nodes))
	copy(out, e.nodes)
	return out
}

// StartHealthChecks begins periodic health checking of all nodes.
// It accepts a context; when the context is cancelled the goroutine exits.
func (e *Engine) StartHealthChecks(ctx context.Context, interval time.Duration) {
	go func() {
		e.health.CheckAll(e.GetNodes())
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.health.CheckAll(e.GetNodes())
			}
		}
	}()
}

// NodesForUser returns nodes filtered and ordered for a specific user+ISP.
func (e *Engine) NodesForUser(email, clientIP string) []Node {
	e.mu.RLock()
	nodes := make([]Node, 0)
	for _, n := range e.nodes {
		if n.Email == email && n.Enabled {
			nodes = append(nodes, n)
		}
	}
	e.mu.RUnlock()

	if len(nodes) == 0 {
		return nil
	}

	// Detect ISP.
	ispName, _ := e.isp.Lookup(clientIP)

	// Get ISP priority order.
	priority := GetISPPriority(ispName)

	// Build priority index.
	priorityIndex := make(map[string]int)
	for i, p := range priority {
		priorityIndex[p] = i
		// Also map common aliases.
		switch p {
		case "ws-cdn":
			priorityIndex["ws"] = i
		case "grpc-cdn":
			priorityIndex["grpc"] = i
		}
	}

	// Sort nodes by ISP priority, health status, and latency.
	sort.SliceStable(nodes, func(i, j int) bool {
		// Health first: up before down.
		iUp := e.health.IsUp(nodes[i].Server, nodes[i].Port)
		jUp := e.health.IsUp(nodes[j].Server, nodes[j].Port)
		if iUp != jUp {
			return iUp
		}

		// ISP priority second.
		iPri, iOk := priorityIndex[nodes[i].Protocol]
		jPri, jOk := priorityIndex[nodes[j].Protocol]
		if iOk && jOk {
			return iPri < jPri
		}
		if iOk {
			return true
		}
		if jOk {
			return false
		}

		// Telemetry-blocked protocols last.
		iBlocked := e.telemetry.IsBlocked(ispName, nodes[i].Protocol)
		jBlocked := e.telemetry.IsBlocked(ispName, nodes[j].Protocol)
		if iBlocked != jBlocked {
			return !iBlocked
		}

		return false
	})

	// Filter out telemetry-confirmed blocked protocols.
	filtered := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		if !e.telemetry.IsBlocked(ispName, n.Protocol) {
			filtered = append(filtered, n)
		}
	}

	if len(filtered) > 0 {
		return filtered
	}
	return nodes // if everything is "blocked", return all anyway
}

// SubscriptionForUser generates a interface{} for a user.

// nodeToProtocolConfig converts a Node to interface{}.

// formatProtocolName produces a clean display name for a protocol.
func formatProtocolName(name string) string {
	switch name {
	case "reality":
		return "Reality"
	case "ws":
		return "WS-CDN"
	case "grpc":
		return "gRPC-CDN"
	case "xhttp":
		return "XHTTP"
	case "ss":
		return "SS-2022"
	case "hysteria2":
		return "Hysteria2"
	case "shadowtls":
		return "ShadowTLS"
	default:
		if len(name) > 0 {
			return strings.ToUpper(name[:1]) + name[1:]
		}
		return name
	}
}

// Handler returns an http.Handler that serves smart subscriptions.
func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", e.handleSubscription)
	mux.HandleFunc("/report", e.handleReport)
	mux.HandleFunc("/admin/", e.handleAdmin)
	mux.HandleFunc("/health", e.handleHealth)
	return mux
}

// handleSubscription is the main subscription endpoint.
// URL pattern: /sub/{token}/{email}
func (e *Engine) handleSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse path: /sub/{token} or /sub/{token}/{email}
	path := strings.TrimPrefix(r.URL.Path, "/sub/")
	path = strings.TrimSuffix(path, "/")

	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	// Get email from path or query.
	email := ""
	if len(parts) > 1 {
		email = parts[1]
	}
	if email == "" {
		email = r.URL.Query().Get("email")
	}

	if !validSubscriptionToken(e.token, email, parts[0]) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	clientIP := extractClientIP(r)
	nodes := e.NodesForUser(email, clientIP)
	if len(nodes) == 0 {
		http.Error(w, "no nodes available", http.StatusNotFound)
		return
	}

	ispName, _ := e.isp.Lookup(clientIP)
	e.logger.Info("subscription request",
		"client_ip", hashIP(clientIP),
		"isp", ispName,
		"nodes", len(nodes),
	)

	w.Header().Set("Subscription-UserInfo", fmt.Sprintf(
		"upload=0; download=0; total=0; expire=%d",
		time.Now().Add(30*24*time.Hour).Unix(),
	))
	w.Header().Set("Profile-Update-Interval", "6")
	// NOTE: ISP name intentionally NOT sent in response headers.
	// Exposing it would let network observers fingerprint HydraFlow traffic
	// and reveal the user's detected ISP.

	data, contentType, err := RenderSubscription(nodes, detectFormat(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}

// handleReport processes anonymous telemetry reports from clients.
func (e *Engine) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var report TelemetryReport
	if err := json.Unmarshal(body, &report); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	clientIP := extractClientIP(r)
	ispName, _ := e.isp.Lookup(clientIP)

	e.telemetry.Record(ispName, report)

	e.logger.Debug("telemetry report",
		"isp", ispName,
		"protocol", report.Protocol,
		"status", report.Status,
	)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

// handleAdmin serves the admin status page.
func (e *Engine) handleAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	// Validate admin token.
	if e.token == "" || subtle.ConstantTimeCompare([]byte(parts[0]), []byte(e.token)) != 1 {
		http.NotFound(w, r)
		return
	}

	status := map[string]interface{}{
		"status":    "ok",
		"uptime":    time.Since(e.startTime).String(),
		"nodes":     len(e.GetNodes()),
		"health":    e.health.GetAll(),
		"telemetry": e.telemetry.GetSnapshot(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleHealth is a simple health check.
func (e *Engine) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
		"uptime": time.Since(e.startTime).String(),
		"nodes":  len(e.GetNodes()),
	})
}

// detectFormat determines output format from request.
func detectFormat(r *http.Request) string {
	if f := r.URL.Query().Get("format"); f != "" {
		switch strings.ToLower(f) {
		case "clash", "clashmeta", "clash-meta":
			return "clash"
		case "singbox", "sing-box", "sb":
			return "singbox"
		case "v2ray", "base64", "b64":
			return "v2ray"
		}
	}

	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "clash") || strings.Contains(ua, "stash") || strings.Contains(ua, "mihomo"):
		return "clash"
	case strings.Contains(ua, "sing-box") || strings.Contains(ua, "singbox") || strings.Contains(ua, "sfi") || strings.Contains(ua, "sfa"):
		return "singbox"
	case strings.Contains(ua, "v2ray") || strings.Contains(ua, "v2rayn") || strings.Contains(ua, "v2rayng") ||
		strings.Contains(ua, "nekoray") || strings.Contains(ua, "hiddify") || strings.Contains(ua, "streisand"):
		return "v2ray"
	}

	return "v2ray"
}

// extractClientIP extracts the real client IP from the request.
// Proxy headers (X-Forwarded-For, X-Real-IP) are only trusted when
// the direct peer is localhost, preventing spoofing from the internet.
func extractClientIP(r *http.Request) string {
	peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if peerIP == "" {
		peerIP = r.RemoteAddr
	}
	trusted := peerIP == "127.0.0.1" || peerIP == "::1"

	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	return peerIP
}

// ---------------------------------------------------------------------------
// ISP Lookup
// ---------------------------------------------------------------------------

const maxISPCacheSize = 10000

// ISPLookup manages ISP detection with caching.
type ISPLookup struct {
	mu     sync.RWMutex
	cache  map[string]*ispCacheEntry
	ttl    time.Duration
	logger *slog.Logger
}

type ispCacheEntry struct {
	ispName   string
	raw       *IPAPIResponse
	expiresAt time.Time
}

// IPAPIResponse is the JSON structure returned by ip-api.com.
type IPAPIResponse struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	ASN     int    `json:"asn,omitempty"`
	Query   string `json:"query"`
}

// NewISPLookup creates a new ISP lookup with caching.
func NewISPLookup(logger *slog.Logger) *ISPLookup {
	l := &ISPLookup{
		cache:  make(map[string]*ispCacheEntry),
		ttl:    1 * time.Hour,
		logger: logger,
	}
	go l.cleanupLoop()
	return l
}

func (l *ISPLookup) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for ip, entry := range l.cache {
			if now.After(entry.expiresAt) {
				delete(l.cache, ip)
			}
		}
		l.mu.Unlock()
	}
}

// Lookup returns the normalized ISP name for an IP address.
func (l *ISPLookup) Lookup(ip string) (string, *IPAPIResponse) {
	// Check cache.
	l.mu.RLock()
	if entry, ok := l.cache[ip]; ok && time.Now().Before(entry.expiresAt) {
		l.mu.RUnlock()
		return entry.ispName, entry.raw
	}
	l.mu.RUnlock()

	// Skip private/loopback.
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() {
		return "default", nil
	}

	// Query ip-api.com.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,isp,org,as,query", ip))
	if err != nil {
		l.logger.Debug("ISP lookup failed", "ip_hash", hashIP(ip), "error", err)
		return "default", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "default", nil
	}

	var result IPAPIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "default", nil
	}

	if result.Status != "success" {
		return "default", nil
	}

	// Extract ASN.
	asn := 0
	if result.AS != "" {
		fmt.Sscanf(strings.TrimPrefix(result.AS, "AS"), "%d", &asn)
	}
	result.ASN = asn

	// Map to ISP name.
	var ispName string
	if name, ok := asnToISP[asn]; ok {
		ispName = name
	} else {
		ispName = fuzzyMatchISP(result.ISP, result.Org)
	}
	if ispName == "" {
		ispName = "default"
	}

	// Cache (with eviction if over limit).
	l.mu.Lock()
	if len(l.cache) >= maxISPCacheSize {
		// Delete the oldest entries by expiry time.
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range l.cache {
			if first || v.expiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.expiresAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(l.cache, oldestKey)
		}
	}
	l.cache[ip] = &ispCacheEntry{
		ispName:   ispName,
		raw:       &result,
		expiresAt: time.Now().Add(l.ttl),
	}
	l.mu.Unlock()

	l.logger.Debug("ISP detected", "ip_hash", hashIP(ip), "asn", asn, "isp", result.ISP, "mapped", ispName)
	return ispName, &result
}

// ---------------------------------------------------------------------------
// ISP priority knowledge base
// ---------------------------------------------------------------------------

// ispPriority maps ISP names to protocol order (best first).
var ispPriority = map[string][]string{
	// Russian ISPs
	"megafon":    {"ws-cdn", "grpc-cdn", "xhttp", "shadowtls"},
	"mts":        {"ws-cdn", "grpc-cdn", "reality"},
	"beeline":    {"reality", "ws-cdn", "hysteria2"},
	"tele2":      {"ws-cdn", "reality", "xhttp"},
	"rostelecom": {"ws-cdn", "grpc-cdn", "reality"},
	"domru":      {"reality", "ws-cdn"},
	"yota":       {"ws-cdn", "grpc-cdn", "reality"},
	"ttk":        {"ws-cdn", "grpc-cdn", "reality"},
	// Chinese ISPs
	"china-telecom": {"ws-cdn", "grpc-cdn", "naiveproxy"},
	"china-mobile":  {"ws-cdn", "grpc-cdn"},
	"china-unicom":  {"ws-cdn", "grpc-cdn", "reality"},
	// Iranian ISPs
	"mci":      {"ws-cdn", "grpc-cdn", "fragment"},
	"irancell": {"ws-cdn", "grpc-cdn"},
	// Default fallback
	"default": {"reality", "ws-cdn", "ss", "hysteria2"},
}

// GetISPPriority returns the protocol priority list for an ISP.
func GetISPPriority(isp string) []string {
	if p, ok := ispPriority[isp]; ok {
		return p
	}
	return ispPriority["default"]
}

// asnToISP maps well-known ASN numbers to normalized ISP names.
var asnToISP = map[int]string{
	// Russia
	31213: "megafon", 25159: "megafon",
	8359: "mts", 15640: "mts", 3216: "mts", 8402: "mts",
	16345: "beeline", 3267: "beeline",
	12389: "rostelecom", 25490: "rostelecom", 42610: "rostelecom", 15378: "rostelecom",
	34533: "tele2", 47395: "tele2",
	49048: "domru", 197695: "domru",
	47541: "yota",
	15774: "ttk", 20485: "ttk",
	// China
	4134: "china-telecom", 4812: "china-telecom",
	4837: "china-unicom", 17816: "china-unicom",
	9808: "china-mobile", 56040: "china-mobile", 56041: "china-mobile", 56042: "china-mobile",
	// Iran
	44244: "irancell", 197207: "irancell",
	12880: "mci", 50810: "mci",
}

// fuzzyMatchISP tries to match an ISP/org string to known ISP names.
func fuzzyMatchISP(isp, org string) string {
	combined := strings.ToLower(isp + " " + org)
	patterns := map[string][]string{
		"megafon":       {"megafon"},
		"mts":           {"mts ", "mobile telesystems"},
		"beeline":       {"beeline", "vimpelcom"},
		"tele2":         {"tele2"},
		"rostelecom":    {"rostelecom"},
		"domru":         {"dom.ru", "domru", "ertelecom"},
		"yota":          {"yota", "scartel"},
		"ttk":           {"ttk", "transtelecom"},
		"china-telecom": {"china telecom", "chinanet"},
		"china-mobile":  {"china mobile", "cmnet"},
		"china-unicom":  {"china unicom", "unicom"},
		"mci":           {"mobile communication company", "mci ", "hamrah-e-aval"},
		"irancell":      {"irancell", "mtn irancell"},
	}
	for name, keywords := range patterns {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				return name
			}
		}
	}
	return "default"
}

// ---------------------------------------------------------------------------
// Protocol Health Checker
// ---------------------------------------------------------------------------

// ProtocolHealth tracks health status of protocol endpoints.
type ProtocolHealth struct {
	mu       sync.RWMutex
	statuses map[string]*HealthStatus // key: "host:port"
	logger   *slog.Logger
}

// HealthStatus represents the health of a single endpoint.
type HealthStatus struct {
	Up        bool      `json:"up"`
	LastCheck time.Time `json:"last_check"`
	LatencyMs int64     `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
}

// NewProtocolHealth creates a new health tracker.
func NewProtocolHealth(logger *slog.Logger) *ProtocolHealth {
	return &ProtocolHealth{
		statuses: make(map[string]*HealthStatus),
		logger:   logger,
	}
}

// CheckAll runs health checks on all given nodes.
func (ph *ProtocolHealth) CheckAll(nodes []Node) {
	// Deduplicate by host:port.
	seen := make(map[string]Node)
	for _, n := range nodes {
		key := fmt.Sprintf("%s:%d", n.Server, n.Port)
		if _, ok := seen[key]; !ok {
			seen[key] = n
		}
	}

	var wg sync.WaitGroup
	for key, node := range seen {
		wg.Add(1)
		go func(k string, n Node) {
			defer wg.Done()
			ph.checkOne(k, n)
		}(key, node)
	}
	wg.Wait()
}

func (ph *ProtocolHealth) checkOne(key string, n Node) {
	start := time.Now()
	status := &HealthStatus{LastCheck: time.Now()}

	addr := net.JoinHostPort(n.Server, fmt.Sprintf("%d", n.Port))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		status.Up = false
		status.Error = fmt.Sprintf("tcp: %v", err)
		status.LatencyMs = time.Since(start).Milliseconds()
		ph.set(key, status)
		ph.logger.Debug("health check failed", "addr", addr, "error", err)
		return
	}

	// Try TLS handshake for TLS-based protocols.
	if n.SNI != "" || n.Port == 443 {
		sni := n.SNI
		if sni == "" {
			sni = n.Server
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
		tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		err = tlsConn.Handshake()
		tlsConn.Close()
	} else {
		conn.Close()
	}

	status.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		status.Up = false
		status.Error = fmt.Sprintf("tls: %v", err)
		ph.logger.Debug("health check TLS failed", "addr", addr, "error", err)
	} else {
		status.Up = true
		ph.logger.Debug("health check OK", "addr", addr, "latency_ms", status.LatencyMs)
	}

	ph.set(key, status)
}

func (ph *ProtocolHealth) set(key string, s *HealthStatus) {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.statuses[key] = s
}

// IsUp returns whether a host:port is healthy.
func (ph *ProtocolHealth) IsUp(host string, port int) bool {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	key := fmt.Sprintf("%s:%d", host, port)
	if s, ok := ph.statuses[key]; ok {
		return s.Up
	}
	return true // assume up if never checked
}

// GetAll returns a copy of all health statuses.
func (ph *ProtocolHealth) GetAll() map[string]*HealthStatus {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	out := make(map[string]*HealthStatus, len(ph.statuses))
	for k, v := range ph.statuses {
		cp := *v
		out[k] = &cp
	}
	return out
}

// ---------------------------------------------------------------------------
// Telemetry Store
// ---------------------------------------------------------------------------

// TelemetryReport is what clients POST to /report.
type TelemetryReport struct {
	ASN      int    `json:"asn"`
	Protocol string `json:"protocol"`
	Status   string `json:"status"` // "ok", "blocked", "slow"
}

// TelemetryStore holds aggregated telemetry data.
type TelemetryStore struct {
	mu      sync.RWMutex
	reports map[string]*ISPTelemetry // key: ISP name
	total   int
}

// ISPTelemetry holds per-ISP protocol telemetry.
type ISPTelemetry struct {
	Protocols map[string]*ProtocolTelemetry `json:"protocols"`
}

// ProtocolTelemetry holds counters for a single protocol on an ISP.
type ProtocolTelemetry struct {
	OK      int `json:"ok"`
	Blocked int `json:"blocked"`
	Slow    int `json:"slow"`
}

// NewTelemetryStore creates a new telemetry store.
func NewTelemetryStore() *TelemetryStore {
	return &TelemetryStore{
		reports: make(map[string]*ISPTelemetry),
	}
}

// knownProtocols is the set of valid protocol names accepted in telemetry reports.
var knownTelemetryProtocols = map[string]bool{
	"reality":   true,
	"ws":        true,
	"ws-cdn":    true,
	"grpc":      true,
	"grpc-cdn":  true,
	"xhttp":     true,
	"ss":        true,
	"hysteria2": true,
	"shadowtls": true,
	"chain":     true,
}

// Record stores a telemetry report. Unknown protocol names are silently rejected.
func (ts *TelemetryStore) Record(isp string, report TelemetryReport) {
	if !knownTelemetryProtocols[report.Protocol] {
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.total++

	if _, ok := ts.reports[isp]; !ok {
		ts.reports[isp] = &ISPTelemetry{
			Protocols: make(map[string]*ProtocolTelemetry),
		}
	}
	ispData := ts.reports[isp]
	if _, ok := ispData.Protocols[report.Protocol]; !ok {
		ispData.Protocols[report.Protocol] = &ProtocolTelemetry{}
	}
	pt := ispData.Protocols[report.Protocol]
	switch report.Status {
	case "ok":
		pt.OK++
	case "blocked":
		pt.Blocked++
	case "slow":
		pt.Slow++
	}
}

// IsBlocked returns true if telemetry suggests a protocol is blocked on this ISP.
func (ts *TelemetryStore) IsBlocked(isp, protocol string) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	ispData, ok := ts.reports[isp]
	if !ok {
		return false
	}
	pt, ok := ispData.Protocols[protocol]
	if !ok {
		return false
	}
	total := pt.OK + pt.Blocked + pt.Slow
	if total < 10 {
		return false
	}
	return float64(pt.Blocked)/float64(total) > 0.6
}

// GetSnapshot returns a deep copy of all telemetry data.
func (ts *TelemetryStore) GetSnapshot() map[string]*ISPTelemetry {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make(map[string]*ISPTelemetry, len(ts.reports))
	for k, v := range ts.reports {
		ispCopy := &ISPTelemetry{
			Protocols: make(map[string]*ProtocolTelemetry, len(v.Protocols)),
		}
		for pk, pv := range v.Protocols {
			ptCopy := *pv
			ispCopy.Protocols[pk] = &ptCopy
		}
		out[k] = ispCopy
	}
	return out
}
