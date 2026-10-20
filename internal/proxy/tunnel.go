package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// ProxyManager manages local proxy listeners for mapped VPN resources
type ProxyManager struct {
	GatewayIP   string
	GatewayPort int
	SessionID   string
	Listeners   map[string]net.Listener
	Resources   []protocol.VPNResource
	Logger      func(level string, format string, args ...any)
	mu          sync.Mutex
	closed      bool
	// ClientCert is presented during the gateway TLS handshake when the
	// session was authenticated with a certificate. Gateways that require
	// client certificates for /vpn/user/auth/cert usually require them for
	// tunnel connections as well; omitting it here yields a successful login
	// where every forwarded connection is reset.
	ClientCert *tls.Certificate
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(gwIP string, gwPort int, sessionID string, logger func(string, string, ...any)) *ProxyManager {
	if logger == nil {
		logger = func(string, string, ...any) {}
	}
	return &ProxyManager{
		GatewayIP:   gwIP,
		GatewayPort: gwPort,
		SessionID:   sessionID,
		Listeners:   make(map[string]net.Listener),
		Logger:      logger,
	}
}

// StartProxies starts local TCP listeners for each resource in the integration info
func (pm *ProxyManager) StartProxies(resources []protocol.TCPUDPResource) ([]protocol.VPNResource, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var mapped []protocol.VPNResource

	for _, res := range resources {
		ports := strings.Split(res.Port, ";")
		for _, pStr := range ports {
			pStr = strings.TrimSpace(pStr)
			if pStr == "" {
				continue
			}
			targetPort, err := strconv.Atoi(pStr)
			if err != nil {
				continue
			}

			// Parse IP ranges or single IPs
			var targetIPs []string
			for _, ipCfg := range res.IPConfigs {
				addr := ipCfg.Addr
				if strings.Contains(addr, "-") {
					addr = strings.Split(addr, "-")[0]
				}
				addr = strings.TrimSpace(addr)
				if addr != "" {
					targetIPs = append(targetIPs, addr)
				}
			}
			if len(targetIPs) == 0 {
				targetIPs = []string{"127.0.0.1"}
			}

			for _, targetIP := range targetIPs {
				// Try to bind to same port on 127.0.0.1 first, or fallback to random free port
				ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
				if err != nil {
					// Port may be occupied, bind to any free port
					ln, err = net.Listen("tcp", "127.0.0.1:0")
				}

				if err != nil {
					pm.Logger("WARN", "Failed to bind local listener for %s:%d: %v", targetIP, targetPort, err)
					continue
				}

				localAddr := ln.Addr().String()
				key := fmt.Sprintf("%s:%d", targetIP, targetPort)
				pm.Listeners[key] = ln

				_, localPortStr, _ := net.SplitHostPort(localAddr)
				accessURL := fmt.Sprintf("http://127.0.0.1:%s", localPortStr)
				if targetPort == 443 || targetPort == 8443 || strings.Contains(strings.ToLower(res.Name), "https") || strings.Contains(res.Name, "堡垒") {
					accessURL = fmt.Sprintf("https://127.0.0.1:%s", localPortStr)
				}

				item := protocol.VPNResource{
					Name:       res.Name,
					Protocol:   strings.ToUpper(res.Protocol),
					RemoteIP:   targetIP,
					RemotePort: strconv.Itoa(targetPort),
					LocalProxy: localAddr,
					Status:     "Listening",
					MapID:      res.MapID,
					AccessURL:  accessURL,
				}
				mapped = append(mapped, item)
				pm.Logger("SUCCESS", "Proxy ready: %s [%s] -> Local: %s (MapID: %s, AccessURL: %s)", res.Name, key, localAddr, res.MapID, accessURL)

				// Spawn listener accept loop with res.MapID
				go pm.handleListener(ln, targetIP, targetPort, res.MapID)
			}
		}
	}

	pm.Resources = mapped
	return mapped, nil
}

// handleListener accepts incoming connections and dials SSL CONNECT tunnel
func (pm *ProxyManager) handleListener(ln net.Listener, targetIP string, targetPort int, mapID string) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			pm.mu.Lock()
			isClosed := pm.closed
			pm.mu.Unlock()
			if isClosed {
				return
			}
			pm.Logger("WARN", "Proxy accept error: %v", err)
			return
		}

		go pm.tunnelTraffic(clientConn, targetIP, targetPort, mapID)
	}
}

// tunnelTraffic connects to the VPN Gateway and sends HTTP CONNECT
func (pm *ProxyManager) tunnelTraffic(clientConn net.Conn, targetIP string, targetPort int, mapID string) {
	defer clientConn.Close()

	pm.Logger("DEBUG", "Inbound connection from %s to target %s:%d (MapID: %s)",
		clientConn.RemoteAddr(), targetIP, targetPort, mapID)

	gwAddr := fmt.Sprintf("%s:%d", pm.GatewayIP, pm.GatewayPort)
	tlsConfig := protocol.GatewayTLSConfig()
	if pm.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*pm.ClientCert}
	}

	remoteConn, err := tls.Dial("tcp", gwAddr, tlsConfig)
	if err != nil {
		pm.Logger("ERROR", "Failed to connect to VPN Gateway SSL %s: %v", gwAddr, err)
		return
	}
	defer remoteConn.Close()

	// Send HTTP CONNECT tunnel header with MapID and session cookie
	var cookieHeader string
	if mapID != "" {
		cookieHeader = fmt.Sprintf("Cookie: MapID=%s; VSG_SESSIONID=%s\r\n", mapID, pm.SessionID)
	} else {
		cookieHeader = fmt.Sprintf("Cookie: VSG_SESSIONID=%s\r\n", pm.SessionID)
	}
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%sUser-Agent: LeadSec VPN Client\r\n\r\n",
		targetIP, targetPort, targetIP, targetPort, cookieHeader)

	if _, err := remoteConn.Write([]byte(connectReq)); err != nil {
		pm.Logger("ERROR", "Failed to send CONNECT request: %v", err)
		return
	}

	// Read CONNECT response header
	reader := bufio.NewReader(remoteConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		pm.Logger("ERROR", "Failed to read gateway CONNECT response: %v", err)
		return
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != 200 {
		pm.Logger("ERROR", "Gateway rejected tunnel connection, status: %s", resp.Status)
		return
	}

	pm.Logger("SUCCESS", "Tunnel established to %s:%d, streaming traffic...", targetIP, targetPort)

	// Bidirectional full-duplex piping
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(remoteConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, reader)
	}()

	wg.Wait()
}

// Stop closes all active proxy listeners
func (pm *ProxyManager) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.closed = true
	for key, ln := range pm.Listeners {
		pm.Logger("INFO", "Closing proxy listener for %s", key)
		_ = ln.Close()
	}
	pm.Listeners = make(map[string]net.Listener)
}
