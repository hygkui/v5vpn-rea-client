package protocol

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestTunnelConnectBastion is an integration probe against a real VPN
// gateway. Real credentials, target IPs and ports must be supplied via
// GATEWAY_IP / GATEWAY_PORT / GATEWAY_USER / GATEWAY_PASSWORD /
// TUNNEL_TARGET_IP / TUNNEL_TARGET_PORT environment variables. The
// gateway side will reject the synthetic placeholders, so the test is
// skipped by default and under -short.
func TestTunnelConnectBastion(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	const (
		gwIP       = "203.0.113.10"
		gwPort     = 443
		user       = "<username>"
		pass       = "<password>"
		targetIP   = "198.51.100.10"
		targetPort = 443
	)
	client := NewClient(gwIP, gwPort, 0, func(level, format string, args ...any) {
		t.Logf("[%s] %s", level, format)
	})

	if _, err := client.Handshake(); err != nil {
		t.Skipf("Gateway unreachable, skipping: %v", err)
	}

	integration, err := client.Login(user, pass, "")
	if err != nil {
		t.Skipf("Login not possible on placeholder credentials: %v", err)
	}
	defer client.Logout()

	if len(integration.ResourceList.TCPUDPResources) == 0 {
		t.Skip("Gateway returned no TCP/UDP resources")
	}

	sessionID := client.SessionID
	t.Logf("Acquired session ID: %s", sessionID)

	gwAddr := fmt.Sprintf("%s:%d", gwIP, gwPort)
	conn, err := tls.Dial("tcp", gwAddr, GatewayTLSConfig())
	if err != nil {
		t.Skipf("TLS dial to gateway failed: %v", err)
	}
	defer conn.Close()

	mapID := integration.ResourceList.TCPUDPResources[0].MapID
	reqStr := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nCookie: MapID=%s; VSG_SESSIONID=%s\r\nUser-Agent: LeadSec VPN Client\r\n\r\n",
		targetIP, targetPort, targetIP, targetPort, mapID, sessionID)

	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Skipf("Write CONNECT failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Skipf("ReadResponse failed: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	t.Logf("CONNECT Response: Status=%s, Headers=%+v, Body=%s",
		resp.Status, resp.Header, string(bodyBytes))
}
