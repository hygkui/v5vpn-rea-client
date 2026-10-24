package mockserver

// 这份集成测试验证 V5VPN protocol 客户端与本地 MockServer 的完整双因素认证与门户资源拉取流程：
//   - Client.AuthPasswordWithCert（口令 -> code 2 -> 证书 串行双因素握手）
//   - Client.FetchIntegration（获取内网资源）
//   - Client.Logout（安全退出会话）

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// startTestGateway starts a mock gateway on a random loopback port and returns
// the server plus the host/port a protocol.Client needs.
func startTestGateway(t *testing.T, mode Mode) (*Server, string, int) {
	return startTestGatewayCfg(t, Config{Addr: "127.0.0.1:0", Mode: mode, Verbose: false})
}

// startTestGatewayCfg is startTestGateway with a full Config (e.g. an NC
// resource fixture mode).
func startTestGatewayCfg(t *testing.T, cfg Config) (*Server, string, int) {
	t.Helper()

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", srv.httpSrv.TLSConfig)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	go func() { _ = srv.httpSrv.Serve(l) }()
	t.Cleanup(func() {
		_ = l.Close()
		_ = srv.Close()
	})

	host, portText, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("bad port %q: %v", portText, err)
	}
	return srv, host, port
}

func TestMockServerIntegrationWithProtocolClient(t *testing.T) {
	_, host, port := startTestGateway(t, ModePwdCert)

	client := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("["+level+"] "+format, args...)
	})

	// 1. Handshake
	_, err := client.Handshake()
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// 2. Prepare mock client cert
	clientCert, _, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// 3. Two-factor login: Password + Certificate (Step 1 -> Code 2 -> Step 2 -> Code 0)
	resp, err := client.AuthPasswordWithCert(&clientCert, "admin", "admin123", "")
	if err != nil {
		t.Fatalf("AuthPasswordWithCert failed: %v", err)
	}
	if resp == nil {
		t.Fatalf("Expected non-nil response")
	}

	if client.SessionID == "" {
		t.Errorf("Expected client.SessionID to be set after 2FA login")
	}

	// 4. Get portal integration info
	info, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if info.Session.ID == "" {
		t.Errorf("Expected non-empty Session ID, got %+v", info)
	}
	if info.User.Name != "admin" {
		t.Errorf("Expected User.Name admin, got %q", info.User.Name)
	}

	// 5. Logout
	err = client.Logout()
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}
}

// TestVerifyCodeRequiresSameSession proves the mock enforces the real
// gateway's binding: a captcha code is valid only on the cookie jar that
// fetched the image. A client that submits the same code from another session
// must be rejected; otherwise this suite cannot catch a client that loses the
// captcha cookies between "fetch image" and "submit login".
func TestVerifyCodeRequiresSameSession(t *testing.T) {
	srv, host, port := startTestGateway(t, ModeVerifyCode)

	imageClient := protocol.NewClient(host, port, 0, nil)
	if _, _, err := imageClient.FetchVerifyCode(); err != nil {
		t.Fatalf("FetchVerifyCode failed: %v", err)
	}
	defer func() { _ = imageClient.Logout() }()

	srv.mu.RLock()
	code := srv.currentVerifyCode
	srv.mu.RUnlock()
	if code == "" {
		t.Fatal("mock did not generate a captcha code")
	}

	if _, err := imageClient.AuthOnly("admin", "admin123", code); err != nil {
		t.Fatalf("login on the captcha session failed: %v", err)
	}

	otherClient := protocol.NewClient(host, port, 0, nil)
	if _, err := otherClient.AuthOnly("admin", "admin123", code); err == nil {
		t.Fatal("a client without the captcha session was accepted")
	}
}
