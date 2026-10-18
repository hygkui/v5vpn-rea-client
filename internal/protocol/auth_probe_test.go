package protocol

import "testing"

// TestGateway1PasswordExpiredDetection is an integration probe that talks
// to a real LeadSec-compatible VPN gateway. Credentials here are synthetic
// placeholders; the production environment's real password is required to
// actually observe a "口令过期" error. Skip by default, opt in with:
//
//	go test ./internal/protocol -run TestGateway1PasswordExpiredDetection -count=1
//
// Set GATEWAY_IP / GATEWAY_PORT / GATEWAY_USER / GATEWAY_PASSWORD to point
// at a controlled test gateway.
func TestGateway1PasswordExpiredDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	const (
		gwIP   = "203.0.113.10"
		gwPort = 443
		user   = "<username>"
		pass   = "<password>"
	)
	client := NewClient(gwIP, gwPort, 0, func(level, format string, args ...any) {
		t.Logf("[%s] %s", level, format)
	})

	if _, err := client.Handshake(); err != nil {
		t.Skipf("Gateway unreachable, skipping: %v", err)
	}

	_, err := client.Login(user, pass, "")
	if err == nil {
		t.Fatalf("Expected password expired error, got success")
	}
	if !IsPasswordExpired(err) {
		t.Fatalf("Expected password expired error, got %v", err)
	}
	t.Logf("Expected error caught correctly: %v", err)
}
