package service

import (
	"path/filepath"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
)

// TestSaveGatewayKeepsCertificateFields mirrors the saved-account rule: the
// gateway editor submits name/IP/port/algo only, so editing a certificate
// gateway must not reset it back to password login.
func TestSaveGatewayKeepsCertificateFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setting.xml")

	s := &VPNService{
		Config: &config.AppConfig{
			SourcePath:     path,
			LastUseGateway: "cert-gw",
			Gateways: []config.GatewayProfile{{
				ID:             "gw-0",
				Name:           "cert-gw",
				IP:             "203.0.113.10",
				Port:           443,
				AuthType:       1,
				CertType:       1,
				CertAutoLogin:  true,
				SelectedCertID: "A1B2C3D4E5F60718293A4B5C6D7E8F90",
			}},
		},
	}

	// Simulate the UI editing the port only.
	err := s.SaveGateway(config.GatewayProfile{
		ID:   "gw-0",
		Name: "cert-gw",
		IP:   "203.0.113.10",
		Port: 8443,
	})
	if err != nil {
		t.Fatalf("SaveGateway: %v", err)
	}

	gw := s.Config.Gateways[0]
	if gw.Port != 8443 {
		t.Fatalf("port was not updated: %d", gw.Port)
	}
	if gw.AuthType != 1 || gw.CertType != 1 || !gw.CertAutoLogin || gw.SelectedCertID == "" {
		t.Fatalf("certificate fields were erased by an edit: %+v", gw)
	}
}

// TestPasswordLoginSwitchesGatewayBackToPasswordMode verifies the mode is not
// sticky: performing a password login records password mode, so the next start
// offers the password form instead of the certificate panel.
func TestPasswordLoginSwitchesGatewayBackToPasswordMode(t *testing.T) {
	s := &VPNService{
		Config: &config.AppConfig{
			Gateways: []config.GatewayProfile{{
				ID:             "gw-0",
				Name:           "cert-gw",
				IP:             "203.0.113.10",
				Port:           443,
				AuthType:       1,
				CertType:       1,
				CertAutoLogin:  true,
				SelectedCertID: "SOME-CERT-ID",
			}},
		},
		Status: "Disconnected",
	}

	s.rememberPasswordMode("cert-gw")

	gw := s.Config.Gateways[0]
	if gw.AuthType != 0 {
		t.Fatalf("password login did not clear certificate mode: %+v", gw)
	}
	// The certificate choice is kept so switching back needs one click.
	if gw.SelectedCertID != "SOME-CERT-ID" {
		t.Fatalf("certificate id should be retained for quick switching: %+v", gw)
	}
}
