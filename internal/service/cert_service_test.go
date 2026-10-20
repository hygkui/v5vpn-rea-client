package service

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/certstore"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestAuthErrorCodeCertificateKinds(t *testing.T) {
	cases := []struct {
		kind protocol.AuthKind
		want string
	}{
		{protocol.AuthKindCertInvalid, "cert_invalid"},
		{protocol.AuthKindCertUnavailable, "cert_unavailable"},
		{protocol.AuthKindCertExpired, "cert_expired"},
		{protocol.AuthKindCertRevoked, "cert_revoked"},
		{protocol.AuthKindCertBadSignature, "cert_signature"},
	}
	for _, tc := range cases {
		err := &protocol.AuthError{Kind: tc.kind, Code: "0x103"}
		if got := AuthErrorCode(err); got != tc.want {
			t.Fatalf("kind %v: got %q want %q", tc.kind, got, tc.want)
		}
		if IsPasswordExpired(err) {
			t.Fatalf("certificate error must not look like a password challenge: %v", tc.kind)
		}
	}
}

func TestListCertificatesEmptyStore(t *testing.T) {
	s := &VPNService{
		Config:    &config.AppConfig{},
		CertStore: mustStore(t),
	}
	list, err := s.ListCertificates(int(certstore.SourceFile))
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %+v", list)
	}
}

func TestImportCertificateValidatesPassword(t *testing.T) {
	s := &VPNService{
		Config:    &config.AppConfig{},
		CertStore: mustStore(t),
	}
	if _, err := s.ImportCertificate("", "", ""); err == nil {
		t.Fatal("expected an error for an empty path")
	}
	if _, err := s.ImportCertificate(filepath.Join(t.TempDir(), "missing.p12"), "", ""); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// TestLoginWithCertUnknownCertificate verifies the failure is reported without
// leaving the service in "Connecting".
func TestLoginWithCertUnknownCertificate(t *testing.T) {
	s := &VPNService{
		Config: &config.AppConfig{
			LastUseGateway: "gw",
			Gateways: []config.GatewayProfile{{
				ID:   "gw-0",
				Name: "gw",
				IP:   "203.0.113.10",
				Port: 443,
			}},
		},
		CertStore: mustStore(t),
		Status:    "Disconnected",
	}
	_, err := s.LoginWithCert("gw", int(certstore.SourceFile), "does-not-exist", "", false)
	if err == nil {
		t.Fatal("expected an error for an unknown certificate")
	}
	if !errors.Is(err, certstore.ErrCertNotFound) {
		t.Fatalf("expected ErrCertNotFound, got %v", err)
	}
	if s.Status != "Error" {
		t.Fatalf("expected status Error, got %q", s.Status)
	}
}

func TestLoginWithCertWhileConnectedRejected(t *testing.T) {
	s := &VPNService{
		Config:    &config.AppConfig{},
		CertStore: mustStore(t),
		Status:    "Connected",
	}
	if _, err := s.LoginWithCert("gw", 0, "id", "", false); err == nil {
		t.Fatal("expected an error while connected")
	}
}

func mustStore(t *testing.T) *certstore.Store {
	t.Helper()
	store, err := certstore.NewStore(filepath.Join(t.TempDir(), "certs"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}
