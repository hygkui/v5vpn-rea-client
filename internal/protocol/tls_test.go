package protocol

import (
	"crypto/tls"
	"testing"
)

func TestGatewayTLSConfigIncludesCBC(t *testing.T) {
	cfg := GatewayTLSConfig()
	if cfg == nil {
		t.Fatal("GatewayTLSConfig returned nil")
	}

	if !cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true for internal gateways")
	}

	if cfg.MinVersion != tls.VersionTLS10 {
		t.Errorf("expected MinVersion TLS 1.0, got %x", cfg.MinVersion)
	}

	requiredSuite := uint16(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
	found := false
	for _, s := range cfg.CipherSuites {
		if s == requiredSuite {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected CipherSuites to include TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0x%x)", requiredSuite)
	}
}
