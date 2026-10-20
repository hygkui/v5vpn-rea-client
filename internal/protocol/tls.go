package protocol

import "crypto/tls"

// GatewayCipherSuites returns the list of TLS cipher suites supported by V5VPN gateways.
// Older enterprise hardware appliances (and V5VPN gateways) often negotiate
// AES-CBC cipher suites (such as TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256).
// Go 1.22+ disabled CBC cipher suites by default in client handshakes; explicitly
// providing this list restores compatibility without sacrificing modern AEAD suites.
func GatewayCipherSuites() []uint16 {
	return []uint16{
		// Modern AEAD suites (preferred)
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,

		// Legacy gateway CBC suites (required by V5VPN gateways)
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
}

// GatewayTLSConfig returns a base TLS client configuration tailored for V5VPN gateways.
// It allows self-signed/internal certificates and enables compatibility cipher suites.
func GatewayTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       GatewayCipherSuites(),
	}
}
