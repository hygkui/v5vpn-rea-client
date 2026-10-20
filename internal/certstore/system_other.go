//go:build !windows

package certstore

import "crypto/tls"

// Non-Windows platforms have no CryptoAPI personal store. The UI hides the
// "系统证书库" option when List reports ErrSystemStoreUnsupported.

func listSystemCerts() ([]CertInfo, error) {
	return nil, ErrSystemStoreUnsupported
}

func loadSystemCert(string) (*tls.Certificate, error) {
	return nil, ErrSystemStoreUnsupported
}
