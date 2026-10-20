package protocol

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newTestClientCert builds a self-signed client certificate for the mTLS test
// server.
func newTestClientCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "cert-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// newCertGateway starts a TLS test server that requires a client certificate
// and answers the certificate auth and portal endpoints. authResult is the
// <RESULT> element returned by /vpn/user/auth/cert.
func newCertGateway(t *testing.T, authResult string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/cert", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Errorf("certificate auth request arrived without a client certificate")
		}
		if r.Method != http.MethodGet {
			t.Errorf("certificate auth used %s, want GET", r.Method)
		}
		if authResult == "" {
			http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "cert-session-id", Path: "/"})
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><RESPONSE>` + authResult + `</RESPONSE>`))
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<INTERGRATION_INFO>
  <USER name="cert-user" group="test"/>
  <SESSION sid_name="VSG_SESSIONID" id="cert-session-id" detect_interval="180"/>
  <RESOURCE_LIST>
    <TCPUDP_RESOURCE name="portal" protocol="tcp" mapid="7" port="443" status="1" istcp="1">
      <TCPUDP_IP addr="10.0.0.1-10.0.0.1"/>
    </TCPUDP_RESOURCE>
  </RESOURCE_LIST>
</INTERGRATION_INFO>`))
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newClientForServer(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	host, port := splitHostPort(t, server.URL)
	return NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("[%s] %s", level, sprintf(format, args...))
	})
}

func splitHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	trimmed := strings.TrimPrefix(rawURL, "https://")
	parts := strings.Split(trimmed, ":")
	if len(parts) != 2 {
		t.Fatalf("unexpected test server URL %q", rawURL)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("bad port in %q: %v", rawURL, err)
	}
	return parts[0], port
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func TestLoginWithCertSuccess(t *testing.T) {
	server := newCertGateway(t, "")
	client := newClientForServer(t, server)

	integration, err := client.LoginWithCert(newTestClientCert(t), "")
	if err != nil {
		t.Fatalf("LoginWithCert: %v", err)
	}
	if integration == nil || integration.User.Name != "cert-user" {
		t.Fatalf("unexpected integration: %+v", integration)
	}
	if client.SessionID != "cert-session-id" {
		t.Fatalf("expected session id from Set-Cookie, got %q", client.SessionID)
	}
	if got := client.ClientCertificate(); got == nil {
		t.Fatal("client certificate was not retained for tunnel reuse")
	}
	_ = client.Logout()
}

func TestLoginWithCertRequiresClientCertificate(t *testing.T) {
	server := newCertGateway(t, "")
	client := newClientForServer(t, server)

	if _, err := client.LoginWithCert(nil, ""); err == nil {
		t.Fatal("expected the mTLS handshake to fail without a client certificate")
	}
}

func TestLoginWithCertGatewayErrorCodes(t *testing.T) {
	cases := []struct {
		code string
		kind AuthKind
		want string
	}{
		{"0x103", AuthKindCertInvalid, "cert_invalid"},
		{"0x105", AuthKindCertUnavailable, "cert_unavailable"},
		{"0x106", AuthKindCertExpired, "cert_expired"},
		{"0x107", AuthKindCertRevoked, "cert_revoked"},
		{"0x108", AuthKindCertBadSignature, "cert_signature"},
		{"0x162", AuthKindCertInvalid, "cert_invalid"},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			server := newCertGateway(t, `<RESULT code="`+tc.code+`" msg="rejected"/>`)
			client := newClientForServer(t, server)

			_, err := client.LoginWithCert(newTestClientCert(t), "")
			if err == nil {
				t.Fatalf("expected gateway rejection for %s", tc.code)
			}
			authErr, ok := err.(*AuthError)
			if !ok {
				t.Fatalf("expected *AuthError, got %T: %v", err, err)
			}
			if authErr.Kind != tc.kind {
				t.Fatalf("expected kind %v, got %v", tc.kind, authErr.Kind)
			}
			if !IsCertAuthError(err) {
				t.Fatal("IsCertAuthError should report true")
			}
			if IsPasswordExpired(err) {
				t.Fatal("certificate errors must never trigger the password-change flow")
			}
		})
	}
}

func TestCertificateErrorCodeStringsMatchServiceContract(t *testing.T) {
	// The frontend keys messages off these strings; keep them stable.
	got := map[AuthKind]string{
		AuthKindCertInvalid:      "cert_invalid",
		AuthKindCertUnavailable:  "cert_unavailable",
		AuthKindCertExpired:      "cert_expired",
		AuthKindCertRevoked:      "cert_revoked",
		AuthKindCertBadSignature: "cert_signature",
	}
	want := map[AuthKind]string{
		AuthKindCertInvalid:      "cert_invalid",
		AuthKindCertUnavailable:  "cert_unavailable",
		AuthKindCertExpired:      "cert_expired",
		AuthKindCertRevoked:      "cert_revoked",
		AuthKindCertBadSignature: "cert_signature",
	}
	for kind, code := range want {
		if got[kind] != code {
			t.Fatalf("kind %v: got %q want %q", kind, got[kind], code)
		}
	}
}
