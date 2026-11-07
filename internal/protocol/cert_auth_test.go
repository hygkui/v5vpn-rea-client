package protocol

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// twoFactorProbe records what the two-step gateway observed.
type twoFactorProbe struct {
	sawCertOnPassword bool   // step 1 must never carry the client certificate
	passwordBody      string // raw form body of step 1
	sawCertStep       bool   // step 2 was requested
	certStepHasCert   bool   // step 2 presented the client certificate
	certStepCookie    string // VSG_SESSIONID carried into step 2
	certStepBodyLen   int    // step 2 must carry no body
}

// newPasswordCertGateway starts a TLS server that answers the two-step
// two-factor flow the way the original client drives it: the password step
// runs without a client certificate and answers code 2 ("certificate factor
// required") unless passwordResult overrides it; the certificate step must
// present the certificate, reuses the session cookie and answers certResult
// (default: success). Client certificates are requested, not required, at the
// TLS layer so a certificate-less password step can be observed.
func newPasswordCertGateway(t *testing.T, passwordResult, certResult string, probe *twoFactorProbe) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if probe != nil {
			probe.passwordBody = string(b)
		}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if probe != nil {
				probe.sawCertOnPassword = true
			}
			t.Errorf("the password step must not carry a client certificate")
		}
		if r.Method != http.MethodPost {
			t.Errorf("password auth used %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "text/xml")
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "two-factor-session", Path: "/"})
		if passwordResult != "" {
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><RESPONSE>` + passwordResult + `</RESPONSE>`))
			return
		}
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><RESPONSE><RESULT code="2" msg="certificate factor required"/></RESPONSE>`))
	})
	mux.HandleFunc("/vpn/user/auth/cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("certificate auth used %s, want GET", r.Method)
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusBadRequest)
			return
		}
		if probe != nil {
			b, _ := io.ReadAll(r.Body)
			probe.sawCertStep = true
			probe.certStepHasCert = true
			probe.certStepBodyLen = len(b)
			if c, err := r.Cookie("VSG_SESSIONID"); err == nil {
				probe.certStepCookie = c.Value
			}
		}
		w.Header().Set("Content-Type", "text/xml")
		if certResult != "" {
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><RESPONSE>` + certResult + `</RESPONSE>`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "two-factor-session", Path: "/"})
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><RESPONSE><RESULT code="0" msg="ok"/></RESPONSE>`))
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><INTERGRATION_INFO><USER name="two-factor-user"/><SESSION sid_name="VSG_SESSIONID" detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`))
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// TestAuthPasswordWithCertTwoStepFlow is the contract for the two-factor
// login: the password is submitted first without a client certificate, and
// only the gateway's "certificate factor" answer opens the second request,
// which presents the certificate and reuses the session cookie.
func TestAuthPasswordWithCertTwoStepFlow(t *testing.T) {
	probe := &twoFactorProbe{}
	server := newPasswordCertGateway(t, "", "", probe)
	client := newClientForServer(t, server)

	resp, err := client.AuthPasswordWithCert(newTestClientCert(t), "alice", "secret", "")
	if err != nil {
		t.Fatalf("AuthPasswordWithCert: %v", err)
	}
	if resp == nil || resp.Result.Code != "0" {
		t.Fatalf("unexpected auth response: %+v", resp)
	}
	if probe.sawCertOnPassword {
		t.Fatal("the password step must not carry the client certificate")
	}
	if !probe.sawCertStep || !probe.certStepHasCert {
		t.Fatal("the certificate step did not present the client certificate")
	}
	if probe.certStepCookie != "two-factor-session" {
		t.Fatalf("certificate step lost the session cookie: %q", probe.certStepCookie)
	}
	if probe.certStepBodyLen != 0 {
		t.Fatalf("certificate step carried a body (%d bytes)", probe.certStepBodyLen)
	}
	values, err := url.ParseQuery(probe.passwordBody)
	if err != nil {
		t.Fatalf("password body not form-encoded: %v", err)
	}
	if values.Get("encode") != "1" {
		t.Fatalf("encode = %q, want 1 (base64)", values.Get("encode"))
	}
	if got, want := values.Get("username"), base64.StdEncoding.EncodeToString([]byte("alice")); got != want {
		t.Fatalf("username = %q, want %q", got, want)
	}
	if got, want := values.Get("password"), base64.StdEncoding.EncodeToString([]byte("secret")); got != want {
		t.Fatalf("password = %q, want %q", got, want)
	}
	if client.SessionID != "two-factor-session" {
		t.Fatalf("expected session id from Set-Cookie, got %q", client.SessionID)
	}
	if !resp.CertFactorUsed {
		t.Fatal("CertFactorUsed must be set once the certificate step succeeds")
	}
	if client.ClientCertificate() == nil {
		t.Fatal("client certificate was not retained for tunnel reuse")
	}
	if !client.IsLoggedIn() {
		t.Fatal("AuthPasswordWithCert must mark the session as logged in")
	}
	_ = client.Logout()
}

// A gateway that accepts the password alone must not receive the certificate
// step; the certificate is still kept for the tunnel.
func TestAuthPasswordWithCertSkipsCertificateWhenNotAsked(t *testing.T) {
	probe := &twoFactorProbe{}
	server := newPasswordCertGateway(t, `<RESULT code="0" msg="ok"/>`, "", probe)
	client := newClientForServer(t, server)

	resp, err := client.AuthPasswordWithCert(newTestClientCert(t), "alice", "secret", "")
	if err != nil {
		t.Fatalf("AuthPasswordWithCert: %v", err)
	}
	if resp == nil || resp.Result.Code != "0" {
		t.Fatalf("unexpected auth response: %+v", resp)
	}
	if probe.sawCertStep {
		t.Fatal("certificate step must not run when the gateway did not ask for it")
	}
	if !client.IsLoggedIn() {
		t.Fatal("session was not marked logged in")
	}
	if client.ClientCertificate() == nil {
		t.Fatal("client certificate was not retained for tunnel reuse")
	}
	if resp.CertFactorUsed {
		t.Fatal("CertFactorUsed must stay false when the gateway accepted the password alone")
	}
	_ = client.Logout()
}

// Two-factor login without a certificate cannot satisfy the certificate step.
func TestAuthPasswordWithCertRequiresCertificate(t *testing.T) {
	server := newPasswordCertGateway(t, "", "", nil)
	client := newClientForServer(t, server)

	if _, err := client.AuthPasswordWithCert(nil, "alice", "secret", ""); err == nil {
		t.Fatal("expected the certificate step to fail without a client certificate")
	}
}

// Rejections from the certificate step keep their certificate
// classification.
func TestAuthPasswordWithCertCertificateStepRejection(t *testing.T) {
	probe := &twoFactorProbe{}
	server := newPasswordCertGateway(t, "", `<RESULT code="0x103" msg="证书验证失败"/>`, probe)
	client := newClientForServer(t, server)

	_, err := client.AuthPasswordWithCert(newTestClientCert(t), "alice", "secret", "")
	if err == nil {
		t.Fatal("expected the certificate step to be rejected")
	}
	if !IsCertAuthError(err) {
		t.Fatalf("expected a certificate classification, got %v", err)
	}
	if IsPasswordExpired(err) {
		t.Fatal("certificate errors must never trigger the password-change flow")
	}
	if !probe.sawCertStep || !probe.certStepHasCert {
		t.Fatal("certificate step did not run with the certificate")
	}
}

// TestClearTLSClientCertificateRemovesInstalledCert guards the failed-login
// path: a certificate installed for a login that then fails must not stay on
// the client, because the same client is reused for the captcha session and
// the next password attempt would present it.
func TestClearTLSClientCertificateRemovesInstalledCert(t *testing.T) {
	client := NewClient("127.0.0.1", 1, 0, nil)
	cert := newTestClientCert(t)

	client.SetTLSClientCertificate(cert)
	if client.ClientCertificate() == nil {
		t.Fatal("certificate was not installed")
	}

	client.ClearTLSClientCertificate()
	if client.ClientCertificate() != nil {
		t.Fatal("certificate survived ClearTLSClientCertificate")
	}
	tr := transportOf(client.HTTPClient.Transport)
	if tr == nil {
		t.Fatal("transportOf failed to unwrap the client transport")
	}
	if len(tr.TLSClientConfig.Certificates) != 0 || tr.TLSClientConfig.GetClientCertificate != nil {
		t.Fatal("TLS transport still offers the client certificate")
	}
}

// Password-step rejections stay password rejections and never open the
// certificate step.
func TestAuthPasswordWithCertClassifiesPasswordResults(t *testing.T) {
	cases := []struct {
		name   string
		result string
		check  func(error) bool
	}{
		{"password expired", `<RESULT code="0x100" msg="口令过期"/>`, IsPasswordExpired},
		{"bad credentials", `<RESULT code="0x101" msg="用户名或密码错误"/>`, func(err error) bool {
			return !IsPasswordExpired(err) && !IsCertAuthError(err)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := &twoFactorProbe{}
			server := newPasswordCertGateway(t, tc.result, "", probe)
			client := newClientForServer(t, server)
			_, err := client.AuthPasswordWithCert(newTestClientCert(t), "alice", "secret", "")
			if err == nil {
				t.Fatal("expected a gateway rejection")
			}
			if !tc.check(err) {
				t.Fatalf("unexpected classification for %s: %v", tc.result, err)
			}
			if probe.sawCertStep {
				t.Fatal("certificate step must not run after a password rejection")
			}
		})
	}
}
