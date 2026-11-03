package service

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
)

const captchaTestSession = "captcha-session"

// newCaptchaGateway is a minimal gateway whose captcha is bound to the
// VSG_SESSIONID issued by /vpn/user/auth/verifycode, like the real appliance.
// It rejects a login that arrives without that cookie or with another code.
func newCaptchaGateway(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/common/verifycode.gif", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: captchaTestSession, Path: "/"})
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("fake-png"))
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		c, err := r.Cookie("VSG_SESSIONID")
		if err != nil || c.Value != captchaTestSession || r.FormValue("verifycode") != "ABCD" {
			_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x80000021" msg="图形验证码错误"/></RESPONSE>`)
			return
		}
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server
}

func captchaService(t *testing.T, srv *httptest.Server) *VPNService {
	t.Helper()
	host, port := hostPortOf(t, srv.URL)
	return &VPNService{
		Config: &config.AppConfig{Gateways: []config.GatewayProfile{{
			ID:   "gw-0",
			Name: "gw",
			IP:   host,
			Port: port,
		}}},
		Status: "Disconnected",
	}
}

// TestLoginReusesCaptchaSession proves that the client that fetched the
// captcha is the one that submits the login; a fresh client without the
// captcha cookie must be rejected by the same gateway.
func TestLoginReusesCaptchaSession(t *testing.T) {
	t.Chdir(t.TempDir())
	server := newCaptchaGateway(t)

	withImage := captchaService(t, server)
	defer withImage.Logout()

	dataURL, err := withImage.GetVerifyCodeImage("gw")
	if err != nil {
		t.Fatalf("GetVerifyCodeImage: %v", err)
	}
	if !strings.HasPrefix(dataURL, "data:image/png;base64,") {
		t.Fatalf("unexpected data URL: %.40s", dataURL)
	}

	res, err := withImage.Login("gw", "alice", "secret", "ABCD", false, false)
	if err != nil {
		t.Fatalf("Login on the captcha session: %v", err)
	}
	if res["status"] != "Connected" {
		t.Fatalf("status = %v, want Connected", res["status"])
	}

	// A second service never fetched an image; the same code must not work.
	withoutImage := captchaService(t, server)
	defer withoutImage.Logout()
	if _, err := withoutImage.Login("gw", "alice", "secret", "ABCD", false, false); err == nil {
		t.Fatal("login without a captcha session was accepted")
	}
}

// TestLoginClassifiesVerifyCodeDemand guards the field-gateway shape: an
// appliance rejecting the captcha-less login with its own result code and a
// bare 验证码不能为空 message. The rejection must still surface as the
// verify_code challenge (the code the UI keys its captcha modal on), and the
// fetch-image → login-with-code chain must then succeed on the captcha
// session.
func TestLoginClassifiesVerifyCodeDemand(t *testing.T) {
	t.Chdir(t.TempDir())

	// 0x80000050 was captured on a production appliance rejecting a
	// captcha-less login; before the capture it was not in the code table, so
	// keep it here as the regression for both the precise code and the shape
	// of the field rejection.
	const unknownCode = "0x80000050"

	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/common/verifycode.gif", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: captchaTestSession, Path: "/"})
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("fake-png"))
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		c, err := r.Cookie("VSG_SESSIONID")
		if err != nil || c.Value != captchaTestSession || r.FormValue("verifycode") != "ABCD" {
			_, _ = io.WriteString(w, `<RESPONSE><RESULT code="`+unknownCode+`" msg="验证码不能为空"/></RESPONSE>`)
			return
		}
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg=""/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	svc := captchaService(t, server)
	defer svc.Logout()

	// First attempt arrives without a captcha, like the login form always does.
	_, err := svc.Login("gw", "alice", "secret", "", false, false)
	if err == nil {
		t.Fatal("captcha-less login was accepted by a captcha gateway")
	}
	if code := AuthErrorCode(err); code != "verify_code" {
		t.Fatalf("AuthErrorCode = %q, want verify_code (err: %v)", code, err)
	}

	// The UI then loads the image and re-logs with the code on that session.
	if _, err := svc.GetVerifyCodeImage("gw"); err != nil {
		t.Fatalf("GetVerifyCodeImage: %v", err)
	}
	res, err := svc.Login("gw", "alice", "secret", "ABCD", false, false)
	if err != nil {
		t.Fatalf("Login with captcha after unknown-code rejection: %v", err)
	}
	if res["status"] != "Connected" {
		t.Fatalf("status = %v, want Connected", res["status"])
	}
}
