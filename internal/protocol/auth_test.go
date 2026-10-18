package protocol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestClassifyAuth(t *testing.T) {
	cases := []struct {
		code string
		msg  string
		kind AuthKind
	}{
		{"0x8000001A", "用户名或密码错误", AuthKindBadCredentials},
		{"0x8000001A", "口令已过期，请修改密码", AuthKindPasswordExpired},
		{"0x00000100", "用户名或密码错误", AuthKindPasswordExpired},
		{"256", "请修改口令", AuthKindPasswordExpired},
		{"0x66600011", "请输入验证码", AuthKindVerifyCode},
		{"0x80000013", "用户被锁定", AuthKindOther},
	}
	for _, tc := range cases {
		if got := classifyAuth(tc.code, tc.msg); got != tc.kind {
			t.Errorf("classify(%s, %q) = %d, want %d", tc.code, tc.msg, got, tc.kind)
		}
	}

	expired := newAuthError("0x8000001A", "口令已过期，请修改密码")
	if !IsPasswordExpired(expired) {
		t.Fatal("expected password-expired error")
	}
	if strings.Contains(expired.Error(), "用户名或密码错误") {
		t.Fatalf("expired error was rewritten as bad credentials: %s", expired.Error())
	}
	if !strings.Contains(expired.Error(), "口令过期") {
		t.Fatalf("expired error missing marker: %s", expired.Error())
	}

	bad := newAuthError("0x8000001A", "用户名或密码错误")
	if IsPasswordExpired(bad) {
		t.Fatal("wrong password classified as expired")
	}
}

func TestLoginDistinguishesExpiredGBKFromBadCredentials(t *testing.T) {
	msg, err := simplifiedchinese.GBK.NewEncoder().String("口令已过期，请修改密码")
	if err != nil {
		t.Fatal(err)
	}
	body := `<?xml version="1.0" encoding="gb2312"?><RESPONSE><RESULT code="0x8000001A" msg="` + msg + `"/></RESPONSE>`

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=gb2312")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	client := testClient(t, srv)
	_, err = client.Login("alice", "old-secret", "")
	if !IsPasswordExpired(err) {
		t.Fatalf("expected password expired, got %v", err)
	}
	if strings.Contains(err.Error(), "用户名或密码错误") {
		t.Fatalf("GBK expiry was shown as bad credentials: %v", err)
	}
}

func TestLoginBadCredentialsStayBadCredentials(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x8000001A" msg="用户名或密码错误"/></RESPONSE>`)
	}))
	defer srv.Close()

	client := testClient(t, srv)
	_, err := client.Login("alice", "wrong", "")
	if err == nil || IsPasswordExpired(err) {
		t.Fatalf("expected bad credentials, got %v", err)
	}
	if !strings.Contains(err.Error(), "用户名或密码错误") {
		t.Fatalf("missing credential message: %v", err)
	}
}

func TestChangePasswordSubmitsPwdChangeEndpoint(t *testing.T) {
	b64Old := "b2xkLXNlY3JldA==" // base64("old-secret")
	b64New := "bmV3LXNlY3JldA==" // base64("new-secret")

	var gotPath, gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/pwdchange", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="密码修改成功"/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)
	if err := client.ChangePassword("alice", "old-secret", "new-secret", ""); err != nil {
		t.Fatal(err)
	}

	if gotPath != "/vpn/user/auth/pwdchange" {
		t.Fatalf("expected /vpn/user/auth/pwdchange, got %q", gotPath)
	}
	if !strings.Contains(gotBody, "old_pwd="+b64Old) {
		t.Fatalf("request body missing old_pwd=%s: %s", b64Old, gotBody)
	}
	if !strings.Contains(gotBody, "new_pwd="+b64New) {
		t.Fatalf("request body missing new_pwd=%s: %s", b64New, gotBody)
	}
	if !strings.Contains(gotBody, "encode=1") {
		t.Fatalf("request body missing encode=1: %s", gotBody)
	}
}

func TestChangePasswordHandlesGatewayErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/pwdchange", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x11A" msg="旧密码错误"/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)
	err := client.ChangePassword("alice", "wrong-old", "new-secret", "")
	if err == nil {
		t.Fatal("expected error on rejected password change")
	}
	if !strings.Contains(err.Error(), "旧密码错误") && !strings.Contains(err.Error(), "0x11A") {
		t.Fatalf("expected error message to contain reason or code: %v", err)
	}
}

func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	client := NewClient("127.0.0.1", 1, 0, func(level, format string, args ...any) {
		t.Logf("[%s] "+format, append([]any{level}, args...)...)
	})
	client.BaseURL = srv.URL
	hc := srv.Client()
	hc.Jar = client.HTTPClient.Jar
	client.HTTPClient = hc
	return client
}
