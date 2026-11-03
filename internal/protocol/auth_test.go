package protocol

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		{"0x8000001A", "口令已过期，请修改密码", AuthKindBadCredentials},
		{"0x101", "用户名或密码错误", AuthKindBadCredentials},
		{"257", "", AuthKindBadCredentials},
		{"0x00000100", "用户名或密码错误", AuthKindPasswordExpired},
		{"256", "请修改口令", AuthKindPasswordExpired},
		{"", "口令已过期，请修改密码", AuthKindOther},
		{"", "用户名或密码错误", AuthKindOther},
		{"not-a-code", "用户名或密码错误", AuthKindOther},
		{"0x66600011", "请输入验证码", AuthKindVerifyCode},
		// 0x80000050：生产网关实抓的「验证码不能为空」拒绝码。
		{"0x80000050", "验证码不能为空", AuthKindVerifyCode},
		{"0x80000013", "用户被锁定", AuthKindOther},
		// 野外网关对空验证码回未收录码值、msg 只有一句「验证码不能为空」：
		// 文案兜底必须把它归成验证码挑战，否则界面永远不弹验证码模态。
		{"0x1000000C", "验证码不能为空", AuthKindVerifyCode},
		{"", "验证码不能为空", AuthKindVerifyCode},
		{"not-a-code", "图形验证码错误，请重新输入", AuthKindVerifyCode},
		// 短信与动态令牌的文案同样含「验证码」，兜底不得把它抢成图形码。
		{"", "短信验证码错误", AuthKindOther},
		{"", "动态令牌验证码错误", AuthKindOther},
	}
	for _, tc := range cases {
		if got := classifyAuth(tc.code, tc.msg); got != tc.kind {
			t.Errorf("classify(%s, %q) = %d, want %d", tc.code, tc.msg, got, tc.kind)
		}
	}

	expired := newAuthError("0x100", "口令过期，需修改密码")
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

	// A ciphertext parse failure with an expiry-sounding message is still a
	// credential error and must be displayed as one.
	decryptFailed := newAuthError("0x8000001A", "口令已过期，请修改密码")
	if IsPasswordExpired(decryptFailed) {
		t.Fatal("ciphertext parse failure classified as expired")
	}
	if strings.Contains(decryptFailed.Error(), "口令过期") {
		t.Fatalf("decrypt failure leaked an expiry message: %s", decryptFailed.Error())
	}
	if !strings.Contains(decryptFailed.Error(), "用户名或密码错误") {
		t.Fatalf("decrypt failure not shown as bad credentials: %s", decryptFailed.Error())
	}
}

func TestLoginClassifiesPasswordExpiryByResultCode(t *testing.T) {
	cases := []struct {
		name        string
		code        string
		msg         string
		expired     bool
		wantMessage string
	}{
		{"0x100 opens change password", "0x100", "口令过期，需修改密码", true, "口令过期"},
		{"0x8000001A stays bad credentials", "0x8000001A", "口令已过期，请修改密码", false, "用户名或密码错误"},
		{"0x101 stays bad credentials", "0x101", "口令已过期，请修改密码", false, "用户名或密码错误"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := gbkAuthResponse(t, tc.code, tc.msg)

			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/xml; charset=gb2312")
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()

			client := testClient(t, srv)
			_, err := client.Login("alice", "old-secret", "")
			if err == nil {
				t.Fatal("expected login rejection")
			}
			if got := IsPasswordExpired(err); got != tc.expired {
				t.Fatalf("IsPasswordExpired = %v, want %v (err: %v)", got, tc.expired, err)
			}
			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("expected %q in error, got %v", tc.wantMessage, err)
			}
		})
	}
}

func gbkAuthResponse(t *testing.T, code, msg string) string {
	t.Helper()
	encoded, err := simplifiedchinese.GBK.NewEncoder().String(msg)
	if err != nil {
		t.Fatal(err)
	}
	return `<?xml version="1.0" encoding="gb2312"?><RESPONSE><RESULT code="` + code + `" msg="` + encoded + `"/></RESPONSE>`
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
	// The original client posts both passwords as plain UTF-8 and sends no
	// encode parameter at all (format "old_pwd=%s&new_pwd=%s").
	if !strings.Contains(gotBody, "old_pwd=old-secret") {
		t.Fatalf("request body missing raw old_pwd: %s", gotBody)
	}
	if !strings.Contains(gotBody, "new_pwd=new-secret") {
		t.Fatalf("request body missing raw new_pwd: %s", gotBody)
	}
	if strings.Contains(gotBody, "encode=") {
		t.Fatalf("pwdchange must not carry an encode parameter: %s", gotBody)
	}
}

// TestChangePasswordPercentEncodesPasswords guards the form encoding: the body
// is application/x-www-form-urlencoded, so a password containing '&', '+' or '%'
// must survive a round trip through url.ParseQuery unchanged.
func TestChangePasswordPercentEncodesPasswords(t *testing.T) {
	var gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/pwdchange", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="密码修改成功"/></RESPONSE>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := testClient(t, srv)
	if err := client.ChangePassword("alice", "a&b=c", "100%+ok", ""); err != nil {
		t.Fatal(err)
	}

	values, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("gateway could not parse the body %q: %v", gotBody, err)
	}
	if values.Get("old_pwd") != "a&b=c" {
		t.Fatalf("old_pwd = %q, want %q (body: %s)", values.Get("old_pwd"), "a&b=c", gotBody)
	}
	if values.Get("new_pwd") != "100%+ok" {
		t.Fatalf("new_pwd = %q, want %q (body: %s)", values.Get("new_pwd"), "100%+ok", gotBody)
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

func TestChangePasswordRequiresSuccessResultCode(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"missing result code", `<RESPONSE></RESPONSE>`, "缺少结果码"},
		{"non-XML body", `<html><body>ok</body></html>`, "无法解析"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/vpn/user/auth/pwdchange", func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			})

			srv := httptest.NewTLSServer(mux)
			defer srv.Close()

			client := testClient(t, srv)
			err := client.ChangePassword("alice", "old-secret", "new-secret", "")
			if err == nil {
				t.Fatal("HTTP 200 without a success result code was treated as success")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestPasswordAuthBodyUsesEncode1Base64(t *testing.T) {
	body := passwordAuthBody(base64AuthParam("alice"), base64AuthParam("s3cret!"), "1234")
	want := "username=YWxpY2U=&password=czNjcmV0IQ==&encode=1&verifycode=1234"
	if body != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestBase64AuthParamMatchesOriginalWrapping pins the exact base64 layout of
// SecLogin.dll (76-column CRLF wrapping, one trailing CRLF stripped, and the
// stray trailing CRLF the original loop leaves when the group part is a
// nonzero multiple of 76 columns).
func TestBase64AuthParamMatchesOriginalWrapping(t *testing.T) {
	std := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	rep := func(n int) string { return strings.Repeat("a", n) }

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"short input stays a single plain line", "alice", std("alice")},
		{"57 bytes keeps the loop's stray trailing CRLF", rep(57), std(rep(57)) + "\r\n"},
		{"58 bytes puts the padding on its own line", rep(58), std(rep(58))[:76] + "\r\n" + std(rep(58))[76:]},
		{"100 bytes wraps before the partial tail", rep(100), std(rep(100))[:76] + "\r\n" + std(rep(100))[76:]},
		{"114 bytes ends a double line with CRLF", rep(114), std(rep(114))[:76] + "\r\n" + std(rep(114))[76:] + "\r\n"},
		{"120 bytes wraps two full lines", rep(120), std(rep(120))[:76] + "\r\n" + std(rep(120))[76:152] + "\r\n" + std(rep(120))[152:]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := base64AuthParam(tc.in); got != tc.want {
				t.Fatalf("base64AuthParam(%d bytes) =\n%q\nwant\n%q", len(tc.in), got, tc.want)
			}
		})
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
