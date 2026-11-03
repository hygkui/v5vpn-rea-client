package protocol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnquoteCookieHeaderStripsOnlyCommaQuotedValues(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"quoted comma session id", `VSG_SESSIONID="aabbccdd,eeff,gghhii"`, `VSG_SESSIONID=aabbccdd,eeff,gghhii`},
		{"multiple cookies", `MapID=7; VSG_SESSIONID="a,b"`, `MapID=7; VSG_SESSIONID=a,b`},
		{"quoted without comma untouched", `A="bcd"`, `A="bcd"`},
		{"plain values untouched", `A=1; B=2`, `A=1; B=2`},
		{"no cookie header", ``, ``},
	}
	for _, tc := range cases {
		if got := unquoteCookieHeader(tc.in); got != tc.want {
			t.Errorf("%s: unquoteCookieHeader(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestTransportOfUnwrapsCookieFixTransport 守卫证书安装/清除路径：
// installClientCertLocked 与 ClearTLSClientCertificate 依赖拿到拨号层
// *http.Transport，cookie 修正层插入后必须仍能解包，否则证书双因子登录
// 会静默丢证书。
func TestTransportOfUnwrapsCookieFixTransport(t *testing.T) {
	client := NewClient("127.0.0.1", 8443, 0, nil)
	tr := transportOf(client.HTTPClient.Transport)
	if tr == nil {
		t.Fatalf("transportOf failed to unwrap cookieFixTransport: got %#v", client.HTTPClient.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatalf("unwrapped transport lost TLSClientConfig")
	}
}

// TestLoginSendsUnquotedCommaSessionCookie 是线上格式守卫，复现 2026-11-02
// 实网问题：真实会话 ID 含逗号时，Go 会把 Cookie 发成
// VSG_SESSIONID="a,b,c"，该网关对带引号的会话查询不回应（35 秒 0 字节），
// 登录后的资源拉取与心跳全部超时；裸值 28ms 返回完整 intergration.xml。
// mock 网关用 Go 解析 Cookie 会自动去引号，暴露不了该差异，因此这里
// 在测试服务器上断言收到的 Cookie 头必须为裸值。
func TestLoginSendsUnquotedCommaSessionCookie(t *testing.T) {
	const sessionID = "aabbccdd,eeff,gghhii" // 实测触发问题的含逗号会话 ID 形态

	var received string
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		// 原厂网关下发的是裸值 Set-Cookie。不能用 http.SetCookie：Go 服务端
		// 会给含逗号的值加引号，而 cookiejar 对带引号的 Set-Cookie 会整个
		// 丢弃（2026-11-02 实测），会话就建立不起来了。
		w.Header().Add("Set-Cookie", `VSG_SESSIONID=`+sessionID+`; Path=/`)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="成功"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<INTERGRATION_INFO>
	<VERSION major="2" minor="0"/>
	<USER name="2475" group="自定义组" type="1" access_type="2" logout_policy="7"/>
</INTERGRATION_INFO>`)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newClientForServer(t, server)
	defer close(client.stopHeartbeat) // Login 已启动心跳，测试结束后停止，避免晚到日志

	integration, err := client.Login("2475", "pwd", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if integration.User.Name != "2475" {
		t.Fatalf("unexpected integration user %q", integration.User.Name)
	}
	if !strings.Contains(received, "VSG_SESSIONID="+sessionID) {
		t.Fatalf("gateway received Cookie %q, want bare VSG_SESSIONID=%s", received, sessionID)
	}
	if strings.Contains(received, `"`) {
		t.Fatalf("gateway received quoted cookie %q; 该网关对带引号会话不回应", received)
	}
}
