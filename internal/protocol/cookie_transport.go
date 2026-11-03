package protocol

import (
	"net/http"
	"strings"
)

// cookieFixTransport rewrites the outgoing Cookie header into the wire format
// the gateway actually accepts.
//
// 网关会话 ID 可能含逗号（如实测会话 VSG_SESSIONID=aabbccdd,eeff,gghhii）。
// Go 的 http.Request.AddCookie 按 RFC 6265 给含逗号的值包一层双引号再发送；
// 原厂 Windows 客户端发的是裸值。2026-11-02 实测：带引号的请求网关不回应
// （35 秒 0 字节，登录后的 intergration.xml 与心跳全部超时），裸值 28ms 返回
// 完整 intergration.xml。mock 网关用 Go 解析 Cookie 会自动去引号，无法暴露
// 该差异，因此在线上格式这里断言，见守卫 TestLoginSendsUnquotedCommaSessionCookie。
//
// 只能在传输层修正：cookiejar 返回的值经 AddCookie 每次都会被重新加引号，
// 改 jar 或改单个请求都拦不住。值本身的引号不会丢失——网关下发的 Set-Cookie
// 被 Go 存储时已去引号，重发时只有含逗号才会被 Go 再加上，恰是这里撤掉的场景。
type cookieFixTransport struct {
	base *http.Transport
}

func (t *cookieFixTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if raw := req.Header.Get("Cookie"); strings.Contains(raw, `"`) {
		req = req.Clone(req.Context())
		req.Header.Set("Cookie", unquoteCookieHeader(raw))
	}
	return t.base.RoundTrip(req)
}

// transportOf returns the dial-level transport behind the client's
// RoundTripper, unwrapping the cookie fix-up layer. Certificate installation
// and clearing mutate the *http.Transport directly and must keep working.
func transportOf(rt http.RoundTripper) *http.Transport {
	if ct, ok := rt.(*cookieFixTransport); ok {
		return ct.base
	}
	t, _ := rt.(*http.Transport)
	return t
}

// unquoteCookieHeader removes the DQUOTE wrapper from cookie values that
// contain a comma. Go 只有在值含逗号（或空格）时才会加引号，因此只撤
// "含逗号且带引号"的值；其余形态原样保留。
func unquoteCookieHeader(raw string) string {
	pairs := strings.Split(raw, "; ")
	for i, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			continue
		}
		inner := value[1 : len(value)-1]
		if strings.Contains(inner, ",") {
			pairs[i] = name + "=" + inner
		}
	}
	return strings.Join(pairs, "; ")
}
