package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// AuthKind classifies a rejected /vpn/user/auth/password result.
//
// Classification is based solely on the gateway result code. Only 0x100 means
// "password expired": SecUI.exe branches on that code alone when it opens the
// password-change view. A gateway can also answer 0x8000001A (ciphertext parse
// failure) with an "expired" sentence in msg, but the code still wins.
type AuthKind int

const (
	AuthKindOther AuthKind = iota
	AuthKindBadCredentials
	AuthKindPasswordExpired
	AuthKindVerifyCode
	// Certificate authentication rejections (0x103-0x108, 0x162). Codes come
	// from language.xml TAG 259-264 and 354; do not infer meaning from the
	// numeric order.
	AuthKindCertInvalid
	AuthKindCertUnavailable
	AuthKindCertExpired
	AuthKindCertRevoked
	AuthKindCertBadSignature
)

const (
	// codePasswordExpired is the only result that opens the password-change view.
	codePasswordExpired = 0x100
	// codeBadCredentials is a real username/password mismatch.
	codeBadCredentials = 0x101
	// codeDecryptFailed means the gateway could not parse the encrypted
	// credentials (for example encode=1 was sent instead of encode=2). The
	// original client still reports it as a credential error.
	codeDecryptFailed = 0x8000001A
	codeVerifyCode    = 0x66600011

	// Certificate authentication results.
	codeCertVerifyFailed = 0x103 // TAG 259 证书验证失败
	codeCertUnavailable  = 0x105 // TAG 261 证书认证不可用
	codeCertExpired      = 0x106 // TAG 262 证书已过期
	codeCertRevoked      = 0x107 // TAG 263 证书已被注销
	codeCertBadSignature = 0x108 // TAG 264 证书签名错误
	codeCertFailed       = 0x162 // TAG 354 证书认证失败（超期或验证失败）
)

// AuthError is a gateway authentication rejection with a stable kind.
type AuthError struct {
	Kind AuthKind
	Code string
	Msg  string
}

func (e *AuthError) Error() string {
	if e == nil {
		return "登录失败"
	}
	msg := e.Msg
	switch e.Kind {
	case AuthKindPasswordExpired:
		if msg == "" {
			msg = "账号口令已过期，需要修改密码"
		}
		// Keep a leading "口令过期" for readable logs; callers use
		// IsPasswordExpired rather than matching this text.
		return fmt.Sprintf("口令过期: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindBadCredentials:
		// Match the original client's error mapping: both a real mismatch and
		// a ciphertext parse failure are shown as an account/password error.
		if msg == "" || isResultCode(e.Code, codeBadCredentials) || isResultCode(e.Code, codeDecryptFailed) {
			msg = "用户名或密码错误"
		}
		return fmt.Sprintf("登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindVerifyCode:
		if msg == "" {
			msg = "需要图形验证码"
		}
		return fmt.Sprintf("登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertInvalid:
		if msg == "" {
			msg = "证书验证失败，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertUnavailable:
		if msg == "" {
			msg = "网关未启用以证书方式登录"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertExpired:
		if msg == "" {
			msg = "证书已过期，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertRevoked:
		if msg == "" {
			msg = "证书已被注销，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindCertBadSignature:
		if msg == "" {
			msg = "证书签名错误，请重新选择证书进行认证"
		}
		return fmt.Sprintf("证书登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	default:
		if msg == "" {
			msg = "网关拒绝登录认证"
		}
		return fmt.Sprintf("登录失败: %s (错误代码: %s)", msg, displayCode(e.Code))
	}
}

// IsPasswordExpired reports whether err is a password-change challenge.
func IsPasswordExpired(err error) bool {
	var authErr *AuthError
	return errors.As(err, &authErr) && authErr.Kind == AuthKindPasswordExpired
}

func displayCode(code string) string {
	if strings.TrimSpace(code) == "" {
		return "unknown"
	}
	return code
}

func newAuthError(code, msg string) *AuthError {
	return &AuthError{
		Kind: classifyAuth(code, msg),
		Code: code,
		Msg:  msg,
	}
}

func classifyAuth(code, _ string) AuthKind {
	n, ok := parseResultCode(code)
	if !ok {
		return AuthKindOther
	}
	switch n {
	case codePasswordExpired:
		return AuthKindPasswordExpired
	case codeBadCredentials, codeDecryptFailed:
		return AuthKindBadCredentials
	case codeVerifyCode:
		return AuthKindVerifyCode
	case codeCertVerifyFailed, codeCertFailed:
		return AuthKindCertInvalid
	case codeCertUnavailable:
		return AuthKindCertUnavailable
	case codeCertExpired:
		return AuthKindCertExpired
	case codeCertRevoked:
		return AuthKindCertRevoked
	case codeCertBadSignature:
		return AuthKindCertBadSignature
	default:
		return AuthKindOther
	}
}

// IsCertAuthError reports whether err is a certificate-authentication
// rejection, so callers never offer a password change for it.
func IsCertAuthError(err error) bool {
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		return false
	}
	switch authErr.Kind {
	case AuthKindCertInvalid, AuthKindCertUnavailable, AuthKindCertExpired,
		AuthKindCertRevoked, AuthKindCertBadSignature:
		return true
	default:
		return false
	}
}

func isResultCode(code string, want uint64) bool {
	n, ok := parseResultCode(code)
	return ok && n == want
}

// parseResultCode reads a gateway RESULT code. Hex forms keep the 0x prefix;
// a pure decimal string is read as decimal so "256" and "0x100" agree.
func parseResultCode(code string) (uint64, bool) {
	s := strings.TrimSpace(code)
	if s == "" {
		return 0, false
	}
	base := 16
	if len(s) >= 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		s = s[2:]
	} else if !strings.ContainsAny(s, "abcdefABCDEF") {
		base = 10
	}
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func isSuccessCode(code string) bool {
	n, ok := parseResultCode(code)
	return ok && n == 0
}

// passwordAuthBody is the v2.0 password login form. Values are already
// AES-128-CBC base64 and must not be URL-escaped: escaping '=' in the
// base64 tail makes the gateway decrypt garbage and return 0x8000001A.
func passwordAuthBody(encUser, encPwd, verifycode string) string {
	return fmt.Sprintf("username=%s&password=%s&encode=2&verifycode=%s", encUser, encPwd, verifycode)
}

// passwordChangeBody formats the request body for /vpn/user/auth/pwdchange.
// Both passwords are standard Base64-encoded, and encode=1 indicates Base64 encoding.
func passwordChangeBody(oldPassword, newPassword string) string {
	b64Old := base64.StdEncoding.EncodeToString([]byte(oldPassword))
	b64New := base64.StdEncoding.EncodeToString([]byte(newPassword))
	return fmt.Sprintf("old_pwd=%s&new_pwd=%s&encode=1", b64Old, b64New)
}
