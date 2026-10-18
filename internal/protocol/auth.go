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
// Only result code 0x100 means "password expired": SecUI.exe branches on that
// code alone when it opens the password-change view. A gateway can also answer
// 0x8000001A (ciphertext parse failure) with an "expired" sentence in msg, but
// that is still a credential error, so message text must never trigger the
// change-password flow.
type AuthKind int

const (
	AuthKindOther AuthKind = iota
	AuthKindBadCredentials
	AuthKindPasswordExpired
	AuthKindVerifyCode
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

func classifyAuth(code, msg string) AuthKind {
	n, ok := parseResultCode(code)
	if ok {
		switch n {
		case codePasswordExpired:
			return AuthKindPasswordExpired
		case codeBadCredentials, codeDecryptFailed:
			return AuthKindBadCredentials
		case codeVerifyCode:
			return AuthKindVerifyCode
		}
	}

	// Message fallback for responses without a usable code. It may classify a
	// credential error, but never a password expiry.
	if containsAny(msg, "用户名或密码错误", "用户名或口令错误", "用户名密码错误") {
		return AuthKindBadCredentials
	}
	if strings.Contains(msg, "验证码") {
		return AuthKindVerifyCode
	}
	return AuthKindOther
}

func isResultCode(code string, want uint64) bool {
	n, ok := parseResultCode(code)
	return ok && n == want
}

func containsAny(msg string, parts ...string) bool {
	if msg == "" {
		return false
	}
	lower := strings.ToLower(msg)
	for _, part := range parts {
		if strings.Contains(lower, strings.ToLower(part)) {
			return true
		}
	}
	return false
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
