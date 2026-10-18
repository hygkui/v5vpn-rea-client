package protocol

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// AuthKind classifies a rejected /vpn/user/auth/password result.
// Password expiry is separate from a wrong username or password: gateways
// reuse 0x8000001A for both, and the Chinese message is what distinguishes them.
type AuthKind int

const (
	AuthKindOther AuthKind = iota
	AuthKindBadCredentials
	AuthKindPasswordExpired
	AuthKindVerifyCode
)

const (
	codeBadCredentials  = 0x8000001A
	codePasswordExpired = 0x100
	codeVerifyCode      = 0x66600011
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
		// Leading "口令过期" is the marker the UI and CLI look for.
		// Do not rewrite this into the bad-credentials sentence.
		return fmt.Sprintf("口令过期: %s (错误代码: %s)", msg, displayCode(e.Code))
	case AuthKindBadCredentials:
		if msg == "" {
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
	if passwordExpired(n, ok, msg) {
		return AuthKindPasswordExpired
	}
	if (ok && n == codeBadCredentials) || containsAny(msg, "用户名或密码错误", "用户名或口令错误", "用户名密码错误") {
		return AuthKindBadCredentials
	}
	if (ok && n == codeVerifyCode) || strings.Contains(msg, "验证码") {
		return AuthKindVerifyCode
	}
	return AuthKindOther
}

func passwordExpired(code uint64, hasCode bool, msg string) bool {
	if hasCode && code == codePasswordExpired {
		return true
	}
	return containsAny(msg,
		"口令过期",
		"密码过期",
		"口令已过期",
		"密码已过期",
		"口令到期",
		"密码到期",
		"请修改密码",
		"请修改口令",
		"强制修改密码",
		"强制修改口令",
		"首次登录修改",
		"首次登陆修改",
		"password expired",
		"must change password",
	)
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

// changePasswordAuthBody is the same login form plus newpassword.
// The field name is a candidate for the Windows v2.0 client. It has not
// been confirmed from SecLogin or a live gateway capture.
func changePasswordAuthBody(encUser, encOld, encNew, verifycode string) string {
	return fmt.Sprintf("username=%s&password=%s&newpassword=%s&encode=2&verifycode=%s", encUser, encOld, encNew, verifycode)
}
