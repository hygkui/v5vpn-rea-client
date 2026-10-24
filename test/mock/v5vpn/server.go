package mockserver

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Mode defines the gateway simulation mode.
type Mode string

const (
	ModePwdCert    Mode = "pwd-cert"     // Two-factor: Password -> code 2 -> Cert -> code 0
	ModePwdCertSMS Mode = "pwd-cert-sms" // Three-factor chain: Password -> code 2 -> Cert -> code 8 -> SMS -> code 0
	ModeFullChain  Mode = "full-chain"   // Every factor in one chain: Password(+captcha) -> code 2 -> Cert -> code 8 -> SMS -> code 4 -> Token -> code 0
	ModePwdOnly    Mode = "pwd-only"     // Single-factor: Password -> code 0
	ModeCertOnly   Mode = "cert-only"    // Standalone mTLS Certificate -> code 0
	ModePwdChange  Mode = "pwd-change"   // Password expired: Password -> code 256 -> PwdChange -> code 0
	ModeVerifyCode Mode = "verifycode"   // Captcha required: Password -> code 0x80 -> Captcha -> code 0
	ModeToken      Mode = "token"        // Password -> code 4 -> Token -> code 0
	ModeSMS        Mode = "sms"          // Password -> code 8 -> SMS -> code 0
	ModeErrAuth    Mode = "err-auth"     // Invalid credentials -> code 0x8000001a
	ModeErrCert    Mode = "err-cert"     // Expired/Invalid certificate -> code 0x106
)

// Config holds options for the mock server.
type Config struct {
	Addr         string
	Mode         Mode
	ExpectedUser string
	ExpectedPwd  string
	RequireCert  bool
	Verbose      bool
	// NCMode controls the portal RESOURCE_LIST fixture: "" (默认) 只下发
	// TCP/UDP 资源；NCModeMixed 追加一个 NC (IPsec) 配置；NCModeOnly 只
	// 下发 NC 配置（模拟「登录成功但 0 TCP/UDP 资源」账号）。
	NCMode string
}

// NC portal-resource fixture modes. See Config.NCMode.
const (
	NCModeMixed = "mixed"
	NCModeOnly  = "only"
)

// Session tracks an active client session.
type Session struct {
	ID         string
	Username   string
	PassedPwd  bool
	PassedCert bool
	AuthMethod string
	VerifyCode string
	SMSCode    string
	TokenCode  string
	CreatedAt  time.Time
}

// Server simulates a Leadsec / WangYu V5VPN SSL VPN Gateway.
type Server struct {
	cfg               Config
	httpSrv           *http.Server
	certPEM           []byte
	mu                sync.RWMutex
	sessions          map[string]*Session
	mode              Mode
	currentVerifyCode string
	currentSMSCode    string
	currentTokenCode  string
	lastChangedTime   time.Time
}

// New creates a new V5VPN mock server.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8443"
	}
	if cfg.Mode == "" {
		cfg.Mode = ModePwdCert
	}
	if cfg.ExpectedUser == "" {
		cfg.ExpectedUser = "admin"
	}
	if cfg.ExpectedPwd == "" {
		cfg.ExpectedPwd = "admin123"
	}

	tlsCert, certPEM, err := GenerateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	s := &Server{
		cfg:      cfg,
		certPEM:  certPEM,
		sessions: make(map[string]*Session),
		mode:     cfg.Mode,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		// RequestClientCert requests client certificate if presented, without dropping TLS connection if absent
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS10,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", s.handleVersion)
	mux.HandleFunc("/vpn/user/auth/password", s.handlePassword)
	mux.HandleFunc("/vpn/user/auth/cert", s.handleCert)
	mux.HandleFunc("/vpn/user/auth/token", s.handleToken)
	mux.HandleFunc("/vpn/user/auth/smc", s.handleSMS)
	mux.HandleFunc("/vpn/user/auth/send_smc", s.handleSendSMS)
	mux.HandleFunc("/vpn/user/auth/pwdchange", s.handlePwdChange)
	mux.HandleFunc("/vpn/user/auth/verifycode", s.handleVerifyCode)
	mux.HandleFunc("/vpn/user/auth/verifycode_status", s.handleVerifyCodeStatus)
	mux.HandleFunc("/api/verifycode", s.handleAPIVerifyCode)
	mux.HandleFunc("/api/smscode", s.handleAPISMCode)
	mux.HandleFunc("/api/tokencode", s.handleAPITokenCode)
	mux.HandleFunc("/vpn/user/check/rule.xml", s.handleRuleXML)
	mux.HandleFunc("/vpn/user/common/SSOConfig.xml", s.handleSSOConfigXML)
	mux.HandleFunc("/vpn/user/client/install.xml", s.handleInstallXML)
	mux.HandleFunc("/vpn/user/portal/intergration.xml", s.handleIntegration)
	mux.HandleFunc("/vpn/user/logout", s.handleLogout)
	mux.HandleFunc("/api/mode", s.handleAPIMode)
	mux.HandleFunc("/", s.handleIndex)

	s.httpSrv = &http.Server{
		Addr:      cfg.Addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	return s, nil
}

// Start begins listening and serving HTTPS requests.
func (s *Server) Start() error {
	log.Printf("[MockServer] Gateway listening on https://%s (Mode: %s)", s.cfg.Addr, s.GetMode())
	return s.httpSrv.ListenAndServeTLS("", "")
}

// Close gracefully stops the server.
func (s *Server) Close() error {
	return s.httpSrv.Close()
}

// GetMode returns the current active simulation mode.
func (s *Server) GetMode() Mode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// SetMode dynamically changes the simulation mode.
func (s *Server) SetMode(m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
	log.Printf("[MockServer] Simulation mode changed to: %s", m)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>V5VPN Gateway Mock Server</title>
<style>
body { font-family: -apple-system, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }
h1 { color: #38bdf8; }
.card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
code { background: #334155; padding: 2px 6px; border-radius: 4px; color: #f1f5f9; }
button { padding: 8px 16px; margin: 4px; border-radius: 4px; border: none; background: #38bdf8; color: #0f172a; font-weight: bold; cursor: pointer; }
button:hover { background: #0284c7; color: #fff; }
</style>
</head>
<body>
<h1>🛡️ Leadsec / 网御星云 V5VPN Gateway Mock Server</h1>
<div class="card">
  <p><strong>Status:</strong> Running</p>
  <p><strong>Current Mode:</strong> <code>%s</code></p>
  <p><strong>Expected User:</strong> <code>%s</code> / <code>%s</code></p>
  <p><strong>Switch Simulation Flow:</strong></p>
  <button onclick="setMode('pwd-cert')">🔐 口令+证书双因素 (pwd-cert)</button>
  <button onclick="setMode('pwd-cert-sms')">🔐💬 口令+证书+短信三因素 (pwd-cert-sms)</button>
  <button onclick="setMode('full-chain')">🧩 全链挑战: 验证码+证书+短信+令牌 (full-chain)</button>
  <button onclick="setMode('pwd-only')">🔑 仅口令直连 (pwd-only)</button>
  <button onclick="setMode('cert-only')">🪪 纯证书免密 (cert-only)</button>
  <button onclick="setMode('pwd-change')">🔄 密码过期改密 (pwd-change)</button>
  <button onclick="setMode('verifycode')">🔢 图形验证码挑战 (verifycode)</button>
  <button onclick="setMode('token')">📱 动态令牌 (token)</button>
  <button onclick="setMode('sms')">💬 短信验证码 (sms)</button>
  <button onclick="setMode('err-auth')">❌ 账密错误拒绝 (err-auth)</button>
  <button onclick="setMode('err-cert')">🚫 证书过期拒绝 (err-cert)</button>
</div>
<script>
function setMode(m) {
  fetch('/api/mode?mode=' + m, { method: 'POST' }).then(() => location.reload());
}
</script>
</body>
</html>`, s.GetMode(), s.cfg.ExpectedUser, s.cfg.ExpectedPwd)
}

func (s *Server) handleAPIMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodGet {
		m := r.URL.Query().Get("mode")
		if m != "" {
			s.SetMode(Mode(m))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"mode":"%s"}`, s.GetMode())
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Verbose {
		log.Printf("[MockServer] -> GET /vpn/version.xml from %s", r.RemoteAddr)
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<VERSION major="2" minor="0"/>`))
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	bodyStr := string(bodyBytes)

	values, _ := url.ParseQuery(bodyStr)
	username := values.Get("username")
	password := values.Get("password")
	encode := values.Get("encode")

	// Decode Base64 if encode=1
	rawUser, rawPwd := username, password
	if encode == "1" {
		cleanedUser := strings.ReplaceAll(strings.ReplaceAll(username, "\r", ""), "\n", "")
		cleanedPwd := strings.ReplaceAll(strings.ReplaceAll(password, "\r", ""), "\n", "")
		if u, err := base64.StdEncoding.DecodeString(cleanedUser); err == nil {
			rawUser = string(u)
		}
		if p, err := base64.StdEncoding.DecodeString(cleanedPwd); err == nil {
			rawPwd = string(p)
		}
	}

	if s.cfg.Verbose {
		log.Printf("[MockServer] -> POST /vpn/user/auth/password (encode=%s, user=%q, pwd=%q)", encode, rawUser, rawPwd)
	}

	mode := s.GetMode()
	effectiveMode := mode

	// Smart routing by username for multi-flow automation testing
	if strings.Contains(rawUser, "pwd_only") || strings.Contains(rawUser, "only_pwd") {
		effectiveMode = ModePwdOnly
	} else if strings.Contains(rawUser, "expired") || strings.Contains(rawUser, "change") {
		effectiveMode = ModePwdChange
	} else if strings.Contains(rawUser, "wrong") || strings.Contains(rawUser, "error") {
		effectiveMode = ModeErrAuth
	} else if strings.Contains(rawUser, "captcha") || strings.Contains(rawUser, "verify") {
		effectiveMode = ModeVerifyCode
	}

	isExpectedUser := (s.cfg.ExpectedUser == "" || rawUser == s.cfg.ExpectedUser || strings.HasPrefix(rawUser, "user_") || strings.HasPrefix(rawUser, "admin_"))
	isExpectedPwd := (rawPwd == s.cfg.ExpectedPwd || strings.HasPrefix(rawUser, "user_"))

	if effectiveMode == ModeErrAuth || !isExpectedUser || !isExpectedPwd {
		log.Printf("[MockServer] <- Authentication failed for user=%q (code: 0x8000001a)", rawUser)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x8000001a" msg="用户名或密码错误" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	// Reuse the session created by the captcha image (or an earlier auth
	// step). The real gateway binds the captcha code to this cookie; minting
	// a new session here would make every captcha look valid.
	sessionID := ""
	if c, err := r.Cookie("VSG_SESSIONID"); err == nil {
		sessionID = c.Value
	}

	authMethod := "口令认证"
	s.mu.RLock()
	justChanged := time.Since(s.lastChangedTime) < 15*time.Second
	s.mu.RUnlock()

	if effectiveMode == ModeVerifyCode || strings.Contains(rawUser, "captcha") || strings.Contains(rawUser, "verify") {
		authMethod = "验证码认证"
	} else if effectiveMode == ModePwdCert || strings.Contains(rawUser, "cert") {
		authMethod = "双因素认证"
	} else if effectiveMode == ModePwdChange || justChanged || strings.Contains(rawUser, "change") || strings.Contains(rawUser, "expired") {
		authMethod = "改密续连"
	} else {
		authMethod = "口令认证"
	}

	newSession := false
	s.mu.Lock()
	sess, exists := s.sessions[sessionID]
	if !exists || sess == nil {
		sessionID = fmt.Sprintf("mock-vsg-%x", time.Now().UnixNano())
		sess = &Session{ID: sessionID, CreatedAt: time.Now()}
		s.sessions[sessionID] = sess
		newSession = true
	}
	sess.Username = rawUser
	sess.PassedPwd = true
	sess.AuthMethod = authMethod
	s.mu.Unlock()

	if newSession {
		http.SetCookie(w, &http.Cookie{
			Name:     "VSG_SESSIONID",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
		})
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	switch effectiveMode {
	case ModePwdOnly, ModeCertOnly:
		log.Printf("[MockServer] <- Single factor login success for %q (code: 0)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModePwdCert, ModePwdCertSMS:
		log.Printf("[MockServer] <- Two-factor challenge for %q: requesting Certificate (code: 2)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="2" msg="need cert" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModePwdChange:
		log.Printf("[MockServer] <- Password expired challenge for %q (code: 256)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="256" msg="password expired" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModeVerifyCode:
		verifycode := values.Get("verifycode")
		if verifycode == "" {
			log.Printf("[MockServer] <- Verifycode required for %q (code: 0x80)", rawUser)
			w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x80" msg="需要图形验证码" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
			return
		}
		expected := s.getExpectedVerifyCode(sessionID)
		if expected == "" || !strings.EqualFold(strings.TrimSpace(verifycode), expected) {
			log.Printf("[MockServer] <- Verifycode MISMATCH for %q: received %q, expected %q (code: 0x80000021)", rawUser, verifycode, expected)
			s.generateNewVerifyCode(sessionID)
			w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x80000021" msg="图形验证码错误，请重新输入" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
			return
		}
		log.Printf("[MockServer] <- Verifycode %q passed (expected: %q), login success for %q (code: 0)", verifycode, expected, rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModeToken:
		// The challenge is issued together with a token code bound to this
		// session — that stands in for "whatever the user's token displays
		// right now"; the E2E driver reads it via the test-only /api/tokencode.
		tokenCode := s.generateNewTokenCode(sessionID)
		log.Printf("[MockServer] <- Token challenge for %q (code: 4, token now shows %q)", rawUser, tokenCode)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="4" msg="need token" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModeFullChain:
		// The password step is guarded by a captcha first — same semantics as
		// ModeVerifyCode: the code rides the password request as a field, it
		// has no endpoint of its own. Once it passes, the gateway walks the
		// remaining factors: cert -> SMS -> token.
		verifycode := values.Get("verifycode")
		if verifycode == "" {
			log.Printf("[MockServer] <- Verifycode required for %q (code: 0x80)", rawUser)
			w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x80" msg="需要图形验证码" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
			return
		}
		expected := s.getExpectedVerifyCode(sessionID)
		if expected == "" || !strings.EqualFold(strings.TrimSpace(verifycode), expected) {
			log.Printf("[MockServer] <- Verifycode MISMATCH for %q: received %q, expected %q (code: 0x80000021)", rawUser, verifycode, expected)
			s.generateNewVerifyCode(sessionID)
			w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x80000021" msg="图形验证码错误，请重新输入" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
			return
		}
		log.Printf("[MockServer] <- Captcha passed for %q, requesting Certificate (code: 2)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="2" msg="need cert" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	case ModeSMS:
		// msg mirrors the real gateway's challenge text (issue #9 screenshot);
		// SecUI.exe switches to its Edit_SendSMS state on this code.
		log.Printf("[MockServer] <- SMS challenge for %q (code: 8)", rawUser)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="8" msg="多因素认证，短信认证" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`)))
	default:
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
	}
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("VSG_SESSIONID")
	sessionID := ""
	if err == nil {
		sessionID = sessionCookie.Value
	}

	s.mu.RLock()
	sess, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	peerCerts := r.TLS.PeerCertificates
	certDesc := "none"
	var fpStr string
	if len(peerCerts) > 0 {
		cert := peerCerts[0]
		fp := sha1.Sum(cert.Raw)
		fpStr = fmt.Sprintf("%X", fp)
		certDesc = fmt.Sprintf("Subject=%q, CN=%q, SHA1=%s", cert.Subject, cert.Subject.CommonName, fpStr)
	}

	if s.cfg.Verbose {
		log.Printf("[MockServer] -> %s /vpn/user/auth/cert (SessionID=%q, ClientCert=[%s])", r.Method, sessionID, certDesc)
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	if s.GetMode() == ModeErrCert {
		log.Printf("[MockServer] <- ModeErrCert: Certificate validation failed (code: 0x106)")
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x106" msg="证书已过期" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	if s.cfg.RequireCert && len(peerCerts) == 0 {
		log.Printf("[MockServer] <- Error: No client TLS certificate presented (code: 0x8000005b)")
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x8000005b" msg="未提供客户端证书" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	if exists && sess != nil {
		sess.PassedCert = true
		sess.AuthMethod = "双因素认证"
		log.Printf("[MockServer] <- Two-factor certificate auth SUCCESS for %q (code: 0)", sess.Username)
	} else {
		if sessionID == "" {
			sessionID = fmt.Sprintf("mock-cert-sess-%d", time.Now().UnixNano())
			http.SetCookie(w, &http.Cookie{
				Name:     "VSG_SESSIONID",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
			})
			certUserName := "certificate"
			if len(peerCerts) > 0 {
				cert := peerCerts[0]
				if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
					certUserName = cn
				} else {
					certUserName = "client-cert"
				}
			}
			s.mu.Lock()
			s.sessions[sessionID] = &Session{
				ID:         sessionID,
				Username:   certUserName,
				PassedCert: true,
				AuthMethod: "证书认证",
				CreatedAt:  time.Now(),
			}
			s.mu.Unlock()
		}
		log.Printf("[MockServer] <- Standalone certificate auth SUCCESS (SessionID=%q, code: 0)", sessionID)
	}

	// Three-factor chain: the certificate factor passed, but the gateway still
	// wants the SMS factor before it grants the session. The challenge text
	// mirrors the real gateway (issue #9 screenshot). The full-chain mode walks
	// the same hop on its way to the token factor.
	if s.GetMode() == ModePwdCertSMS || s.GetMode() == ModeFullChain {
		log.Printf("[MockServer] <- SMS challenge after certificate factor for session %q (code: 8)", sessionID)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="8" msg="多因素认证，短信认证" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

// handleToken backs POST /vpn/user/auth/token: the client submits the code
// the user's hardware/software token displays. A mismatch answers 0x109 and
// — like the SMS flow — does NOT regenerate the code: the token keeps
// displaying the same digits until its own cycle rolls them, and a mistyped
// retry must not invalidate what the user is looking at. 0x109 itself is an
// inference (the SMS rejection is 0x10A / TAG 266 and the token message sits
// next to it in the original language tables); the real gateway has not been
// captured on a token rejection yet.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	values, _ := url.ParseQuery(string(body))
	token := strings.TrimSpace(values.Get("token"))

	sessionID := ""
	if c, err := r.Cookie("VSG_SESSIONID"); err == nil {
		sessionID = c.Value
	}
	expected := s.getExpectedTokenCode(sessionID)

	log.Printf("[MockServer] -> POST /vpn/user/auth/token (SessionID=%q, token=%q)", sessionID, token)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	if expected == "" || !strings.EqualFold(token, expected) {
		log.Printf("[MockServer] <- Token code MISMATCH for session %q: got %q, expected %q (code: 0x109)", sessionID, token, expected)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x109" msg="动态令牌码错误" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	s.mu.Lock()
	if sess, ok := s.sessions[sessionID]; ok && sess != nil {
		sess.AuthMethod = "动态令牌认证"
	}
	s.mu.Unlock()

	log.Printf("[MockServer] <- Token code %q passed for session %q, login success (code: 0)", token, sessionID)
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

// getExpectedTokenCode returns the token code issued to one session. No
// global fallback: the code another session was challenged with must never
// validate here.
func (s *Server) getExpectedTokenCode(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess, ok := s.sessions[sessionID]; ok && sess != nil {
		return sess.TokenCode
	}
	return ""
}

// generateNewTokenCode issues a fresh 6-digit code, stores it on the session
// and mirrors it into currentTokenCode for the test-only /api/tokencode
// endpoint. It stands in for the user's token display.
func (s *Server) generateNewTokenCode(sessionID string) string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := fmt.Sprintf("%06d", rnd.Intn(1000000))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentTokenCode = code
	if sessionID != "" {
		if sess, ok := s.sessions[sessionID]; ok && sess != nil {
			sess.TokenCode = code
		}
	}
	return code
}

// handleAPITokenCode exposes the last issued token code to the test harness
// (the E2E driver has no token device). Test-only, same shape as /api/smscode.
func (s *Server) handleAPITokenCode(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	code := s.currentTokenCode
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"code":%q}`, code)
}

// handleSendSMS backs GET /vpn/user/auth/send_smc: the client asks the gateway
// to deliver the SMS verification code to the user's registered phone. The
// code is generated here and bound to the requesting session, the way the real
// gateway binds it to the VSG_SESSIONID that received the 0x8 challenge.
func (s *Server) handleSendSMS(w http.ResponseWriter, r *http.Request) {
	sessionID := ""
	if c, err := r.Cookie("VSG_SESSIONID"); err == nil {
		sessionID = c.Value
	}

	code := s.generateNewSMSCode(sessionID)
	log.Printf("[MockServer] <- SMS code delivered for session %q (Code: %q)", sessionID, code)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="ok" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

// handleSMS backs POST /vpn/user/auth/smc: the client submits the code from
// the user's phone. A mismatch answers 0x10A (language.xml TAG 266 短信码
// 错误) and — unlike the captcha flow — does NOT regenerate the code: the
// real gateway already sent that SMS, and a mistyped retry must not
// invalidate what is sitting in the user's inbox.
func (s *Server) handleSMS(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	values, _ := url.ParseQuery(string(body))
	smc := strings.TrimSpace(values.Get("smc"))

	sessionID := ""
	if c, err := r.Cookie("VSG_SESSIONID"); err == nil {
		sessionID = c.Value
	}
	expected := s.getExpectedSMSCode(sessionID)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	if expected == "" || !strings.EqualFold(smc, expected) {
		log.Printf("[MockServer] <- SMS code MISMATCH for session %q: got %q, expected %q (code: 0x10A)", sessionID, smc, expected)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x10A" msg="短信码错误" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	s.mu.Lock()
	if sess, ok := s.sessions[sessionID]; ok && sess != nil {
		sess.AuthMethod = "短信认证"
	}
	s.mu.Unlock()

	// Full chain: the SMS factor passed, but the gateway still wants the
	// dynamic-token factor. Issue a token code bound to this session — the
	// user's token "display" — and challenge with code 4, exactly like the
	// dedicated token mode does on its password step.
	if s.GetMode() == ModeFullChain {
		tokenCode := s.generateNewTokenCode(sessionID)
		log.Printf("[MockServer] <- Token challenge after SMS factor for session %q (code: 4, token now shows %q)", sessionID, tokenCode)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="4" msg="need token" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	log.Printf("[MockServer] <- SMS code %q passed for session %q, login success (code: 0)", smc, sessionID)
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

// getExpectedSMSCode returns the SMS code issued to one session. No global
// fallback: the code another session requested must never validate here.
func (s *Server) getExpectedSMSCode(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess, ok := s.sessions[sessionID]; ok && sess != nil {
		return sess.SMSCode
	}
	return ""
}

// generateNewSMSCode issues a fresh 6-digit code, stores it on the session and
// mirrors it into currentSMSCode for the test-only /api/smscode endpoint.
func (s *Server) generateNewSMSCode(sessionID string) string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := fmt.Sprintf("%06d", rnd.Intn(1000000))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentSMSCode = code
	if sessionID != "" {
		if sess, ok := s.sessions[sessionID]; ok && sess != nil {
			sess.SMSCode = code
		}
	}
	return code
}

// handleAPISMCode exposes the last issued SMS code to the test harness (the
// E2E driver has no access to the phone the mock "texted"). Test-only, same
// shape as /api/verifycode.
func (s *Server) handleAPISMCode(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	code := s.currentSMSCode
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"code":%q}`, code)
}

func (s *Server) handlePwdChange(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("[MockServer] -> POST /vpn/user/auth/pwdchange: %s", string(body))
	values, _ := url.ParseQuery(string(body))
	newPwd := values.Get("new_pwd")
	s.mu.Lock()
	s.lastChangedTime = time.Now()
	if newPwd != "" {
		s.cfg.ExpectedPwd = newPwd
		log.Printf("[MockServer] Expected password updated to: %q", newPwd)
	}
	sessionCookie, _ := r.Cookie("VSG_SESSIONID")
	if sessionCookie != nil {
		if sess, ok := s.sessions[sessionCookie.Value]; ok && sess != nil {
			sess.AuthMethod = "改密续连"
		}
	}
	s.mu.Unlock()
	if s.GetMode() == ModePwdChange {
		s.SetMode(ModePwdOnly)
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="密码修改成功" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

func (s *Server) handleIntegration(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Verbose {
		log.Printf("[MockServer] -> GET /vpn/user/portal/intergration.xml (query: %s)", r.URL.RawQuery)
	}
	sessionCookie, _ := r.Cookie("VSG_SESSIONID")
	sid := "mock-session"
	username := s.cfg.ExpectedUser
	authMethod := ""

	if sessionCookie != nil {
		sid = sessionCookie.Value
		s.mu.RLock()
		if sess, ok := s.sessions[sid]; ok && sess != nil {
			if sess.Username != "" {
				username = sess.Username
			}
			authMethod = sess.AuthMethod
			if authMethod == "" {
				if sess.PassedCert && sess.PassedPwd {
					authMethod = "双因素认证"
				} else if sess.PassedCert {
					authMethod = "证书认证"
				} else {
					authMethod = "口令认证"
				}
			}
		}
		s.mu.RUnlock()
	}

	if authMethod == "" {
		switch s.GetMode() {
		case ModeCertOnly:
			authMethod = "证书认证"
		case ModePwdCert:
			authMethod = "双因素认证"
		case ModePwdCertSMS:
			authMethod = "多因素认证"
		case ModeFullChain:
			authMethod = "多因素认证"
		case ModeVerifyCode:
			authMethod = "验证码认证"
		case ModePwdChange:
			authMethod = "改密续连"
		case ModeSMS:
			authMethod = "短信认证"
		case ModeToken:
			authMethod = "动态令牌认证"
		default:
			authMethod = "口令认证"
		}
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<INTERGRATION_INFO>
  <VERSION major="2" minor="0"/>
  <USER name="%s" group="网络与数据安全研发中心" type="user" access_type="1" logout_policy="0" pwd_overtime="45"/>
  <SESSION sid_name="VSG_SESSIONID" id="%s" detect_interval="60" login-addr="127.0.0.1" login-time="2026-10-22 11:00:00"/>
  <GATEWAY version="5.3.3.32"/>
  <RESOURCE_LIST>%s
  </RESOURCE_LIST>
  <DNS_INFO>
    <DOMAIN_HOST dnssrv="10.8.0.2;10.8.0.3" dnssrv_v6=""/>
  </DNS_INFO>
</INTERGRATION_INFO>`, html.EscapeString(username), sid, s.resourceListXML())
}

// resourceListXML renders the portal RESOURCE_LIST fixture. The default is
// the three TCP/UDP proxy resources; NCMode appends or swaps in an NC (IPsec)
// profile so NC-aware code paths can be exercised end to end.
func (s *Server) resourceListXML() string {
	const tcpudp = `
    <TCPUDP_RESOURCE name="内网OA协同办公" protocol="tcp" mapid="1" port="8080" status="1" istcp="1">
      <TCPUDP_IP addr="10.8.0.10-10.8.0.10"/>
    </TCPUDP_RESOURCE>
    <TCPUDP_RESOURCE name="研发代码仓库 (GitLab)" protocol="tcp" mapid="2" port="443" status="1" istcp="1">
      <TCPUDP_IP addr="10.8.0.20-10.8.0.20"/>
    </TCPUDP_RESOURCE>
    <TCPUDP_RESOURCE name="核心运维堡垒机 (SSH/RDP)" protocol="tcp" mapid="3" port="22" status="1" istcp="1">
      <TCPUDP_IP addr="10.8.0.30-10.8.0.30"/>
    </TCPUDP_RESOURCE>`

	switch s.cfg.NCMode {
	case NCModeMixed:
		return tcpudp + ncResourceXML
	case NCModeOnly:
		return ncResourceXML
	default:
		return tcpudp
	}
}

// ncResourceXML mirrors the shape real gateways send for <NC_RESOURCE>
// (docs/ipsec.md §1): IKEv1 main mode + PSK, a session virtual IP and one
// tunnel with secured routes. Addresses are TEST-NET (RFC 5737) so nothing
// here can ever route anywhere real; the PSK is an obvious fixture value.
const ncResourceXML = `
    <NC_RESOURCE name="nc">
      <IKE version="v1">
        <SERVER ip="198.51.100.10" port="1194" id-type="ipv4" id="198.51.100.10"/>
        <CLIENT port="1194" id-type="key_id" id="mock-nc-session"/>
        <Exchange mode="main"/>
        <PSK key="mock-psk-fixture"/>
      </IKE>
      <PRIVATE-IP ip="10.70.0.5" subnet="255.255.255.255"/>
      <TUNNEL tunnel-name="Mock 办公网" mapid="198.51.100.10" status="1">
        <EXTENSIONS>
          <SECURED-ROUTE><ROUTE addr="198.51.100.0/24"/></SECURED-ROUTE>
          <SECURED-ROUTES><ROUTE addr="203.0.113.0/24"/></SECURED-ROUTES>
        </EXTENSIONS>
      </TUNNEL>
    </NC_RESOURCE>`

func (s *Server) handleRuleXML(w http.ResponseWriter, r *http.Request) {
	log.Printf("[MockServer] -> GET /vpn/user/check/rule.xml")
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RULE_LIST>
  <RULE id="1" name="防病毒软件实时防护检测" type="antivirus" enable="1" action="warn"/>
  <RULE id="2" name="操作系统安全补丁与合规基线" type="patch" enable="1" action="allow"/>
  <RULE id="3" name="主机防火墙开启状态检测" type="firewall" enable="1" action="warn"/>
</RULE_LIST>`))
}

func (s *Server) handleSSOConfigXML(w http.ResponseWriter, r *http.Request) {
	log.Printf("[MockServer] -> GET /vpn/user/common/SSOConfig.xml")
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<SSO_CONFIG>
  <APP id="101" name="内网统一协同办公系统" type="web" url="http://oa.internal:8080" auto_login="1"/>
  <APP id="102" name="GitLab企业代码仓库" type="web" url="https://git.internal" auto_login="1"/>
  <APP id="103" name="企业云盘与知识库系统" type="web" url="http://wiki.internal:9000" auto_login="0"/>
</SSO_CONFIG>`))
}

func (s *Server) handleInstallXML(w http.ResponseWriter, r *http.Request) {
	log.Printf("[MockServer] -> GET /vpn/user/client/install.xml")
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<CLIENT_INFO>
  <VERSION major="5" minor="3" build="32"/>
  <MIN_VERSION major="5" minor="0" build="0"/>
  <RELEASE_DATE>2026-08-18</RELEASE_DATE>
  <DESCRIPTION>网御星云安全接入客户端 V5.3 标准版</DESCRIPTION>
</CLIENT_INFO>`))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Verbose {
		log.Printf("[MockServer] -> POST /vpn/user/logout")
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="logged out" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

var font5x7 = map[rune][7]uint8{
	'0': {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E},
	'1': {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E},
	'2': {0x0E, 0x11, 0x01, 0x06, 0x08, 0x10, 0x1F},
	'3': {0x1F, 0x02, 0x04, 0x06, 0x01, 0x11, 0x0E},
	'4': {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02},
	'5': {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E},
	'6': {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E},
	'7': {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
	'8': {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E},
	'9': {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C},
	'A': {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	'B': {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},
	'C': {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E},
	'D': {0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C},
	'E': {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F},
	'F': {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10},
	'G': {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F},
	'H': {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	'J': {0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x0E},
	'K': {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},
	'L': {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F},
	'M': {0x11, 0x1B, 0x15, 0x11, 0x11, 0x11, 0x11},
	'N': {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11},
	'P': {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10},
	'R': {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},
	'S': {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E},
	'T': {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
	'U': {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
	'V': {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04},
	'W': {0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11},
	'X': {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11},
	'Y': {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04},
	'Z': {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F},
}

// getExpectedVerifyCode returns the code issued to one session. There is no
// global fallback: a code fetched by another client must never validate here,
// otherwise the mock cannot catch a client that drops the captcha cookie jar.
func (s *Server) getExpectedVerifyCode(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess, ok := s.sessions[sessionID]; ok && sess != nil {
		return sess.VerifyCode
	}
	return ""
}

func (s *Server) generateNewVerifyCode(sessionID string) string {
	chars := []rune("23456789ABCDEFGHJKLMNPRSTUVWXYZ")
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := make([]rune, 4)
	for i := range code {
		code[i] = chars[rnd.Intn(len(chars))]
	}
	codeStr := string(code)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentVerifyCode = codeStr
	if sessionID != "" {
		if sess, ok := s.sessions[sessionID]; ok && sess != nil {
			sess.VerifyCode = codeStr
		}
	}
	return codeStr
}

func (s *Server) generateCaptchaImageBytes(code string) ([]byte, error) {
	width, height := 130, 42
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Pastel background
	bgR := uint8(240 + r.Intn(16))
	bgG := uint8(240 + r.Intn(16))
	bgB := uint8(240 + r.Intn(16))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{bgR, bgG, bgB, 255})
		}
	}

	// Random noise dots
	for i := 0; i < 60; i++ {
		img.Set(r.Intn(width), r.Intn(height), color.RGBA{uint8(r.Intn(200)), uint8(r.Intn(200)), uint8(r.Intn(200)), 200})
	}

	// Draw characters
	charColors := []color.RGBA{
		{26, 82, 118, 255}, // Blue
		{146, 43, 33, 255}, // Red
		{20, 90, 50, 255},  // Green
		{110, 44, 0, 255},  // Brown
		{74, 35, 90, 255},  // Purple
	}

	scale := 3
	charW := 5 * scale
	charH := 7 * scale
	n := len(code)
	spacing := (width - n*charW) / (n + 1)
	if spacing < 4 {
		spacing = 4
	}

	for idx, ch := range code {
		grid, ok := font5x7[ch]
		if !ok {
			grid = font5x7['8']
		}
		charCol := charColors[r.Intn(len(charColors))]
		startX := spacing + idx*(charW+spacing)
		startY := (height-charH)/2 + r.Intn(7) - 3
		if startY < 2 {
			startY = 2
		}
		if startY+charH >= height {
			startY = height - charH - 2
		}

		for row := 0; row < 7; row++ {
			bits := grid[row]
			for col := 0; col < 5; col++ {
				if (bits>>(4-col))&1 == 1 {
					for py := 0; py < scale; py++ {
						for px := 0; px < scale; px++ {
							x := startX + col*scale + px
							y := startY + row*scale + py
							if x >= 0 && x < width && y >= 0 && y < height {
								img.Set(x, y, charCol)
							}
						}
					}
				}
			}
		}
	}

	// Wave interference lines
	for l := 0; l < 2; l++ {
		lineCol := color.RGBA{uint8(r.Intn(180)), uint8(r.Intn(180)), uint8(r.Intn(180)), 220}
		freq := 0.05 + r.Float64()*0.05
		phase := r.Float64() * math.Pi * 2
		amp := 4.0 + r.Float64()*5.0
		baseY := float64(height)/2.0 + float64(r.Intn(height/2)-height/4)

		for x := 0; x < width; x++ {
			y := int(baseY + math.Sin(float64(x)*freq+phase)*amp)
			if y >= 0 && y < height {
				img.Set(x, y, lineCol)
				if y+1 < height {
					img.Set(x, y+1, lineCol)
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("VSG_SESSIONID")
	sessionID := ""
	if err == nil {
		sessionID = sessionCookie.Value
	}

	if r.Method == http.MethodGet {
		// Ensure the session exists, even when the caller presents a stale
		// cookie; the code is stored on this session and checked on login.
		newSession := false
		s.mu.Lock()
		if sessionID == "" {
			sessionID = fmt.Sprintf("mock-vc-sess-%d", time.Now().UnixNano())
			newSession = true
		}
		if sess, ok := s.sessions[sessionID]; !ok || sess == nil {
			s.sessions[sessionID] = &Session{
				ID:        sessionID,
				CreatedAt: time.Now(),
			}
			newSession = true
		}
		s.mu.Unlock()
		if newSession {
			http.SetCookie(w, &http.Cookie{
				Name:     "VSG_SESSIONID",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
			})
		}

		code := s.generateNewVerifyCode(sessionID)
		log.Printf("[MockServer] <- Generating random captcha image for session %q (Code: %q)", sessionID, code)
		imgBytes, err := s.generateCaptchaImageBytes(code)
		if err != nil {
			http.Error(w, "captcha generation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write(imgBytes)
		return
	}

	// POST /vpn/user/auth/verifycode
	body, _ := io.ReadAll(r.Body)
	values, _ := url.ParseQuery(string(body))
	vc := values.Get("verifycode")
	expected := s.getExpectedVerifyCode(sessionID)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	if expected == "" || !strings.EqualFold(strings.TrimSpace(vc), expected) {
		log.Printf("[MockServer] POST /vpn/user/auth/verifycode MISMATCH: got %q, expected %q", vc, expected)
		s.generateNewVerifyCode(sessionID)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0x80000021" msg="图形验证码错误，请重新输入" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
		return
	}

	log.Printf("[MockServer] POST /vpn/user/auth/verifycode SUCCESS: %q", vc)
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT code="0" msg="" sid_name="VSG_SESSIONID"></RESULT></RESPONSE>`))
}

func (s *Server) handleVerifyCodeStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("[MockServer] -> GET /vpn/user/auth/verifycode_status")
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<RESPONSE><RESULT status="1" len="4" url="/vpn/user/auth/verifycode"></RESULT></RESPONSE>`))
}

func (s *Server) handleAPIVerifyCode(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	code := s.currentVerifyCode
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"code":%q}`, code)
}
