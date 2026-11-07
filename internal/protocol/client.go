package protocol

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// resourceFetchTimeout bounds one portal integration request. Some gateways
	// compute the resource list lazily and answer slowly on the first call; a
	// timeout is reported as a ResourceFetchError and retried rather than
	// treated as a login failure, because the session cookie is already valid.
	resourceFetchTimeout = 30 * time.Second
	// defaultHeartbeatInterval is used until the gateway reports detect_interval.
	defaultHeartbeatInterval = 180 * time.Second
	// apiTimeout bounds the lightweight handshake/auth requests.
	apiTimeout = 30 * time.Second
)

// ResourceFetchError reports that authentication succeeded but the portal
// resource list could not be retrieved. The session cookie is valid, so the
// caller may enter the connected view with an empty list and retry later.
type ResourceFetchError struct {
	Err error
}

func (e *ResourceFetchError) Error() string {
	return fmt.Sprintf("认证成功，但获取内网资源失败: %v", e.Err)
}

func (e *ResourceFetchError) Unwrap() error { return e.Err }

// IsResourceFetchError reports whether err means "logged in, resources missing".
func IsResourceFetchError(err error) bool {
	var fetchErr *ResourceFetchError
	return errors.As(err, &fetchErr)
}

// Client handles network interaction with V5VPN Gateway
type Client struct {
	BaseURL       string
	GatewayIP     string
	GatewayPort   int
	Algo          int
	HTTPClient    *http.Client
	SessionID     string
	SessionCookie string
	Integration   *IntegrationInfo
	Logger        func(level string, format string, args ...any)
	stopHeartbeat chan struct{}
	mu            sync.Mutex
	isLoggedIn    bool
	// lastAuthMsg 保存最近一次认证成功响应里的网关提示（常为口令到期文案）。
	lastAuthMsg   string
	tlsClientCert *tls.Certificate
}

// NewClient creates a new V5VPN gateway protocol client
func NewClient(ip string, port int, algo int, logger func(string, string, ...any)) *Client {
	if logger == nil {
		logger = func(level string, format string, args ...any) {
			// default noop
		}
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 6 * time.Second,
		TLSClientConfig:     GatewayTLSConfig(),
		DisableKeepAlives:   true,
	}

	httpClient := &http.Client{
		Transport: &cookieFixTransport{base: tr},
		Jar:       jar,
		Timeout:   apiTimeout,
	}

	baseURL := fmt.Sprintf("https://%s:%d", ip, port)

	return &Client{
		BaseURL:       baseURL,
		GatewayIP:     ip,
		GatewayPort:   port,
		Algo:          algo,
		HTTPClient:    httpClient,
		Logger:        logger,
		stopHeartbeat: make(chan struct{}),
	}
}

// Handshake checks gateway version via /vpn/version.xml
// Handshake checks gateway version via /vpn/version.xml
//
// 网关链路存在短时抖动：TCP 能建连，但 TLS 握手被重置或超时，几十秒后自愈。
// 这种瞬时故障不应让整次登录失败，因此失败后自动重试一次。
func (c *Client) Handshake() (*VersionResponse, error) {
	u := fmt.Sprintf("%s/vpn/version.xml", c.BaseURL)
	c.Logger("INFO", "Connecting to gateway: %s", u)

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		resp, err := c.HTTPClient.Get(u)
		if err != nil {
			lastErr = err
			if attempt == 1 && !isContextCancelled(err) {
				c.Logger("WARN", "握手失败（第 1 次）: %v，500ms 后重试", err)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			break
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			break
		}

		var v VersionResponse
		if err := xml.Unmarshal(body, &v); err != nil {
			c.Logger("WARN", "Failed to parse version.xml: %s, fallback to default", string(body))
			return &VersionResponse{Major: "2", Minor: "0"}, nil
		}

		c.Logger("SUCCESS", "Gateway handshake OK. Version %s.%s", v.Major, v.Minor)
		return &v, nil
	}

	c.Logger("ERROR", "Handshake failed: %v", lastErr)
	return nil, fmt.Errorf("gateway handshake failed: %w", lastErr)
}

// isContextCancelled 判断是否由调用方主动取消，这类错误重试没有意义。
func isContextCancelled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// Login authenticates the user with the gateway (Base64 credentials, encode=1) and then loads the portal integration info.
func (c *Client) Login(username, password, verifycode string) (*IntegrationInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authenticate(username, password, verifycode)
}

// ChangePassword submits the old and new passwords to /vpn/user/auth/pwdchange.
// The original client posts both as UTF-8 plaintext with no encode parameter.
func (c *Client) ChangePassword(username, oldPassword, newPassword, verifycode string) error {
	if strings.TrimSpace(newPassword) == "" {
		return fmt.Errorf("新密码不能为空")
	}
	if newPassword == oldPassword {
		return fmt.Errorf("新密码不能与当前密码相同")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.Logger("INFO", "Submitting password change for user: %s", username)

	// The 0x100 login challenge may have set VSG_SESSIONID. Refresh it from
	// the jar so the change request carries the same session as the original
	// client.
	c.captureSession()

	// 明文提交是原厂的默认形态；部分网关的 pwdchange 与登录一样按
	// Base64 + encode=1 解析，此时会回「原密码错误」。被拒后换编码重试一次。
	err := c.submitPasswordChange(passwordChangeBody(oldPassword, newPassword))
	if err != nil && isPasswordMismatch(err) {
		c.Logger("WARN", "改密被网关判为原密码错误（%v），改用 Base64 + encode=1 重试", err)
		err = c.submitPasswordChange(passwordChangeBodyEncoded(oldPassword, newPassword))
	}
	if err != nil {
		return err
	}

	c.captureSession()
	c.Logger("SUCCESS", "Password changed successfully for user: %s", username)
	return nil
}

// submitPasswordChange posts one password-change body and parses the RESULT.
func (c *Client) submitPasswordChange(changeBody string) error {
	changeURL := fmt.Sprintf("%s/vpn/user/auth/pwdchange", c.BaseURL)

	req, err := http.NewRequest(http.MethodPost, changeURL, strings.NewReader(changeBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "LeadSec VPN Client")
	// A non-nil jar attaches VSG_SESSIONID itself; setting the header too
	// would make Go send the same cookie twice.
	if c.HTTPClient.Jar == nil && c.SessionCookie != "" {
		req.Header.Set("Cookie", c.SessionCookie)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		c.Logger("ERROR", "Password change request failed: %v", err)
		return fmt.Errorf("修改密码网络请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("读取修改密码响应失败: %w", readErr)
	}
	respBody = prepareGatewayXML(respBody)
	c.Logger("INFO", "Password change response status: %s", resp.Status)

	var authResp AuthResponse
	parseErr := xml.Unmarshal(respBody, &authResp)
	if parseErr != nil {
		c.Logger("WARN", "Password change response was not XML: %s", string(respBody))
	}
	resultCode := strings.TrimSpace(authResp.Result.Code)

	// A gateway error is authoritative even when it arrives with a non-200
	// status, so surface it before the HTTP status check.
	if parseErr == nil && resultCode != "" && !isSuccessCode(resultCode) {
		authErr := newAuthError(resultCode, authResp.Result.Msg)
		c.Logger("ERROR", "Gateway rejected password change: %s", authErr.Error())
		return authErr
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("password change failed with HTTP status %d: %s", resp.StatusCode, string(respBody))
	}
	if parseErr != nil {
		return fmt.Errorf("修改密码响应无法解析: %w", parseErr)
	}
	if resultCode == "" {
		return fmt.Errorf("修改密码响应缺少结果码，无法确认修改成功")
	}
	return nil
}

// isPasswordMismatch 判断网关是否把 old_pwd 判成了错误（可换编码重试）。
func isPasswordMismatch(err error) bool {
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		return false
	}
	if authErr.Kind == AuthKindBadCredentials {
		return true
	}
	return strings.Contains(authErr.Msg, "原密码") ||
		strings.Contains(authErr.Msg, "旧密码") ||
		strings.Contains(authErr.Msg, "密码错误")
}

// AuthPassword verifies the user credentials against /vpn/user/auth/password
// and captures the session cookie without fetching integration resources.
func (c *Client) AuthPassword(username, password, verifycode string) (*AuthResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authPasswordLocked(username, password, verifycode)
}

func (c *Client) authPasswordLocked(username, password, verifycode string) (*AuthResponse, error) {
	c.Logger("INFO", "Initiating password authentication for user: %s", username)

	// The shipped Windows client submits both fields standard-Base64 encoded
	// with encode=1 (SecLogin.dll exposes no AES encrypt on this path and the
	// string "encode=2" occurs nowhere in its binaries). The body is raw
	// concatenation without URL-escaping.
	authBody := passwordAuthBody(base64AuthParam(username), base64AuthParam(password), verifycode)

	authResp, respBody, statusCode, err := c.postAuth(authBody)
	if err != nil {
		return nil, err
	}

	c.captureSession()

	if authResp.Result.Code != "" && !isSuccessCode(authResp.Result.Code) {
		authErr := newAuthError(authResp.Result.Code, authResp.Result.Msg)
		c.Logger("ERROR", "Gateway authentication failed: %s", authErr.Error())
		return &authResp, authErr
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed with HTTP status %d: %s", statusCode, string(respBody))
	}

	if c.SessionID == "" {
		c.Logger("ERROR", "No valid Session ID received from gateway. Response: %s", string(respBody))
		return nil, fmt.Errorf("登录未下发有效会话ID (可能凭证错误或需要图形验证码)")
	}

	// 成功响应的 msg 常带口令有效期提示（如「密码还有 X 天过期」），
	// 原厂客户端会把它展示给用户；保留下来供服务层展示。
	if msg := strings.TrimSpace(authResp.Result.Msg); msg != "" {
		c.lastAuthMsg = msg
		c.Logger("INFO", "网关提示: %s", msg)
	}

	return &authResp, nil
}

// authenticate posts /vpn/user/auth/password for login authentication. Caller holds c.mu.
//
// Authentication and resource retrieval are separate steps: a successful
// authentication is recorded even when the portal resource list cannot be
// fetched, so the caller can show the connected view with an empty list and
// retry with RefreshResources.
func (c *Client) authenticate(username, password, verifycode string) (*IntegrationInfo, error) {
	if _, err := c.authPasswordLocked(username, password, verifycode); err != nil {
		return nil, err
	}

	c.markLoggedInLocked()

	integration, err := c.fetchIntegrationInfo()
	if err != nil {
		c.Logger("ERROR", "Fetch integration info failed: %v", err)
		return nil, &ResourceFetchError{Err: err}
	}

	c.applyIntegrationLocked(integration)
	c.Logger("SUCCESS", "Login successful! User: %s, Assigned resources: %d",
		integration.User.Name, len(integration.ResourceList.TCPUDPResources))
	return integration, nil
}

// AuthOnly performs password authentication and marks the session as logged in
// without waiting for the resource list. It exists so the caller can show the
// connected view immediately and load resources asynchronously.
func (c *Client) AuthOnly(username, password, verifycode string) (*AuthResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.authPasswordLocked(username, password, verifycode)
	if err != nil {
		return resp, err
	}
	c.markLoggedInLocked()
	return resp, nil
}

// AuthSMC submits the SMS verification code on /vpn/user/auth/smc and marks
// the session logged in. It completes a login the gateway challenged with the
// SMS factor (RESULT code 0x8), so it must run on the same client that
// received the challenge: the gateway binds the code to the VSG_SESSIONID
// cookie issued with that response. A wrong code (0x10A) leaves the challenge
// live, so the caller may ask the user to re-enter it.
func (c *Client) AuthSMC(code string) (*AuthResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Logger("INFO", "Submitting SMS verification code")

	authResp, respBody, statusCode, err := c.postAuthForm("/vpn/user/auth/smc", smsAuthBody(code))
	if err != nil {
		return nil, err
	}

	c.captureSession()

	if authResp.Result.Code != "" && !isSuccessCode(authResp.Result.Code) {
		authErr := newAuthError(authResp.Result.Code, authResp.Result.Msg)
		c.Logger("ERROR", "Gateway rejected the SMS code: %s", authErr.Error())
		return &authResp, authErr
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("sms auth failed with HTTP status %d: %s", statusCode, string(respBody))
	}

	if c.SessionID == "" {
		c.Logger("ERROR", "No valid Session ID received after SMS auth. Response: %s", string(respBody))
		return nil, fmt.Errorf("短信认证未下发有效会话ID")
	}

	c.markLoggedInLocked()
	return &authResp, nil
}

// AuthToken submits the dynamic-token (OTP) code on /vpn/user/auth/token and
// marks the session logged in. It completes a login the gateway challenged
// with the token factor (RESULT code 0x4), so it must run on the same client
// that received the challenge: the gateway binds the code to the VSG_SESSIONID
// cookie issued with that response. A wrong code leaves the challenge live,
// so the caller may ask the user to re-enter it.
func (c *Client) AuthToken(code string) (*AuthResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Logger("INFO", "Submitting dynamic token code")

	authResp, respBody, statusCode, err := c.postAuthForm("/vpn/user/auth/token", tokenAuthBody(code))
	if err != nil {
		return nil, err
	}

	c.captureSession()

	if authResp.Result.Code != "" && !isSuccessCode(authResp.Result.Code) {
		authErr := newAuthError(authResp.Result.Code, authResp.Result.Msg)
		c.Logger("ERROR", "Gateway rejected the token code: %s", authErr.Error())
		return &authResp, authErr
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("token auth failed with HTTP status %d: %s", statusCode, string(respBody))
	}

	if c.SessionID == "" {
		c.Logger("ERROR", "No valid Session ID received after token auth. Response: %s", string(respBody))
		return nil, fmt.Errorf("动态令牌认证未下发有效会话ID")
	}

	c.markLoggedInLocked()
	return &authResp, nil
}

// SendSMC asks the gateway to deliver the SMS verification code to the user's
// registered phone. The original client binds it to the "发送短信" button
// (SecLogin.dll vtable slot 12: GET /vpn/user/auth/send_smc, no body); the
// gateway answers RESULT code 0 once the message is queued. Rejections — for
// instance a user with no phone number on file — arrive as ordinary RESULT
// codes and surface as AuthError.
func (c *Client) SendSMC() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sendURL := fmt.Sprintf("%s/vpn/user/auth/send_smc", c.BaseURL)
	req, err := http.NewRequest(http.MethodGet, sendURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	c.Logger("INFO", "Requesting the gateway to send the SMS verification code")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		c.Logger("ERROR", "Send SMS request failed: %v", err)
		return fmt.Errorf("发送短信请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("读取发送短信响应失败: %w", readErr)
	}
	respBody = prepareGatewayXML(respBody)

	var authResp AuthResponse
	parseErr := xml.Unmarshal(respBody, &authResp)
	if parseErr != nil {
		c.Logger("WARN", "Send SMS response was not XML: %s", string(respBody))
	}
	resultCode := strings.TrimSpace(authResp.Result.Code)

	// A gateway error is authoritative even when it arrives with a non-200
	// status, so surface it before the HTTP status check.
	if parseErr == nil && resultCode != "" && !isSuccessCode(resultCode) {
		authErr := newAuthError(resultCode, authResp.Result.Msg)
		c.Logger("ERROR", "Gateway refused SMS delivery: %s", authErr.Error())
		return authErr
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("send sms failed with HTTP status %d: %s", resp.StatusCode, string(respBody))
	}
	if parseErr != nil {
		return fmt.Errorf("发送短信响应无法解析: %w", parseErr)
	}
	if resultCode == "" {
		return fmt.Errorf("发送短信响应缺少结果码，无法确认已发送")
	}

	c.Logger("SUCCESS", "Gateway accepted the SMS delivery request")
	return nil
}

// AuthPasswordWithCert performs the two-factor "password + certificate" login
// the way the original client drives it. SecUI.exe submits the password first
// on a connection that presents no client certificate; only when the
// gateway's RESULT code asks for the certificate factor does it submit the
// certificate on /vpn/user/auth/cert, reusing the session cookie from the
// password step. The certificate request carries no body — the certificate
// itself travels in the TLS handshake.
//
// On success the response's CertFactorUsed reports whether the gateway
// actually asked for the certificate. A gateway that accepts the password
// alone leaves it false, so the caller must not record the session as
// two-factor.
func (c *Client) AuthPasswordWithCert(cert *tls.Certificate, username, password, verifycode string) (*AuthResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Step 1: password only. The original password request sets no
	// CURLOPT_SSLCERT, so no client certificate goes out here.
	resp, err := c.authPasswordLocked(username, password, verifycode)
	if err == nil {
		// The gateway accepted the session without requesting a second
		// factor; submit nothing further. Keep the certificate installed for
		// the tunnel connections.
		if cert != nil {
			c.installClientCertLocked(cert)
		}
		c.markLoggedInLocked()
		return resp, nil
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) || nextAuthStep(authErr.Code) != AuthStepCertificate {
		return resp, err
	}

	// Step 2: the gateway asked for the certificate factor.
	c.Logger("INFO", "Password step accepted; submitting the client certificate")
	if cert != nil {
		c.installClientCertLocked(cert)
	}
	// The certificate factor was requested and presented. A challenge that
	// follows on the certificate step (for instance the SMS factor) must
	// still report the certificate as part of the chain.
	resp.CertFactorUsed = true
	certResp, err := c.certAuthLocked(verifycode)
	if err != nil {
		return resp, err
	}
	certResp.CertFactorUsed = true
	c.markLoggedInLocked()
	return certResp, nil
}

// AuthCertOnly performs certificate authentication and marks the session as
// logged in without waiting for the resource list.
func (c *Client) AuthCertOnly(cert *tls.Certificate, verifycode string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert != nil {
		c.installClientCertLocked(cert)
	}
	if _, err := c.certAuthLocked(verifycode); err != nil {
		return err
	}
	c.markLoggedInLocked()
	return nil
}

// installClientCertLocked wires the certificate into the HTTP transport.
// Caller holds c.mu.
func (c *Client) installClientCertLocked(cert *tls.Certificate) {
	c.tlsClientCert = cert
	tr := transportOf(c.HTTPClient.Transport)
	if tr != nil && tr.TLSClientConfig != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
		// The original client never reuses a connection across auth steps
		// (every SecLogin.dll request is a fresh curl easy handle), so the
		// certificate step always handshakes anew. Idle connections pooled
		// before the certificate was installed would be reused without one,
		// dropping the mTLS factor silently; close them so the next request
		// dials a connection that presents the certificate.
		tr.CloseIdleConnections()
	}
}

// markLoggedInLocked starts the heartbeat without waiting for the resource
// list, so an unreachable portal does not leave the session unauthenticated.
// Caller holds c.mu.
func (c *Client) markLoggedInLocked() {
	c.isLoggedIn = true
	interval := defaultHeartbeatInterval
	if c.Integration != nil && c.Integration.Session.DetectInterval > 0 {
		interval = time.Duration(c.Integration.Session.DetectInterval) * time.Second
	}
	c.startHeartbeatLoop(interval)
}

// applyIntegrationLocked stores a fetched resource list. Caller holds c.mu.
func (c *Client) applyIntegrationLocked(integration *IntegrationInfo) {
	c.Integration = integration
}

// FetchIntegration retrieves the portal resource list for the authenticated
// session and stores it. It is the explicit, retryable half of the login flow.
func (c *Client) FetchIntegration() (*IntegrationInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isLoggedIn || c.SessionID == "" {
		return nil, fmt.Errorf("当前没有有效会话，请重新登录")
	}
	integration, err := c.fetchIntegrationInfo()
	if err != nil {
		return nil, &ResourceFetchError{Err: err}
	}
	c.applyIntegrationLocked(integration)
	return integration, nil
}

// RefreshResources re-fetches the portal resource list for an authenticated
// client. It is used by the UI's "retry" action after a login that
// authenticated but could not load resources.
func (c *Client) RefreshResources() (*IntegrationInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isLoggedIn || c.SessionID == "" {
		return nil, fmt.Errorf("当前没有有效会话，请重新登录")
	}
	integration, err := c.fetchIntegrationInfo()
	if err != nil {
		return nil, &ResourceFetchError{Err: err}
	}
	c.applyIntegrationLocked(integration)
	// The gateway may report a different keepalive interval once resources load.
	c.restartHeartbeatLocked(integration)
	return integration, nil
}

// restartHeartbeatLocked swaps the heartbeat interval to the gateway's
// reported value. Caller holds c.mu.
func (c *Client) restartHeartbeatLocked(integration *IntegrationInfo) {
	if integration == nil || integration.Session.DetectInterval <= 0 {
		return
	}
	interval := time.Duration(integration.Session.DetectInterval) * time.Second
	select {
	case c.stopHeartbeat <- struct{}{}:
	default:
	}
	c.startHeartbeatLoop(interval)
}

func (c *Client) postAuth(authBody string) (AuthResponse, []byte, int, error) {
	return c.postAuthForm("/vpn/user/auth/password", authBody)
}

// postAuthForm posts one application/x-www-form-urlencoded auth request and
// parses the gateway's <RESPONSE><RESULT> envelope. It backs the password and
// the SMS-code submissions, which share the request shape.
func (c *Client) postAuthForm(path, authBody string) (AuthResponse, []byte, int, error) {
	authURL := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequest(http.MethodPost, authURL, strings.NewReader(authBody))
	if err != nil {
		return AuthResponse{}, nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		c.Logger("ERROR", "Auth request failed: %v", err)
		// A gateway enforcing "password + certificate", or one that only
		// accepts requests over mutual TLS, aborts the handshake when the
		// request carries no client certificate; name that cause instead of
		// leaving a bare TLS alert, which reads like a network outage.
		if isCertificateHandshakeError(err) {
			return AuthResponse{}, nil, 0, fmt.Errorf("auth request network error: %w (网关可能要求口令 + 证书双因子认证，请选择证书后重试)", err)
		}
		return AuthResponse{}, nil, 0, fmt.Errorf("auth request network error: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	respBody = prepareGatewayXML(respBody)
	c.Logger("INFO", "Auth response status: %s", resp.Status)

	var authResp AuthResponse
	if err := xml.Unmarshal(respBody, &authResp); err != nil {
		c.Logger("WARN", "Auth response was not XML: %s", string(respBody))
	}
	return authResp, respBody, resp.StatusCode, nil
}

// isCertificateHandshakeError reports whether a request failed because the TLS
// handshake was rejected over client certificates. A gateway enforcing a
// "password + certificate" policy answers without one by tearing the handshake
// down, which surfaces as "tls: certificate required" (or a bad-certificate
// alert) and would otherwise look like an unreachable gateway.
func isCertificateHandshakeError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"certificate required",
		"bad certificate",
		"unknown certificate",
		"unsupported certificate",
		"certificate expired",
		"certificate revoked",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func (c *Client) captureSession() {
	u, err := url.Parse(c.BaseURL)
	if err != nil || c.HTTPClient.Jar == nil {
		return
	}
	for _, cookie := range c.HTTPClient.Jar.Cookies(u) {
		if strings.EqualFold(cookie.Name, "VSG_SESSIONID") && cookie.Value != "" {
			c.SessionID = cookie.Value
			c.SessionCookie = cookie.String()
			c.Logger("SUCCESS", "Acquired Session ID: %s", c.SessionID)
			return
		}
	}
}

// fetchIntegrationInfo retrieves the integration.xml containing resources and policies.
// It uses its own shorter deadline so a slow portal cannot consume the whole
// login budget; the session stays valid and the caller can retry.
func (c *Client) fetchIntegrationInfo() (*IntegrationInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resourceFetchTimeout)
	defer cancel()

	reqURL := fmt.Sprintf("%s/vpn/user/portal/intergration.xml?version=2.0", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info IntegrationInfo
	if err := xml.Unmarshal(prepareGatewayXML(data), &info); err != nil {
		return nil, fmt.Errorf("failed to parse intergration.xml: %w", err)
	}

	return &info, nil
}

// startHeartbeatLoop runs the periodic detect/keepalive probe
func (c *Client) startHeartbeatLoop(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopHeartbeat:
				return
			case <-ticker.C:
				c.mu.Lock()
				if !c.isLoggedIn {
					c.mu.Unlock()
					return
				}
				c.mu.Unlock()

				probeURL := fmt.Sprintf("%s/vpn/user/portal/intergration.xml?period=%d&version=2.0",
					c.BaseURL, int(interval.Seconds()))
				resp, err := c.HTTPClient.Get(probeURL)
				if err != nil {
					c.Logger("WARN", "Heartbeat probe failed: %v", err)
				} else {
					resp.Body.Close()
					c.Logger("DEBUG", "Heartbeat keepalive acknowledged (%d)", resp.StatusCode)
				}
			}
		}
	}()
}

// SetTLSClientCertificate installs the certificate used for mTLS. The proxy
// manager reuses the same certificate for the tunnel connections, because a
// gateway that authenticates clients with certificates usually enforces them on
// the CONNECT endpoint too.
func (c *Client) SetTLSClientCertificate(cert *tls.Certificate) {
	if cert == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installClientCertLocked(cert)
}

// ClearTLSClientCertificate removes a previously installed client certificate.
// A login that installed one and then failed must call it: the same client is
// reused for the captcha session, and the next password attempt would otherwise
// present the certificate on a step that must not carry one.
func (c *Client) ClearTLSClientCertificate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tlsClientCert = nil
	tr := transportOf(c.HTTPClient.Transport)
	if tr == nil || tr.TLSClientConfig == nil {
		return
	}
	tr.TLSClientConfig.Certificates = nil
	tr.TLSClientConfig.GetClientCertificate = nil
	// Mirror installClientCertLocked: pooled connections handshaked with the
	// certificate must not leak it into steps that must not carry one.
	tr.CloseIdleConnections()
}

// LoginWithCert authenticates with a client certificate at
// /vpn/user/auth/cert (mutual TLS) and then loads the portal integration info,
// mirroring Login for password auth.
//
// The original client sends a GET request; the RSA/CAPI, file and UKEY variants
// all use the same endpoint and differ only in how the TLS client certificate
// is supplied.
func (c *Client) LoginWithCert(cert *tls.Certificate, verifycode string) (*IntegrationInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cert != nil {
		c.installClientCertLocked(cert)
	}
	if _, err := c.certAuthLocked(verifycode); err != nil {
		return nil, err
	}

	c.markLoggedInLocked()

	integration, err := c.fetchIntegrationInfo()
	if err != nil {
		c.Logger("ERROR", "Fetch integration info failed: %v", err)
		return nil, &ResourceFetchError{Err: err}
	}

	c.applyIntegrationLocked(integration)
	c.Logger("SUCCESS", "Certificate login successful! User: %s, Assigned resources: %d",
		integration.User.Name, len(integration.ResourceList.TCPUDPResources))

	return integration, nil
}

// certAuthLocked performs the certificate authentication request and captures
// the session cookie. Caller holds c.mu. It returns the parsed gateway
// response so a two-step login can report the final result of the sequence.
func (c *Client) certAuthLocked(verifycode string) (*AuthResponse, error) {
	c.Logger("INFO", "Initiating certificate authentication against %s", c.BaseURL)

	authURL := fmt.Sprintf("%s/vpn/user/auth/cert", c.BaseURL)
	if verifycode != "" {
		authURL += "?verifycode=" + url.QueryEscape(verifycode)
	}

	req, err := http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		// A TLS-level failure (unknown CA, no shared cipher, client certificate
		// rejected) surfaces here rather than as a RESULT code.
		c.Logger("ERROR", "Certificate auth request failed: %v", err)
		return nil, fmt.Errorf("证书认证握手失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("读取证书认证响应失败: %w", readErr)
	}
	respBody = prepareGatewayXML(respBody)
	c.Logger("INFO", "Certificate auth response status: %s", resp.Status)

	var authResp AuthResponse
	parseErr := xml.Unmarshal(respBody, &authResp)
	if parseErr != nil {
		c.Logger("WARN", "Certificate auth response was not XML: %s", string(respBody))
	}

	// Capture the session before the result-code check, mirroring the password
	// path: a challenge response (for instance the SMS factor after the
	// certificate) issues the VSG_SESSIONID the follow-up factor must bind to.
	c.captureSession()

	// The gateway error code is authoritative even with a non-200 status.
	if parseErr == nil {
		resultCode := strings.TrimSpace(authResp.Result.Code)
		if resultCode != "" && !isSuccessCode(resultCode) {
			authErr := newAuthError(resultCode, authResp.Result.Msg)
			c.Logger("ERROR", "Gateway rejected certificate authentication: %s", authErr.Error())
			return nil, authErr
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("证书登录失败，HTTP 状态 %d: %s", resp.StatusCode, string(respBody))
	}
	if parseErr != nil {
		return nil, fmt.Errorf("证书登录响应无法解析: %w", parseErr)
	}

	if c.SessionID == "" {
		c.Logger("ERROR", "No valid Session ID received after certificate auth. Response: %s", string(respBody))
		return nil, fmt.Errorf("证书登录未下发有效会话ID")
	}
	if msg := strings.TrimSpace(authResp.Result.Msg); msg != "" {
		c.lastAuthMsg = msg
		c.Logger("INFO", "网关提示: %s", msg)
	}
	return &authResp, nil
}

// LastAuthMessage 返回最近一次认证成功响应携带的网关提示文案
// （常见为「密码还有 X 天过期」），没有则为空。
func (c *Client) LastAuthMessage() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastAuthMsg
}

// ClientCertificate returns the certificate installed for mTLS, or nil.
func (c *Client) ClientCertificate() *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tlsClientCert
}

// Logout sends logout notification and tears down session
func (c *Client) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isLoggedIn {
		return nil
	}

	c.Logger("INFO", "Logging out of VPN gateway...")
	select {
	case c.stopHeartbeat <- struct{}{}:
	default:
	}

	logoutURL := fmt.Sprintf("%s/vpn/user/logout", c.BaseURL)
	_, _ = c.HTTPClient.Get(logoutURL)

	c.isLoggedIn = false
	c.SessionID = ""
	c.Integration = nil
	c.Logger("SUCCESS", "Logged out successfully")
	return nil
}

// IsLoggedIn returns login status
func (c *Client) IsLoggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isLoggedIn
}

// FetchVerifyCode fetches the graphic captcha image bytes and content type from the gateway.
//
// The picture lives on /vpn/user/common/verifycode.gif — the portal driver's
// own route table (jquery.sslvpn.js: Route("verifycode")) fetches it there with
// a cache-busting query. GET /vpn/user/auth/verifycode is a different endpoint
// (the POST check's path): a production appliance answers that GET with the XML
// rejection code=0x80000050「验证码不能为空」, which the old URL here happily
// wrapped into a data URL the browser rendered as a broken-image glyph.
func (c *Client) FetchVerifyCode() ([]byte, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	reqURL := fmt.Sprintf("%s/vpn/user/common/verifycode.gif?t=%d", c.BaseURL, time.Now().UnixNano())
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		c.Logger("ERROR", "Fetch verifycode image request failed: %v", err)
		return nil, "", fmt.Errorf("获取验证码请求失败: %w", err)
	}
	defer resp.Body.Close()

	c.captureSession()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("获取验证码失败，HTTP 状态码: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "image/gif"
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取验证码数据失败: %w", err)
	}

	// A non-image answer is the gateway talking XML (challenge, misrouted
	// check endpoint, session trouble) — surfacing it beats returning a data
	// URL the <img> renders as a silent broken-image glyph.
	if !strings.HasPrefix(contentType, "image/") {
		c.Logger("ERROR", "Verifycode endpoint returned non-image content (%s): %.160s", contentType, string(data))
		return nil, "", fmt.Errorf("验证码接口返回非图片内容 (%s)：%.160s", contentType, strings.TrimSpace(string(data)))
	}

	c.Logger("INFO", "Fetched verifycode image (%d bytes, %s)", len(data), contentType)
	return data, contentType, nil
}
