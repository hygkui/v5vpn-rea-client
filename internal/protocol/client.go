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

	"github.com/hygkui/v5vpn-rea-client/internal/crypto"
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
		Transport: tr,
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
func (c *Client) Handshake() (*VersionResponse, error) {
	u := fmt.Sprintf("%s/vpn/version.xml", c.BaseURL)
	c.Logger("INFO", "Connecting to gateway: %s", u)

	resp, err := c.HTTPClient.Get(u)
	if err != nil {
		c.Logger("ERROR", "Handshake failed: %v", err)
		return nil, fmt.Errorf("gateway handshake failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var v VersionResponse
	if err := xml.Unmarshal(body, &v); err != nil {
		c.Logger("WARN", "Failed to parse version.xml: %s, fallback to default", string(body))
		return &VersionResponse{Major: "2", Minor: "0"}, nil
	}

	c.Logger("SUCCESS", "Gateway handshake OK. Version %s.%s", v.Major, v.Minor)
	return &v, nil
}

// Login authenticates user with gateway using AES-128-CBC encrypted credentials.
func (c *Client) Login(username, password, verifycode string) (*IntegrationInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authenticate(username, password, verifycode)
}

// ChangePassword submits the old and new passwords to /vpn/user/auth/pwdchange.
// Both passwords are base64-encoded with encode=1.
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

	changeBody := passwordChangeBody(oldPassword, newPassword)
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

	c.captureSession()
	c.Logger("SUCCESS", "Password changed successfully for user: %s", username)
	return nil
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

	encUser, err := crypto.EncryptAuthParam(username)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt username: %w", err)
	}
	encPwd, err := crypto.EncryptAuthParam(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt password: %w", err)
	}

	// encode=2 tells a v2.0 gateway to AES-128-CBC decrypt. encode=1 is
	// legacy base64 and makes the gateway answer 0x8000001A. The body is
	// raw concatenation without URL-escaping.
	authBody := passwordAuthBody(encUser, encPwd, verifycode)

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

// AuthCertOnly performs certificate authentication and marks the session as
// logged in without waiting for the resource list.
func (c *Client) AuthCertOnly(cert *tls.Certificate, verifycode string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert != nil {
		c.installClientCertLocked(cert)
	}
	return c.certAuthLocked(verifycode)
}

// installClientCertLocked wires the certificate into the HTTP transport.
// Caller holds c.mu.
func (c *Client) installClientCertLocked(cert *tls.Certificate) {
	c.tlsClientCert = cert
	if tr, ok := c.HTTPClient.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
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
	authURL := fmt.Sprintf("%s/vpn/user/auth/password", c.BaseURL)
	req, err := http.NewRequest(http.MethodPost, authURL, strings.NewReader(authBody))
	if err != nil {
		return AuthResponse{}, nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		c.Logger("ERROR", "Auth request failed: %v", err)
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
	c.tlsClientCert = cert
	if tr, ok := c.HTTPClient.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}
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
	if err := c.certAuthLocked(verifycode); err != nil {
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
// the session cookie. Caller holds c.mu.
func (c *Client) certAuthLocked(verifycode string) error {
	c.Logger("INFO", "Initiating certificate authentication against %s", c.BaseURL)

	authURL := fmt.Sprintf("%s/vpn/user/auth/cert", c.BaseURL)
	if verifycode != "" {
		authURL += "?verifycode=" + url.QueryEscape(verifycode)
	}

	req, err := http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		// A TLS-level failure (unknown CA, no shared cipher, client certificate
		// rejected) surfaces here rather than as a RESULT code.
		c.Logger("ERROR", "Certificate auth request failed: %v", err)
		return fmt.Errorf("证书认证握手失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("读取证书认证响应失败: %w", readErr)
	}
	respBody = prepareGatewayXML(respBody)
	c.Logger("INFO", "Certificate auth response status: %s", resp.Status)

	var authResp AuthResponse
	parseErr := xml.Unmarshal(respBody, &authResp)
	if parseErr != nil {
		c.Logger("WARN", "Certificate auth response was not XML: %s", string(respBody))
	}

	// The gateway error code is authoritative even with a non-200 status.
	if parseErr == nil {
		resultCode := strings.TrimSpace(authResp.Result.Code)
		if resultCode != "" && !isSuccessCode(resultCode) {
			authErr := newAuthError(resultCode, authResp.Result.Msg)
			c.Logger("ERROR", "Gateway rejected certificate authentication: %s", authErr.Error())
			return authErr
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("证书登录失败，HTTP 状态 %d: %s", resp.StatusCode, string(respBody))
	}
	if parseErr != nil {
		return fmt.Errorf("证书登录响应无法解析: %w", parseErr)
	}

	c.captureSession()
	if c.SessionID == "" {
		c.Logger("ERROR", "No valid Session ID received after certificate auth. Response: %s", string(respBody))
		return fmt.Errorf("证书登录未下发有效会话ID")
	}
	return nil
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
