package protocol

import (
	"crypto/tls"
	"encoding/xml"
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
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Internal VPN gateways often use private/self-signed certs
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}

	httpClient := &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   15 * time.Second,
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

// authenticate posts /vpn/user/auth/password for login authentication. Caller holds c.mu.
func (c *Client) authenticate(username, password, verifycode string) (*IntegrationInfo, error) {
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
		return nil, authErr
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed with HTTP status %d: %s", statusCode, string(respBody))
	}

	if c.SessionID == "" {
		c.Logger("ERROR", "No valid Session ID received from gateway. Response: %s", string(respBody))
		return nil, fmt.Errorf("登录未下发有效会话ID (可能凭证错误或需要图形验证码)")
	}

	integration, err := c.fetchIntegrationInfo()
	if err != nil {
		c.Logger("ERROR", "Fetch integration info failed: %v", err)
		return nil, fmt.Errorf("获取内网受保护资源失败: %w", err)
	}

	c.Integration = integration
	c.Logger("SUCCESS", "Login successful! User: %s, Assigned resources: %d",
		integration.User.Name, len(integration.ResourceList.TCPUDPResources))

	c.isLoggedIn = true

	interval := 180 * time.Second
	if c.Integration.Session.DetectInterval > 0 {
		interval = time.Duration(c.Integration.Session.DetectInterval) * time.Second
	}
	c.startHeartbeatLoop(interval)

	return c.Integration, nil
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

// fetchIntegrationInfo retrieves the integration.xml containing resources and policies
func (c *Client) fetchIntegrationInfo() (*IntegrationInfo, error) {
	reqURL := fmt.Sprintf("%s/vpn/user/portal/intergration.xml?version=2.0", c.BaseURL)
	req, err := http.NewRequest("GET", reqURL, nil)
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
	if err := xml.Unmarshal(data, &info); err != nil {
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
