package service

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
	"github.com/hygkui/v5vpn-rea-client/internal/proxy"
)

// passwordChallenge retains the HTTP client that received a 0x100 login
// challenge. /vpn/user/auth/pwdchange must reuse it so the VSG_SESSIONID
// cookie issued by that response is sent with the change request.
type passwordChallenge struct {
	client   *protocol.Client
	username string
}

// VPNService is the backend service exposed to the MyGo frontend
type VPNService struct {
	Config            *config.AppConfig
	Client            *protocol.Client
	ProxyMgr          *proxy.ProxyManager
	Status            string // "Disconnected", "Connecting", "Connected", "Error"
	StatusDetail      string
	Resources         []protocol.VPNResource
	Logs              []string
	OnStatusChange    func(string)
	appVersion        string
	passwordChallenge *passwordChallenge
	mu                sync.Mutex
	logMu             sync.Mutex
	onLog             func(string)
}

// NewVPNService initializes the VPN service with loaded settings
func NewVPNService(onLog func(string)) *VPNService {
	cfg, err := config.LoadSettingXML("")
	if err != nil {
		// Provide default config if not found
		cfg = AppConfigDefault()
	}

	s := &VPNService{
		Config:       cfg,
		Status:       "Disconnected",
		StatusDetail: "Ready",
		Logs:         make([]string, 0),
		onLog:        onLog,
	}

	s.Log("INFO", "V5VPN Client Service initialized. Loaded %d gateway profiles.", len(cfg.Gateways))
	return s
}

// placeholderGatewayIP / placeholderGatewayPort are RFC 5737 documentation
// block addresses so the default config never points at a real gateway.
const (
	placeholderGatewayIP   = "203.0.113.10"
	placeholderGatewayPort = 443
)

func AppConfigDefault() *config.AppConfig {
	return &config.AppConfig{
		LastUseGateway: "demo-gateway",
		Remember:       true,
		HideToTray:     true,
		Gateways: []config.GatewayProfile{
			{
				ID:   "gw-demo-0",
				Name: "demo-gateway-0",
				IP:   placeholderGatewayIP,
				Port: placeholderGatewayPort,
				Algo: 0,
			},
			{
				ID:   "gw-demo-1",
				Name: "demo-gateway-1",
				IP:   placeholderGatewayIP,
				Port: placeholderGatewayPort,
				Algo: 0,
			},
		},
	}
}

func (s *VPNService) setStatus(status, detail string) {
	s.mu.Lock()
	s.Status = status
	s.StatusDetail = detail
	fn := s.OnStatusChange
	s.mu.Unlock()
	if fn != nil {
		go fn(status)
	}
}

// OpenURL launches a URL in the user's default web browser
func (s *VPNService) OpenURL(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", rawURL)
	case "darwin":
		cmd = exec.Command("open", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	return cmd.Start()
}

// SetAppVersion sets the application version used for update checks
func (s *VPNService) SetAppVersion(ver string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appVersion = ver
}

// CheckForUpdates checks GitHub releases for a newer version than currentVersion.
func (s *VPNService) CheckForUpdates() *UpdateInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.mu.Lock()
	current := s.appVersion
	s.mu.Unlock()
	if current == "" {
		current = "v0.1.1"
	}

	repo := "hygkui/v5vpn-rea-client"

	// 1. Try manifest from releases/latest/download/ (no rate limit, contains release notes and assets)
	if info, err := CheckUpdateManifest(ctx, repo, current); err == nil && info != nil {
		return info
	}

	// 2. Try 302 redirect of https://github.com/<repo>/releases/latest (no rate limit)
	if info, err := CheckGitHubReleaseRedirect(ctx, repo, current); err == nil && info != nil {
		return info
	}

	// 3. Fallback to GitHub REST API
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	info, err := CheckUpdateFromURL(ctx, apiURL, current)
	if err != nil {
		return &UpdateInfo{
			HasUpdate:      false,
			CurrentVersion: current,
			Error:          "检查更新失败（请检查网络连接或直接访问 GitHub Releases）",
			ReleaseURL:     "https://github.com/" + repo + "/releases",
		}
	}
	return info
}

// Log adds a log entry with timestamp and level
func (s *VPNService) Log(level string, format string, args ...any) {
	s.logMu.Lock()
	defer s.logMu.Unlock()

	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf("[%s] [%s] %s", timestamp, level, msg)
	s.Logs = append(s.Logs, formatted)
	if len(s.Logs) > 500 {
		s.Logs = s.Logs[len(s.Logs)-500:]
	}

	if s.onLog != nil {
		go s.onLog(formatted)
	}
}

// GetConfig returns the full application configuration
func (s *VPNService) GetConfig() *config.AppConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Config
}

// GetGateways returns configured gateway profiles
func (s *VPNService) GetGateways() []config.GatewayProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Config.Gateways
}

// SaveGateway adds or updates a gateway profile
func (s *VPNService) SaveGateway(gw config.GatewayProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for i := range s.Config.Gateways {
		if s.Config.Gateways[i].ID == gw.ID || s.Config.Gateways[i].Name == gw.Name {
			s.Config.Gateways[i] = gw
			found = true
			break
		}
	}
	if !found {
		if gw.ID == "" {
			gw.ID = fmt.Sprintf("gw-%d", len(s.Config.Gateways))
		}
		s.Config.Gateways = append(s.Config.Gateways, gw)
	}

	return s.Config.SaveSettingXML("")
}

// DeleteGateway removes a gateway profile
func (s *VPNService) DeleteGateway(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	newGWs := make([]config.GatewayProfile, 0, len(s.Config.Gateways))
	for _, gw := range s.Config.Gateways {
		if gw.ID != id && gw.Name != id {
			newGWs = append(newGWs, gw)
		}
	}
	s.Config.Gateways = newGWs
	return s.Config.SaveSettingXML("")
}

// Login performs authentication and establishes VPN tunnel
func (s *VPNService) Login(gwIdentifier, username, password, verifycode string, remember, auto bool) (map[string]any, error) {
	s.mu.Lock()
	if s.Status == "Connecting" || s.Status == "Connected" {
		s.mu.Unlock()
		return nil, fmt.Errorf("VPN is already connected or connecting")
	}
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}

	gwName := gw.Name
	gwIP := gw.IP
	gwPort := gw.Port
	gwAlgo := gw.Algo
	s.Config.LastUseGateway = gw.Name
	// A fresh authentication attempt supersedes any previous challenge.
	s.passwordChallenge = nil

	if remember {
		s.storeAccountLocked(gw, username, password, remember, auto)
		_ = s.Config.SaveSettingXML("")
	}
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Connecting to %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Initiating login sequence to %s (%s:%d)...", gwName, gwIP, gwPort)

	client := protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)

	// Step 1: Handshake
	_, err := client.Handshake()
	if err != nil {
		s.setStatus("Error", fmt.Sprintf("Handshake failed: %v", err))
		return nil, err
	}

	// Step 2: Authenticate
	if _, err = client.Login(username, password, verifycode); err != nil {
		if protocol.IsPasswordExpired(err) {
			// Keep this client so ChangePassword can reuse its jar and send
			// the VSG_SESSIONID issued with the 0x100 response.
			s.mu.Lock()
			s.passwordChallenge = &passwordChallenge{
				client:   client,
				username: username,
			}
			s.mu.Unlock()
		}
		s.setStatus("Error", fmt.Sprintf("认证失败: %v", err))
		return nil, err
	}

	return s.connectTunnel(client, username)
}

// ChangePassword replaces an expired VPN password and then connects.
// When the gateway changes the password without opening a session, this
// signs in with the new password.
func (s *VPNService) ChangePassword(gwIdentifier, username, password, newPassword, verifycode string, remember, auto bool) (map[string]any, error) {
	if strings.TrimSpace(newPassword) == "" {
		return nil, fmt.Errorf("新密码不能为空")
	}
	if newPassword == password {
		return nil, fmt.Errorf("新密码不能与当前密码相同")
	}

	s.mu.Lock()
	if s.Status == "Connecting" || s.Status == "Connected" {
		s.mu.Unlock()
		return nil, fmt.Errorf("VPN is already connected or connecting")
	}
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}
	gwName := gw.Name
	gwIP := gw.IP
	gwPort := gw.Port
	gwAlgo := gw.Algo
	s.Config.LastUseGateway = gw.Name
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Changing password on %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Changing password for %s on %s (%s:%d)...", username, gwName, gwIP, gwPort)

	s.mu.Lock()
	client := s.Client
	challenge := s.passwordChallenge
	s.mu.Unlock()

	// Reuse the HTTP client that received the 0x100 challenge when it belongs
	// to this gateway and user; its cookie jar carries VSG_SESSIONID.
	if challenge != nil && challenge.username == username &&
		challenge.client.GatewayIP == gwIP && challenge.client.GatewayPort == gwPort {
		client = challenge.client
	}
	if client == nil || client.GatewayIP != gwIP || client.GatewayPort != gwPort {
		client = protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)
		if _, err := client.Handshake(); err != nil {
			s.setStatus("Error", fmt.Sprintf("Handshake failed: %v", err))
			return nil, err
		}
	}

	// Ensure the client has an active session cookie (VSG_SESSIONID) required by pwdchange.
	if client.SessionID == "" {
		if _, err := client.AuthPassword(username, password, verifycode); err != nil {
			if !protocol.IsPasswordExpired(err) {
				s.setStatus("Error", fmt.Sprintf("验证当前密码失败: %v", err))
				return nil, err
			}
		}
	}

	if err := client.ChangePassword(username, password, newPassword, verifycode); err != nil {
		s.setStatus("Error", fmt.Sprintf("修改密码失败: %v", err))
		return nil, err
	}

	s.mu.Lock()
	if s.passwordChallenge != nil && s.passwordChallenge.client == client {
		s.passwordChallenge = nil
	}
	s.Status = "Disconnected"
	s.StatusDetail = "密码已更新，正在登录"
	s.mu.Unlock()
	s.Log("SUCCESS", "Password changed for %s; signing in with the new password", username)
	return s.Login(gwIdentifier, username, newPassword, verifycode, remember, auto)
}

// AuthErrorCode returns the stable machine-readable code for a gateway
// authentication rejection, or "" when err is not an auth error. The frontend
// keys its login messaging off this code instead of parsing error text.
func AuthErrorCode(err error) string {
	var authErr *protocol.AuthError
	if !errors.As(err, &authErr) {
		return ""
	}
	switch authErr.Kind {
	case protocol.AuthKindPasswordExpired:
		return "password_expired"
	case protocol.AuthKindBadCredentials:
		return "bad_credentials"
	case protocol.AuthKindVerifyCode:
		return "verify_code"
	default:
		return ""
	}
}

// IsPasswordExpired reports a gateway password-change challenge.
func IsPasswordExpired(err error) bool {
	return AuthErrorCode(err) == "password_expired"
}

func (s *VPNService) storeAccountLocked(gw *config.GatewayProfile, username, password string, remember, auto bool) {
	gw.LastUserName = username
	for idx := range gw.SavedAccounts {
		if gw.SavedAccounts[idx].Username == username {
			gw.SavedAccounts[idx].Password = password
			gw.SavedAccounts[idx].Remember = remember
			gw.SavedAccounts[idx].Auto = auto
			return
		}
	}
	gw.SavedAccounts = append(gw.SavedAccounts, config.UserAccount{
		Username: username,
		Password: password,
		Remember: remember,
		Auto:     auto,
	})
}

func (s *VPNService) connectTunnel(client *protocol.Client, username string) (map[string]any, error) {
	integration := client.Integration
	if integration == nil {
		s.setStatus("Error", "未获取到网关资源")
		return nil, fmt.Errorf("登录完成但未收到网关资源列表")
	}

	proxyMgr := proxy.NewProxyManager(client.GatewayIP, client.GatewayPort, client.SessionID, s.Log)
	resources, err := proxyMgr.StartProxies(integration.ResourceList.TCPUDPResources)
	if err != nil {
		s.Log("WARN", "Proxy start partially encountered issues: %v", err)
	}

	s.mu.Lock()
	s.Client = client
	s.ProxyMgr = proxyMgr
	s.Resources = resources
	s.Status = "Connected"
	s.StatusDetail = fmt.Sprintf("Connected as %s (%d resources active)", username, len(resources))
	fn := s.OnStatusChange
	s.mu.Unlock()
	if fn != nil {
		go fn("Connected")
	}

	s.Log("SUCCESS", "VPN Tunnel fully connected and ready for traffic.")

	return map[string]any{
		"status":        "Connected",
		"username":      username,
		"sessionId":     client.SessionID,
		"loginAddress":  integration.Session.LoginAddr,
		"resourceCount": len(resources),
		"resources":     resources,
	}, nil
}

// Logout disconnects the VPN tunnel
func (s *VPNService) Logout() (bool, error) {
	s.mu.Lock()
	proxyMgr := s.ProxyMgr
	client := s.Client
	s.ProxyMgr = nil
	s.Client = nil
	s.passwordChallenge = nil
	s.Status = "Disconnected"
	s.StatusDetail = "Disconnected"
	s.Resources = nil
	fn := s.OnStatusChange
	s.mu.Unlock()

	if fn != nil {
		go fn("Disconnected")
	}

	s.Log("INFO", "Tearing down VPN session...")

	if proxyMgr != nil {
		proxyMgr.Stop()
	}

	if client != nil {
		_ = client.Logout()
	}

	s.Log("SUCCESS", "VPN session disconnected successfully.")
	return true, nil
}

// GetStatus returns the current connection state and resources
func (s *VPNService) GetStatus() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Logs has its own mutex (logMu); read its length under that lock to
	// avoid racing with Log().
	s.logMu.Lock()
	logCount := len(s.Logs)
	s.logMu.Unlock()

	return map[string]any{
		"status":         s.Status,
		"statusDetail":   s.StatusDetail,
		"resources":      s.Resources,
		"lastUseGateway": s.Config.LastUseGateway,
		"logCount":       logCount,
	}
}

// GetLogs returns all logged messages
func (s *VPNService) GetLogs() []string {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	copied := make([]string, len(s.Logs))
	copy(copied, s.Logs)
	return copied
}

// ClearLogs clears in-memory log entries
func (s *VPNService) ClearLogs() bool {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.Logs = make([]string, 0)
	return true
}
