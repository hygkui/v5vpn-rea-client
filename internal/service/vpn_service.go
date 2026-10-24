package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/certstore"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/ipsec"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
	"github.com/hygkui/v5vpn-rea-client/internal/proxy"
)

// authChallenge retains the HTTP client that received a gateway challenge: a
// RESULT code asking for another factor. The gateway — not the client — drives
// the login sequence (every submitted factor answers with a RESULT code, and
// protocol.NextAuthStep names the follow-up), so whatever the next step is,
// its request must reuse this exact client: the gateway binds the pending
// factor to the VSG_SESSIONID cookie issued with the challenge response.
type authChallenge struct {
	client   *protocol.Client
	username string
	// next is the factor the gateway asked for (protocol.AuthStep...). It is
	// the dispatch key: each follow-up (ChangePassword, SendSMSCode,
	// LoginWithSMSCode) matches the pending challenge by this field, so a new
	// factor the gateway starts asking for needs no new challenge type here.
	next protocol.AuthStep
	// cert, when set, is the certificate factor this chain already presented:
	// the completed login tunnels with it, and a password change must present
	// it again on the follow-up sign-in.
	cert *tls.Certificate
	// afterAuth, when non-nil, receives the resolved gateway ID once the
	// challenge completes, so the owning flow persists its mode selection. A
	// nil afterAuth completes as a plain password login.
	afterAuth func(gwID string)
	// authType is how the completed login is reported to the frontend
	// (authTypePassword, authTypePasswordCertificate, authTypeCertificate).
	authType string
}

// PasswordChangedError reports that the gateway accepted the new password but
// the automatic sign-in that follows failed. The UI must move the form back to
// the login state (with the new password) instead of asking the user to retry
// the change with the now-invalid old password.
type PasswordChangedError struct {
	Err error
}

func (e *PasswordChangedError) Error() string { return e.Err.Error() }

func (e *PasswordChangedError) Unwrap() error { return e.Err }

// PasswordChanged reports whether err means the password was already updated.
func PasswordChanged(err error) bool {
	var changed *PasswordChangedError
	return errors.As(err, &changed)
}

// preAuthClient is the HTTP client that fetched a captcha image. The gateway
// binds the code to the VSG_SESSIONID cookie issued by that response, so the
// login that submits the code must reuse this exact client. It is deliberately
// kept out of Client, which is the session-of-record for the connected tunnel.
type preAuthClient struct {
	client    *protocol.Client
	createdAt time.Time
}

// pendingClientTTL bounds how long a fetched captcha session may be reused.
const pendingClientTTL = 10 * time.Minute

// VPNService is the backend service exposed to the MyGo frontend
type VPNService struct {
	Config   *config.AppConfig
	Client   *protocol.Client
	ProxyMgr *proxy.ProxyManager
	// 端口区间类资源（堡垒机等）不映射固定本地端口，各起一个本地 CONNECT 代理。
	WebProxies   []*proxy.WebProxy
	WebResources []WebResource
	localPort    int // 本地 HTTP 服务端口，用于生成系统 PAC 地址
	webProxyCfg  webProxyConfig
	// passwordExpiryDays 是网关下发的口令剩余有效天数（0 表示无提示）。
	passwordExpiryDays int
	// loginNotice 是网关认证成功时返回的提示文案（如「密码还有 X 天过期」）。
	loginNotice  string
	CertStore    *certstore.Store
	Status       string // "Disconnected", "Connecting", "Connected", "Error"
	StatusDetail string
	Resources    []protocol.VPNResource
	// IPsecResources summarizes Network Connect profiles the gateway granted.
	// They have no local proxy (the SSL tunnel path cannot carry them); they
	// exist so the connected view can say what was assigned instead of "0 resources".
	IPsecResources []protocol.IPsecResource
	// IPsec data-plane state, populated asynchronously after resources load.
	ipsecMgr     *ipsec.Manager
	ipsecCfg     *ipsec.Config
	ipsecGateway string
	ipsecState   string // "", "starting", "up", "error", "unavailable"
	ipsecError   string
	// newIPsecManager builds the WSL Manager for a session. nil means
	// ipsec.NewManager; tests substitute it to inject a fake CommandRunner.
	newIPsecManager func(confPath string) *ipsec.Manager
	resourceState   ResourceLoadState
	resourceError   string
	Logs            []string
	OnStatusChange  func(string)
	appVersion      string
	authType        string
	challenge       *authChallenge
	pendingClients  map[string]*preAuthClient
	mu              sync.Mutex
	logMu           sync.Mutex
	onLog           func(string)
}

// NewVPNService initializes the VPN service with loaded settings
func NewVPNService(onLog func(string)) *VPNService {
	// 上次进程被强杀时来不及还原系统代理，这里先收拾干净。
	recoverSystemProxy()

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
		webProxyCfg:  loadWebProxyConfig(),
	}

	s.Log("INFO", "V5VPN Client Service initialized. Loaded %d gateway profiles.", len(cfg.Gateways))
	return s
}

// newCertStore places imported certificates next to setting.xml so an
// auto-update of the application directory does not delete them. Tests and
// portable runs without a user data directory fall back to ./certs.
func newCertStore() *certstore.Store {
	dir := filepath.Join(config.UserDataDir(), "certs")
	if config.UserDataDir() == "" {
		dir = filepath.Join(".", "certs")
	}
	store, err := certstore.NewStore(dir)
	if err != nil {
		// A read-only location should not prevent the client from starting;
		// certificate operations will report the same error when used.
		return nil
	}
	return store
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
		// Unknown build version: assume the oldest possible one so a real
		// release is always offered, rather than pinning a stale literal
		// that would silently drift out of date on every release.
		current = "v0.0.0"
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

// GetConfig returns a snapshot copy of the application configuration.
//
// The returned value is a deep copy: Login rewrites LastUseGateway and
// SaveGateway/DeleteGateway replace Gateways under s.mu, so handing out the
// live *config.AppConfig let callers (the /api/config handler encodes it,
// the tray menu reads LastUseGateway) race with those writes. Mutating the
// returned config is a no-op on the service, as intended for a getter.
func (s *VPNService) GetConfig() *config.AppConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Config.Snapshot()
}

// GetGateways returns a deep copy of the configured gateway profiles.
func (s *VPNService) GetGateways() []config.GatewayProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Config == nil {
		return nil
	}
	// Reuse Snapshot's copy so the two paths cannot drift apart.
	return s.Config.Snapshot().Gateways
}

// SetLastUseGateway records which gateway was used most recently.
//
// aTrust 后端通过 ATrustHost 接口调用它：两边共用 setting.xml 里同一个
// LastUseGateway 字段，cmd 侧按它决定启动时先打开哪套界面
// （见 cmd.initialUIPath）。与 V5VPN 的 Login 路径一致，写入后立即
// 持久化，失败返回给调用方记日志。
func (s *VPNService) SetLastUseGateway(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Config == nil {
		return fmt.Errorf("配置尚未加载")
	}
	if s.Config.LastUseGateway == name {
		return nil
	}
	s.Config.LastUseGateway = name
	return s.Config.SaveSettingXML("")
}

// SaveGateway adds or updates a gateway profile.
//
// When an existing profile matches by ID or name, only the fields the caller
// actually edits are replaced: ID, SavedAccounts and LastUserName are kept
// from the stored profile. The add-gateway form only submits name/IP/port/algo,
// so a plain struct assignment used to zero the saved accounts, let the caller
// silently drop every stored credential, and then write that loss to disk.
//
// A non-empty SavedAccounts list still replaces the stored accounts. Nil and
// empty are both treated as "not supplied": no caller, the UI included, can
// express "delete every saved credential", and an empty JSON array used to
// wipe them the same way a plain struct assignment did.
func (s *VPNService) SaveGateway(gw config.GatewayProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.Config.Gateways {
		existing := &s.Config.Gateways[i]
		if existing.ID == gw.ID || existing.Name == gw.Name {
			// Preserve the identity and credential fields the caller did not
			// supply, so correcting an IP or port cannot cost the operator
			// their saved passwords.
			if gw.ID == "" {
				gw.ID = existing.ID
			}
			if gw.LastUserName == "" {
				gw.LastUserName = existing.LastUserName
			}
			if len(gw.SavedAccounts) == 0 {
				gw.SavedAccounts = existing.SavedAccounts
			}
			// The gateway editor only submits name/IP/port/algo, so an empty
			// authentication block means "unchanged" and must not erase the
			// certificate selection saved by a certificate login.
			if gw.AuthType == 0 && gw.SelectedCertID == "" && gw.CertType == 0 && !gw.CertAutoLogin && !gw.CertWithPassword {
				gw.AuthType = existing.AuthType
				gw.CertType = existing.CertType
				gw.CertAutoLogin = existing.CertAutoLogin
				gw.CertWithPassword = existing.CertWithPassword
				gw.SelectedCertID = existing.SelectedCertID
			}
			*existing = gw
			return s.Config.SaveSettingXML("")
		}
	}

	if gw.ID == "" {
		gw.ID = nextGatewayID(s.Config.Gateways)
	}
	s.Config.Gateways = append(s.Config.Gateways, gw)

	return s.Config.SaveSettingXML("")
}

// nextGatewayID returns the smallest "gw-N" identifier not already in use.
// Deriving the ID from len(gateways) reuses the ID of a hidden gap: delete
// gw-0 out of {gw-0, gw-1}, add a gateway, and it becomes another gw-1.
// DeleteGateway matches on ID, so the duplicate then removes both profiles.
func nextGatewayID(gateways []config.GatewayProfile) string {
	used := make(map[string]bool, len(gateways))
	for _, gw := range gateways {
		used[gw.ID] = true
	}
	for n := 0; ; n++ {
		id := fmt.Sprintf("gw-%d", n)
		if !used[id] {
			return id
		}
	}
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
	var preAuth *protocol.Client
	s.mu.Lock()
	if s.Status == "Connecting" || s.Status == "Connected" {
		s.cleanupStaleSessionLocked()
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
	s.challenge = nil
	// The captcha code is bound to the cookie jar of the client that fetched
	// the image; reuse it so the VSG_SESSIONID travels with this login.
	preAuth = s.pendingClientLocked(gw)

	if remember {
		s.storeAccountLocked(gw, username, password, remember, auto)
		_ = s.Config.SaveSettingXML("")
	}
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Connecting to %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Initiating login sequence to %s (%s:%d)...", gwName, gwIP, gwPort)

	client := preAuth
	if client == nil {
		client = protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)
	}

	// Step 1: Handshake
	_, err := client.Handshake()
	if err != nil {
		s.setStatus("Error", fmt.Sprintf("Handshake failed: %v", err))
		return nil, err
	}

	// Step 2: Authenticate. Resource loading happens asynchronously so the
	// connected view appears right away instead of hanging on the login screen
	// while the portal computes the resource list.
	if _, err = client.AuthOnly(username, password, verifycode); err != nil {
		// Whatever the gateway asks for next (change password, SMS,
		// certificate, ...) is kept as a challenge on this session; a chain
		// that never presents a certificate completes as a plain password
		// login, and SubmitCertFactor upgrades the record when it answers a
		// certificate challenge.
		s.mu.Lock()
		s.keepChallengeLocked(client, username, err, nil, nil, authTypePassword)
		s.mu.Unlock()
		s.setStatus("Error", fmt.Sprintf("认证失败: %v", err))
		return nil, err
	}

	// Password login is now the gateway's mode of record; the certificate
	// selection is kept for a one-click switch back. Only a successful login
	// flips the mode: a rejected attempt must not erase a two-factor setting.
	s.rememberPasswordMode(gwName)

	return s.enterConnected(client, username, nil, authTypePassword), nil
}

// authTypePassword / authTypeCertificate / authTypePasswordCertificate are the
// values reported to the frontend in the login result.
const (
	authTypePassword            = "password"
	authTypeCertificate         = "certificate"
	authTypePasswordCertificate = "password+certificate"
)

// LoginWithPasswordAndCert performs the two-factor "password + certificate"
// login: the password is posted to /vpn/user/auth/password, and when the
// gateway's result code asks for the certificate factor, the certificate is
// presented on /vpn/user/auth/cert over the same session — the two-step
// order the original client uses. It mirrors Login, with the certificate
// loaded from the store first.
func (s *VPNService) LoginWithPasswordAndCert(gwIdentifier, username, password, verifycode string, source int, certID string, remember, auto bool) (map[string]any, error) {
	store := s.certStore()
	if store == nil {
		return nil, fmt.Errorf("证书目录不可用")
	}
	cert, err := store.LoadTLS(certID, certstore.Source(source))
	if err != nil {
		s.setStatus("Error", fmt.Sprintf("加载证书失败: %v", err))
		return nil, err
	}
	return s.loginWithPasswordCert(gwIdentifier, username, password, verifycode, cert, func(gwID string) {
		s.persistPasswordCertSelection(gwID, source, certID)
	}, remember, auto)
}

// LoginWithPasswordAndCertExternal is LoginWithPasswordAndCert for a
// certificate file that lives outside the store (the CLI form). The file is
// loaded in place and never copied; the two-factor choice is not persisted
// because there is no store id to remember.
func (s *VPNService) LoginWithPasswordAndCertExternal(gwIdentifier, username, password, certPath, certPassword, verifycode string) (map[string]any, error) {
	cert, err := certstore.LoadTLSFile(certPath, certPassword)
	if err != nil {
		return nil, err
	}
	return s.loginWithPasswordCert(gwIdentifier, username, password, verifycode, cert, nil, false, false)
}

// loginWithPasswordCert runs the shared two-factor login sequence. afterAuth,
// when non-nil, receives the resolved gateway ID after a successful
// authentication.
func (s *VPNService) loginWithPasswordCert(gwIdentifier, username, password, verifycode string, cert *tls.Certificate, afterAuth func(gwID string), remember, auto bool) (map[string]any, error) {
	var preAuth *protocol.Client
	s.mu.Lock()
	if s.Status == "Connecting" || s.Status == "Connected" {
		s.cleanupStaleSessionLocked()
	}
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}
	gwID, gwName, gwIP, gwPort, gwAlgo := gw.ID, gw.Name, gw.IP, gw.Port, gw.Algo
	s.Config.LastUseGateway = gw.Name
	s.challenge = nil
	preAuth = s.pendingClientLocked(gw)
	if remember {
		s.storeAccountLocked(gw, username, password, remember, auto)
		_ = s.Config.SaveSettingXML("")
	}
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Password + certificate login to %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Initiating password + certificate login to %s (%s:%d), user=%s, cert=%s",
		gwName, gwIP, gwPort, username, certDisplayName(cert, "certificate"))

	client := preAuth
	if client == nil {
		client = protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)
	}

	// No certificate is attached up front: the original client submits the
	// password over a plain TLS connection first and only presents the
	// certificate when the gateway asks for it (AuthPasswordWithCert installs
	// it for the certificate step and keeps it for the tunnel).
	if _, err := client.Handshake(); err != nil {
		s.setStatus("Error", fmt.Sprintf("Handshake failed: %v", err))
		return nil, err
	}

	authResp, err := client.AuthPasswordWithCert(cert, username, password, verifycode)
	if err != nil {
		// The chain context: a challenge that follows a presented certificate
		// factor (password -> certificate -> SMS, or a password change on the
		// two-factor flow) keeps the certificate, the flow's persistence
		// callback and the two-factor authType. A challenge that bypassed the
		// certificate step (the gateway asked for SMS straight on the password
		// step) must complete as a plain password login — the certificate was
		// never presented and must not be recorded as a used factor.
		certFactor, afterAuthChain, authTypeChain := cert, afterAuth, authTypePasswordCertificate
		if protocol.IsSMSChallenge(err) && (authResp == nil || !authResp.CertFactorUsed) {
			certFactor, afterAuthChain, authTypeChain = nil, nil, authTypePassword
		}
		s.mu.Lock()
		s.keepChallengeLocked(client, username, err, certFactor, afterAuthChain, authTypeChain)
		s.mu.Unlock()
		s.setStatus("Error", fmt.Sprintf("认证失败: %v", err))
		return nil, err
	}

	// The gateway decides whether the certificate factor was needed. When it
	// accepted the password alone, recording the session as two-factor would
	// force the two-factor tab on the next launch for a gateway that never
	// asked for a certificate.
	if authResp != nil && authResp.CertFactorUsed {
		if afterAuth != nil {
			afterAuth(gwID)
		}
		return s.enterConnected(client, username, cert, authTypePasswordCertificate), nil
	}
	s.rememberPasswordMode(gwName)
	return s.enterConnected(client, username, nil, authTypePassword), nil
}

// ResourceLoadState is exposed to the UI while the portal resource list loads.
type ResourceLoadState string

const (
	ResourceLoading ResourceLoadState = "loading"
	ResourceReady   ResourceLoadState = "ready"
	ResourceError   ResourceLoadState = "error"
)

// enterConnected publishes the connected state immediately after a successful
// authentication and loads the resource list in the background. authType names
// the method that produced the session and is reported to the frontend.
func (s *VPNService) enterConnected(client *protocol.Client, username string, cert *tls.Certificate, authType string) map[string]any {
	s.mu.Lock()
	s.Client = client
	// The pre-auth client has become the session of record; drop the pending
	// reference so it cannot be picked up by another login.
	s.clearPendingClientLocked(client)
	// A completed login supersedes any challenge still pending against this
	// gateway (for instance a certificate login that succeeded while an SMS
	// panel was left open).
	s.challenge = nil
	s.Resources = nil
	s.IPsecResources = nil
	s.loginNotice = client.LastAuthMessage()
	s.resourceState = ResourceLoading
	s.resourceError = ""
	s.Status = "Connected"
	s.StatusDetail = "已连接，正在拉取内网资源..."
	s.authType = authType
	fn := s.OnStatusChange
	s.mu.Unlock()
	if fn != nil {
		go fn("Connected")
	}

	s.Log("SUCCESS", "Authentication succeeded; loading protected resources in the background...")
	go s.loadResources(client, cert)

	return map[string]any{
		"status":        "Connected",
		"username":      username,
		"authType":      authType,
		"sessionId":     client.SessionID,
		"resourceState": string(ResourceLoading),
		"resourceCount": 0,
		"resources":     []protocol.VPNResource{},
	}
}

// loadResources fetches the portal list for an authenticated client, starts the
// proxies and publishes the outcome. A failure leaves the session connected
// with an empty list so the user can retry without re-authenticating.
func (s *VPNService) loadResources(client *protocol.Client, cert *tls.Certificate) {
	s.Log("INFO", "Fetching protected resources from gateway...")
	integration, err := client.FetchIntegration()

	s.mu.Lock()
	if s.Client != client {
		// The session was replaced or logged out while this fetch was running.
		s.mu.Unlock()
		return
	}
	staleProxy := s.ProxyMgr
	s.mu.Unlock()

	if err != nil {
		if staleProxy != nil {
			staleProxy.Stop()
		}
		s.mu.Lock()
		s.ProxyMgr = nil
		s.Resources = nil
		s.IPsecResources = nil
		s.resourceState = ResourceError
		s.resourceError = err.Error()
		s.StatusDetail = "已连接，但获取内网资源失败"
		fn := s.OnStatusChange
		s.mu.Unlock()
		if fn != nil {
			go fn("Connected")
		}
		s.Log("WARN", "Authenticated, but the gateway did not return the resource list: %v", err)
		return
	}

	proxyMgr := proxy.NewProxyManager(client.GatewayIP, client.GatewayPort, client.SessionID, s.Log)
	if cert != nil {
		proxyMgr.ClientCert = cert
	}
	resources, startErr := proxyMgr.StartProxies(integration.ResourceList.TCPUDPResources)
	if startErr != nil {
		s.Log("WARN", "Proxy start partially encountered issues: %v", startErr)
	}
	// 端口区间类资源（堡垒机等）无法映射固定本地端口，改走本地 CONNECT 代理。
	webProxies, webResources := s.startWebResources(client, cert, integration.ResourceList.TCPUDPResources)
	if days := integration.User.PwdOvertime; days > 0 {
		s.Log("WARN", "登录密码将在 %d 天后过期，建议尽快修改", days)
	}
	if staleProxy != nil {
		staleProxy.Stop()
	}
	ipsecResources := protocol.SummarizeNCResources(integration.ResourceList.NCResources)

	s.mu.Lock()
	if s.Client != client {
		s.mu.Unlock()
		proxyMgr.Stop()
		for _, wp := range webProxies {
			wp.Stop()
		}
		return
	}
	staleWebProxies := s.WebProxies
	s.ProxyMgr = proxyMgr
	s.WebProxies = webProxies
	s.WebResources = webResources
	s.Resources = resources
	s.IPsecResources = ipsecResources
	s.passwordExpiryDays = integration.User.PwdOvertime
	s.resourceState = ResourceReady
	s.resourceError = ""
	s.StatusDetail = fmt.Sprintf("Connected as %s (%d resources active, %d web)",
		resourceDisplayUser(client), len(resources), len(webResources))
	s.mu.Unlock()

	for _, wp := range staleWebProxies {
		wp.Stop()
	}

	// 网页资源存在时启用系统 PAC，让用户自己打开的浏览器也能访问；
	// 代理白名单与 PAC 规则同步刷新（资源地址可能变化）。
	s.syncWebProxyHosts()
	s.syncSystemPAC(len(webResources) > 0)

	s.Log("SUCCESS", "Loaded %d protected resources (%d web).", len(resources), len(webResources))
	if len(ipsecResources) > 0 {
		if len(resources) == 0 {
			s.Log("INFO", "Gateway granted %d IPsec (NC) profile(s); starting the IPsec data plane", len(ipsecResources))
		}
		go s.startIPsec(integration.ResourceList.NCResources)
	}
}

// startIPsec builds the IKEv1 profile for this session and asks the Manager to
// bring it up through WSL/strongSwan. Failures are recorded in ipsecState so
// the UI can explain why the subnets are unreachable.
func (s *VPNService) startIPsec(ncs []protocol.NCResource) {
	cfg, err := ipsec.FromNC(ncs)
	if err != nil {
		s.setIPsecState("error", err.Error())
		s.Log("ERROR", "IPsec 配置无效: %v", err)
		return
	}
	confDir := config.UserDataDir()
	if confDir == "" {
		s.setIPsecState("error", "用户数据目录不可用")
		s.Log("ERROR", "IPsec 配置目录不可用")
		return
	}

	newMgr := s.newIPsecManager
	if newMgr == nil {
		newMgr = ipsec.NewManager
	}
	mgr := newMgr(filepath.Join(confDir, "ipsec.conf"))
	s.mu.Lock()
	s.ipsecMgr = mgr
	s.ipsecCfg = cfg
	s.ipsecGateway = ""
	s.ipsecError = ""
	s.ipsecState = "starting"
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if !mgr.Available(ctx) {
		msg := "WSL 发行版 v5vpn 不可用，请先运行 scripts/setup-ipsec-wsl.ps1"
		s.setIPsecState("unavailable", msg)
		s.Log("WARN", "IPsec 数据面不可用: %s", msg)
		return
	}

	s.Log("INFO", "正在通过 WSL/strongSwan 建立 IPsec 隧道到 %s ...", ipsec.FormatServerPort(*cfg))
	if out, err := mgr.Start(ctx, *cfg); err != nil {
		s.setIPsecState("error", err.Error())
		s.Log("ERROR", "IPsec 隧道建立失败: %v", err)
		if out != "" {
			s.Log("DEBUG", "swanctl: %s", out)
		}
		return
	}

	gateway := ""
	if ip, err := mgr.WSLIP(ctx); err == nil {
		gateway = ip
		s.mu.Lock()
		s.ipsecGateway = gateway
		s.mu.Unlock()
		if err := ipsec.AddRoutes(ctx, cfg.Routes, gateway); err != nil {
			if errors.Is(err, ipsec.ErrNotElevated) {
				s.Log("WARN", "IPsec 隧道已建立，但当前进程不是管理员：Windows 应用暂时无法自动路由到内网（可手动添加路由，或从 WSL 内访问）")
			} else {
				s.Log("WARN", "添加 Windows 路由失败: %v", err)
			}
		} else {
			s.Log("SUCCESS", "已为 IPsec 网段添加 Windows 路由（网关 %s）", gateway)
		}
	} else {
		s.Log("WARN", "无法获取 WSL 地址，跳过 Windows 路由: %v", err)
	}

	s.setIPsecState("up", "")
	s.Log("SUCCESS", "IPsec 隧道已建立: %s", ipsec.FormatServerPort(*cfg))
}

func (s *VPNService) setIPsecState(state, errMsg string) {
	s.mu.Lock()
	s.ipsecState = state
	s.ipsecError = errMsg
	s.mu.Unlock()
}

// stopIPsec tears the tunnel down and removes the routes it added. It is safe
// to call when no tunnel is running.
func (s *VPNService) stopIPsec() {
	s.mu.Lock()
	mgr := s.ipsecMgr
	cfg := s.ipsecCfg
	gateway := s.ipsecGateway
	s.ipsecMgr = nil
	s.ipsecCfg = nil
	s.ipsecGateway = ""
	s.ipsecState = ""
	s.ipsecError = ""
	s.mu.Unlock()

	if mgr == nil || cfg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if gateway != "" {
		_ = ipsec.RemoveRoutes(ctx, cfg.Routes, gateway)
	}
	if err := mgr.Stop(ctx, *cfg); err != nil {
		s.Log("WARN", "停止 IPsec 隧道失败: %v", err)
		return
	}
	s.Log("INFO", "IPsec 隧道已停止")
}

// resourceDisplayUser falls back to the session ID when the gateway reports no
// user name (certificate authentication often omits it).
func resourceDisplayUser(client *protocol.Client) string {
	if client.Integration != nil && client.Integration.User.Name != "" {
		return client.Integration.User.Name
	}
	return "certificate"
}

// RefreshResources re-fetches the portal resource list for the active session.
// It backs the UI's retry action after a login whose resource load failed.
func (s *VPNService) RefreshResources() (map[string]any, error) {
	s.mu.Lock()
	client := s.Client
	if client == nil || s.Status != "Connected" {
		s.mu.Unlock()
		return nil, fmt.Errorf("当前没有已连接的 VPN 会话")
	}
	s.resourceState = ResourceLoading
	s.resourceError = ""
	s.StatusDetail = "正在重新获取内网资源..."
	s.mu.Unlock()

	s.Log("INFO", "Refreshing protected resources from gateway...")
	integration, err := client.RefreshResources()
	if err != nil {
		s.mu.Lock()
		s.resourceState = ResourceError
		s.resourceError = err.Error()
		s.StatusDetail = "已连接，但获取内网资源失败"
		s.mu.Unlock()
		return nil, err
	}

	proxyMgr := proxy.NewProxyManager(client.GatewayIP, client.GatewayPort, client.SessionID, s.Log)
	if cert := client.ClientCertificate(); cert != nil {
		proxyMgr.ClientCert = cert
	}
	resources, startErr := proxyMgr.StartProxies(integration.ResourceList.TCPUDPResources)
	if startErr != nil {
		s.Log("WARN", "Proxy start partially encountered issues: %v", startErr)
	}
	webProxies, webResources := s.startWebResources(client, client.ClientCertificate(), integration.ResourceList.TCPUDPResources)

	s.mu.Lock()
	staleProxy := s.ProxyMgr
	staleWebProxies := s.WebProxies
	s.ProxyMgr = proxyMgr
	s.WebProxies = webProxies
	s.WebResources = webResources
	s.Resources = resources
	s.passwordExpiryDays = integration.User.PwdOvertime
	s.resourceState = ResourceReady
	s.resourceError = ""
	s.StatusDetail = fmt.Sprintf("Connected as %s (%d resources active, %d web)",
		resourceDisplayUser(client), len(resources), len(webResources))
	s.mu.Unlock()
	if staleProxy != nil {
		staleProxy.Stop()
	}
	for _, wp := range staleWebProxies {
		wp.Stop()
	}

	s.syncWebProxyHosts()
	s.syncSystemPAC(len(webResources) > 0)

	s.Log("SUCCESS", "Refreshed %d protected resources (%d web).", len(resources), len(webResources))
	return map[string]any{
		"status":        "Connected",
		"sessionId":     client.SessionID,
		"resourceState": string(ResourceReady),
		"resourceCount": len(resources),
		"resources":     resources,
		"webResources":  webResources,
	}, nil
}

// ListCertificates returns the certificates available for a login source.
func (s *VPNService) ListCertificates(source int) ([]certstore.CertInfo, error) {
	store := s.certStore()
	if store == nil {
		return nil, fmt.Errorf("证书目录不可用")
	}
	return store.List(certstore.Source(source))
}

// ImportCertificate copies a PKCS#12 file into the local certificate store.
// The certificate is validated with the supplied password before anything is
// written, so a wrong password never leaves a broken entry behind.
func (s *VPNService) ImportCertificate(srcPath, alias, password string) (*certstore.CertInfo, error) {
	if strings.TrimSpace(srcPath) == "" {
		return nil, fmt.Errorf("请选择证书文件")
	}
	store := s.certStore()
	if store == nil {
		return nil, fmt.Errorf("证书目录不可用")
	}
	info, err := store.ImportFile(srcPath, alias, password)
	if err != nil {
		s.Log("ERROR", "Import certificate failed: %v", err)
		return nil, err
	}
	s.Log("SUCCESS", "Imported certificate %q (ID %s)", info.Name, info.ID)
	return info, nil
}

// DeleteCertificate removes an imported file certificate.
func (s *VPNService) DeleteCertificate(id string) error {
	store := s.certStore()
	if store == nil {
		return fmt.Errorf("证书目录不可用")
	}
	if err := store.Delete(id); err != nil {
		return err
	}
	s.Log("INFO", "Deleted certificate %s", id)
	return nil
}

// LoadExternalCertificate validates a PKCS#12 file outside the store. It backs
// the CLI's "-cert /path/to/cert.p12" form, which must not copy the file.
// It is unexported because tls.Certificate cannot cross the IPC boundary; the
// frontend path uses LoginWithCertExternal instead.
func (s *VPNService) loadExternalCertificate(path, password string) (*tls.Certificate, error) {
	return certstore.LoadTLSFile(path, password)
}

func (s *VPNService) certStore() *certstore.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CertStore == nil {
		s.CertStore = newCertStore()
	}
	return s.CertStore
}

// LoginWithCert authenticates with a client certificate and establishes the
// tunnel. It mirrors Login: handshake, certificate authentication, then the
// shared resource/proxy path.
func (s *VPNService) LoginWithCert(gwIdentifier string, source int, certID, verifycode string, auto bool) (map[string]any, error) {
	store := s.certStore()
	if store == nil {
		return nil, fmt.Errorf("证书目录不可用")
	}
	cert, err := store.LoadTLS(certID, certstore.Source(source))
	if err != nil {
		s.setStatus("Error", fmt.Sprintf("加载证书失败: %v", err))
		return nil, err
	}
	return s.loginWithLoadedCert(gwIdentifier, cert, verifycode, func(gwID string) {
		// Persist the successful choice so the UI can preselect it next time.
		s.persistCertSelection(gwID, source, certID, auto)
	})
}

// LoginWithCertExternal is LoginWithCert for a certificate that lives outside
// the store (the CLI -cert <path> form). The file is loaded in place and never
// copied. It takes strings rather than a tls.Certificate because every exported
// VPNService method is also bridged to the frontend, and a tls.Certificate
// cannot cross the JSON IPC boundary.
func (s *VPNService) LoginWithCertExternal(gwIdentifier, certPath, certPassword, verifycode string) (map[string]any, error) {
	cert, err := certstore.LoadTLSFile(certPath, certPassword)
	if err != nil {
		return nil, err
	}
	return s.loginWithLoadedCert(gwIdentifier, cert, verifycode, nil)
}

// loginWithLoadedCert runs the certificate authentication and tunnel setup for
// an already loaded certificate. afterAuth, when non-nil, receives the resolved
// gateway ID after a successful authentication.
func (s *VPNService) loginWithLoadedCert(gwIdentifier string, cert *tls.Certificate, verifycode string, afterAuth func(gwID string)) (map[string]any, error) {
	var preAuth *protocol.Client
	s.mu.Lock()
	if s.Status == "Connecting" || s.Status == "Connected" {
		s.cleanupStaleSessionLocked()
	}
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}
	gwID, gwName, gwIP, gwPort, gwAlgo := gw.ID, gw.Name, gw.IP, gw.Port, gw.Algo
	s.Config.LastUseGateway = gw.Name
	// A pending password-change challenge is left alone: dropping it here
	// would throw away the session cookie a later ChangePassword needs, just
	// because a certificate login was attempted in between. Only a challenge
	// this flow itself receives (certificate -> SMS) replaces it.
	preAuth = s.pendingClientLocked(gw)
	s.mu.Unlock()

	name := certDisplayName(cert, "certificate")
	s.setStatus("Connecting", fmt.Sprintf("Certificate login to %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Initiating certificate login to %s (%s:%d), cert=%s", gwName, gwIP, gwPort, name)

	client := preAuth
	if client == nil {
		client = protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)
	}
	client.SetTLSClientCertificate(cert)

	if _, err := client.Handshake(); err != nil {
		client.ClearTLSClientCertificate()
		s.setStatus("Error", fmt.Sprintf("Handshake failed: %v", err))
		return nil, err
	}
	if err := client.AuthCertOnly(cert, verifycode); err != nil {
		if protocol.IsSMSChallenge(err) {
			// The gateway wants the SMS factor on top of the certificate
			// (certificate -> SMS chain). Keep the certificate installed on
			// the challenged client: the follow-up requests and the tunnel
			// must present the same certificate.
			s.mu.Lock()
			s.keepChallengeLocked(client, name, err, cert, afterAuth, authTypeCertificate)
			s.mu.Unlock()
		} else {
			client.ClearTLSClientCertificate()
		}
		s.setStatus("Error", fmt.Sprintf("证书认证失败: %v", err))
		return nil, err
	}

	if afterAuth != nil {
		afterAuth(gwID)
	}
	return s.enterConnected(client, name, cert, authTypeCertificate), nil
}

// persistCertSelection records the certificate login mode on the gateway.
func (s *VPNService) persistCertSelection(gwID string, source int, certID string, auto bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.Config.Gateways {
		if s.Config.Gateways[idx].ID != gwID {
			continue
		}
		s.Config.Gateways[idx].AuthType = 1 // certificate
		s.Config.Gateways[idx].CertType = source
		s.Config.Gateways[idx].CertAutoLogin = auto
		s.Config.Gateways[idx].CertWithPassword = false
		s.Config.Gateways[idx].SelectedCertID = certID
		break
	}
	if err := s.Config.SaveSettingXML(""); err != nil {
		s.Log("WARN", "Failed to save certificate selection: %v", err)
	}
}

// persistPasswordCertSelection records the two-factor "password + certificate"
// mode. authtype is kept at 0 so the gateway entry still reads as a password
// login for the original client; certwithpwd="1" is what marks the extra
// factor for this client. certautologin stays 0: a certificate alone cannot
// complete a two-factor login, so the password account's own auto flag governs.
func (s *VPNService) persistPasswordCertSelection(gwID string, source int, certID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.Config.Gateways {
		if s.Config.Gateways[idx].ID != gwID {
			continue
		}
		s.Config.Gateways[idx].AuthType = 0 // password
		s.Config.Gateways[idx].CertType = source
		s.Config.Gateways[idx].CertAutoLogin = false
		s.Config.Gateways[idx].CertWithPassword = true
		s.Config.Gateways[idx].SelectedCertID = certID
		break
	}
	if err := s.Config.SaveSettingXML(""); err != nil {
		s.Log("WARN", "Failed to save password + certificate selection: %v", err)
	}
}

// rememberPasswordMode records that the gateway was last used with password
// login. The certificate id is kept so switching back needs one click; only
// the mode flips.
func (s *VPNService) rememberPasswordMode(gwIdentifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil || (gw.AuthType == 0 && !gw.CertWithPassword) {
		return
	}
	gw.AuthType = 0
	gw.CertAutoLogin = false
	gw.CertWithPassword = false
	if err := s.Config.SaveSettingXML(""); err != nil {
		s.Log("WARN", "Failed to save authentication mode: %v", err)
	}
}

// certDisplayName is used as the "username" in the connected view and logs.
func certDisplayName(cert *tls.Certificate, fallback string) string {
	if cert != nil && cert.Leaf != nil {
		if cn := strings.TrimSpace(cert.Leaf.Subject.CommonName); cn != "" {
			return cn
		}
	}
	if fallback != "" {
		return fallback
	}
	return "certificate"
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
	storedTwoFactor := gw.CertWithPassword
	storedCertSource := gw.CertType
	storedCertID := gw.SelectedCertID
	s.Config.LastUseGateway = gw.Name
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Changing password on %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Changing password for %s on %s (%s:%d)...", username, gwName, gwIP, gwPort)

	s.mu.Lock()
	client := s.Client
	challenge := s.challengeLocked(s.Config.FindGateway(gwIdentifier), protocol.AuthStepPasswordChange)
	s.mu.Unlock()

	// The certificate that satisfied the mTLS side of a challenged two-factor
	// login; the sign-in after the password change must present it again. The
	// profile's stored selection covers a challenge that started on a client
	// this process no longer holds (ChangePassword with no live challenge).
	var challengeCert *tls.Certificate
	challengeMatches := challenge != nil && challenge.username == username
	if challengeMatches {
		challengeCert = challenge.cert
		// Reuse the HTTP client that received the 0x100 challenge; its cookie
		// jar carries VSG_SESSIONID.
		client = challenge.client
	}
	if challengeCert == nil && storedTwoFactor && storedCertID != "" && s.certStore() != nil {
		if cert, loadErr := s.certStore().LoadTLS(storedCertID, certstore.Source(storedCertSource)); loadErr == nil {
			challengeCert = cert
		}
	}
	if client == nil || client.GatewayIP != gwIP || client.GatewayPort != gwPort {
		client = protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)
		// 证书不在这里安装：口令步必须不带证书，等网关返回 0x2 证书挑战后
		// 再由 AuthCertOnly 呈递，否则握手顺序与原厂不一致。
		if _, err := client.Handshake(); err != nil {
			s.setStatus("Error", fmt.Sprintf("Handshake failed: %v", err))
			return nil, err
		}
	}

	// Ensure the client has an active session cookie (VSG_SESSIONID) required by pwdchange.
	if client.SessionID == "" {
		if _, err := client.AuthPassword(username, password, verifycode); err != nil {
			var authErr *protocol.AuthError
			isCertChallenge := errors.As(err, &authErr) &&
				protocol.NextAuthStep(authErr.Code) == protocol.AuthStepCertificate

			switch {
			case protocol.IsPasswordExpired(err):
				// 口令过期：网关已下发会话，直接进入改密。
			case isCertChallenge && challengeCert != nil:
				// 双因子网关：口令步之后必须补呈证书，会话才算完整。
				s.Log("INFO", "口令校验通过，正在补呈客户端证书以完成改密会话")
				if certErr := client.AuthCertOnly(challengeCert, verifycode); certErr != nil {
					s.setStatus("Error", fmt.Sprintf("证书认证失败: %v", certErr))
					return nil, certErr
				}
			case isCertChallenge:
				s.setStatus("Error", "该网关要求口令 + 证书双因子，但未找到可用证书")
				return nil, fmt.Errorf("该网关要求客户端证书，请先在登录页选择证书后再修改密码")
			default:
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
	if s.challenge != nil && s.challenge.client == client {
		s.challenge = nil
	}
	s.Status = "Disconnected"
	s.StatusDetail = "密码已更新，正在登录"
	s.mu.Unlock()
	s.Log("SUCCESS", "Password changed for %s; signing in with the new password", username)

	// A two-factor gateway needs the certificate on every login, so the
	// follow-up sign-in runs the full password + certificate flow again; a
	// plain password login would be rejected right after the change. The
	// follow-up must reuse the client that just changed the password: its
	// cookie jar holds the session the captcha was issued against, and a fresh
	// client resubmitting the same code is rejected.
	if challengeCert != nil {
		s.mu.Lock()
		if gw := s.Config.FindGateway(gwIdentifier); gw != nil {
			s.storePendingClientLocked(gw, client)
		}
		s.mu.Unlock()
		res, loginErr := s.loginWithPasswordCert(gwIdentifier, username, newPassword, verifycode, challengeCert, nil, remember, auto)
		if loginErr != nil {
			s.Log("WARN", "Password changed, but the follow-up two-factor login failed: %v", loginErr)
			return nil, &PasswordChangedError{Err: loginErr}
		}
		return res, nil
	}
	s.mu.Lock()
	gwProfile := s.Config.FindGateway(gwIdentifier)
	twoFactor := gwProfile != nil && gwProfile.CertWithPassword
	s.mu.Unlock()
	if twoFactor {
		s.Log("WARN", "网关要求口令 + 证书双因子，但未找到上次使用的证书，将以纯口令方式登录")
	}
	res, loginErr := s.Login(gwIdentifier, username, newPassword, verifycode, remember, auto)
	if loginErr != nil {
		s.Log("WARN", "Password changed, but the follow-up login failed: %v", loginErr)
		return nil, &PasswordChangedError{Err: loginErr}
	}
	return res, nil
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
	case protocol.AuthKindSMCRequired:
		return "sms_challenge"
	case protocol.AuthKindSMCCodeError:
		return "sms_code_error"
	case protocol.AuthKindTokenRequired:
		return "token_challenge"
	case protocol.AuthKindTokenCodeError:
		return "token_code_error"
	case protocol.AuthKindCertInvalid:
		return "cert_invalid"
	case protocol.AuthKindCertUnavailable:
		return "cert_unavailable"
	case protocol.AuthKindCertExpired:
		return "cert_expired"
	case protocol.AuthKindCertRevoked:
		return "cert_revoked"
	case protocol.AuthKindCertBadSignature:
		return "cert_signature"
	default:
		// A RESULT code asking for the certificate factor (0x2 on the
		// password step) is not a rejection: the login continues by
		// presenting a certificate on the same session (SubmitCertFactor).
		if protocol.NextAuthStep(authErr.Code) == protocol.AuthStepCertificate {
			return "cert_challenge"
		}
		return ""
	}
}

// IsPasswordExpired reports a gateway password-change challenge.
func IsPasswordExpired(err error) bool {
	return AuthErrorCode(err) == "password_expired"
}

// keepChallengeLocked records a gateway challenge so its follow-up factor can
// be submitted on the same session. The next step is read from the gateway's
// own result code (protocol.NextAuthStep), not from the calling flow, so any
// challenge this build knows how to drive — password change, SMS, and
// whatever factor is added to the switch below — is kept the same way.
//
// cert/afterAuth/authType carry what the challenged chain already presented
// (nil cert for a password-only chain); the completed login reports and
// tunnels with them. Caller holds s.mu.
func (s *VPNService) keepChallengeLocked(client *protocol.Client, username string, err error, cert *tls.Certificate, afterAuth func(gwID string), authType string) bool {
	var authErr *protocol.AuthError
	if !errors.As(err, &authErr) {
		return false
	}
	next := protocol.NextAuthStep(authErr.Code)
	switch next {
	case protocol.AuthStepPasswordChange, protocol.AuthStepSMC,
		protocol.AuthStepCertificate, protocol.AuthStepToken:
		// Follow-ups this build can drive. Anything else (machine info, ...)
		// falls through to the caller's generic error path.
	default:
		return false
	}
	s.challenge = &authChallenge{
		client:    client,
		username:  username,
		next:      next,
		cert:      cert,
		afterAuth: afterAuth,
		authType:  authType,
	}
	return true
}

// challengeLocked returns the pending challenge for a gateway whose next step
// matches, or nil. Caller holds s.mu.
func (s *VPNService) challengeLocked(gw *config.GatewayProfile, step protocol.AuthStep) *authChallenge {
	if s.challenge == nil || gw == nil {
		return nil
	}
	ch := s.challenge
	if ch.client == nil || ch.next != step ||
		ch.client.GatewayIP != gw.IP || ch.client.GatewayPort != gw.Port {
		return nil
	}
	return ch
}

// SendSMSCode asks the gateway to deliver the SMS verification code to the
// user's registered phone. It backs the login form's "发送短信" button and
// runs on the client that received the 0x8 challenge, so the code is issued
// for that exact session.
func (s *VPNService) SendSMSCode(gwIdentifier string) error {
	s.mu.Lock()
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return fmt.Errorf("gateway %q not found", gwIdentifier)
	}
	ch := s.challengeLocked(gw, protocol.AuthStepSMC)
	if ch == nil {
		s.mu.Unlock()
		return fmt.Errorf("当前没有待完成的短信认证，请重新登录")
	}
	client := ch.client
	s.mu.Unlock()

	s.Log("INFO", "Requesting SMS verification code from %s (%s:%d)...", gw.Name, gw.IP, gw.Port)
	if err := client.SendSMC(); err != nil {
		s.Log("ERROR", "Send SMS code failed: %v", err)
		return err
	}
	return nil
}

// LoginWithSMSCode completes a login the gateway challenged with the SMS
// factor: the code from the user's phone is submitted on /vpn/user/auth/smc
// over the challenged session, and on success the tunnel comes up exactly as
// after a plain login. A wrong code keeps the challenge alive for a retry.
// The hop count is the gateway's choice: a code the gateway accepts can be
// answered with yet another challenge (for instance a password change), which
// is kept and surfaced the same way as the SMS hop was.
func (s *VPNService) LoginWithSMSCode(gwIdentifier, code string) (map[string]any, error) {
	s.mu.Lock()
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}
	ch := s.challengeLocked(gw, protocol.AuthStepSMC)
	if ch == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("当前没有待完成的短信认证，请重新登录")
	}
	client, username, cert, afterAuth, authType := ch.client, ch.username, ch.cert, ch.afterAuth, ch.authType
	gwID, gwName := gw.ID, gw.Name
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Submitting SMS verification code to %s (%s:%d)...", gwName, client.GatewayIP, client.GatewayPort))
	s.Log("INFO", "Submitting SMS verification code for user %s", username)

	if _, err := client.AuthSMC(code); err != nil {
		s.mu.Lock()
		if protocol.IsSMCCodeError(err) {
			// A wrong code: the challenge stays live for an in-place retry.
		} else if !s.keepChallengeLocked(client, username, err, cert, afterAuth, authType) {
			// The code was accepted but the gateway asks for a factor this
			// build cannot drive (for instance a token): the SMS hop is
			// consumed either way, so the stale challenge must go.
			s.challenge = nil
		}
		s.mu.Unlock()
		s.setStatus("Error", fmt.Sprintf("短信认证失败: %v", err))
		return nil, err
	}

	// The challenge is consumed; nothing else may submit against this session.
	s.mu.Lock()
	if s.challenge == ch {
		s.challenge = nil
	}
	s.mu.Unlock()

	// The chain the challenge grew out of decides how the completed login is
	// recorded: its afterAuth persists the flow's mode selection (password +
	// certificate, certificate), and a password-only chain keeps the password
	// mode of record.
	if afterAuth != nil {
		afterAuth(gwID)
	} else {
		s.rememberPasswordMode(gwName)
	}
	return s.enterConnected(client, username, cert, authType), nil
}

// LoginWithToken completes a login the gateway challenged with the
// dynamic-token (OTP) factor: the code from the user's hardware or software
// token is submitted on /vpn/user/auth/token over the challenged session, and
// on success the tunnel comes up exactly as after a plain login. A wrong code
// keeps the challenge alive for a retry. The hop count is the gateway's
// choice: an accepted code can be answered with yet another challenge, which
// is kept and surfaced the same way the token hop was.
func (s *VPNService) LoginWithToken(gwIdentifier, code string) (map[string]any, error) {
	s.mu.Lock()
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}
	ch := s.challengeLocked(gw, protocol.AuthStepToken)
	if ch == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("当前没有待完成的动态令牌认证，请重新登录")
	}
	client, username, cert, afterAuth, authType := ch.client, ch.username, ch.cert, ch.afterAuth, ch.authType
	gwID, gwName := gw.ID, gw.Name
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Submitting dynamic token code to %s (%s:%d)...", gwName, client.GatewayIP, client.GatewayPort))
	s.Log("INFO", "Submitting dynamic token code for user %s", username)

	if _, err := client.AuthToken(code); err != nil {
		s.mu.Lock()
		if protocol.IsTokenCodeError(err) {
			// A wrong code: the challenge stays live for an in-place retry.
		} else if !s.keepChallengeLocked(client, username, err, cert, afterAuth, authType) {
			// The code was accepted but the gateway asks for a factor this
			// build cannot drive: the token hop is consumed either way, so
			// the stale challenge must go.
			s.challenge = nil
		}
		s.mu.Unlock()
		s.setStatus("Error", fmt.Sprintf("动态令牌认证失败: %v", err))
		return nil, err
	}

	// The challenge is consumed; nothing else may submit against this session.
	s.mu.Lock()
	if s.challenge == ch {
		s.challenge = nil
	}
	s.mu.Unlock()

	if afterAuth != nil {
		afterAuth(gwID)
	} else {
		s.rememberPasswordMode(gwName)
	}
	return s.enterConnected(client, username, cert, authType), nil
}

// SubmitCertFactor answers a gateway certificate challenge — the password step
// returned RESULT code 0x2 — by presenting the chosen certificate on
// /vpn/user/auth/cert over the challenged session. The hop count is the
// gateway's choice: the certificate step's response goes through the same
// dispatch as every other factor, so it may complete the login, ask for the
// SMS factor, or open a password change. A rejected certificate keeps the
// challenge live so the user can pick another one and retry.
func (s *VPNService) SubmitCertFactor(gwIdentifier string, source int, certID, verifycode string) (map[string]any, error) {
	store := s.certStore()
	if store == nil {
		return nil, fmt.Errorf("证书目录不可用")
	}
	cert, err := store.LoadTLS(certID, certstore.Source(source))
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}
	ch := s.challengeLocked(gw, protocol.AuthStepCertificate)
	if ch == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("当前没有待完成的证书认证，请重新登录")
	}
	client, username := ch.client, ch.username
	gwID := gw.ID
	s.mu.Unlock()

	s.setStatus("Connecting", fmt.Sprintf("Presenting client certificate to %s (%s:%d)...", gw.Name, client.GatewayIP, client.GatewayPort))
	s.Log("INFO", "Submitting the certificate factor for user %s, cert=%s", username, certDisplayName(cert, "certificate"))

	// The certificate factor was presented; a challenge that follows on this
	// step (SMS, password change) completes as a password + certificate
	// session, and the selection is persisted once the chain finishes.
	afterAuth := func(id string) { s.persistPasswordCertSelection(id, source, certID) }

	if err := client.AuthCertOnly(cert, verifycode); err != nil {
		s.mu.Lock()
		if protocol.IsCertAuthError(err) {
			// The certificate itself was rejected; the challenge stays live
			// so the user can pick another certificate and retry.
		} else if !s.keepChallengeLocked(client, username, err, cert, afterAuth, authTypePasswordCertificate) {
			// The certificate was accepted but the gateway asks for a factor
			// this build cannot drive (for instance a token): the
			// certificate hop is consumed either way, so the stale challenge
			// must go.
			s.challenge = nil
		}
		s.mu.Unlock()
		s.setStatus("Error", fmt.Sprintf("证书认证失败: %v", err))
		return nil, err
	}

	// The challenge is consumed; nothing else may submit against this session.
	s.mu.Lock()
	if s.challenge == ch {
		s.challenge = nil
	}
	s.mu.Unlock()

	afterAuth(gwID)
	return s.enterConnected(client, username, cert, authTypePasswordCertificate), nil
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

// cleanupStaleSessionLocked shuts down any active or connecting session before a
// fresh authentication begins, so reconnect attempts never fail with "already connected".
// Caller holds s.mu; this drops and reacquires s.mu while stopping network proxies.
func (s *VPNService) cleanupStaleSessionLocked() {
	if s.Status != "Connecting" && s.Status != "Connected" {
		return
	}
	s.Log("WARN", "Tearing down existing session (status: %s) to start fresh login attempt", s.Status)
	oldClient := s.Client
	oldProxy := s.ProxyMgr
	s.Client = nil
	s.ProxyMgr = nil
	s.challenge = nil
	s.Status = "Disconnected"
	s.StatusDetail = "Disconnected"
	s.Resources = nil
	s.IPsecResources = nil
	s.resourceState = ""
	s.resourceError = ""
	s.mu.Unlock()

	if oldProxy != nil {
		oldProxy.Stop()
	}
	if oldClient != nil {
		_ = oldClient.Logout()
	}

	s.mu.Lock()
}

// Logout disconnects the VPN tunnel
func (s *VPNService) Logout() (bool, error) {
	s.mu.Lock()
	proxyMgr := s.ProxyMgr
	webProxies := s.WebProxies
	client := s.Client
	s.ProxyMgr = nil
	s.WebProxies = nil
	s.WebResources = nil
	s.Client = nil
	s.challenge = nil
	s.pendingClients = nil
	s.Status = "Disconnected"
	s.StatusDetail = "Disconnected"
	s.Resources = nil
	s.IPsecResources = nil
	s.resourceState = ""
	s.resourceError = ""
	s.passwordExpiryDays = 0
	s.loginNotice = ""
	fn := s.OnStatusChange
	s.mu.Unlock()

	if fn != nil {
		go fn("Disconnected")
	}

	s.Log("INFO", "Tearing down VPN session...")

	s.stopIPsec()

	if proxyMgr != nil {
		proxyMgr.Stop()
	}
	for _, wp := range webProxies {
		wp.Stop()
	}

	// 断开即还原系统代理，避免残留 PAC 指向一个已停止的服务。
	s.disableSystemPAC()

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
		"status":             s.Status,
		"statusDetail":       s.StatusDetail,
		"authType":           s.authType,
		"resources":          s.Resources,
		"webResources":       s.WebResources,
		"ipsecResources":     s.IPsecResources,
		"ipsecState":         s.ipsecState,
		"ipsecError":         s.ipsecError,
		"resourceState":      string(s.resourceState),
		"resourceError":      s.resourceError,
		"passwordExpiryDays": s.passwordExpiryDays,
		"loginNotice":        s.loginNotice,
		"lastUseGateway":     s.Config.LastUseGateway,
		"logCount":           logCount,
	}
}

// GetLogs returns all logged messages
// UserDataDir 返回 setting.xml 所在的每用户目录（未设置时为空）。
//
// 由 ATrustHost 接口使用：aTrust 后端要在同一目录下存设备标识文件。
// 这里只是把 config 包级的取值转出去，不引入额外状态。
func (s *VPNService) UserDataDir() string { return config.UserDataDir() }

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

// pendingClientKey identifies one gateway endpoint. Editing the profile changes
// the key, so an image fetched before the edit can never be used for the new
// target.
func pendingClientKey(gw *config.GatewayProfile) string {
	return fmt.Sprintf("%s|%s|%d|%d", gw.ID, gw.IP, gw.Port, gw.Algo)
}

// pendingClientLocked returns the pre-auth client for gw without consuming it,
// so a failed password/captcha attempt can reuse the same captcha session.
// Caller holds s.mu.
func (s *VPNService) pendingClientLocked(gw *config.GatewayProfile) *protocol.Client {
	key := pendingClientKey(gw)
	entry := s.pendingClients[key]
	if entry == nil {
		return nil
	}
	if time.Since(entry.createdAt) > pendingClientTTL {
		delete(s.pendingClients, key)
		return nil
	}
	return entry.client
}

// storePendingClientLocked records the client that fetched the captcha image.
// Caller holds s.mu.
func (s *VPNService) storePendingClientLocked(gw *config.GatewayProfile, client *protocol.Client) {
	if s.pendingClients == nil {
		s.pendingClients = make(map[string]*preAuthClient)
	}
	now := time.Now()
	for key, entry := range s.pendingClients {
		if now.Sub(entry.createdAt) > pendingClientTTL {
			delete(s.pendingClients, key)
		}
	}
	s.pendingClients[pendingClientKey(gw)] = &preAuthClient{client: client, createdAt: now}
}

// clearPendingClientLocked drops the pre-auth client once a login succeeds.
// Caller holds s.mu.
func (s *VPNService) clearPendingClientLocked(client *protocol.Client) {
	for key, entry := range s.pendingClients {
		if entry.client == client {
			delete(s.pendingClients, key)
		}
	}
}

// GetVerifyCodeImage fetches the graphical captcha image from the target gateway
// and returns a data URL format string (e.g. data:image/png;base64,...).
//
// The client that fetched the image is kept as a pre-auth client: the code is
// bound to the VSG_SESSIONID cookie issued by this response, and the login that
// submits it must use the same cookie jar. It is never stored in s.Client,
// which belongs to the connected session.
func (s *VPNService) GetVerifyCodeImage(gwIdentifier string) (string, error) {
	s.mu.Lock()
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil {
		s.mu.Unlock()
		return "", fmt.Errorf("未找到网关配置: %s", gwIdentifier)
	}
	gwCopy := *gw
	client := s.pendingClientLocked(&gwCopy)
	if client == nil {
		client = protocol.NewClient(gwCopy.IP, gwCopy.Port, gwCopy.Algo, s.Log)
	}
	s.mu.Unlock()

	data, contentType, err := client.FetchVerifyCode()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.storePendingClientLocked(&gwCopy, client)
	s.mu.Unlock()

	b64 := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", contentType, b64), nil
}
