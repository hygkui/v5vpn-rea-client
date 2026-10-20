package service

import (
	"context"
	"crypto/tls"
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
	CertStore         *certstore.Store
	Status            string // "Disconnected", "Connecting", "Connected", "Error"
	StatusDetail      string
	Resources         []protocol.VPNResource
	resourceState     ResourceLoadState
	resourceError     string
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
			if gw.AuthType == 0 && gw.SelectedCertID == "" && gw.CertType == 0 && !gw.CertAutoLogin {
				gw.AuthType = existing.AuthType
				gw.CertType = existing.CertType
				gw.CertAutoLogin = existing.CertAutoLogin
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
	s.passwordChallenge = nil

	if remember {
		s.storeAccountLocked(gw, username, password, remember, auto)
		_ = s.Config.SaveSettingXML("")
	}
	s.mu.Unlock()

	// Password login is now the gateway's mode of record; the certificate
	// selection is kept for a one-click switch back.
	s.rememberPasswordMode(gwName)

	s.setStatus("Connecting", fmt.Sprintf("Connecting to %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Initiating login sequence to %s (%s:%d)...", gwName, gwIP, gwPort)

	client := protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)

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

	return s.enterConnected(client, username, nil), nil
}

// ResourceLoadState is exposed to the UI while the portal resource list loads.
type ResourceLoadState string

const (
	ResourceLoading ResourceLoadState = "loading"
	ResourceReady   ResourceLoadState = "ready"
	ResourceError   ResourceLoadState = "error"
)

// enterConnected publishes the connected state immediately after a successful
// authentication and loads the resource list in the background.
func (s *VPNService) enterConnected(client *protocol.Client, username string, cert *tls.Certificate) map[string]any {
	s.mu.Lock()
	s.Client = client
	s.Resources = nil
	s.resourceState = ResourceLoading
	s.resourceError = ""
	s.Status = "Connected"
	s.StatusDetail = "已连接，正在拉取内网资源..."
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
		"authType":      authTypeFor(cert),
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
	if staleProxy != nil {
		staleProxy.Stop()
	}

	s.mu.Lock()
	if s.Client != client {
		s.mu.Unlock()
		proxyMgr.Stop()
		return
	}
	s.ProxyMgr = proxyMgr
	s.Resources = resources
	s.resourceState = ResourceReady
	s.resourceError = ""
	s.StatusDetail = fmt.Sprintf("Connected as %s (%d resources active)", resourceDisplayUser(client), len(resources))
	s.mu.Unlock()

	s.Log("SUCCESS", "Loaded %d protected resources.", len(resources))
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

	s.mu.Lock()
	staleProxy := s.ProxyMgr
	s.ProxyMgr = proxyMgr
	s.Resources = resources
	s.resourceState = ResourceReady
	s.resourceError = ""
	s.StatusDetail = fmt.Sprintf("Connected as %s (%d resources active)", resourceDisplayUser(client), len(resources))
	s.mu.Unlock()
	if staleProxy != nil {
		staleProxy.Stop()
	}

	s.Log("SUCCESS", "Refreshed %d protected resources.", len(resources))
	return map[string]any{
		"status":        "Connected",
		"sessionId":     client.SessionID,
		"resourceState": string(ResourceReady),
		"resourceCount": len(resources),
		"resources":     resources,
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
func (s *VPNService) LoginWithCertExternal(gwIdentifier, certPath, certPassword string) (map[string]any, error) {
	cert, err := certstore.LoadTLSFile(certPath, certPassword)
	if err != nil {
		return nil, err
	}
	return s.loginWithLoadedCert(gwIdentifier, cert, "", nil)
}

// loginWithLoadedCert runs the certificate authentication and tunnel setup for
// an already loaded certificate. afterAuth, when non-nil, receives the resolved
// gateway ID after a successful authentication.
func (s *VPNService) loginWithLoadedCert(gwIdentifier string, cert *tls.Certificate, verifycode string, afterAuth func(gwID string)) (map[string]any, error) {
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
	s.passwordChallenge = nil
	s.mu.Unlock()

	name := certDisplayName(cert, "certificate")
	s.setStatus("Connecting", fmt.Sprintf("Certificate login to %s (%s:%d)...", gwName, gwIP, gwPort))
	s.Log("INFO", "Initiating certificate login to %s (%s:%d), cert=%s", gwName, gwIP, gwPort, name)

	client := protocol.NewClient(gwIP, gwPort, gwAlgo, s.Log)
	client.SetTLSClientCertificate(cert)

	if _, err := client.Handshake(); err != nil {
		s.setStatus("Error", fmt.Sprintf("Handshake failed: %v", err))
		return nil, err
	}
	if err := client.AuthCertOnly(cert, verifycode); err != nil {
		s.setStatus("Error", fmt.Sprintf("证书认证失败: %v", err))
		return nil, err
	}

	if afterAuth != nil {
		afterAuth(gwID)
	}
	return s.enterConnected(client, name, cert), nil
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
		s.Config.Gateways[idx].SelectedCertID = certID
		break
	}
	if err := s.Config.SaveSettingXML(""); err != nil {
		s.Log("WARN", "Failed to save certificate selection: %v", err)
	}
}

// rememberPasswordMode records that the gateway was last used with password
// login. The certificate id is kept so switching back needs one click; only
// the mode flips.
func (s *VPNService) rememberPasswordMode(gwIdentifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	gw := s.Config.FindGateway(gwIdentifier)
	if gw == nil || gw.AuthType == 0 {
		return
	}
	gw.AuthType = 0
	gw.CertAutoLogin = false
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

// authTypeFor reports which authentication produced the session.
func authTypeFor(cert *tls.Certificate) string {
	if cert != nil {
		return "certificate"
	}
	return "password"
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
	s.passwordChallenge = nil
	s.Status = "Disconnected"
	s.StatusDetail = "Disconnected"
	s.Resources = nil
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
	client := s.Client
	s.ProxyMgr = nil
	s.Client = nil
	s.passwordChallenge = nil
	s.Status = "Disconnected"
	s.StatusDetail = "Disconnected"
	s.Resources = nil
	s.resourceState = ""
	s.resourceError = ""
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
		"resourceState":  string(s.resourceState),
		"resourceError":  s.resourceError,
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
