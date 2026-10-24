package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/egoist/mygo"
	"github.com/hygkui/v5vpn-rea-client/internal/certstore"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/service"
)

//go:embed all:ui
var uiEmbedFS embed.FS

// AppName MUST match mygo.json "name". `mygo build` embeds that value in
// the executable's version resource and mygo.App.Name() reads it from there;
// a plain `go build` has no resource, so main sets it explicitly with
// mygo.App.SetName. Without that, developer builds derive the name from the
// executable and store setting.xml under a different directory than the
// released binary. TestAppNameMatchesMygoJSON guards the pair.
const AppName = "v5vpn-rea"

// AppVersion MUST match mygo.json "version" (with "v" prefix); the
// TestAppVersionMatchesMygoJSON test fails the build if they drift.
// NOTE: "2.0" is the gateway protocol version (/vpn/version.xml), not the
// app version — do not "fix" this back to v2.0.0.
var AppVersion = "v0.6.0"

var mainWindow *mygo.Window

// 窗口尺寸按视图分别记忆（登录 / 已连接 / 设置）：用户手动调整过某个视图
// 后，切回该视图或重启客户端都会恢复对应尺寸。
var (
	windowSizes     = map[string][2]int{}
	windowStatePath string
	currentView     = "login"
)

func loadWindowSizes() {
	dir := config.UserDataDir()
	if dir == "" {
		return
	}
	windowStatePath = filepath.Join(dir, "window-sizes.json")
	if data, err := os.ReadFile(windowStatePath); err == nil {
		_ = json.Unmarshal(data, &windowSizes) // 文件损坏则忽略，回退默认尺寸
	}
}

func persistWindowSizes() {
	if windowStatePath == "" || len(windowSizes) == 0 {
		return
	}
	data, err := json.MarshalIndent(windowSizes, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(windowStatePath, data, 0o600)
}

func windowSizeFor(mode string, defW, defH int) (int, int) {
	if s, ok := windowSizes[mode]; ok && s[0] >= 320 && s[1] >= 400 {
		return s[0], s[1]
	}
	return defW, defH
}

// captureWindowSize 记录当前视图的窗口尺寸，必须在主线程调用。
func captureWindowSize(w *mygo.Window) {
	if w == nil || w.IsDestroyed() {
		return
	}
	width, height := w.Size()
	if width <= 0 || height <= 0 {
		return
	}
	windowSizes[currentView] = [2]int{width, height}
}

// applyWindowView 先记录当前视图的尺寸，再应用目标视图记住的尺寸。
func applyWindowView(mode string) {
	if mainWindow == nil || mainWindow.IsDestroyed() {
		return
	}
	captureWindowSize(mainWindow)
	switch mode {
	case "login":
		w, h := windowSizeFor("login", 460, 718)
		mainWindow.SetSize(w, h)
		mainWindow.Center()
	case "connected":
		w, h := windowSizeFor("connected", 1248, 832)
		mainWindow.SetSize(w, h)
		mainWindow.Center()
	case "settings":
		w, h := windowSizeFor("settings", 920, 660)
		mainWindow.SetSize(w, h)
		mainWindow.Center()
	default:
		return
	}
	currentView = mode
	persistWindowSizes()
}

func init() {
	attachConsole()
}

// mustReadIcon reads an embedded UI asset, returning nil when it is missing so
// the tray falls back to its drawn emblem.
func mustReadIcon(fsys fs.FS, name string) []byte {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil
	}
	return data
}

func main() {
	// Command-line flags
	cliMode := flag.Bool("cli", false, "Run in CLI/headless mode without desktop GUI")
	dumpPasswords := flag.Bool("dump-passwords", false, "Print all decrypted usernames and passwords from V5VPN settings")
	connectGW := flag.String("connect", "", "Connect to gateway by name or IP in CLI mode")
	userFlag := flag.String("user", "", "Username for CLI connection (defaults to remembered user)")
	pwdFlag := flag.String("pwd", "", "Password for CLI connection (defaults to remembered password)")
	newPwdFlag := flag.String("new-pwd", "", "New password when the gateway requires a password change")
	forceFlag := flag.Bool("force", false, "Force password change even if current password is not expired")
	httpPort := flag.Int("port", 0, "Serve web UI on custom HTTP port (0 for auto)")
	certFlag := flag.String("cert", "", "Certificate login: imported certificate ID/alias, or a .p12/.pfx path")
	certPwdFlag := flag.String("cert-pwd", "", "Private key password for an external certificate file")
	certTypeFlag := flag.Int("cert-type", 0, "Certificate source: 0 imported file (2 USB key, not yet supported)")
	// -pwd-cert switches -cert from certificate-only to the two-factor
	// "password + certificate" login, which also needs -user and -pwd.
	pwdCertFlag := flag.Bool("pwd-cert", false, "Combine -cert with -user/-pwd: gateway requires both factors")
	verifyCodeFlag := flag.String("code", "", "Verification code / captcha (if requested by gateway)")
	listCertsFlag := flag.Bool("list-certs", false, "List installed certificates and exit")
	importCertFlag := flag.String("import-cert", "", "Import a .p12/.pfx file into the local certificate store and exit")
	certAliasFlag := flag.String("cert-alias", "", "Display alias used with -import-cert")
	flag.Parse()

	// Resolve the per-user data directory BEFORE anything loads setting.xml.
	// NewVPNService calls config.LoadSettingXML("") in its constructor, so
	// registering the directory afterwards left every mode (GUI and CLI)
	// reading the working directory / exe directory instead of the file this
	// build actually writes to. The loader also needs this for the
	// -dump-passwords path, which returns before the GUI ever starts.
	//
	// SetName makes PathUserData resolve to the same directory for every build
	// flavor: mygo build reads the name from the version resource it embeds,
	// while a plain go build would otherwise fall back to the executable name
	// (v5vpn-rea.exe → %APPDATA%\v5vpn-rea.exe). It must run before Path,
	// which uses the name to build the directory.
	mygo.App.SetName(AppName)
	if dataDir, err := mygo.App.Path(mygo.PathUserData); err == nil && dataDir != "" {
		config.SetUserDataDir(dataDir)
	}
	// 用户上次调整过的窗口尺寸（按视图分别记忆）。
	loadWindowSizes()

	// Handle password dumping
	if *dumpPasswords {
		runDumpPasswords()
		return
	}

	// Sub-filesystem for UI files (stripping "ui/" prefix)
	uiFS, err := fs.Sub(uiEmbedFS, "ui")
	if err != nil {
		log.Fatalf("Failed to initialize embedded UI: %v", err)
	}

	vpnService := service.NewVPNService(func(msg string) {
		// Log handler for CLI output
		if *cliMode {
			fmt.Println(msg)
		}
	})
	vpnService.SetAppVersion(AppVersion)

	// Certificate inventory and import run before any UI/network work.
	if *listCertsFlag {
		runListCertificates(vpnService)
		return
	}
	if *importCertFlag != "" {
		runImportCertificate(vpnService, *importCertFlag, *certAliasFlag, *certPwdFlag)
		return
	}

	// CLI Connect Mode
	if *cliMode && *connectGW != "" {
		if *certFlag != "" {
			runCLIConnectWithCert(vpnService, *connectGW, *certFlag, *certPwdFlag, *certTypeFlag, *userFlag, *pwdFlag, *verifyCodeFlag, *pwdCertFlag)
			return
		}
		runCLIConnect(vpnService, *connectGW, *userFlag, *pwdFlag, *newPwdFlag, *verifyCodeFlag, *forceFlag)
		return
	}

	// If CLI flag specified with -list
	if *cliMode {
		runCLIList(vpnService)
		return
	}

	// Setup local HTTP server for Webview and browser fallback
	serverPort := 45678
	if *httpPort > 0 {
		serverPort = *httpPort
	}

	// aTrust 后端与 V5VPN 并列。它借用 VPNService 的配置与日志
	// （ATrustHost 接口），但连接状态完全独立。
	atrustService := service.NewATrustService(vpnService)
	svcPair := &backends{v5vpn: vpnService, atrust: atrustService}

	actualPort := startHTTPServer(serverPort, uiFS, vpnService, atrustService)
	// PAC 必须能被系统浏览器访问，地址基于实际监听端口生成。
	vpnService.SetLocalPort(actualPort)

	// Initialize MyGo Desktop Framework
	log.Printf("Starting V5VPN Client with MyGo framework...")
	// Belt-and-braces: even if a quit is triggered by a code path that
	// forgets to call vpnService.Logout(), the OnBeforeQuit hook fires before the process exits
	// and tears the VPN tunnel down so the gateway does not see an
	// orphan session on the next reconnect.
	//
	// 只登出当前有会话的后端（§14.5.2 边界三）：aTrust 未连接时
	// 不该在 V5VPN 的日志里留一条 "Tearing down VPN session"。
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		svcPair.logoutActive()
	})
	mygo.BindAs("VPNService", vpnService)
	// 名字必须与 VPNService 不同：mygo 按服务名注册，同名会 panic。
	mygo.BindAs("ATrustService", atrustService)
	mygo.SetFrontend(uiFS)

	mygo.App.WhenReady(func() {
		startW, startH := windowSizeFor("login", 460, 718)
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:  fmt.Sprintf("V5VPN 现代客户端 %s (MyGo)", AppVersion),
			Width:  startW,
			Height: startH,
			// 两套界面按协议分家后没有统一的 /index.html，先打开哪一套
			// 取决于上次使用的网关协议（见 ui_routes.go）。
			URL: fmt.Sprintf("http://127.0.0.1:%d%s", actualPort, initialUIPath(vpnService.GetConfig())),
		})
		mainWindow = win
		var isExiting bool

		// The tray mirrors the application icon: the colored shield while a
		// session is up, a desaturated copy while disconnected.
		trayIconConnected, trayIconDisconnected := buildTrayIcons(
			mustReadIcon(uiFS, "icon.png"),
		)

		if win != nil {
			log.Printf("V5VPN desktop window opened successfully.")
			if iconData, err := fs.ReadFile(uiFS, "icon.png"); err == nil && len(iconData) > 0 {
				_ = win.SetIcon(iconData)
			}
			// Ask user whether to minimize to tray or completely quit
			win.OnClose(func(e *mygo.CloseEvent) {
				if isExiting {
					return
				}
				e.PreventDefault()
				go func() {
					res, err := mygo.Dialog.Message(mygo.MessageOptions{
						Parent:        win,
						Title:         "V5VPN 客户端",
						Message:       "请选择关闭操作",
						Detail:        "“最小化到托盘”将保持 VPN 并在后台运行；“完全退出”将断开连接并完全退出程序。",
						Buttons:       []string{"最小化到托盘", "完全退出", "取消"},
						DefaultButton: 0,
						CancelButton:  2,
					})
					if err != nil {
						mygo.RunOnMain(func() { win.Hide() })
						return
					}
					switch res.Button {
					case 0: // 最小化到托盘
						mygo.RunOnMain(func() {
							win.Hide()
							log.Printf("Window minimized to system tray.")
						})
					case 1: // 完全退出（可选是否重启用于自更新）
						log.Printf("Exiting V5VPN client upon user confirmation...")
						isExiting = true
						svcPair.logoutActive()
						mygo.RunOnMain(func() {
							captureWindowSize(win)
							persistWindowSizes()
							win.Destroy()
							mygo.App.Quit()
							os.Exit(0)
						})
					case 2: // 取消
						// User cancelled close
					}
				}()
			})
		}

		// Setup System Tray with the application icon
		tray, trayErr := mygo.NewTray(mygo.TrayOptions{
			Icon:    trayIconDisconnected,
			Title:   "V5VPN",
			ToolTip: "V5VPN 客户端 (未连接)",
		})
		if trayErr != nil {
			log.Printf("Notice: Tray icon initialization: %v", trayErr)
			return
		}

		// Function to update tray menu with real-time connection status.
		//
		// 两个后端都要看：只看 V5VPN 会让 aTrust 已连接时托盘显示"未连接"，
		// 并且菜单里会给出"登录 VPN"而不是"断开 VPN"。
		updateTray := func() {
			v5st := vpnService.GetStatus()
			v5Status, _ := v5st["status"].(string)
			atst := atrustService.GetStatus()
			atStatus, _ := atst["status"].(string)

			v5Conn := v5Status == "Connected"
			atConn := atStatus == "Connected"
			v5Busy := v5Status == "Connecting"
			atBusy := atStatus == "Connecting"

			var statusLabel string
			var isConn bool

			switch {
			case v5Conn:
				// GetStatus already carries the gateway name; copying the whole
				// config here would deep-copy every gateway and cleartext
				// password on each status change just to read one field.
				gwName, _ := v5st["lastUseGateway"].(string)
				statusLabel = fmt.Sprintf("状态: 已连接 [%s]", gwName)
				isConn = true
				tray.SetToolTip(fmt.Sprintf("V5VPN - 已连接 [%s]", gwName))
				_ = tray.SetIcon(trayIconConnected, false)
			case atConn:
				gwName, _ := atst["lastUseGateway"].(string)
				statusLabel = fmt.Sprintf("状态: 已连接 [%s · aTrust]", gwName)
				isConn = true
				tray.SetToolTip(fmt.Sprintf("V5VPN - 已连接 [%s · aTrust]", gwName))
				_ = tray.SetIcon(trayIconConnected, false)
			case v5Busy || atBusy:
				statusLabel = "状态: 正在连接..."
				tray.SetToolTip("V5VPN - 正在连接...")
				_ = tray.SetIcon(trayIconDisconnected, false)
			default:
				statusLabel = "状态: 未连接"
				tray.SetToolTip("V5VPN - 未连接")
				_ = tray.SetIcon(trayIconDisconnected, false)
			}

			menuItems := []*mygo.MenuItem{
				{
					Label:    statusLabel,
					Disabled: true,
				},
				mygo.Separator(),
				{
					Label: "显示主界面",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						if win != nil {
							win.Show()
							win.Restore()
							win.Focus()
						}
					},
				},
				{
					Label: "检查更新...",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						go func() {
							info := vpnService.CheckForUpdates()
							if info.Error != "" {
								res, err := mygo.Dialog.Message(mygo.MessageOptions{
									Parent:  win,
									Title:   "检查更新",
									Message: "检查更新失败",
									Detail:  info.Error,
									Buttons: []string{"确定", "前往 GitHub 查看"},
								})
								if err == nil && res.Button == 1 {
									_ = vpnService.OpenURL(info.ReleaseURL)
								}
								return
							}

							if info.HasUpdate {
								detail := fmt.Sprintf("当前版本: %s\n最新版本: %s\n\n更新说明:\n%s", info.CurrentVersion, info.LatestVersion, info.ReleaseNotes)
								res, err := mygo.Dialog.Message(mygo.MessageOptions{
									Parent:        win,
									Title:         "发现新版本",
									Message:       fmt.Sprintf("发现新版本 %s！", info.LatestVersion),
									Detail:        detail,
									Buttons:       []string{"前往下载", "稍后再说"},
									DefaultButton: 0,
									CancelButton:  1,
								})
								if err == nil && res.Button == 0 {
									_ = vpnService.OpenURL(info.ReleaseURL)
								}
							} else {
								_, _ = mygo.Dialog.Message(mygo.MessageOptions{
									Parent:  win,
									Title:   "检查更新",
									Message: "当前已是最新版本",
									Detail:  fmt.Sprintf("当前版本 %s 已是最新版本，无需更新。", info.CurrentVersion),
									Buttons: []string{"确定"},
								})
							}
						}()
					},
				},
				mygo.Separator(),
			}

			if isConn {
				menuItems = append(menuItems, &mygo.MenuItem{
					Label: "断开 VPN",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						// 只断开有会话的那一个（可能是 V5VPN，也可能是 aTrust）。
						go svcPair.logoutActive()
					},
				})
			} else {
				menuItems = append(menuItems, &mygo.MenuItem{
					Label: "登录 VPN",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						if win != nil {
							win.Show()
							win.Restore()
							win.Focus()
						}
					},
				})
			}

			menuItems = append(menuItems,
				mygo.Separator(),
				&mygo.MenuItem{
					Label: "完全退出",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						go func() {
							isExiting = true
							svcPair.logoutActive()
							mygo.RunOnMain(func() {
								captureWindowSize(win)
								persistWindowSizes()
								if win != nil {
									win.Destroy()
								}
								mygo.App.Quit()
								os.Exit(0)
							})
						}()
					},
				},
			)

			tray.SetMenu(mygo.NewMenu(menuItems))
		}

		// Initial menu setup
		updateTray()

		// Left click on tray brings window to front
		tray.OnClick(func() {
			if win != nil {
				win.Show()
				win.Restore()
				win.Focus()
			}
		})

		// Right click on tray opens context menu
		tray.OnRightClick(func() {
			tray.PopUpMenu()
		})

		// Update tray and notify UI reactively on status change without polling
		vpnService.OnStatusChange = func(status string) {
			mygo.RunOnMain(func() {
				updateTray()
				if mainWindow != nil && !mainWindow.IsDestroyed() {
					if status == "Disconnected" {
						applyWindowView("login")
						page := mainWindow.Page()
						if page != nil {
							_, _ = page.Eval("window.onVPNDisconnected && window.onVPNDisconnected()")
						}
					}
				}
			})
		}
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatalf("MyGo application terminated with error: %v", err)
	}
}

// startHTTPServer starts the local REST and asset server.
//
// atrustSvc 单独传入而不是塞进 VPNService：两条后端在 service 层就是
// 并列的独立类型，捆绑会让"改 aTrust 不会碰到 V5VPN"这条边界失效。
func startHTTPServer(port int, uiFS fs.FS, vpnService *service.VPNService, atrustSvc *service.ATrustService) int {
	mux := newAPIRouter(uiFS, vpnService, atrustSvc)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("Failed to bind local HTTP server: %v", err)
		}
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port

	go func() {
		log.Printf("UI Bridge server listening at http://127.0.0.1:%d", actualPort)
		if err := http.Serve(ln, mux); err != nil {
			log.Printf("HTTP server terminated: %v", err)
		}
	}()
	return actualPort
}

// newAPIRouter 构造全部路由，不监听端口。
//
// 单独抽出来是为了可测：路由表里最容易出错的是"请求被送到了错误的
// 后端"这种接线错误，而不是任何单个 handler 的逻辑。能在不启监听、
// 不建窗口的前提下用 httptest 打进来，这类错误才能被测试覆盖。
func newAPIRouter(uiFS fs.FS, vpnService *service.VPNService, atrustSvc *service.ATrustService) *http.ServeMux {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cfg := vpnService.GetConfig()
		resp := map[string]any{
			"gateways":       cfg.Gateways,
			"lastUseGateway": cfg.LastUseGateway,
			"remember":       cfg.Remember,
			"autoLogin":      cfg.AutoLogin,
			"sourcePath":     cfg.SourcePath,
			"appVersion":     AppVersion,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		st := vpnService.GetStatus()
		st["appVersion"] = AppVersion

		// 两个后端都有会话时，UI 需要知道该渲染哪一份资源表。
		// 这里把"当前激活的后端"一并给出：V5VPN 优先（老用户的主路径），
		// 它没有会话时才看 aTrust。与 /api/logout 的判定保持一致。
		//
		// 注意不能简单地用 aTrust 状态覆盖 status：V5VPN 的
		// statusDetail / resourceError 与 aTrust 语义不同，
		// 混在一起会让界面把两种失败原因显示成同一条。
		active := (&backends{v5vpn: vpnService, atrust: atrustSvc}).active()
		st["activeBackend"] = active
		if active == "atrust" {
			at := atrustSvc.GetStatus()
			for k, v := range at {
				st[k] = v
			}
			// appVersion 必须保留，前端用它显示版本号。
			st["appVersion"] = AppVersion
		}
		_ = json.NewEncoder(w).Encode(st)
	})

	// 网页代理设置：PAC 开关 + 额外代理地址（持久化到用户数据目录）。
	// 该端点写入的地址会进入系统 PAC（每次浏览器请求都执行的 JS），
	// 因此只吃显式 JSON，拒绝跨站网页用 text/plain 简单请求伪造的 POST。
	mux.HandleFunc("/api/web-proxy/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(vpnService.GetWebProxyConfig())
		case http.MethodPost:
			// 恶意网页可用 text/plain 发跨站简单请求（无预检），必须挡掉。
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Content-Type must be application/json"})
				return
			}
			var req struct {
				PACEnabled   bool   `json:"pacEnabled"`
				ExtraTargets string `json:"extraTargets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			if err := vpnService.SetWebProxyConfig(req.PACEnabled, req.ExtraTargets); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// 系统 PAC：只把网页资源的目标地址指向本地代理，其余直连。
	mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, vpnService.PACScript())
	})

	mux.HandleFunc("/api/window-size", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if mainWindow != nil {
			mygo.RunOnMain(func() {
				applyWindowView(req.Mode)
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			vpnService.ClearLogs()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vpnService.GetLogs())
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID       string `json:"gwId"`
			Username   string `json:"username"`
			Password   string `json:"password"`
			VerifyCode string `json:"verifycode"`
			Remember   bool   `json:"remember"`
			Auto       bool   `json:"auto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// 协议守卫：这个端点只服务 V5VPN 网关。
		//
		// 没有它的时候，一个发错端点的 aTrust 请求会被真的当作 V5VPN
		// 连接发出去——对端是 aTrust 网关，于是拿到一个语焉不详的
		// "未下发有效会话ID"，同时把 V5VPN 后端的状态改成 Error。
		// 界面看到的是"V5VPN 认证失败"，而实际原因只是选错了后端。
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, config.ProtocolATrust)
			return
		}

		res, err := vpnService.Login(req.GWID, req.Username, req.Password, req.VerifyCode, req.Remember, req.Auto)
		writeLoginResult(w, res, err)
	})

	mux.HandleFunc("/api/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		source := 0
		if raw := r.URL.Query().Get("source"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				source = parsed
			}
		}
		certs, err := vpnService.ListCertificates(source)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(certs)
	})

	mux.HandleFunc("/api/certs/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Path     string `json:"path"`
			Alias    string `json:"alias"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		info, err := vpnService.ImportCertificate(req.Path, req.Alias, req.Password)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(info)
	})

	mux.HandleFunc("/api/certs/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/certs/")
		w.Header().Set("Content-Type", "application/json")
		if err := vpnService.DeleteCertificate(id); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/login-cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID       string `json:"gwId"`
			Source     int    `json:"source"`
			CertID     string `json:"certId"`
			VerifyCode string `json:"verifycode"`
			Auto       bool   `json:"auto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Same protocol guard as /api/login and /api/login-pwd-cert: without it a
		// certificate login speaks V5VPN mutual TLS to an aTrust gateway.
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, config.ProtocolATrust)
			return
		}
		res, err := vpnService.LoginWithCert(req.GWID, req.Source, req.CertID, req.VerifyCode, req.Auto)
		writeLoginResult(w, res, err)
	})

	// /api/cert/pick opens the native file picker for a .p12/.pfx file. The
	// dialog needs the GUI process, so it lives in main rather than the service.
	// /api/login-pwd-cert is the two-factor login: the password is submitted
	// first and the client certificate follows on /vpn/user/auth/cert once the
	// gateway asks for it (two-step serial flow).
	mux.HandleFunc("/api/login-pwd-cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID       string `json:"gwId"`
			Username   string `json:"username"`
			Password   string `json:"password"`
			Source     int    `json:"source"`
			CertID     string `json:"certId"`
			VerifyCode string `json:"verifycode"`
			Remember   bool   `json:"remember"`
			Auto       bool   `json:"auto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, config.ProtocolATrust)
			return
		}
		res, err := vpnService.LoginWithPasswordAndCert(req.GWID, req.Username, req.Password, req.VerifyCode, req.Source, req.CertID, req.Remember, req.Auto)
		writeLoginResult(w, res, err)
	})

	mux.HandleFunc("/api/verifycode-image", func(w http.ResponseWriter, r *http.Request) {
		gwId := r.URL.Query().Get("gwId")
		if gwId == "" {
			http.Error(w, "missing gwId", http.StatusBadRequest)
			return
		}
		dataURL, err := vpnService.GetVerifyCodeImage(gwId)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"dataUrl": dataURL})
	})

	mux.HandleFunc("/api/cert/pick", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if mainWindow == nil {
			w.WriteHeader(http.StatusNotImplemented)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "当前以 Web 模式运行，无法打开系统文件对话框，请手动输入证书路径",
			})
			return
		}
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent: mainWindow,
			Title:  "选择证书文件",
			Filters: []mygo.FileFilter{
				{Name: "证书文件 (*.p12, *.pfx)", Extensions: []string{"p12", "pfx"}},
			},
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if len(paths) == 0 {
			_ = json.NewEncoder(w).Encode(map[string]string{"path": ""})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"path": paths[0]})
	})

	mux.HandleFunc("/api/change-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID        string `json:"gwId"`
			Username    string `json:"username"`
			Password    string `json:"password"`
			NewPassword string `json:"newPassword"`
			VerifyCode  string `json:"verifycode"`
			Remember    bool   `json:"remember"`
			Auto        bool   `json:"auto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := vpnService.ChangePassword(req.GWID, req.Username, req.Password, req.NewPassword, req.VerifyCode, req.Remember, req.Auto)
		writeLoginResult(w, res, err)
	})

	// /api/sms-send asks the gateway to deliver the SMS verification code for
	// a login the gateway challenged with the SMS factor (RESULT code 0x8).
	// The challenged session lives in the service; the request only names the
	// gateway so the session cannot be crossed between profiles.
	mux.HandleFunc("/api/sms-send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID string `json:"gwId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, config.ProtocolATrust)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := vpnService.SendSMSCode(req.GWID); err != nil {
			code := service.AuthErrorCode(err)
			payload := map[string]any{"error": err.Error()}
			if code != "" {
				payload["code"] = code
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(payload)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	// /api/sms-login submits the SMS verification code and finishes the
	// challenged login: /vpn/user/auth/smc over the session that got code 8.
	mux.HandleFunc("/api/sms-login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID string `json:"gwId"`
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, config.ProtocolATrust)
			return
		}
		res, err := vpnService.LoginWithSMSCode(req.GWID, req.Code)
		writeLoginResult(w, res, err)
	})

	// /api/token-login submits the dynamic-token (OTP) code and finishes the
	// challenged login: /vpn/user/auth/token over the session that got code 4.
	mux.HandleFunc("/api/token-login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID string `json:"gwId"`
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, config.ProtocolATrust)
			return
		}
		res, err := vpnService.LoginWithToken(req.GWID, req.Code)
		writeLoginResult(w, res, err)
	})

	// /api/cert-factor answers a gateway certificate challenge (password step
	// returned code 2): the chosen certificate is presented on
	// /vpn/user/auth/cert over the challenged session.
	mux.HandleFunc("/api/cert-factor", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID       string `json:"gwId"`
			Source     int    `json:"source"`
			CertID     string `json:"certId"`
			Verifycode string `json:"verifycode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, config.ProtocolATrust)
			return
		}
		res, err := vpnService.SubmitCertFactor(req.GWID, req.Source, req.CertID, req.Verifycode)
		writeLoginResult(w, res, err)
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		// 共用入口：UI 的断开按钮不区分协议。按"谁在活动"决定断开谁，
		// 否则 aTrust 连接时点断开会去登出 V5VPN（一个空会话）而毫无效果。
		//
		// 两个后端同时活动是不正常状态（登录时会拆旧会话），但真发生时
		// 全部断开比留下一个孤儿会话好。
		state := &backends{v5vpn: vpnService, atrust: atrustSvc}
		state.logoutActive()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/resources/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		res, err := vpnService.RefreshResources()
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/api/gateways", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(vpnService.GetGateways())
			return
		}
		if r.Method == http.MethodPost {
			var gw config.GatewayProfile
			if err := json.NewDecoder(r.Body).Decode(&gw); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = vpnService.SaveGateway(gw)
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	})

	mux.HandleFunc("/api/gateways/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/api/gateways/")
			_ = vpnService.DeleteGateway(id)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		}
	})

	mux.HandleFunc("/api/open-url", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err := vpnService.OpenURL(req.URL)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/check-updates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		info := vpnService.CheckForUpdates()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	})

	// ---------- aTrust 后端 ----------
	//
	// 与 /api/*（V5VPN）完全并列、互不复用。前端按 gateway.protocol 选择
	// 打到哪一组 endpoint；两条链路共享的只有 setting.xml 里的网关表。
	mux.HandleFunc("/api/atrust/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID     string `json:"gwId"`
			Username string `json:"username"`
			Password string `json:"password"`
			Remember bool   `json:"remember"`
			Auto     bool   `json:"auto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// 反向守卫：aTrust 端点只服务 aTrust 网关。
		// ATrustService.Login 内部也有同样的检查（防止直接调用绕过），
		// 这里提前拦是为了给出统一的 409 + wrong_backend 形状。
		if gw := vpnService.GetConfig().FindGateway(req.GWID); gw != nil && !gw.IsATrust() {
			writeATrustRoutingError(w, gw.Name, gw.EffectiveProtocol())
			return
		}

		res, err := atrustSvc.Login(req.GWID, req.Username, req.Password, req.Remember, req.Auto)
		writeATrustResult(w, res, err)
	})

	mux.HandleFunc("/api/atrust/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		st := atrustSvc.GetStatus()
		st["appVersion"] = AppVersion
		// activeBackend 与 /api/status 保持同一语义，前端可以用同一段
		// 轮询代码处理两种响应。
		st["activeBackend"] = (&backends{v5vpn: vpnService, atrust: atrustSvc}).active()
		_ = json.NewEncoder(w).Encode(st)
	})

	mux.HandleFunc("/api/atrust/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := atrustSvc.Logout(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/atrust/resources/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		res, err := atrustSvc.RefreshResources()
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	})

	// Static UI assets. 两套界面各自在 /v5vpn/ 与 /atrust/ 下（uiFS 以
	// ui/ 目录为根，子目录直接对应根路径），根目录没有 index.html ——
	// 直接交给 FileServer 会把 uiFS 列成目录清单。
	// 根路径（和旧书签里的 /index.html）按上次使用的网关协议重定向到对应
	// 界面；其余路径原样交给 FileServer。
	fileServer := http.FileServer(http.FS(uiFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html":
			http.Redirect(w, r, initialUIPath(vpnService.GetConfig()), http.StatusFound)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	return mux
}

// runDumpPasswords dumps decrypted passwords from original installation
func runDumpPasswords() {
	cfg, err := config.LoadSettingXML("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading V5VPN configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("==================================================")
	fmt.Println("   V5VPN 凭证反解与配置提取器 (REA Tool)        ")
	fmt.Println("==================================================")
	fmt.Printf("配置文件路径: %s\n", cfg.SourcePath)
	fmt.Printf("上次使用网关: %s\n\n", cfg.LastUseGateway)

	for i, gw := range cfg.Gateways {
		fmt.Printf("[%d] 网关: %s\n", i+1, gw.Name)
		fmt.Printf("    地址: %s:%d (算法: %s)\n", gw.IP, gw.Port, algoName(gw.Algo))
		if len(gw.SavedAccounts) == 0 {
			fmt.Println("    账号: (无保存的账号)")
		} else {
			fmt.Println("    已解密凭证:")
			for _, acc := range gw.SavedAccounts {
				fmt.Printf("      - 用户名: %-18s 密码: %s (记住: %v, 自动: %v)\n",
					acc.Username, acc.Password, acc.Remember, acc.Auto)
			}
		}
		fmt.Println("--------------------------------------------------")
	}
}

func algoName(a int) string {
	if a == 1 {
		return "国密 GM/SM"
	}
	return "国际标准 TLS"
}

func runCLIList(svc *service.VPNService) {
	gws := svc.GetGateways()
	fmt.Printf("发现 %d 个已配置的网关:\n", len(gws))
	for i, gw := range gws {
		fmt.Printf("  [%d] %-16s %s:%d\n", i+1, gw.Name, gw.IP, gw.Port)
	}
}

func writeLoginResult(w http.ResponseWriter, res map[string]any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		code := service.AuthErrorCode(err)
		status := http.StatusBadRequest
		// A challenge is not a rejected request: the credentials were
		// accepted and the gateway asks for another factor, so the caller
		// gets the same 409 as the password-expiry challenge.
		if code == "password_expired" || code == "sms_challenge" ||
			code == "cert_challenge" || code == "token_challenge" {
			status = http.StatusConflict
		}
		payload := map[string]any{"error": err.Error()}
		if code != "" {
			payload["code"] = code
		}
		// The password was accepted but the automatic sign-in failed; the UI
		// must switch to the login state instead of retrying with the old one.
		if service.PasswordChanged(err) {
			payload["passwordChanged"] = true
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
		return
	}
	_ = json.NewEncoder(w).Encode(res)
}

// writeATrustRoutingError 报告"这个网关不属于当前端点"。
//
// 用 409 Conflict 而不是 400：请求本身没问题，是它指向的资源
// （网关）与这个端点不匹配。
func writeATrustRoutingError(w http.ResponseWriter, gwName, protocol string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": fmt.Sprintf("网关 %q 使用的是 %s 协议，不能通过当前端点登录", gwName, protocol),
		"code":  "wrong_backend",
	})
}

// writeATrustResult 是 writeLoginResult 的 aTrust 版本。
//
// 单独一个函数而不是加参数复用：两边的错误码集合不同
// （aTrust 没有 password_expired，V5VPN 没有 mfa_required），
// 混在一起会让任何一侧新增码值时都要重新确认另一侧。
func writeATrustResult(w http.ResponseWriter, res map[string]any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		code := service.ATrustErrorCode(err)
		payload := map[string]string{"error": err.Error()}
		if code != "" {
			payload["code"] = code
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(payload)
		return
	}
	_ = json.NewEncoder(w).Encode(res)
}

// cliConnector is the subset of VPNService used by the CLI connect flow.
type cliConnector interface {
	Login(gwIdentifier, username, password, verifycode string, remember, auto bool) (map[string]any, error)
	ChangePassword(gwIdentifier, username, password, newPassword, verifycode string, remember, auto bool) (map[string]any, error)
	Logout() (bool, error)
}

// connectWithOptionalPasswordChange handles password expiry checks and optional password changes.
// If force is true, it proceeds to change password directly.
// If force is false and the current password is valid (unexpired), it prompts for confirmation.
func connectWithOptionalPasswordChange(c cliConnector, gwName, user, pwd, newPwd, verifyCode string, force bool) (map[string]any, bool, error) {
	if newPwd == "" {
		res, err := c.Login(gwName, user, pwd, verifyCode, true, false)
		return res, false, err
	}

	if force {
		res, err := c.ChangePassword(gwName, user, pwd, newPwd, verifyCode, true, false)
		return res, err == nil, err
	}

	// Probe with remember disabled: the old password may be wrong, and only the
	// post-change login should persist a password.
	res, err := c.Login(gwName, user, pwd, verifyCode, false, false)
	if err == nil {
		fmt.Print("\n网关检测提示: 当前密码有效（未过期）。\n是否确认修改密码？[y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "y" || answer == "yes" {
			fmt.Println("用户确认修改密码，正在更新密码...")
			_, _ = c.Logout()
			res, err = c.ChangePassword(gwName, user, pwd, newPwd, verifyCode, true, false)
			return res, err == nil, err
		}
		fmt.Println("已取消修改密码，使用当前密码继续连接。")
		return res, false, nil
	}
	if !service.IsPasswordExpired(err) {
		return nil, false, err
	}

	res, err = c.ChangePassword(gwName, user, pwd, newPwd, verifyCode, true, false)
	return res, err == nil, err
}

func runCLIConnect(svc *service.VPNService, gwName, user, pwd, newPwd, verifyCode string, force bool) {
	gw := svc.Config.FindGateway(gwName)
	if gw == nil {
		fmt.Fprintf(os.Stderr, "未找到网关: %s\n", gwName)
		os.Exit(1)
	}

	if user == "" && len(gw.SavedAccounts) > 0 {
		user = gw.SavedAccounts[0].Username
	}
	if pwd == "" && len(gw.SavedAccounts) > 0 {
		pwd = gw.SavedAccounts[0].Password
	}

	if user == "" || pwd == "" {
		fmt.Fprintln(os.Stderr, "错误: 请指定 -user 和 -pwd")
		os.Exit(1)
	}

	fmt.Printf("正在连接网关 %s (%s:%d), 用户: %s...\n", gw.Name, gw.IP, gw.Port, user)
	res, passwordChanged, err := connectWithOptionalPasswordChange(svc, gw.Name, user, pwd, newPwd, verifyCode, force)
	if err == nil && newPwd != "" && !passwordChanged && force {
		fmt.Fprintln(os.Stderr, "网关未提示口令过期，-new-pwd 未生效；已使用当前密码连接。")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接失败: %v\n", err)
		if service.IsPasswordExpired(err) {
			fmt.Fprintln(os.Stderr, "口令已过期。请加上 -new-pwd <新密码> 后重试，或在图形界面中修改密码。")
		}
		os.Exit(1)
	}

	fmt.Println("连接成功!")
	data, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(data))
	fmt.Println("\n按 Ctrl+C 退出并断开连接...")

	select {}
}

// runListCertificates prints the imported file certificates.
func runListCertificates(svc *service.VPNService) {
	certs, err := svc.ListCertificates(int(certstore.SourceFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取证书列表失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[本地文件证书] 共 %d 张证书:\n", len(certs))
	for i, c := range certs {
		state := "有效"
		if c.IsExpired {
			state = "已过期"
		}
		fmt.Printf("  [%d] %s\n", i+1, c.Name)
		fmt.Printf("      ID: %s\n", c.ID)
		fmt.Printf("      颁发者: %s\n", c.Issuer)
		fmt.Printf("      有效期: %s 到 %s (%s)\n", c.ValidFrom, c.ValidTo, state)
	}
	if len(certs) == 0 {
		fmt.Println("\n未找到可用证书。可用 -import-cert <文件> [-cert-alias 别名] [-cert-pwd 口令] 导入。")
	}
}

func runImportCertificate(svc *service.VPNService, path, alias, password string) {
	info, err := svc.ImportCertificate(path, alias, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "导入证书失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("证书导入成功:")
	fmt.Printf("  ID: %s\n", info.ID)
	fmt.Printf("  名称: %s\n", info.Name)
	fmt.Printf("  颁发者: %s\n", info.Issuer)
	fmt.Printf("  有效期: %s 到 %s\n", info.ValidFrom, info.ValidTo)
	fmt.Printf("\n使用 -cli -connect <网关> -cert %s 登录。\n", info.ID)
}

// runCLIConnectWithCert authenticates with a certificate. -cert either names an
// imported certificate (ID or alias) or points at a .p12/.pfx file; the latter
// is loaded in place and never copied into the store.
func runCLIConnectWithCert(svc *service.VPNService, gwName, certRef, certPwd string, certType int, user, pwd, verifyCode string, withPassword bool) {
	gw := svc.Config.FindGateway(gwName)
	if gw == nil {
		fmt.Fprintf(os.Stderr, "未找到网关: %s\n", gwName)
		os.Exit(1)
	}
	if withPassword && (user == "" || pwd == "") {
		fmt.Fprintln(os.Stderr, "口令 + 证书登录需要同时提供 -user 与 -pwd")
		os.Exit(1)
	}

	certID := certRef
	if info, err := os.Stat(certRef); err == nil && !info.IsDir() {
		if withPassword {
			fmt.Printf("正在连接网关 %s (%s:%d), 证书: %s, 用户: %s...\n", gw.Name, gw.IP, gw.Port, certRef, user)
			res, err := svc.LoginWithPasswordAndCertExternal(gw.Name, user, pwd, certRef, certPwd, verifyCode)
			finishCLIConnect(res, err)
			return
		}
		fmt.Printf("正在连接网关 %s (%s:%d), 证书: %s...\n", gw.Name, gw.IP, gw.Port, certRef)
		res, err := svc.LoginWithCertExternal(gw.Name, certRef, certPwd, verifyCode)
		finishCLIConnect(res, err)
		return
	}

	resolvedID, name, err := resolveCertificateRef(svc, certRef, certType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	certID = resolvedID

	if withPassword {
		fmt.Printf("正在连接网关 %s (%s:%d), 证书: %s, 用户: %s...\n", gw.Name, gw.IP, gw.Port, name, user)
		res, err := svc.LoginWithPasswordAndCert(gw.Name, user, pwd, verifyCode, certType, certID, false, false)
		finishCLIConnect(res, err)
		return
	}

	if user != "" || pwd != "" {
		fmt.Fprintln(os.Stderr, "提示: 已指定证书登录，-user/-pwd 将被忽略。需口令+证书双因子时请加 -pwd-cert。")
	}
	res, err := svc.LoginWithCert(gw.Name, certType, certID, verifyCode, false)
	finishCLIConnect(res, err)
}

// resolveCertificateRef accepts either a certificate ID or its display alias.
func resolveCertificateRef(svc *service.VPNService, ref string, certType int) (string, string, error) {
	certs, err := svc.ListCertificates(certType)
	if err != nil {
		return "", "", err
	}
	for _, c := range certs {
		if c.ID == ref || c.Name == ref {
			return c.ID, c.Name, nil
		}
	}
	return "", "", fmt.Errorf("未找到证书 %q，请先运行 -list-certs 查看可用证书", ref)
}

func finishCLIConnect(res map[string]any, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("连接成功!")
	data, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(data))
	fmt.Println("\n按 Ctrl+C 退出并断开连接...")

	select {}
}
