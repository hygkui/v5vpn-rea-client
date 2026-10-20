package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
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
var AppVersion = "v0.3.0"

var mainWindow *mygo.Window

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
			runCLIConnectWithCert(vpnService, *connectGW, *certFlag, *certPwdFlag, *certTypeFlag, *userFlag, *pwdFlag)
			return
		}
		runCLIConnect(vpnService, *connectGW, *userFlag, *pwdFlag, *newPwdFlag, *forceFlag)
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
	actualPort := startHTTPServer(serverPort, uiFS, vpnService)

	// Initialize MyGo Desktop Framework
	log.Printf("Starting V5VPN Client with MyGo framework...")
	// Belt-and-braces: even if a quit is triggered by a code path that
	// forgets to call vpnService.Logout(), the OnBeforeQuit hook fires before the process exits
	// and tears the VPN tunnel down so the gateway does not see an
	// orphan session on the next reconnect.
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		if _, err := vpnService.Logout(); err != nil {
			log.Printf("OnBeforeQuit logout error (ignored): %v", err)
		}
	})
	mygo.BindAs("VPNService", vpnService)
	mygo.SetFrontend(uiFS)

	mygo.App.WhenReady(func() {
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:  fmt.Sprintf("V5VPN 现代客户端 %s (MyGo)", AppVersion),
			Width:  460,
			Height: 718,
			URL:    fmt.Sprintf("http://127.0.0.1:%d/index.html", actualPort),
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
						_, _ = vpnService.Logout()
						mygo.RunOnMain(func() {
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

		// Function to update tray menu with real-time connection status
		updateTray := func() {
			st := vpnService.GetStatus()
			statusStr, _ := st["status"].(string)
			var statusLabel string
			var isConn bool

			if statusStr == "Connected" {
				// GetStatus already carries the gateway name; copying the whole
				// config here would deep-copy every gateway and cleartext
				// password on each status change just to read one field.
				gwName, _ := st["lastUseGateway"].(string)
				statusLabel = fmt.Sprintf("状态: 已连接 [%s]", gwName)
				isConn = true
				tray.SetToolTip(fmt.Sprintf("V5VPN - 已连接 [%s]", gwName))
				_ = tray.SetIcon(trayIconConnected, false)
			} else if statusStr == "Connecting" {
				statusLabel = "状态: 正在连接..."
				tray.SetToolTip("V5VPN - 正在连接...")
				_ = tray.SetIcon(trayIconDisconnected, false)
			} else {
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
						go vpnService.Logout()
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
							_, _ = vpnService.Logout()
							mygo.RunOnMain(func() {
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
						mainWindow.SetSize(460, 718)
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

// startHTTPServer starts the local REST and asset server
func startHTTPServer(port int, uiFS fs.FS, vpnService *service.VPNService) int {
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
		_ = json.NewEncoder(w).Encode(st)
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
				switch req.Mode {
				case "login":
					mainWindow.SetSize(460, 718)
					mainWindow.Center()
				case "connected":
					mainWindow.SetSize(1248, 832)
					mainWindow.Center()
				case "settings":
					mainWindow.SetSize(920, 660)
					mainWindow.Center()
				}
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
		res, err := vpnService.LoginWithCert(req.GWID, req.Source, req.CertID, req.VerifyCode, req.Auto)
		writeLoginResult(w, res, err)
	})

	// /api/cert/pick opens the native file picker for a .p12/.pfx file. The
	// dialog needs the GUI process, so it lives in main rather than the service.
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

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		_, err := vpnService.Logout()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
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

	// Static UI assets
	mux.Handle("/", http.FileServer(http.FS(uiFS)))

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
		if code == "password_expired" {
			status = http.StatusConflict
		}
		payload := map[string]string{"error": err.Error()}
		if code != "" {
			payload["code"] = code
		}
		w.WriteHeader(status)
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
func connectWithOptionalPasswordChange(c cliConnector, gwName, user, pwd, newPwd string, force bool) (map[string]any, bool, error) {
	if newPwd == "" {
		res, err := c.Login(gwName, user, pwd, "", true, false)
		return res, false, err
	}

	if force {
		res, err := c.ChangePassword(gwName, user, pwd, newPwd, "", true, false)
		return res, err == nil, err
	}

	// Probe with remember disabled: the old password may be wrong, and only the
	// post-change login should persist a password.
	res, err := c.Login(gwName, user, pwd, "", false, false)
	if err == nil {
		fmt.Print("\n网关检测提示: 当前密码有效（未过期）。\n是否确认修改密码？[y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "y" || answer == "yes" {
			fmt.Println("用户确认修改密码，正在更新密码...")
			_, _ = c.Logout()
			res, err = c.ChangePassword(gwName, user, pwd, newPwd, "", true, false)
			return res, err == nil, err
		}
		fmt.Println("已取消修改密码，使用当前密码继续连接。")
		return res, false, nil
	}
	if !service.IsPasswordExpired(err) {
		return nil, false, err
	}

	res, err = c.ChangePassword(gwName, user, pwd, newPwd, "", true, false)
	return res, err == nil, err
}

func runCLIConnect(svc *service.VPNService, gwName, user, pwd, newPwd string, force bool) {
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
	res, passwordChanged, err := connectWithOptionalPasswordChange(svc, gw.Name, user, pwd, newPwd, force)
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
func runCLIConnectWithCert(svc *service.VPNService, gwName, certRef, certPwd string, certType int, user, pwd string) {
	gw := svc.Config.FindGateway(gwName)
	if gw == nil {
		fmt.Fprintf(os.Stderr, "未找到网关: %s\n", gwName)
		os.Exit(1)
	}
	if user != "" || pwd != "" {
		fmt.Fprintln(os.Stderr, "提示: 已指定证书登录，-user/-pwd 将被忽略。")
	}

	certID := certRef
	if info, err := os.Stat(certRef); err == nil && !info.IsDir() {
		fmt.Printf("正在连接网关 %s (%s:%d), 证书: %s...\n", gw.Name, gw.IP, gw.Port, certRef)
		res, err := svc.LoginWithCertExternal(gw.Name, certRef, certPwd)
		finishCLIConnect(res, err)
		return
	}

	resolvedID, name, err := resolveCertificateRef(svc, certRef, certType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	certID = resolvedID
	fmt.Printf("正在连接网关 %s (%s:%d), 证书: %s...\n", gw.Name, gw.IP, gw.Port, name)

	res, err := svc.LoginWithCert(gw.Name, certType, certID, "", false)
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
