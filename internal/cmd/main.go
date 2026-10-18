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
	"strings"

	"github.com/egoist/mygo"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/service"
)

//go:embed all:ui
var uiEmbedFS embed.FS

// AppVersion MUST match mygo.json "version" (with "v" prefix); the
// TestAppVersionMatchesMygoJSON test fails the build if they drift.
// NOTE: "2.0" is the gateway protocol version (/vpn/version.xml), not the
// app version — do not "fix" this back to v2.0.0.
var AppVersion = "v0.1.1"

var mainWindow *mygo.Window

func init() {
	attachConsole()
}

func main() {
	// Command-line flags
	cliMode := flag.Bool("cli", false, "Run in CLI/headless mode without desktop GUI")
	dumpPasswords := flag.Bool("dump-passwords", false, "Print all decrypted usernames and passwords from V5VPN settings")
	connectGW := flag.String("connect", "", "Connect to gateway by name or IP in CLI mode")
	userFlag := flag.String("user", "", "Username for CLI connection (defaults to remembered user)")
	pwdFlag := flag.String("pwd", "", "Password for CLI connection (defaults to remembered password)")
	newPwdFlag := flag.String("new-pwd", "", "New password when the gateway requires a password change")
	httpPort := flag.Int("port", 0, "Serve web UI on custom HTTP port (0 for auto)")
	flag.Parse()

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

	// CLI Connect Mode
	if *cliMode && *connectGW != "" {
		runCLIConnect(vpnService, *connectGW, *userFlag, *pwdFlag, *newPwdFlag)
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
	// Tell the config package where the production build stores its
	// saved credentials. mygo.App.Path(PathUserData) returns a per-user
	// directory such as %APPDATA%\Roaming5vpn-rea on Windows or
	// ~/.local/share/v5vpn-rea on Linux. An updater-driven replacement
	// of the application directory no longer erases the operator's
	// saved credentials when the file lives here instead of next to
	// the executable.
	if dataDir, err := mygo.App.Path(mygo.PathUserData); err == nil && dataDir != "" {
		config.SetUserDataDir(dataDir)
	}
	mygo.BindAs("VPNService", vpnService)
	mygo.SetFrontend(uiFS)

	mygo.App.WhenReady(func() {
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:  fmt.Sprintf("V5VPN 现代客户端 %s (MyGo)", AppVersion),
			Width:  460,
			Height: 700,
			URL:    fmt.Sprintf("http://127.0.0.1:%d/index.html", actualPort),
		})
		mainWindow = win
		var isExiting bool

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

		// Setup System Tray with crisp 32x32 PNG Icon
		tray, trayErr := mygo.NewTray(mygo.TrayOptions{
			Icon:    generateTrayIcon(false),
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
				gwName := vpnService.GetConfig().LastUseGateway
				statusLabel = fmt.Sprintf("状态: 已连接 [%s]", gwName)
				isConn = true
				tray.SetToolTip(fmt.Sprintf("V5VPN - 已连接 [%s]", gwName))
				_ = tray.SetIcon(generateTrayIcon(true), false)
			} else if statusStr == "Connecting" {
				statusLabel = "状态: 正在连接..."
				tray.SetToolTip("V5VPN - 正在连接...")
				_ = tray.SetIcon(generateTrayIcon(false), false)
			} else {
				statusLabel = "状态: 未连接"
				tray.SetToolTip("V5VPN - 未连接")
				_ = tray.SetIcon(generateTrayIcon(false), false)
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
					Label: "连接 VPN",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						cfg := vpnService.GetConfig()
						gw := cfg.FindGateway(cfg.LastUseGateway)
						if gw != nil && len(gw.SavedAccounts) > 0 {
							go vpnService.Login(gw.Name, gw.SavedAccounts[0].Username, gw.SavedAccounts[0].Password, "", true, false)
						} else {
							if win != nil {
								win.Show()
								win.Restore()
								win.Focus()
							}
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

		// Update tray reactively on status change without polling
		vpnService.OnStatusChange = func(status string) {
			mygo.RunOnMain(updateTray)
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
					mainWindow.SetSize(460, 700)
					mainWindow.Center()
				case "connected":
					mainWindow.SetSize(1248, 832)
					mainWindow.Center()
				case "settings":
					mainWindow.SetSize(720, 620)
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
}

// connectWithOptionalPasswordChange mirrors the original client: authenticate
// with the current password first. Only a 0x100 challenge triggers a password
// change; otherwise the successful login is kept and the new password ignored.
func connectWithOptionalPasswordChange(c cliConnector, gwName, user, pwd, newPwd string) (map[string]any, bool, error) {
	if newPwd == "" {
		res, err := c.Login(gwName, user, pwd, "", true, false)
		return res, false, err
	}

	// Probe with remember disabled: the old password may be wrong, and only the
	// post-change login should persist a password.
	res, err := c.Login(gwName, user, pwd, "", false, false)
	if err == nil {
		return res, false, nil
	}
	if !service.IsPasswordExpired(err) {
		return nil, false, err
	}

	res, err = c.ChangePassword(gwName, user, pwd, newPwd, "", true, false)
	return res, err == nil, err
}

func runCLIConnect(svc *service.VPNService, gwName, user, pwd, newPwd string) {
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
	res, passwordChanged, err := connectWithOptionalPasswordChange(svc, gw.Name, user, pwd, newPwd)
	if err == nil && newPwd != "" && !passwordChanged {
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
