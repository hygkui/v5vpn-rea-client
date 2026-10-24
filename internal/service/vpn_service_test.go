package service

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
)

func TestVPNService_LogoutNoDeadlock(t *testing.T) {
	var logged int32
	var statusChanged int32

	s := NewVPNService(func(msg string) {
		atomic.AddInt32(&logged, 1)
	})

	s.OnStatusChange = func(status string) {
		atomic.AddInt32(&statusChanged, 1)
	}

	// Test Logout when already disconnected
	done := make(chan bool, 1)
	go func() {
		ok, err := s.Logout()
		if err != nil {
			t.Errorf("Logout error: %v", err)
		}
		done <- ok
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Errorf("expected Logout to return true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Logout deadlocked!")
	}

	st := s.GetStatus()
	if st["status"] != "Disconnected" {
		t.Errorf("expected status Disconnected, got %v", st["status"])
	}
}

func TestVPNService_ConcurrentLoggingAndStatus(t *testing.T) {
	s := NewVPNService(nil)

	// Launch concurrent log writers and status readers
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				s.Log("INFO", "worker %d iteration %d", id, j)
				_ = s.GetStatus()
				_ = s.GetLogs()
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	logs := s.GetLogs()
	if len(logs) == 0 {
		t.Errorf("expected logs to be recorded")
	}
}

func TestChangePasswordRejectsBlankOrUnchanged(t *testing.T) {
	s := NewVPNService(nil)

	_, err := s.ChangePassword("demo-gateway", "alice", "old-secret", "", "", false, false)
	if err == nil || !strings.Contains(err.Error(), "新密码不能为空") {
		t.Fatalf("empty new password: %v", err)
	}

	_, err = s.ChangePassword("demo-gateway", "alice", "same-secret", "same-secret", "", false, false)
	if err == nil || !strings.Contains(err.Error(), "不能与当前密码相同") {
		t.Fatalf("unchanged password: %v", err)
	}

	if s.GetStatus()["status"] != "Disconnected" {
		t.Fatalf("rejected change password altered status: %v", s.GetStatus()["status"])
	}
}

// The add-gateway form posts only name/IP/port/algo. Editing an existing
// gateway through it must not wipe the credentials the operator saved by
// logging in, and must not persist that loss to setting.xml.
func TestSaveGatewayKeepsSavedAccountsWhenEditing(t *testing.T) {
	s := NewVPNService(nil)
	s.Config = &config.AppConfig{
		Gateways: []config.GatewayProfile{{
			ID:           "gw-0",
			Name:         "office",
			IP:           "203.0.113.10",
			Port:         443,
			Algo:         0,
			LastUserName: "alice",
			SavedAccounts: []config.UserAccount{
				{Username: "alice", Password: "secret", Remember: true},
			},
		}},
	}
	// Keep the test off the real user data directory.
	t.Chdir(t.TempDir())

	// Same name, corrected IP and port: exactly what the UI submits.
	if err := s.SaveGateway(config.GatewayProfile{
		Name: "office",
		IP:   "198.51.100.7",
		Port: 8443,
		Algo: 1,
	}); err != nil {
		t.Fatalf("SaveGateway failed: %v", err)
	}

	gateways := s.GetGateways()
	if len(gateways) != 1 {
		t.Fatalf("expected 1 gateway, got %d (a duplicate was appended)", len(gateways))
	}
	gw := gateways[0]
	if gw.IP != "198.51.100.7" || gw.Port != 8443 || gw.Algo != 1 {
		t.Fatalf("edited fields were not applied: %+v", gw)
	}
	if gw.ID != "gw-0" {
		t.Errorf("gateway ID changed: %q", gw.ID)
	}
	if gw.LastUserName != "alice" {
		t.Errorf("LastUserName was cleared: %q", gw.LastUserName)
	}
	if len(gw.SavedAccounts) != 1 || gw.SavedAccounts[0].Password != "secret" {
		t.Fatalf("saved accounts were wiped: %+v", gw.SavedAccounts)
	}
}

// A brand-new gateway still gets an ID and is appended exactly once.
func TestSaveGatewayAddsNewGateway(t *testing.T) {
	s := NewVPNService(nil)
	s.Config = &config.AppConfig{}
	t.Chdir(t.TempDir())

	if err := s.SaveGateway(config.GatewayProfile{Name: "new", IP: "198.51.100.9", Port: 443}); err != nil {
		t.Fatalf("SaveGateway failed: %v", err)
	}

	gateways := s.GetGateways()
	if len(gateways) != 1 {
		t.Fatalf("expected 1 gateway, got %d", len(gateways))
	}
	if gateways[0].ID != "gw-0" {
		t.Errorf("new gateway ID = %q, want gw-0", gateways[0].ID)
	}
}

// Deleting a gateway leaves a gap in the ID sequence. A new gateway must not
// fill it with an ID that is still in use, because DeleteGateway matches on
// the duplicate and would remove both profiles.
func TestSaveGatewayIDsAreUniqueAfterDelete(t *testing.T) {
	s := NewVPNService(nil)
	s.Config = &config.AppConfig{Gateways: []config.GatewayProfile{
		{ID: "gw-0", Name: "office"},
		{ID: "gw-1", Name: "home"},
	}}
	t.Chdir(t.TempDir())

	if err := s.DeleteGateway("gw-0"); err != nil {
		t.Fatalf("DeleteGateway failed: %v", err)
	}
	if err := s.SaveGateway(config.GatewayProfile{Name: "new"}); err != nil {
		t.Fatalf("SaveGateway failed: %v", err)
	}

	gateways := s.GetGateways()
	if len(gateways) != 2 {
		t.Fatalf("expected 2 gateways, got %d", len(gateways))
	}
	seen := map[string]bool{}
	for _, gw := range gateways {
		if seen[gw.ID] {
			t.Fatalf("duplicate gateway ID %q in %+v", gw.ID, gateways)
		}
		seen[gw.ID] = true
	}

	if err := s.DeleteGateway("gw-0"); err != nil {
		t.Fatalf("DeleteGateway on the new gateway failed: %v", err)
	}
	if got := s.GetGateways(); len(got) != 1 || got[0].Name != "home" {
		t.Fatalf("deleting the new gateway removed the wrong profiles: %+v", got)
	}
}

// An empty account list is how a caller that omits the field arrives over
// JSON; it must keep the stored credentials just like a nil slice does.
func TestSaveGatewayTreatsEmptyAccountsAsOmitted(t *testing.T) {
	s := NewVPNService(nil)
	s.Config = &config.AppConfig{Gateways: []config.GatewayProfile{{
		ID:            "gw-0",
		Name:          "office",
		SavedAccounts: []config.UserAccount{{Username: "alice", Password: "secret"}},
	}}}
	t.Chdir(t.TempDir())

	if err := s.SaveGateway(config.GatewayProfile{
		Name:          "office",
		IP:            "198.51.100.7",
		SavedAccounts: []config.UserAccount{},
	}); err != nil {
		t.Fatalf("SaveGateway failed: %v", err)
	}

	gw := s.GetGateways()[0]
	if len(gw.SavedAccounts) != 1 || gw.SavedAccounts[0].Password != "secret" {
		t.Fatalf("empty account list wiped the stored credentials: %+v", gw.SavedAccounts)
	}
}

func TestVPNService_LoginGateway2(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	var active atomic.Bool
	active.Store(true)
	defer func() {
		active.Store(false)
	}()

	s := NewVPNService(func(msg string) {
		if active.Load() {
			t.Log(msg)
		}
	})

	res, err := s.Login("demo-gateway", "<username>", "<password>", "", false, false)
	if err != nil {
		active.Store(false)
		t.Skipf("Login not possible on placeholder credentials: %v", err)
	}

	if res["status"] != "Connected" {
		t.Fatalf("Expected status Connected, got %v", res["status"])
	}

	s.Logout()
	time.Sleep(50 * time.Millisecond)
}

// TestChangePasswordReusesExpiredLoginClient verifies that the HTTP client
// which received the 0x100 challenge is reused for /vpn/user/auth/pwdchange,
// so the VSG_SESSIONID cookie from that response is sent with the request
// instead of being lost with the failed login.
func TestChangePasswordReusesExpiredLoginClient(t *testing.T) {
	var (
		mu            sync.Mutex
		handshakes    int
		loginCalls    int
		pwdCookie     string
		pwdHandshakes int
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/vpn/version.xml", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		handshakes++
		mu.Unlock()
		_, _ = io.WriteString(w, `<VERSION major="2" minor="0"/>`)
	})
	mux.HandleFunc("/vpn/user/auth/password", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		loginCalls++
		call := loginCalls
		mu.Unlock()

		if call == 1 {
			http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "challenge-session", Path: "/"})
			_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0x100" msg="口令过期，需修改密码"/></RESPONSE>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "VSG_SESSIONID", Value: "logged-in-session", Path: "/"})
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/auth/pwdchange", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pwdCookie = r.Header.Get("Cookie")
		pwdHandshakes = handshakes
		mu.Unlock()
		_, _ = io.WriteString(w, `<RESPONSE><RESULT code="0" msg="密码修改成功"/></RESPONSE>`)
	})
	mux.HandleFunc("/vpn/user/portal/intergration.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<INTERGRATION_INFO><USER name="alice"/><SESSION detect_interval="180"/><RESOURCE_LIST></RESOURCE_LIST></INTERGRATION_INFO>`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	s := NewVPNService(nil)
	s.Config = &config.AppConfig{
		Gateways: []config.GatewayProfile{{
			ID:   "gw-test",
			Name: "gw-test",
			IP:   host,
			Port: port,
		}},
	}
	defer s.Logout()

	if _, err := s.Login("gw-test", "alice", "old-secret", "", false, false); !IsPasswordExpired(err) {
		t.Fatalf("expected expired login challenge, got %v", err)
	}

	res, err := s.ChangePassword("gw-test", "alice", "old-secret", "new-secret", "", false, false)
	if err != nil {
		t.Fatalf("change password failed: %v", err)
	}
	if res["status"] != "Connected" {
		t.Fatalf("expected Connected after password change, got %v", res["status"])
	}

	mu.Lock()
	gotCookie, gotHandshakes := pwdCookie, pwdHandshakes
	mu.Unlock()

	if gotHandshakes != 1 {
		t.Fatalf("pwdchange should reuse the challenged client (1 handshake), saw %d", gotHandshakes)
	}
	if !strings.Contains(gotCookie, "VSG_SESSIONID=challenge-session") {
		t.Fatalf("pwdchange did not carry the challenge session cookie: %q", gotCookie)
	}
	if strings.Count(gotCookie, "VSG_SESSIONID=") != 1 {
		t.Fatalf("pwdchange sent duplicate session cookies: %q", gotCookie)
	}
}
