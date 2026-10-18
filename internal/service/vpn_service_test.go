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
