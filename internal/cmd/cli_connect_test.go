package main

import (
	"errors"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

type fakeCLIConnector struct {
	loginRes  map[string]any
	loginErr  error
	changeRes map[string]any
	changeErr error

	loginCalls     int
	changeCalls    int
	lastGw         string
	lastUser       string
	lastPwd        string
	lastNewPwd     string
	loginRemember  bool
	changeRemember bool
}

func (f *fakeCLIConnector) Login(gw, user, pwd, _ string, remember, _ bool) (map[string]any, error) {
	f.loginCalls++
	f.lastGw, f.lastUser, f.lastPwd = gw, user, pwd
	f.loginRemember = remember
	return f.loginRes, f.loginErr
}

func (f *fakeCLIConnector) ChangePassword(gw, user, pwd, newPwd, _ string, remember, _ bool) (map[string]any, error) {
	f.changeCalls++
	f.lastGw, f.lastUser, f.lastPwd, f.lastNewPwd = gw, user, pwd, newPwd
	f.changeRemember = remember
	return f.changeRes, f.changeErr
}

func TestConnectWithOptionalPasswordChange(t *testing.T) {
	expired := &protocol.AuthError{Kind: protocol.AuthKindPasswordExpired, Code: "0x100"}
	badCredentials := &protocol.AuthError{Kind: protocol.AuthKindBadCredentials, Code: "0x101"}
	connected := map[string]any{"status": "Connected"}

	t.Run("no new password only logs in", func(t *testing.T) {
		f := &fakeCLIConnector{loginRes: connected}
		res, changed, err := connectWithOptionalPasswordChange(f, "gw", "alice", "old-secret", "")
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Fatal("password changed without -new-pwd")
		}
		if res["status"] != "Connected" {
			t.Fatalf("unexpected result: %v", res)
		}
		if f.loginCalls != 1 || f.changeCalls != 0 {
			t.Fatalf("login=%d change=%d, want 1/0", f.loginCalls, f.changeCalls)
		}
		if !f.loginRemember {
			t.Fatal("normal CLI login should remember the password")
		}
	})

	t.Run("valid old password skips change", func(t *testing.T) {
		f := &fakeCLIConnector{loginRes: connected}
		res, changed, err := connectWithOptionalPasswordChange(f, "gw", "alice", "old-secret", "new-secret")
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Fatal("password changed even though login succeeded")
		}
		if res["status"] != "Connected" {
			t.Fatalf("unexpected result: %v", res)
		}
		if f.loginCalls != 1 || f.changeCalls != 0 {
			t.Fatalf("login=%d change=%d, want 1/0", f.loginCalls, f.changeCalls)
		}
		if f.loginRemember {
			t.Fatal("password probe must not persist credentials")
		}
	})

	t.Run("expired password changes after login", func(t *testing.T) {
		f := &fakeCLIConnector{loginErr: expired, changeRes: connected}
		res, changed, err := connectWithOptionalPasswordChange(f, "gw", "alice", "old-secret", "new-secret")
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Fatal("expired password was not changed")
		}
		if res["status"] != "Connected" {
			t.Fatalf("unexpected result: %v", res)
		}
		if f.loginCalls != 1 || f.changeCalls != 1 {
			t.Fatalf("login=%d change=%d, want 1/1", f.loginCalls, f.changeCalls)
		}
		if f.lastGw != "gw" || f.lastUser != "alice" || f.lastPwd != "old-secret" || f.lastNewPwd != "new-secret" {
			t.Fatalf("unexpected change args: gw=%q user=%q old=%q new=%q",
				f.lastGw, f.lastUser, f.lastPwd, f.lastNewPwd)
		}
		if f.loginRemember {
			t.Fatal("password probe must not persist credentials")
		}
		if !f.changeRemember {
			t.Fatal("successful change should persist the new password")
		}
	})

	t.Run("bad credentials do not change", func(t *testing.T) {
		f := &fakeCLIConnector{loginErr: badCredentials}
		_, changed, err := connectWithOptionalPasswordChange(f, "gw", "alice", "wrong", "new-secret")
		if !errors.Is(err, badCredentials) {
			t.Fatalf("expected bad credentials, got %v", err)
		}
		if changed {
			t.Fatal("password changed after bad credentials")
		}
		if f.loginCalls != 1 || f.changeCalls != 0 {
			t.Fatalf("login=%d change=%d, want 1/0", f.loginCalls, f.changeCalls)
		}
		if f.loginRemember {
			t.Fatal("password probe must not persist credentials")
		}
	})

	t.Run("failed change reports error", func(t *testing.T) {
		changeErr := errors.New("gateway rejected change")
		f := &fakeCLIConnector{loginErr: expired, changeErr: changeErr}
		_, changed, err := connectWithOptionalPasswordChange(f, "gw", "alice", "old-secret", "new-secret")
		if !errors.Is(err, changeErr) {
			t.Fatalf("expected change error, got %v", err)
		}
		if changed {
			t.Fatal("failed change reported as changed")
		}
		if f.loginCalls != 1 || f.changeCalls != 1 {
			t.Fatalf("login=%d change=%d, want 1/1", f.loginCalls, f.changeCalls)
		}
		if f.loginRemember || !f.changeRemember {
			t.Fatalf("unexpected remember flags: login=%v change=%v", f.loginRemember, f.changeRemember)
		}
	})
}
