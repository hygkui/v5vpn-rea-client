//go:build linux

package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeJournalDoesNotPersistSecrets(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	p.Journal = true
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(p.RunDir, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{nativeProfile().PSK, nativeProfile().ClientID} {
		if strings.Contains(string(b), secret) {
			t.Fatal("secret persisted in recovery journal")
		}
	}
	info, _ := os.Stat(filepath.Join(p.RunDir, "session.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatal("journal not private")
	}
	if err := RecoverNativeSession(context.Background(), p.RunDir, r); err == nil {
		t.Fatal("active owner was taken over")
	}
}

func TestNativeRecoveryRemovesOnlyRecordedDeadSession(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := `{"version":1,"ownerPid":99999999,"ownerStart":"1","vip":"10.70.0.5","undo":[]}`
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "swanctl.conf"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverNativeSession(context.Background(), dir, &nativeRunner{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dead session directory remains")
	}
}

func TestNativeRecoveryRejectsMalformedPendingOperation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session")
	os.Mkdir(dir, 0o700)
	data := `{"version":1,"ownerPid":99999999,"ownerStart":"1","vip":"10.70.0.5","undo":[],"pending":{"name":"iptables","args":[]}}`
	os.WriteFile(filepath.Join(dir, "session.json"), []byte(data), 0o600)
	defer func() {
		if r := recover(); r != nil {
			t.Fatal("malformed journal panicked", r)
		}
	}()
	if err := RecoverNativeSession(context.Background(), dir, &nativeRunner{}); err == nil {
		t.Fatal("malformed operation accepted")
	}
}

func TestNativeRecoveryHonorsLifecycleLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session")
	os.Mkdir(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "session.json"), []byte(`{"version":1,"ownerPid":99999999,"ownerStart":"1","vip":"10.70.0.5","undo":[]}`), 0o600)
	marker := filepath.Join(dir, "swanctl.conf")
	os.WriteFile(marker, []byte("active-session"), 0o600)
	lock, err := acquireNativeLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseNativeLock(lock)
	if err := RecoverNativeSession(context.Background(), dir, &nativeRunner{}); err == nil {
		t.Fatal("concurrent recovery bypassed lifetime lock")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("concurrent recovery deleted session files")
	}
}
