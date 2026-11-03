package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/ipsec"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

type nativeServiceBackend struct {
	mu                   sync.Mutex
	started              bool
	installed            bool
	probeErr, errorStart error
	stopCount            int
	seen                 ipsec.Config
}

func (*nativeServiceBackend) Platform() string              { return "linux" }
func (b *nativeServiceBackend) Probe(context.Context) error { return b.probeErr }
func (b *nativeServiceBackend) Start(_ context.Context, c ipsec.Config) (ipsec.StartResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = true
	b.seen = c
	return ipsec.StartResult{}, b.errorStart
}
func (b *nativeServiceBackend) Status(context.Context) (ipsec.TunnelStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return ipsec.TunnelStatus{Installed: b.installed}, nil
}
func (b *nativeServiceBackend) Stop(context.Context, ipsec.Config) error {
	b.mu.Lock()
	b.stopCount++
	b.mu.Unlock()
	return nil
}

func TestNativeIPsecHandsCurrentSessionToPlatformBackend(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{})
	s.Client = protocol.NewClient("192.0.2.10", 8443, 0, nil)
	b := &nativeServiceBackend{installed: true}
	s.newIPsecBackend = func(_ string, peer string) ipsec.TunnelBackend {
		if peer != "192.0.2.10" {
			t.Error("wrong authenticated transport peer")
		}
		return b
	}
	t.Cleanup(s.stopIPsec)
	s.startIPsec(ncTestResources(t))
	if s.GetStatus()["ipsecState"] != "up" || s.GetStatus()["ipsecPlatform"] != "linux" {
		t.Fatal("native status not exposed")
	}
	if b.seen.PSK != "mock-psk-fixture" || b.seen.VirtualIP != "10.70.0.5" {
		t.Fatal("current NC parameters not transferred")
	}
	s.stopIPsec()
	if s.GetStatus()["ipsecState"] != "" {
		t.Fatal("disconnect left stale state")
	}
}

func TestNativeIPsecFailureKeepsLoginAndResourceState(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{})
	b := &nativeServiceBackend{errorStart: errors.New("route installation failed")}
	s.newIPsecBackend = func(string, string) ipsec.TunnelBackend { return b }
	s.resourceState = ResourceReady
	s.startIPsec(ncTestResources(t))
	st := s.GetStatus()
	if st["ipsecState"] != "error" || st["status"] != "Connected" || st["resourceState"] != string(ResourceReady) {
		t.Fatal("NC failure affected portal session", st["ipsecState"])
	}
	if !strings.Contains(st["ipsecError"].(string), "route") {
		t.Fatal("failure reason not exposed")
	}
}

func TestNativeIPsecRejectsOldClientResourceCompletion(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{})
	old := protocol.NewClient("192.0.2.1", 8443, 0, nil)
	s.Client = protocol.NewClient("192.0.2.2", 8443, 0, nil)
	b := &nativeServiceBackend{installed: true}
	s.newIPsecBackend = func(string, string) ipsec.TunnelBackend { return b }
	s.startIPsecForClient(old, ncTestResources(t))
	if b.started || s.GetStatus()["ipsecState"] != "" {
		t.Fatal("stale NC completion replaced current session")
	}
}

func TestNativeIPsecDetectsLostChildSA(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{})
	b := &nativeServiceBackend{installed: true}
	s.newIPsecBackend = func(string, string) ipsec.TunnelBackend { return b }
	t.Cleanup(s.stopIPsec)
	s.startIPsec(ncTestResources(t))
	b.mu.Lock()
	b.installed = false
	b.mu.Unlock()
	s.mu.Lock()
	epoch := s.ipsecGeneration
	s.mu.Unlock()
	misses := 0
	s.pollNativeIPsec(context.Background(), epoch, b, &misses)
	s.pollNativeIPsec(context.Background(), epoch, b, &misses)
	if s.GetStatus()["ipsecState"] != "error" {
		t.Fatal("lost SA remained up")
	}
}
