package main

import (
	"testing"

	"github.com/egoist/mygo"
	"github.com/hygkui/v5vpn-rea-client/internal/service"
)

// TestVPNServiceBindsToIPC guards the frontend bridge: mygo.BindAs reflects over
// every exported method and rejects parameter or result types that cannot cross
// the JSON IPC boundary. A method taking *tls.Certificate (or any type holding a
// channel/func) would panic at startup, before the window is ever shown.
func TestVPNServiceBindsToIPC(t *testing.T) {
	svc := service.NewVPNService(nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VPNService cannot be bound to IPC: %v", r)
		}
	}()
	mygo.BindAs("VPNService", svc)
}
