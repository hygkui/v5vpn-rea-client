package ipsec

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// TestLiveManagerStart brings the tunnel up through WSL using a real portal
// response. It is opt-in because it needs a live session (the PSK, virtual IP
// and key id are all session-specific):
//
//	IPSEC_PORTAL_XML=/path/to/intergration.xml go test ./internal/ipsec -run TestLiveManagerStart -v
//
// The session can be obtained with a normal login; see docs/ipsec.md.
func TestLiveManagerStart(t *testing.T) {
	xmlPath := os.Getenv("IPSEC_PORTAL_XML")
	if xmlPath == "" {
		t.Skip("set IPSEC_PORTAL_XML to a gateway intergration.xml to run this test")
	}
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		t.Fatalf("read portal xml: %v", err)
	}
	var info protocol.IntegrationInfo
	if err := xml.Unmarshal(data, &info); err != nil {
		t.Fatalf("parse portal xml: %v", err)
	}
	cfg, err := FromNC(info.ResourceList.NCResources)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	mgr := NewManager(filepath.Join(t.TempDir(), "ipsec.conf"))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if !mgr.Available(ctx) {
		t.Skip("WSL distribution v5vpn is not available")
	}
	out, err := mgr.Start(ctx, *cfg)
	if err != nil {
		t.Fatalf("Start: %v\n%s", err, out)
	}
	t.Logf("swanctl output:\n%s", out)

	status, err := mgr.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	t.Logf("SAs:\n%s", status)
	if !strings.Contains(status, "INSTALLED") {
		t.Fatalf("no INSTALLED SA in:\n%s", status)
	}

	if err := mgr.Stop(ctx, *cfg); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
