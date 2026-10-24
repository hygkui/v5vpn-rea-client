package ipsec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func sampleNC() protocol.NCResource {
	return protocol.NCResource{
		Name: "nc",
		IKE: protocol.IKEParams{
			Version: "v1",
			Server:  protocol.IKEEndpoint{IP: "198.51.100.10", Port: 1194},
			Client:  protocol.IKEEndpoint{IDType: "key_id", ID: "sess-42"},
			PSK:     protocol.IKEPSK{Key: `p@ss"word`},
		},
		PrivateIP: protocol.PrivateIP{IP: "10.70.0.5"},
		Tunnels: []protocol.NCTunnel{
			{Name: "office", Routes: []protocol.NCRoute{{Addr: "198.51.100.0/24"}, {Addr: "198.51.100.0/24"}}},
			{Name: "mail", Named: []protocol.NCRoute{{Addr: "203.0.113.25/32"}}},
		},
	}
}

func TestFromNC(t *testing.T) {
	cfg, err := FromNC([]protocol.NCResource{sampleNC()})
	if err != nil {
		t.Fatalf("FromNC: %v", err)
	}
	if cfg.Server != "198.51.100.10" || cfg.ServerPort != 1194 {
		t.Errorf("server = %s:%d", cfg.Server, cfg.ServerPort)
	}
	if cfg.ClientID != "sess-42" || cfg.VirtualIP != "10.70.0.5" {
		t.Errorf("id/vip = %q/%q", cfg.ClientID, cfg.VirtualIP)
	}
	want := []string{"198.51.100.0/24", "203.0.113.25/32"}
	if len(cfg.Routes) != len(want) {
		t.Fatalf("routes = %v, want %v", cfg.Routes, want)
	}
	for i := range want {
		if cfg.Routes[i] != want[i] {
			t.Fatalf("routes = %v, want %v", cfg.Routes, want)
		}
	}
}

func TestFromNCRejectsIncomplete(t *testing.T) {
	cases := map[string]func(*protocol.NCResource){
		"no psk":    func(nc *protocol.NCResource) { nc.IKE.PSK.Key = "" },
		"no vip":    func(nc *protocol.NCResource) { nc.PrivateIP.IP = "" },
		"no routes": func(nc *protocol.NCResource) { nc.Tunnels = nil },
		"no server": func(nc *protocol.NCResource) { nc.IKE.Server.IP = "" },
	}
	for name, mutate := range cases {
		nc := sampleNC()
		mutate(&nc)
		if _, err := FromNC([]protocol.NCResource{nc}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := FromNC(nil); err == nil {
		t.Error("empty list: expected an error")
	}
	if _, err := FromNC([]protocol.NCResource{sampleNC(), sampleNC()}); err == nil {
		t.Error("two profiles: expected an error")
	}
}

func TestRenderSwanctl(t *testing.T) {
	cfg, err := FromNC([]protocol.NCResource{sampleNC()})
	if err != nil {
		t.Fatal(err)
	}
	conf := RenderSwanctl(*cfg)

	for _, want := range []string{
		"version = 1",
		"remote_addrs = 198.51.100.10",
		"remote_port = 1194",
		"local_port = 1194",
		"proposals = aes192-sha1-modp1024",
		`id = "keyid:sess-42"`,
		"local_ts = 10.70.0.5/32",
		"remote_ts = 0.0.0.0/0",
		"esp_proposals = aes192-sha1",
		"start_action = start",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q:\n%s", want, conf)
		}
	}
	// The PSK must be quoted and escaped, never rendered raw.
	if !strings.Contains(conf, `secret = "p@ss\"word"`) {
		t.Errorf("PSK was not escaped:\n%s", conf)
	}
}

func TestParseCIDR(t *testing.T) {
	cases := []struct{ cidr, network, mask string }{
		{"198.51.100.0/24", "198.51.100.0", "255.255.255.0"},
		{"203.0.113.10/32", "203.0.113.10", "255.255.255.255"},
		{"198.51.0.0/16", "198.51.0.0", "255.255.0.0"},
	}
	for _, tc := range cases {
		n, m, err := ParseCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%s): %v", tc.cidr, err)
		}
		if n != tc.network || m != tc.mask {
			t.Errorf("ParseCIDR(%s) = %s/%s, want %s/%s", tc.cidr, n, m, tc.network, tc.mask)
		}
	}
	if _, _, err := ParseCIDR("not-a-cidr"); err == nil {
		t.Error("expected an error for malformed CIDR")
	}
	if _, _, err := ParseCIDR("2001:db8::/32"); err == nil {
		t.Error("expected an error for IPv6")
	}
}

func TestWindowsPathToWSL(t *testing.T) {
	got := WindowsPathToWSL(`C:\Users\Admin\AppData\Roaming\v5vpn-rea\ipsec.conf`)
	want := "/mnt/c/Users/Admin/AppData/Roaming/v5vpn-rea/ipsec.conf"
	if got != want {
		t.Fatalf("WindowsPathToWSL = %q, want %q", got, want)
	}
}

type fakeRunner struct {
	calls  [][]string
	output []byte
	err    error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.output, f.err
}

func TestManagerStartWritesConfAndRunsSwanctl(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "ipsec.conf")
	m := NewManager(confPath)
	fr := &fakeRunner{output: []byte("initiate completed successfully")}
	m.Runner = fr

	cfg, err := FromNC([]protocol.NCResource{sampleNC()})
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Start(context.Background(), *cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.Contains(out, "initiate") {
		t.Errorf("output = %q", out)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("conf not written: %v", err)
	}
	if !strings.Contains(string(data), "remote_ts = 0.0.0.0/0") {
		t.Errorf("conf content wrong:\n%s", data)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(fr.calls))
	}
	call := strings.Join(fr.calls[0], " ")
	for _, want := range []string{"wsl.exe", "-d v5vpn", "-u root", "swanctl --load-all", "swanctl --initiate --child v5vpn", "ip addr add 10.70.0.5/32"} {
		if !strings.Contains(call, want) {
			t.Errorf("wsl call missing %q: %s", want, call)
		}
	}
}

func TestManagerStartReportsFailure(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "ipsec.conf"))
	m.Runner = &fakeRunner{output: []byte("no such file or directory"), err: errors.New("exit status 1")}
	cfg, err := FromNC([]protocol.NCResource{sampleNC()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Start(context.Background(), *cfg)
	if err == nil || !strings.Contains(err.Error(), "启动 IPsec 隧道失败") {
		t.Fatalf("Start error = %v", err)
	}
}
