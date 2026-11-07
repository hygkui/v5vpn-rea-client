//go:build linux

package ipsec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeProbeRejectsUnsafeProfile(t *testing.T) {
	for name, edit := range map[string]func(*Config){
		"server":   func(c *Config) { c.Server = "127.0.0.1;touch /tmp/unwanted" },
		"vip":      func(c *Config) { c.VirtualIP = "2001:db8::1" },
		"port":     func(c *Config) { c.ServerPort = 65536 },
		"identity": func(c *Config) { c.ClientID = "session\"\nconnections {" },
		"psk":      func(c *Config) { c.PSK = "secret\nnew-section" },
		"route":    func(c *Config) { c.Routes = []string{"203.0.113.0/24;true"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := nativeProfile()
			edit(&c)
			if _, err := normalizeNativeProfile(c); err == nil {
				t.Fatal("unsafe NC profile accepted")
			}
		})
	}
}

func nativeProfile() Config {
	return Config{Server: "198.51.100.10", ServerPort: 1194, ClientID: "session-42", PSK: `fixture\"psk`, VirtualIP: "10.70.0.5", Routes: []string{"198.51.100.0/24", "203.0.113.25/32"}}
}

type nativeRunner struct {
	calls           []string
	fail            string
	failed          bool
	installed       bool
	cancel          context.CancelFunc
	foreignXFRM     bool
	vipCommitted    bool
	protectedRoute  bool
	emptyXFRMOutput bool
}

func (r *nativeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	line := filepath.Base(name) + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	var operation []string
	for _, arg := range args {
		if !filepath.IsAbs(arg) && !strings.HasPrefix(arg, "unix://") {
			operation = append(operation, arg)
		}
	}
	operationLine := filepath.Base(name) + " " + strings.Join(operation, " ")
	if r.fail != "" && !r.failed && strings.Contains(operationLine, r.fail) {
		r.failed = true
		if r.cancel != nil {
			if strings.Contains(operationLine, "ip address add") {
				r.vipCommitted = true
			}
			r.cancel()
			return nil, context.Canceled
		}
		return nil, errors.New("injected command failure")
	}
	switch {
	case strings.HasPrefix(line, "ip -j xfrm") && r.emptyXFRMOutput:
		return nil, nil
	case strings.HasPrefix(line, "ip -j xfrm") && r.foreignXFRM:
		return []byte(`[{"existing":true}]`), nil
	case strings.HasPrefix(line, "ip -j route get"):
		if r.protectedRoute && args[len(args)-1] == "203.0.113.25" {
			return []byte(`[{"dev":"enp3s0","prefsrc":"10.70.0.5","table":186}]`), nil
		}
		return []byte(`[{"dev":"enp3s0","gateway":"192.0.2.1","prefsrc":"192.0.2.2"}]`), nil
	case strings.HasPrefix(line, "ip -j address show"):
		if r.vipCommitted {
			return []byte(`[{"addr_info":[{"local":"10.70.0.5","protocol":186}]}]`), nil
		}
		return []byte(`[{"addr_info":[{"family":"inet","local":"192.0.2.2"}]}]`), nil
	case strings.HasPrefix(line, "ip -j"):
		return []byte(`[]`), nil
	case strings.Contains(line, "--list-sas"):
		if !r.installed {
			return []byte("no IKE_SAs"), nil
		}
		return []byte("v5vpn: #1, ESTABLISHED, IKEv1\n  v5vpn: #1, reqid 1, INSTALLED, TUNNEL\n    in  01234567, 240 bytes, 2 packets\n    out abcdef01, 120 bytes, 1 packets\n    local 10.70.0.5/32\n    remote 0.0.0.0/0\n"), nil
	}
	return nil, nil
}

func probeForTest(t *testing.T, r *nativeRunner) (*NativeProbe, *int) {
	t.Helper()
	p := NewNativeProbe(filepath.Join(t.TempDir(), "session"), r)
	stops := new(int)
	p.Launch = func(_, _ string) (func(context.Context) error, error) {
		return func(context.Context) error { *stops++; return nil }, nil
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	return p, stops
}

func TestNativeProbeStartsWithPrivateConfigurationAndDiscoveredRoute(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, stops := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(p.RunDir, "swanctl.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"local_addrs = 192.0.2.2", "local_port = 1194", "remote_port = 1194", "start_action = none", "local_ts = 10.70.0.5/32", "remote_ts = 0.0.0.0/0", "aes192-sha1-modp1024"} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("configuration missing %s", want)
		}
	}
	info, _ := os.Stat(filepath.Join(p.RunDir, "swanctl.conf"))
	if info.Mode().Perm() != 0o600 {
		t.Fatal("secret file permissions")
	}
	commands := strings.Join(r.calls, "\n")
	for _, want := range []string{
		"ip address add 10.70.0.5/32 dev enp3s0",
		"ip route add table 186 203.0.113.25/32 via 192.0.2.1 dev enp3s0 src 10.70.0.5",
		"ip rule add priority 18599 to 198.51.100.10/32 lookup main",
		"--to-source 10.70.0.5",
		"--uri unix://" + filepath.Join(p.RunDir, "charon.vici"),
	} {
		if !strings.Contains(commands, want) {
			t.Errorf("missing network operation: %s", want)
		}
	}
	for _, bad := range []string{"wsl.exe", "route.exe", "bash -lc", "ip_forward", "iptables -F", "ip xfrm state flush"} {
		if strings.Contains(commands, bad) {
			t.Errorf("unexpected operation: %s", bad)
		}
	}
	status, err := p.Status(context.Background())
	if err != nil || !status.Installed || status.InBytes != 240 || status.OutBytes != 120 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *stops != 1 {
		t.Fatalf("daemon stopped %d times", *stops)
	}
	if _, err := os.Stat(p.RunDir); !os.IsNotExist(err) {
		t.Fatalf("secret directory remains: %v", err)
	}
}

func TestNativeProbeRollsBackStartupFailures(t *testing.T) {
	for _, fail := range []string{"--load-all", "--initiate", "iptables -t nat -N", "--to-source", "ip route add table 186", "ip rule add priority 18600", "iptables -t nat -I"} {
		t.Run(fail, func(t *testing.T) {
			r := &nativeRunner{installed: true, fail: fail}
			p, stops := probeForTest(t, r)
			if err := p.Start(context.Background(), nativeProfile()); err == nil {
				t.Fatal("startup failure ignored")
			}
			if *stops != 1 {
				t.Fatal("daemon not stopped on failure")
			}
			if !strings.Contains(strings.Join(r.calls, "\n"), "ip address del 10.70.0.5/32 dev enp3s0") {
				t.Fatal("VIP not rolled back")
			}
			if _, err := os.Stat(p.RunDir); !os.IsNotExist(err) {
				t.Fatal("secret directory not removed")
			}
		})
	}
}

func TestNativeProbeRequiresInstalledChild(t *testing.T) {
	r := &nativeRunner{}
	p, stops := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err == nil {
		t.Fatal("reported success without installed child SA")
	}
	if *stops != 1 {
		t.Fatal("daemon not stopped")
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "ip route add") {
		t.Fatal("routes installed without SA")
	}
}

func TestNativeProbeCleanupUsesFreshContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &nativeRunner{installed: true, fail: "ip rule add priority 18600", cancel: cancel}
	p, _ := probeForTest(t, r)
	if err := p.Start(ctx, nativeProfile()); err == nil {
		t.Fatal("cancelled start succeeded")
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "ip address del") {
		t.Fatal("cancelled startup prevented cleanup")
	}
}

func TestNativeProbeDoesNotDeleteForeignDirectory(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	if err := os.Mkdir(p.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(p.RunDir, "foreign")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), nativeProfile()); err == nil {
		t.Fatal("existing directory accepted")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("deleted foreign state")
	}
	if len(r.calls) != 0 {
		t.Fatal("changed network before claiming directory")
	}
}

func TestNativeProbeNormalizesRoutesAndRejectsUnprotectedTarget(t *testing.T) {
	c := nativeProfile()
	c.Routes = []string{"198.51.100.19/24", "198.51.100.0/24"}
	n, err := normalizeNativeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Routes) != 1 || n.Routes[0] != "198.51.100.0/24" {
		t.Fatalf("routes=%v", n.Routes)
	}
	if err := CheckNativeTarget(n, "https://203.0.113.25/"); err == nil {
		t.Fatal("unprotected target accepted")
	}
	if err := CheckNativeTarget(n, "https://198.51.100.19/dashboard"); err != nil {
		t.Fatal(err)
	}
}

func TestNativeProbePreservesPrintableSessionIdentity(t *testing.T) {
	c := nativeProfile()
	c.ClientID = `session/base64+=\"`
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	if err := p.Start(context.Background(), c); err != nil {
		t.Fatal("printable key_id rejected:", err)
	}
	b, err := os.ReadFile(filepath.Join(p.RunDir, "swanctl.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `id = "keyid:session/base64+=\\\""`) {
		t.Fatal("session identity not quoted and escaped")
	}
}

func TestNativeProbeRetainsFailedCleanupForRetry(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	r.fail = "ip rule del priority 18600"
	if err := p.Stop(context.Background()); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal("cleanup retry failed:", err)
	}
	if strings.Count(strings.Join(r.calls, "\n"), "ip rule del priority 18600") != 2 {
		t.Fatal("failed cleanup operation was forgotten")
	}
}

func TestNativeProbeDiagnosticsHideSessionSecrets(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	c := nativeProfile()
	if err := p.Start(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	log := "connecting " + c.Server + " keyid " + c.ClientID + " secret " + c.PSK + " VIP " + c.VirtualIP + " identity 73:65:73:73:69:6f:6e:2d:34:32"
	if err := os.WriteFile(filepath.Join(p.RunDir, "charon.log"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := strings.Join(p.Diagnostics, "\n")
	if s == "" {
		t.Fatal("diagnostics lost on cleanup")
	}
	for _, secret := range []string{c.Server, c.ClientID, c.PSK, c.VirtualIP, "73:65:73:73:69:6f:6e:2d:34:32"} {
		if strings.Contains(s, secret) {
			t.Fatal("diagnostic exposed private session data")
		}
	}
}

func TestNativeProbePreservesExistingXFRM(t *testing.T) {
	r := &nativeRunner{installed: true, foreignXFRM: true}
	p, _ := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err == nil {
		t.Fatal("existing IPsec state was not protected")
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "ip address add") {
		t.Fatal("network changed despite existing XFRM")
	}
}

func TestNativeProbeExcludesGatewayFromSNAT(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.calls, "\n")
	guard := strings.Index(calls, "iptables -t nat -A V5VPN_NATIVE_CHECK -d 198.51.100.10/32 -j RETURN")
	nat := strings.Index(calls, "--to-source 10.70.0.5")
	if guard < 0 || guard > nat {
		t.Fatal("gateway IKE/portal traffic can be SNATed to VIP")
	}
}

func TestNativeProbeReconcilesCancelledMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &nativeRunner{installed: true, fail: "ip address add", cancel: cancel}
	p, _ := probeForTest(t, r)
	if err := p.Start(ctx, nativeProfile()); err == nil {
		t.Fatal("cancelled mutation succeeded")
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "ip address del 10.70.0.5/32 dev enp3s0") {
		t.Fatal("possibly committed mutation was not reconciled")
	}
}

func TestNativeProbeDoesNotClaimCleanupWithResidualXFRM(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	r.foreignXFRM = true
	if err := p.Stop(context.Background()); err == nil {
		t.Fatal("residual XFRM reported clean")
	}
}

func TestNativeProcessReportsUnexpectedExit(t *testing.T) {
	stop, err := launchNativeProcess(exec.Command("/bin/sh", "-c", "exit 7"), filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := stop(context.Background()); err == nil {
		t.Fatal("abnormal daemon exit reported as clean")
	}
}

func TestNativeProbeChecksTargetUsesVIPRoute(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyTargetRoute(context.Background(), "https://203.0.113.25/"); err == nil {
		t.Fatal("physical route accepted as VPN proof")
	}
	r.protectedRoute = true
	if err := p.VerifyTargetRoute(context.Background(), "https://203.0.113.25/"); err != nil {
		t.Fatal(err)
	}
	if err := CheckNativeTarget(nativeProfile(), "https://198.51.100.10/"); err == nil {
		t.Fatal("gateway bypass accepted as tunnel target")
	}
}

func TestNativeProbeAcceptsEmptyXFRMListing(t *testing.T) {
	r := &nativeRunner{installed: true, emptyXFRMOutput: true}
	p, _ := probeForTest(t, r)
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal("iproute2 empty listing rejected:", err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNativeProbePeerOverridePreservesGatewayIdentity(t *testing.T) {
	r := &nativeRunner{installed: true}
	p, _ := probeForTest(t, r)
	p.PeerAddress = "192.0.2.10"
	if err := p.Start(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(p.RunDir, "swanctl.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "remote_addrs = 192.0.2.10") || !strings.Contains(string(b), "id = 198.51.100.10") {
		t.Fatal("transport override changed the XML IKE identity")
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "-d 192.0.2.10/32 -j RETURN") {
		t.Fatal("actual transport gateway not exempt from SNAT")
	}
}
