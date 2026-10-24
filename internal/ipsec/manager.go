package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultDistro is the WSL distribution imported by scripts/setup-ipsec-wsl.ps1.
const DefaultDistro = "v5vpn"

// ErrNotElevated means the Windows route table cannot be changed from this
// process. The tunnel itself still runs inside WSL; only transparent routing
// for Windows applications needs administrator rights.
var ErrNotElevated = errors.New("需要管理员权限才能修改 Windows 路由")

// CommandRunner abstracts external commands so the WSL orchestration can be
// tested without a real distribution.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real processes.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// Manager drives one strongSwan connection inside WSL2.
type Manager struct {
	Distro   string
	ConfPath string // Windows path of the generated swanctl.conf
	Runner   CommandRunner
}

// NewManager returns a manager that writes the connection to confPath.
func NewManager(confPath string) *Manager {
	abs, err := filepath.Abs(confPath)
	if err == nil {
		confPath = abs
	}
	return &Manager{
		Distro:   DefaultDistro,
		ConfPath: confPath,
		Runner:   ExecRunner{},
	}
}

func (m *Manager) runner() CommandRunner {
	if m.Runner != nil {
		return m.Runner
	}
	return ExecRunner{}
}

func (m *Manager) distro() string {
	if strings.TrimSpace(m.Distro) == "" {
		return DefaultDistro
	}
	return m.Distro
}

// Available reports whether the WSL distribution exists and can run commands.
func (m *Manager) Available(ctx context.Context) bool {
	_, err := m.runner().Run(ctx, "wsl.exe", "-d", m.distro(), "--", "true")
	return err == nil
}

// Start writes the swanctl configuration, installs the virtual IP, loads the
// connection and initiates it.
func (m *Manager) Start(ctx context.Context, cfg Config) (string, error) {
	if err := os.MkdirAll(filepath.Dir(m.ConfPath), 0o700); err != nil {
		return "", fmt.Errorf("创建 IPsec 配置目录失败: %w", err)
	}
	if err := os.WriteFile(m.ConfPath, []byte(RenderSwanctl(cfg)), 0o600); err != nil {
		return "", fmt.Errorf("写入 IPsec 配置失败: %w", err)
	}

	wslConf := WindowsPathToWSL(m.ConfPath)
	natRoutes := strings.Fields(strings.Join(cfg.Routes, " "))
	var nat strings.Builder
	for _, route := range natRoutes {
		fmt.Fprintf(&nat, `
iptables -t nat -C POSTROUTING -d %s -m comment --comment v5vpn-ipsec -j SNAT --to-source %s 2>/dev/null || \
iptables -t nat -A POSTROUTING -d %s -m comment --comment v5vpn-ipsec -j SNAT --to-source %s`, route, cfg.VirtualIP, route, cfg.VirtualIP)
	}

	script := fmt.Sprintf(`set -e
mkdir -p /etc/swanctl/conf.d
install -m 600 '%s' /etc/swanctl/conf.d/v5vpn.conf
ip addr add %s/32 dev eth0 2>/dev/null || true
sysctl -q -w net.ipv4.ip_forward=1
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -A FORWARD -j ACCEPT
if ! grep -q 'port = 1194' /etc/strongswan.d/charon.conf 2>/dev/null; then
  sed -i '0,/charon {/s//charon {\n    port = 1194/' /etc/strongswan.d/charon.conf
  ipsec restart >/dev/null 2>&1 || true
  sleep 3
fi
if ! pgrep -x charon >/dev/null 2>&1; then
  ipsec start >/dev/null 2>&1 || true
  sleep 2
fi%s
swanctl --load-all
swanctl --initiate --child v5vpn`, wslConf, cfg.VirtualIP, nat.String())

	out, err := m.wsl(ctx, script)
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("启动 IPsec 隧道失败: %w (%s)", err, lastLine(text))
	}
	return text, nil
}

// Stop terminates the child SA, removes the SNAT rules and drops the virtual
// IP. The configuration file stays in place for the next session and for
// debugging.
func (m *Manager) Stop(ctx context.Context, cfg Config) error {
	var del strings.Builder
	for _, route := range cfg.Routes {
		fmt.Fprintf(&del, "\niptables -t nat -D POSTROUTING -d %s -m comment --comment v5vpn-ipsec -j SNAT --to-source %s 2>/dev/null || true", route, cfg.VirtualIP)
	}
	script := fmt.Sprintf(`swanctl --terminate --ike v5vpn >/dev/null 2>&1 || swanctl --terminate --child v5vpn >/dev/null 2>&1 || true%s
if [ -n '%s' ]; then ip addr del %s/32 dev eth0 2>/dev/null || true; fi
true`, del.String(), cfg.VirtualIP, cfg.VirtualIP)
	out, err := m.wsl(ctx, script)
	if err != nil {
		return fmt.Errorf("停止 IPsec 隧道失败: %w (%s)", err, lastLine(strings.TrimSpace(string(out))))
	}
	return nil
}

// Status returns the raw `swanctl --list-sas` output, or an error when the
// tunnel cannot be queried.
func (m *Manager) Status(ctx context.Context) (string, error) {
	out, err := m.wsl(ctx, "swanctl --list-sas")
	return strings.TrimSpace(string(out)), err
}

// WSLIP returns the first IPv4 address of the distribution. Windows routes
// point at this address for the tunnel subnets.
func (m *Manager) WSLIP(ctx context.Context, exclude ...string) (string, error) {
	out, err := m.runner().Run(ctx, "wsl.exe", "-d", m.distro(), "--", "hostname", "-I")
	if err != nil {
		return "", err
	}
	excludeSet := make(map[string]bool)
	for _, ex := range exclude {
		if parsed := net.ParseIP(strings.TrimSpace(ex)); parsed != nil {
			excludeSet[parsed.String()] = true
		}
	}
	for _, f := range strings.Fields(string(out)) {
		if parsed := net.ParseIP(strings.TrimSpace(f)); parsed != nil && parsed.To4() != nil {
			if !excludeSet[parsed.String()] {
				return parsed.String(), nil
			}
		}
	}
	return "", fmt.Errorf("无法获取 WSL 的 IPv4 地址")
}

func (m *Manager) wsl(ctx context.Context, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return m.runner().Run(ctx, "wsl.exe", "-d", m.distro(), "-u", "root", "--", "bash", "-lc", script)
}

func lastLine(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// WindowsPathToWSL converts C:\a\b into /mnt/c/a/b. WSL's /mnt/c is the
// standard mount, and the generated path contains no shell metacharacters.
func WindowsPathToWSL(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) >= 2 && p[1] == ':' {
		return "/mnt/" + strings.ToLower(string(p[0])) + p[2:]
	}
	return p
}

// IsElevated reports whether this process can modify the route table. `net
// session` is a Windows administrative command; it succeeds only elevated.
func IsElevated() bool {
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

// AddRoutes points the given CIDRs at the WSL address. Existing routes are
// left alone (route.exe reports "already exists" and we ignore that case).
func AddRoutes(ctx context.Context, routes []string, gateway string) error {
	if !IsElevated() {
		return ErrNotElevated
	}
	for _, cidr := range routes {
		network, mask, err := ParseCIDR(cidr)
		if err != nil {
			return err
		}
		out, err := exec.CommandContext(ctx, "route.exe", "add", network, "mask", mask, gateway).CombinedOutput()
		if err != nil && !routeAlreadyExists(string(out)) {
			return fmt.Errorf("添加路由 %s 失败: %w (%s)", cidr, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// RemoveRoutes deletes the routes added by AddRoutes.
func RemoveRoutes(ctx context.Context, routes []string, gateway string) error {
	for _, cidr := range routes {
		network, mask, err := ParseCIDR(cidr)
		if err != nil {
			continue
		}
		_, _ = exec.CommandContext(ctx, "route.exe", "delete", network, "mask", mask, gateway).CombinedOutput()
	}
	return nil
}

func routeAlreadyExists(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "already exists") || strings.Contains(output, "已存在") ||
		strings.Contains(output, "exists in the route table")
}
