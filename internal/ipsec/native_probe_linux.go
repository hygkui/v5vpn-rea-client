//go:build linux

package ipsec

// This is an explicit root-only validation path. It is not selected by the
// desktop service and does not replace the existing Windows/WSL manager.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

const nativeChain = "V5VPN_NATIVE_CHECK"

type NativeProbeStatus struct {
	Installed bool   `json:"child_sa_installed"`
	InBytes   uint64 `json:"rx_bytes"`
	OutBytes  uint64 `json:"tx_bytes"`
}

type nativeUndo struct {
	name string
	args []string
}

// NativeProbe owns only objects it successfully created. RunDir must not
// already exist. A stale directory is deliberately refused, never adopted.
type NativeProbe struct {
	RunDir      string
	PeerAddress string // Explicit NAT transport override; XML identity remains unchanged.
	Runner      CommandRunner
	Launch      func(confPath, logPath string) (func(context.Context) error, error)
	Diagnostics []string
	Journal     bool
	pending     *nativeUndo
	daemonPID   int
	launched    bool
	unresolved  bool
	owned       bool
	undo        []nativeUndo
	stopDaemon  func(context.Context) error
	cfg         Config
}

func NewNativeProbe(runDir string, runner CommandRunner) *NativeProbe {
	if runner == nil {
		runner = ExecRunner{}
	}
	p := &NativeProbe{RunDir: runDir, Runner: runner}
	p.Launch = func(conf, log string) (func(context.Context) error, error) {
		if !p.Journal {
			return launchNativeCharon(conf, log)
		}
		cmd := exec.Command("/usr/lib/ipsec/charon")
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "STRONGSWAN_CONF=" + conf}
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		stop, err := launchNativeProcess(cmd, log)
		if err == nil {
			p.daemonPID = cmd.Process.Pid
			err = p.saveJournal()
		}
		return stop, err
	}
	return p
}

func normalizeNativeProfile(c Config) (Config, error) {
	for _, value := range []string{c.Server, c.VirtualIP} {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return Config{}, errors.New("NC 网关和 VIP 必须是有效的 IPv4 地址")
		}
	}
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return Config{}, errors.New("NC 远端端口无效")
	}
	if strings.TrimSpace(c.ClientID) == "" || len(c.ClientID) > 512 || strings.ContainsFunc(c.ClientID, func(r rune) bool { return r < 32 || r == 127 }) {
		return Config{}, errors.New("NC 身份包含不支持的字符")
	}
	if c.PSK == "" || strings.ContainsFunc(c.PSK, func(r rune) bool { return r < 32 || r == 127 }) {
		return Config{}, errors.New("NC PSK 为空或包含控制字符")
	}
	if len(c.Routes) == 0 || len(c.Routes) > 256 {
		return Config{}, errors.New("NC 保护路由数量无效")
	}
	var routes []string
	seen := map[string]bool{}
	for _, cidr := range c.Routes {
		ip, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || ip.To4() == nil {
			return Config{}, errors.New("NC 保护路由必须是 IPv4 CIDR")
		}
		if !seen[n.String()] {
			routes = append(routes, n.String())
			seen[n.String()] = true
		}
	}
	c.Routes = routes
	return c, nil
}

// ReadNativeProfile reads a private, bounded portal XML file. The caller must
// obtain it from a current authenticated session, not reuse yesterday's PSK.
func ReadNativeProfile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("无法读取私有 NC XML")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return Config{}, errors.New("NC XML 必须是普通私有文件（权限 0600）")
	}
	data, err := io.ReadAll(io.LimitReader(f, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return Config{}, errors.New("NC XML 超过大小限制或读取失败")
	}
	var info protocol.IntegrationInfo
	if err := xml.Unmarshal(config.EnsureUTF8(data), &info); err != nil {
		return Config{}, errors.New("NC XML 格式无效")
	}
	for _, nc := range info.ResourceList.NCResources {
		if nc.IKE.Version != "" && nc.IKE.Version != "v1" {
			return Config{}, errors.New("验证入口只支持 IKEv1")
		}
		if nc.IKE.Exchange.Mode != "" && nc.IKE.Exchange.Mode != "main" {
			return Config{}, errors.New("验证入口只支持 Main Mode")
		}
		if nc.IKE.Client.IDType != "" && nc.IKE.Client.IDType != "key_id" {
			return Config{}, errors.New("验证入口只支持 key_id 身份")
		}
	}
	c, err := FromNC(info.ResourceList.NCResources)
	if err != nil {
		return Config{}, err
	}
	return normalizeNativeProfile(*c)
}

func CheckNativeTarget(c Config, target string) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return errors.New("验证目标必须是 HTTP/HTTPS URL，不能携带账号")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || ip.To4() == nil {
		return errors.New("验证目标必须使用明确的 IPv4 地址")
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.ParseIP(c.Server)) || ip.Equal(net.ParseIP(c.VirtualIP)) {
		return errors.New("验证目标不能是本机、VIP 或网关 bypass 地址")
	}
	for _, cidr := range c.Routes {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(ip) {
			return nil
		}
	}
	return errors.New("验证目标不在 NC 下发的保护网段内")
}

func (p *NativeProbe) VerifyTargetRoute(ctx context.Context, target string) error {
	if err := CheckNativeTarget(p.cfg, target); err != nil {
		return err
	}
	u, _ := url.Parse(target)
	if p.PeerAddress != "" && u.Hostname() == p.PeerAddress {
		return errors.New("验证目标不能是实际网关 bypass 地址")
	}
	out, err := p.run(ctx, "ip", "-j", "route", "get", u.Hostname())
	if err != nil {
		return err
	}
	var rows []struct {
		Dev    string `json:"dev"`
		Type   string `json:"type"`
		Source string `json:"prefsrc"`
		Table  any    `json:"table"`
	}
	if err = json.Unmarshal(out, &rows); err != nil {
		return err
	}
	if len(rows) != 1 || rows[0].Dev == "lo" || rows[0].Type == "local" || rows[0].Source != p.cfg.VirtualIP || fmt.Sprint(rows[0].Table) != "186" {
		return errors.New("目标未走本次 VIP/保护路由，不能作为隧道证据")
	}
	return nil
}

func (p *NativeProbe) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := p.Runner.Run(ctx, name, args...)
	if err != nil {
		return out, fmt.Errorf("%s 操作失败: %w", filepath.Base(name), err)
	}
	return out, nil
}

func (p *NativeProbe) change(ctx context.Context, name string, args, undo []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	mutation, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.pending = &nativeUndo{name: name, args: args}
	if err := p.saveJournal(); err != nil {
		return err
	}
	if _, err := p.run(mutation, name, args...); err != nil {
		if mutation.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			check, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			exists, checkErr := p.effectExists(check, name, args)
			if checkErr != nil {
				p.unresolved = true
			} else if exists {
				p.undo = append(p.undo, nativeUndo{name: name, args: undo})
			}
		}
		if !p.unresolved {
			p.pending = nil
		}
		_ = p.saveJournal()
		return err
	}
	p.undo = append(p.undo, nativeUndo{name: name, args: undo})
	p.pending = nil
	if err := p.saveJournal(); err != nil {
		return err
	}
	return ctx.Err()
}

// Reconcile an interrupted single-object mutation against its exact attributes.
// Every checked object was absent at preflight, or lives in our private chain.
func (p *NativeProbe) effectExists(ctx context.Context, name string, args []string) (bool, error) {
	value := func(key string) string {
		for i, a := range args {
			if a == key && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	if name == "iptables" {
		if args[2] == "-N" {
			out, err := p.run(ctx, name, "-t", "nat", "-S")
			return strings.Contains(string(out), "-N "+nativeChain), err
		}
		check := append([]string(nil), args...)
		check[2] = "-C"
		if args[2] == "-I" {
			check = append(check[:4], check[5:]...)
		}
		_, err := p.run(ctx, name, check...)
		if err == nil {
			return true, nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}
	if args[0] == "address" {
		out, err := p.run(ctx, "ip", "-j", "address", "show", "dev", value("dev"))
		if err != nil {
			return false, err
		}
		var rows []struct {
			Info []struct {
				Local    string `json:"local"`
				Protocol any    `json:"protocol"`
			} `json:"addr_info"`
		}
		if err = json.Unmarshal(out, &rows); err != nil {
			return false, err
		}
		for _, r := range rows {
			for _, a := range r.Info {
				if a.Local == p.cfg.VirtualIP {
					if fmt.Sprint(a.Protocol) != "186" {
						return false, errors.New("VIP 的所有权属性变化")
					}
					return true, nil
				}
			}
		}
		return false, nil
	}
	if args[0] == "route" {
		out, err := p.run(ctx, "ip", "-j", "route", "show", "table", "186")
		if err != nil {
			return false, err
		}
		var rows []struct {
			Dst     string `json:"dst"`
			Dev     string `json:"dev"`
			Source  string `json:"prefsrc"`
			Gateway string `json:"gateway"`
		}
		if err = json.Unmarshal(out, &rows); err != nil {
			return false, err
		}
		for _, r := range rows {
			dst := r.Dst
			if dst == "default" {
				dst = "0.0.0.0/0"
			}
			if dst == args[4] && r.Dev == value("dev") && r.Source == p.cfg.VirtualIP && r.Gateway == value("via") {
				return true, nil
			}
		}
		return false, nil
	}
	if args[0] == "rule" {
		out, err := p.run(ctx, "ip", "-j", "rule", "show")
		if err != nil {
			return false, err
		}
		var rows []struct {
			Priority int    `json:"priority"`
			Dst      string `json:"dst"`
			Table    any    `json:"table"`
		}
		if err = json.Unmarshal(out, &rows); err != nil {
			return false, err
		}
		for _, r := range rows {
			dst := r.Dst
			if !strings.Contains(dst, "/") {
				dst += "/32"
			}
			table := fmt.Sprint(r.Table)
			if table == "254" {
				table = "main"
			}
			if strconv.Itoa(r.Priority) == value("priority") && dst == value("to") && table == value("lookup") {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("无法确认网络变更结果")
}

func (p *NativeProbe) xfrmEmpty(ctx context.Context) error {
	for _, args := range [][]string{{"-j", "xfrm", "state", "list", "nokeys"}, {"-j", "xfrm", "policy", "list"}} {
		out, err := p.run(ctx, "ip", args...)
		if err != nil {
			return err
		}
		// iproute2's XFRM empty listing may be zero bytes rather than [].
		if len(strings.TrimSpace(string(out))) == 0 {
			continue
		}
		var objects []json.RawMessage
		if err = json.Unmarshal(out, &objects); err != nil {
			return err
		}
		if len(objects) > 0 {
			return errors.New("内核已有或残留 XFRM 对象；拒绝影响其他 IPsec")
		}
	}
	return nil
}

func (p *NativeProbe) uri() string { return "unix://" + filepath.Join(p.RunDir, "charon.vici") }

func (p *NativeProbe) Start(ctx context.Context, c Config) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	c, err = normalizeNativeProfile(c)
	if err != nil {
		return err
	}
	peer := c.Server
	if p.PeerAddress != "" {
		ip := net.ParseIP(p.PeerAddress)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("显式 IKE 传输地址无效")
		}
		peer = ip.String()
	}
	if err = os.Mkdir(p.RunDir, 0o700); err != nil {
		return errors.New("验证运行目录已经存在或不可创建；拒绝覆盖")
	}
	p.owned = true
	p.cfg = c
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = errors.Join(err, p.Stop(cleanup))
		}
	}()
	if err = p.saveJournal(); err != nil {
		return err
	}
	if out, e := p.run(ctx, "pgrep", "-x", "charon"); e == nil && len(strings.TrimSpace(string(out))) > 0 {
		return errors.New("已有 charon，验证入口拒绝影响其他 VPN")
	}
	if _, e := os.Stat("/run/charon.pid"); e == nil {
		return errors.New("已有系统 charon PID 文件，需先确认它的所有者")
	}
	if e := p.xfrmEmpty(ctx); e != nil {
		return e
	}
	ports, e := p.run(ctx, "ss", "-H", "-lun", "( sport = :1194 or sport = :4500 )")
	if e != nil {
		return e
	}
	if len(strings.TrimSpace(string(ports))) > 0 {
		return errors.New("UDP 1194 或 4500 已被占用")
	}
	raw, e := p.run(ctx, "ip", "-j", "route", "get", peer)
	if e != nil {
		return e
	}
	var exits []struct {
		Dev     string `json:"dev"`
		Source  string `json:"prefsrc"`
		Gateway string `json:"gateway"`
	}
	if json.Unmarshal(raw, &exits) != nil || len(exits) != 1 {
		return errors.New("无法确定网关的原始出口")
	}
	exit := exits[0]
	if exit.Dev == "" || net.ParseIP(exit.Source).To4() == nil || strings.HasPrefix(exit.Dev, "tun") || strings.HasPrefix(exit.Dev, "tap") || exit.Dev == "lo" {
		return errors.New("物理出口无效或存在 TUN 冲突")
	}
	if exit.Gateway != "" && net.ParseIP(exit.Gateway).To4() == nil {
		return errors.New("出口下一跳不是 IPv4")
	}
	links, e := p.run(ctx, "ip", "-j", "-d", "link", "show", "dev", exit.Dev)
	if e != nil {
		return e
	}
	var linkInfo []struct {
		Info struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(links, &linkInfo) != nil {
		return errors.New("无法检查出口设备类型")
	}
	for _, link := range linkInfo {
		if link.Info.Kind == "tun" || link.Info.Kind == "xfrm" || link.Info.Kind == "wireguard" {
			return errors.New("网关出口已经被其他隧道接管")
		}
	}
	rules, e := p.run(ctx, "ip", "-j", "rule", "show")
	if e != nil {
		return e
	}
	var currentRules []struct {
		Priority int `json:"priority"`
		Table    any `json:"table"`
	}
	if json.Unmarshal(rules, &currentRules) != nil {
		return errors.New("无法检查现有路由规则")
	}
	for _, r := range currentRules {
		if fmt.Sprint(r.Table) == "186" || r.Priority >= 18599 && r.Priority < 18600+len(c.Routes) {
			return errors.New("验证路由表或优先级被已有规则占用")
		}
	}
	routes, e := p.run(ctx, "ip", "-j", "route", "show", "table", "186")
	if e != nil && !strings.Contains(string(routes), "FIB table does not exist") {
		return e
	}
	if e == nil && strings.TrimSpace(string(routes)) != "[]" {
		return errors.New("验证路由表 186 已有配置")
	}
	nat, e := p.run(ctx, "iptables", "-t", "nat", "-S")
	if e != nil {
		return e
	}
	if strings.Contains(string(nat), nativeChain) {
		return errors.New("验证 SNAT 链已经存在")
	}
	addresses, e := p.run(ctx, "ip", "-j", "address", "show")
	if e != nil {
		return e
	}
	var addrList []struct {
		Info []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(addresses, &addrList) != nil {
		return errors.New("无法检查已有本地地址")
	}
	for _, a := range addrList {
		for _, ip := range a.Info {
			if ip.Local == c.VirtualIP {
				return errors.New("NC VIP 与已有本地地址冲突")
			}
		}
	}
	renderConfig := c
	renderConfig.ClientID = escapeSwanctl(c.ClientID)
	conf := strings.Replace(RenderSwanctl(renderConfig), "local_addrs = %any", "local_addrs = "+exit.Source, 1)
	conf = strings.Replace(conf, "remote_addrs = "+c.Server, "remote_addrs = "+peer, 1)
	conf = strings.Replace(conf, "start_action = start", "start_action = none", 1)
	if e = os.WriteFile(filepath.Join(p.RunDir, "swanctl.conf"), []byte(conf), 0o600); e != nil {
		return e
	}
	daemonConf := fmt.Sprintf("charon {\n port = 1194\n port_nat_t = 4500\n install_routes = no\n pid_file = %s\n load_modular = no\n load = random nonce aes sha1 sha2 hmac gmp openssl kernel-netlink socket-default vici\n plugins {\n vici { socket = %s }\n }\n}\n", filepath.Join(p.RunDir, "charon.pid"), p.uri())
	if e = os.WriteFile(filepath.Join(p.RunDir, "strongswan.conf"), []byte(daemonConf), 0o600); e != nil {
		return e
	}
	if e = p.change(ctx, "ip", []string{"address", "add", c.VirtualIP + "/32", "dev", exit.Dev, "proto", "186"}, []string{"address", "del", c.VirtualIP + "/32", "dev", exit.Dev, "proto", "186"}); e != nil {
		return e
	}
	p.stopDaemon, e = p.Launch(filepath.Join(p.RunDir, "strongswan.conf"), filepath.Join(p.RunDir, "charon.log"))
	if e != nil {
		return e
	}
	p.launched = true
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if _, e = p.run(ctx, "swanctl", "--stats", "--uri", p.uri()); e == nil {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		return errors.New("私有 charon/VICI 启动失败（检查私有日志及 AppArmor）")
	}
	if _, e = p.run(ctx, "swanctl", "--load-all", "--file", filepath.Join(p.RunDir, "swanctl.conf"), "--uri", p.uri()); e != nil {
		return e
	}
	if _, e = p.run(ctx, "swanctl", "--initiate", "--child", "v5vpn", "--uri", p.uri()); e != nil {
		return e
	}
	status, e := p.Status(ctx)
	if e != nil {
		return e
	}
	if !status.Installed {
		return errors.New("本次 Child SA 未安装或选择器不匹配")
	}
	if e = p.change(ctx, "iptables", []string{"-t", "nat", "-N", nativeChain}, []string{"-t", "nat", "-X", nativeChain}); e != nil {
		return e
	}
	if e = p.change(ctx, "iptables", []string{"-t", "nat", "-A", nativeChain, "-d", peer + "/32", "-j", "RETURN"}, []string{"-t", "nat", "-D", nativeChain, "-d", peer + "/32", "-j", "RETURN"}); e != nil {
		return e
	}
	for _, cidr := range c.Routes {
		add := []string{"-t", "nat", "-A", nativeChain, "-d", cidr, "-j", "SNAT", "--to-source", c.VirtualIP}
		del := append([]string(nil), add...)
		del[2] = "-D"
		if e = p.change(ctx, "iptables", add, del); e != nil {
			return e
		}
	}
	if e = p.change(ctx, "ip", []string{"rule", "add", "priority", "18599", "to", peer + "/32", "lookup", "main"}, []string{"rule", "del", "priority", "18599", "to", peer + "/32", "lookup", "main"}); e != nil {
		return e
	}
	for i, cidr := range c.Routes {
		add := []string{"route", "add", "table", "186", cidr}
		if exit.Gateway != "" {
			add = append(add, "via", exit.Gateway)
		}
		add = append(add, "dev", exit.Dev, "src", c.VirtualIP)
		del := append([]string(nil), add...)
		del[1] = "del"
		if e = p.change(ctx, "ip", add, del); e != nil {
			return e
		}
		add = []string{"rule", "add", "priority", strconv.Itoa(18600 + i), "to", cidr, "lookup", "186"}
		del = append([]string(nil), add...)
		del[1] = "del"
		if e = p.change(ctx, "ip", add, del); e != nil {
			return e
		}
	}
	if e = p.change(ctx, "iptables", []string{"-t", "nat", "-I", "POSTROUTING", "1", "-m", "comment", "--comment", "v5vpn-native-check", "-j", nativeChain}, []string{"-t", "nat", "-D", "POSTROUTING", "-m", "comment", "--comment", "v5vpn-native-check", "-j", nativeChain}); e != nil {
		return e
	}
	return nil
}

func (p *NativeProbe) Status(ctx context.Context) (NativeProbeStatus, error) {
	out, err := p.run(ctx, "swanctl", "--list-sas", "--ike", "v5vpn", "--uri", p.uri())
	if err != nil {
		return NativeProbeStatus{}, err
	}
	s := string(out)
	status := NativeProbeStatus{Installed: strings.Contains(s, "INSTALLED") && strings.Contains(s, p.cfg.VirtualIP+"/32") && strings.Contains(s, "0.0.0.0/0")}
	for _, pair := range []struct {
		dir   string
		value *uint64
	}{{"in", &status.InBytes}, {"out", &status.OutBytes}} {
		m := regexp.MustCompile(`(?m)\b` + pair.dir + `\s+[a-fA-F0-9]+,\s+(\d+) bytes`).FindStringSubmatch(s)
		if len(m) == 2 {
			*pair.value, _ = strconv.ParseUint(m[1], 10, 64)
		}
	}
	return status, nil
}

func (p *NativeProbe) Stop(ctx context.Context) error {
	if !p.owned {
		return nil
	}
	var errs []error
	var remaining []nativeUndo
	for i := len(p.undo) - 1; i >= 0; i-- {
		u := p.undo[i]
		if _, err := p.run(ctx, u.name, u.args...); err != nil {
			errs = append(errs, err)
			remaining = append([]nativeUndo{u}, remaining...)
		}
	}
	p.undo = remaining
	if p.stopDaemon != nil {
		if err := p.stopDaemon(ctx); err != nil {
			errs = append(errs, err)
		} else {
			p.stopDaemon = nil
		}
	}
	if p.launched {
		errs = append(errs, p.xfrmEmpty(ctx))
	}
	if p.unresolved {
		errs = append(errs, errors.New("中断变更的结果无法确认，需人工核对"))
	}
	if data, err := os.ReadFile(filepath.Join(p.RunDir, "charon.log")); err == nil {
		text := string(data)
		for _, secret := range []string{p.cfg.PSK, p.cfg.ClientID, p.cfg.Server, p.cfg.VirtualIP} {
			if secret != "" {
				text = strings.ReplaceAll(text, secret, "[REDACTED]")
				var encoded []string
				for _, b := range []byte(secret) {
					encoded = append(encoded, fmt.Sprintf("%02x", b))
				}
				hexID := strings.Join(encoded, ":")
				text = strings.ReplaceAll(text, hexID, "[REDACTED]")
				text = strings.ReplaceAll(text, strings.ToUpper(hexID), "[REDACTED]")
			}
		}
		text = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`).ReplaceAllString(text, "[REDACTED_IP]")
		lines := strings.Split(strings.TrimSpace(text), "\n")
		if len(lines) > 24 {
			lines = lines[len(lines)-24:]
		}
		p.Diagnostics = lines
	}
	// If cleanup failed, retain private evidence and refuse the next run.
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for _, name := range []string{"swanctl.conf", "strongswan.conf", "charon.log", "charon.vici", "charon.pid", "session.json"} {
		if err := os.Remove(filepath.Join(p.RunDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Remove(p.RunDir); err != nil {
		return err
	}
	p.owned = false
	return nil
}

func launchNativeCharon(confPath, logPath string) (func(context.Context) error, error) {
	cmd := exec.Command("/usr/lib/ipsec/charon")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "STRONGSWAN_CONF=" + confPath}
	return launchNativeProcess(cmd, logPath)
}

func launchNativeProcess(cmd *exec.Cmd, logPath string) (func(context.Context) error, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	cmd.Stdout = f
	cmd.Stderr = f
	if err = cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); _ = f.Close(); close(done) }()
	return func(ctx context.Context) error {
		select {
		case <-done:
			return waitErr
		default:
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
			return waitErr
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			return errors.New("charon 未在清理期限内退出，需核对残留")
		}
	}, nil
}
