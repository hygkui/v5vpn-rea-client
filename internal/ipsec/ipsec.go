// Package ipsec drives the IPsec (Network Connect) data plane that the V5VPN
// gateway grants through <NC_RESOURCE>. The SSL VPN code path in internal/proxy
// cannot carry these subnets: they need IKEv1 + ESP and a virtual interface.
//
// The heavy lifting is delegated to strongSwan inside WSL2. This package only
// renders the swanctl configuration from the portal response and runs the
// wsl/swanctl commands; it does not implement IKE itself.
package ipsec

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// ikePort is the IKE/UDP port used by this gateway family. The portal reports
// SERVER port=1194 and the vendor's charon log shows the same port on the
// client side; sending from UDP 500 gets no response at all. The Linux kernel
// also floats the encrypted exchange to UDP 4500 (NAT-T), which the gateway
// supports.
const ikePort = 1194

// Config is the runtime profile for one NC session. Every login returns new
// values (session id, virtual IP, PSK), so it is built per session.
type Config struct {
	Server     string   // gateway IKE address
	ServerPort int      // gateway IKE port (the portal reports a non-default one)
	ClientID   string   // session id, sent as a KEY_ID identity
	PSK        string   // gateway pre-shared key
	VirtualIP  string   // internal address assigned to this session
	Routes     []string // CIDR subnets protected by the tunnel
}

// FromNC builds the runtime config from the portal's first NC resource.
// Multiple NC resources are not produced by the gateways seen so far; the
// caller should treat more than one as unsupported rather than guessing.
func FromNC(list []protocol.NCResource) (*Config, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("网关未下发 IPsec（NC）资源")
	}
	if len(list) > 1 {
		return nil, fmt.Errorf("网关下发了 %d 个 IPsec 配置，暂不支持", len(list))
	}

	nc := list[0]
	cfg := &Config{
		Server:     strings.TrimSpace(nc.IKE.Server.IP),
		ServerPort: nc.IKE.Server.Port,
		ClientID:   strings.TrimSpace(nc.IKE.Client.ID),
		PSK:        nc.IKE.PSK.Key,
		VirtualIP:  strings.TrimSpace(nc.PrivateIP.IP),
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 500
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("IPsec 配置缺少网关地址")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("IPsec 配置缺少客户端标识")
	}
	if cfg.PSK == "" {
		return nil, fmt.Errorf("IPsec 配置缺少预共享密钥")
	}
	if cfg.VirtualIP == "" {
		return nil, fmt.Errorf("IPsec 配置缺少虚拟 IP")
	}

	seen := make(map[string]struct{})
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		cfg.Routes = append(cfg.Routes, addr)
	}
	for _, tun := range nc.Tunnels {
		for _, r := range tun.Routes {
			add(r.Addr)
		}
		for _, r := range tun.Named {
			add(r.Addr)
		}
	}
	if len(cfg.Routes) == 0 {
		return nil, fmt.Errorf("IPsec 配置没有可路由的子网")
	}
	return cfg, nil
}

// RenderSwanctl returns the swanctl.conf body for strongSwan. IKEv1 main mode
// with PSK, the proposals observed in the live portal (aes192-sha1-modp1024),
// and a static virtual IP. The virtual IP is installed on the interface by the
// manager; it is not requested through ModeConfig, because the gateway already
// assigned it in the portal response.
func RenderSwanctl(c Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "connections {\n  v5vpn {\n")
	fmt.Fprintf(&b, "    version = 1\n")
	fmt.Fprintf(&b, "    local_addrs = %%any\n")
	fmt.Fprintf(&b, "    local_port = %d\n", ikePort)
	fmt.Fprintf(&b, "    remote_addrs = %s\n", c.Server)
	fmt.Fprintf(&b, "    remote_port = %d\n", c.ServerPort)
	fmt.Fprintf(&b, "    proposals = aes192-sha1-modp1024\n")
	fmt.Fprintf(&b, "    local-1 {\n      auth = psk\n      id = \"keyid:%s\"\n    }\n", c.ClientID)
	fmt.Fprintf(&b, "    remote-1 {\n      auth = psk\n      id = %s\n    }\n", c.Server)
	fmt.Fprintf(&b, "    children {\n      v5vpn {\n")
	fmt.Fprintf(&b, "        local_ts = %s/32\n", c.VirtualIP)
	// The gateway negotiates the child SA as VIP/32 === 0.0.0.0/0 (verified
	// against the vendor's charon log). The per-tunnel SECURED-ROUTE entries
	// are used for the Windows route table, not as traffic selectors.
	fmt.Fprintf(&b, "        remote_ts = 0.0.0.0/0\n")
	fmt.Fprintf(&b, "        esp_proposals = aes192-sha1\n")
	fmt.Fprintf(&b, "        start_action = start\n")
	fmt.Fprintf(&b, "        dpd_action = restart\n")
	fmt.Fprintf(&b, "      }\n    }\n  }\n}\n")
	fmt.Fprintf(&b, "secrets {\n  ike-v5vpn {\n    secret = \"%s\"\n  }\n}\n", escapeSwanctl(c.PSK))
	return b.String()
}

func escapeSwanctl(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// ParseCIDR splits an IPv4 CIDR into network address and dotted mask, as
// expected by route.exe. It rejects IPv6 and malformed input.
func ParseCIDR(cidr string) (network, mask string, err error) {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", "", err
	}
	v4 := ip.To4()
	if v4 == nil || ipnet.IP.To4() == nil {
		return "", "", fmt.Errorf("只支持 IPv4 子网: %s", cidr)
	}
	maskIP := net.IP(ipnet.Mask).To4()
	if maskIP == nil {
		return "", "", fmt.Errorf("无法解析子网掩码: %s", cidr)
	}
	return v4.Mask(net.IPMask(maskIP)).String(), maskIP.String(), nil
}

// FormatServerPort is used in logs; it keeps the port visible without exposing
// any key material.
func FormatServerPort(c Config) string {
	return c.Server + ":" + strconv.Itoa(c.ServerPort)
}
