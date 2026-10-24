package mockserver

// NC（Network Connect / IPsec）资源链路集成测试：网关下发 <NC_RESOURCE> 后，
// 协议客户端要完整解析 IKE 参数、虚拟 IP 与路由，摘要不得泄漏 PSK，且
// ipsec.FromNC 能据此生成数据面配置。这层是 UI E2E（ui:v5vpn-nc 场景）的
// 裁判依据：mock 的 NC 夹具形态以 docs/ipsec.md §1 为准。

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/ipsec"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestNCResourcesFlowThroughProtocolClient(t *testing.T) {
	_, host, port := startTestGatewayCfg(t, Config{
		Addr:    "127.0.0.1:0",
		Mode:    ModePwdOnly,
		NCMode:  NCModeOnly,
		Verbose: false,
	})

	client := protocol.NewClient(host, port, 0, func(level, format string, args ...any) {
		t.Logf("["+level+"] "+format, args...)
	})
	if _, err := client.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if _, err := client.AuthOnly("admin", "admin123", ""); err != nil {
		t.Fatalf("AuthOnly failed: %v", err)
	}

	info, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}

	// only 模式模拟「NC 全路由账号」：没有 TCP/UDP 代理资源。
	if got := len(info.ResourceList.TCPUDPResources); got != 0 {
		t.Errorf("NC-only 账号不应下发 TCP/UDP 资源, got %d", got)
	}

	ncs := info.ResourceList.NCResources
	if len(ncs) != 1 {
		t.Fatalf("期望 1 个 NC 资源, got %d", len(ncs))
	}
	nc := ncs[0]
	if nc.IKE.Server.IP != "198.51.100.10" || nc.IKE.Server.Port != 1194 {
		t.Errorf("IKE SERVER 解析错误: %+v", nc.IKE.Server)
	}
	if nc.IKE.PSK.Key != "mock-psk-fixture" {
		t.Errorf("PSK 解析错误: %q", nc.IKE.PSK.Key)
	}
	if nc.PrivateIP.IP != "10.70.0.5" {
		t.Errorf("PRIVATE-IP 解析错误: %q", nc.PrivateIP.IP)
	}
	if len(nc.Tunnels) != 1 || nc.Tunnels[0].Name != "Mock 办公网" {
		t.Fatalf("隧道解析错误: %+v", nc.Tunnels)
	}
	routeAddrs := func(rs []protocol.NCRoute) string {
		parts := make([]string, 0, len(rs))
		for _, r := range rs {
			parts = append(parts, r.Addr)
		}
		return strings.Join(parts, " ")
	}
	if !strings.Contains(routeAddrs(nc.Tunnels[0].Routes), "198.51.100.0/24") {
		t.Errorf("SECURED-ROUTE 路由缺失: %+v", nc.Tunnels[0].Routes)
	}
	if !strings.Contains(routeAddrs(nc.Tunnels[0].Named), "203.0.113.0/24") {
		t.Errorf("SECURED-ROUTES 路由缺失: %+v", nc.Tunnels[0].Named)
	}

	// 摘要（进 /api/status 与界面的形态）必须不含密钥。
	blob, err := json.Marshal(protocol.SummarizeNCResources(ncs))
	if err != nil {
		t.Fatalf("Marshal summary failed: %v", err)
	}
	if strings.Contains(string(blob), "mock-psk-fixture") {
		t.Fatalf("PSK 泄漏进摘要 JSON: %s", blob)
	}

	// 数据面配置可由网关响应直接生成。
	cfg, err := ipsec.FromNC(ncs)
	if err != nil {
		t.Fatalf("FromNC failed: %v", err)
	}
	if cfg.Server != "198.51.100.10" || cfg.ServerPort != 1194 {
		t.Errorf("FromNC Server/Port 错误: %+v", cfg)
	}
	if cfg.VirtualIP != "10.70.0.5" || cfg.ClientID != "mock-nc-session" {
		t.Errorf("FromNC VIP/ClientID 错误: %+v", cfg)
	}
}

// mixed 模式：NC 与 TCP/UDP 并存，两条列表都要完整到达客户端。
func TestNCResourcesMixedWithTCPUDP(t *testing.T) {
	_, host, port := startTestGatewayCfg(t, Config{
		Addr:    "127.0.0.1:0",
		Mode:    ModePwdOnly,
		NCMode:  NCModeMixed,
		Verbose: false,
	})

	client := protocol.NewClient(host, port, 0, nil)
	if _, err := client.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if _, err := client.AuthOnly("admin", "admin123", ""); err != nil {
		t.Fatalf("AuthOnly failed: %v", err)
	}
	info, err := client.FetchIntegration()
	if err != nil {
		t.Fatalf("FetchIntegration failed: %v", err)
	}
	if got := len(info.ResourceList.TCPUDPResources); got != 3 {
		t.Errorf("mixed 模式应保留 3 个 TCP/UDP 资源, got %d", got)
	}
	if got := len(info.ResourceList.NCResources); got != 1 {
		t.Errorf("mixed 模式应附 1 个 NC 资源, got %d", got)
	}
}
