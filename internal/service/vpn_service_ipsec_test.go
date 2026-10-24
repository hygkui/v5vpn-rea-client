package service

// VPNService 的 IPsec 编排状态机测试：startIPsec / stopIPsec 把
// ipsecState 在 "" → starting → up / error / unavailable 间迁移，并把
// 失败原因暴露到 /api/status。WSL 侧通过 newIPsecManager 缝注入 fake
// CommandRunner，不依赖（也不触碰）真实 WSL / route.exe——后者属于
// Windows 现网验证，见 docs/ipsec.md 与 internal/ipsec/live_test.go。

import (
	"context"
	"encoding/xml"
	"errors"
	"strings"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/ipsec"
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

// fakeIPsecRunner 记录每条 wsl.exe 命令并按命令形态作答：
// "-- true" 是 Available 探针；"swanctl --load-all" 是 Start；
// "hostname -I" 是 WSLIP——单测里让它失败，避免 AddRoutes 碰到真实
// route.exe / 路由表（该路径由实网验证覆盖）。
type fakeIPsecRunner struct {
	available bool
	startOK   bool
	calls     []string
}

func (f *fakeIPsecRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, line)
	switch {
	case strings.HasSuffix(line, "-- true"):
		if !f.available {
			return nil, errors.New("exit status 1")
		}
	case strings.Contains(line, "hostname -I"):
		return nil, errors.New("exit status 1")
	case strings.Contains(line, "swanctl --load-all"):
		if !f.startOK {
			return []byte("mock: initiate failed"), errors.New("exit status 1")
		}
		return []byte("mock: initiated"), nil
	}
	return []byte("mock: ok"), nil
}

// newIPsecTestService 构造注入了 fake Runner 的服务，并把用户数据目录
// 指到临时目录（startIPsec 会往里面写 ipsec.conf）。
func newIPsecTestService(t *testing.T, runner ipsec.CommandRunner) *VPNService {
	t.Helper()
	prev := config.UserDataDir()
	config.SetUserDataDir(t.TempDir())
	t.Cleanup(func() { config.SetUserDataDir(prev) })

	s := NewVPNService(nil)
	s.newIPsecManager = func(confPath string) *ipsec.Manager {
		m := ipsec.NewManager(confPath)
		m.Runner = runner
		return m
	}
	return s
}

// ncTestResources 与 test/mock/v5vpn/server.go 的 ncResourceXML 夹具同构
// （TEST-NET 地址、mock PSK），保证单测、mock 集成测试与 UI E2E 断言的
// 是同一份网关行为。
func ncTestResources(t *testing.T) []protocol.NCResource {
	t.Helper()
	const fixture = `<RESOURCE_LIST>
  <NC_RESOURCE name="nc">
    <IKE version="v1">
      <SERVER ip="198.51.100.10" port="1194" id-type="ipv4" id="198.51.100.10"/>
      <CLIENT port="1194" id-type="key_id" id="mock-nc-session"/>
      <Exchange mode="main"/>
      <PSK key="mock-psk-fixture"/>
    </IKE>
    <PRIVATE-IP ip="10.70.0.5" subnet="255.255.255.255"/>
    <TUNNEL tunnel-name="Mock 办公网" mapid="198.51.100.10" status="1">
      <EXTENSIONS>
        <SECURED-ROUTE><ROUTE addr="198.51.100.0/24"/></SECURED-ROUTE>
        <SECURED-ROUTES><ROUTE addr="203.0.113.0/24"/></SECURED-ROUTES>
      </EXTENSIONS>
    </TUNNEL>
  </NC_RESOURCE>
</RESOURCE_LIST>`
	var list protocol.ResourceList
	if err := xml.Unmarshal([]byte(fixture), &list); err != nil {
		t.Fatalf("解析 NC 夹具失败: %v", err)
	}
	if len(list.NCResources) != 1 {
		t.Fatalf("夹具应含 1 个 NC 资源, got %d", len(list.NCResources))
	}
	return list.NCResources
}

func ipsecStatus(t *testing.T, s *VPNService) map[string]any {
	t.Helper()
	st := s.GetStatus()
	if st["ipsecState"] == nil {
		t.Fatalf("GetStatus 缺少 ipsecState 字段")
	}
	return st
}

func logContains(s *VPNService, want string) bool {
	for _, line := range s.GetLogs() {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}

// WSL 探针失败（未安装发行版）：状态必须是 unavailable，并把安装指引
// 原样暴露给界面，而不是笼统的 error。
func TestStartIPsecMarksUnavailableWhenWSLProbeFails(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{available: false})
	s.startIPsec(ncTestResources(t))

	st := ipsecStatus(t, s)
	if st["ipsecState"] != "unavailable" {
		t.Fatalf("ipsecState = %v, want unavailable", st["ipsecState"])
	}
	if msg, _ := st["ipsecError"].(string); !strings.Contains(msg, "v5vpn 不可用") {
		t.Errorf("ipsecError = %q, want WSL 发行版指引", msg)
	}
}

// 隧道成功建立：状态迁移到 up。WSLIP 故意失败以跳过 Windows 路由,
// 断言这只产生 WARN 而不影响 up。
func TestStartIPsecReachesUpWhenManagerStarts(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{available: true, startOK: true})
	s.startIPsec(ncTestResources(t))

	st := ipsecStatus(t, s)
	if st["ipsecState"] != "up" {
		t.Fatalf("ipsecState = %v, want up", st["ipsecState"])
	}
	if st["ipsecError"] != "" {
		t.Errorf("up 状态不应带错误信息, got %v", st["ipsecError"])
	}
	if !logContains(s, "无法获取 WSL 地址") {
		t.Errorf("WSLIP 失败应记录跳过路由的 WARN 日志")
	}
	if !logContains(s, "IPsec 隧道已建立") {
		t.Errorf("缺少隧道建立成功日志")
	}
}

// swanctl 启动失败：状态是 error，错误信息透传给界面。
func TestStartIPsecRecordsManagerStartFailure(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{available: true, startOK: false})
	s.startIPsec(ncTestResources(t))

	st := ipsecStatus(t, s)
	if st["ipsecState"] != "error" {
		t.Fatalf("ipsecState = %v, want error", st["ipsecState"])
	}
	if msg, _ := st["ipsecError"].(string); !strings.Contains(msg, "启动 IPsec 隧道失败") {
		t.Errorf("ipsecError = %q, want 启动失败原因", msg)
	}
}

// stopIPsec 必须清空状态并真的向 WSL 下发 terminate。
func TestStopIPsecClearsStateAndTerminates(t *testing.T) {
	runner := &fakeIPsecRunner{available: true, startOK: true}
	s := newIPsecTestService(t, runner)
	s.startIPsec(ncTestResources(t))

	s.stopIPsec()

	st := ipsecStatus(t, s)
	if st["ipsecState"] != "" || st["ipsecError"] != "" {
		t.Fatalf("stop 后状态未清空: state=%v err=%v", st["ipsecState"], st["ipsecError"])
	}
	terminated := false
	for _, c := range runner.calls {
		if strings.Contains(c, "swanctl --terminate") {
			terminated = true
		}
	}
	if !terminated {
		t.Errorf("stop 未下发 swanctl --terminate, calls = %v", runner.calls)
	}
}

// 网关下发的 NC 配置没有可路由子网时，FromNC 拒绝：状态是 error 而非 up。
func TestStartIPsecRejectsProfileWithoutRoutes(t *testing.T) {
	s := newIPsecTestService(t, &fakeIPsecRunner{available: true, startOK: true})
	s.startIPsec([]protocol.NCResource{{
		Name: "nc",
		IKE: protocol.IKEParams{
			Version: "v1",
			Server:  protocol.IKEEndpoint{IP: "198.51.100.10", Port: 1194},
			Client:  protocol.IKEEndpoint{ID: "mock-nc-session"},
			PSK:     protocol.IKEPSK{Key: "mock-psk-fixture"},
		},
		PrivateIP: protocol.PrivateIP{IP: "10.70.0.5"},
	}})

	st := ipsecStatus(t, s)
	if st["ipsecState"] != "error" {
		t.Fatalf("ipsecState = %v, want error", st["ipsecState"])
	}
	if msg, _ := st["ipsecError"].(string); !strings.Contains(msg, "没有可路由的子网") {
		t.Errorf("ipsecError = %q, want FromNC 的拒绝原因", msg)
	}
}
