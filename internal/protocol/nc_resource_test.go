package protocol

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
)

const ncPortalFixture = `<?xml version="1.0" encoding="UTF-8"?>
<INTERGRATION_INFO>
  <VERSION major="2" minor="0"/>
  <USER name="alice" group="接入BAP"/>
  <SESSION sid_name="VSG_SESSIONID" id="sess-1" detect_interval="180"/>
  <RESOURCE_LIST>
    <NC_RESOURCE name='nc'><IKE version='v1'>
      <SERVER ip='198.51.100.10' port='1194' id-type='ipv4' id='198.51.100.10'/>
      <CLIENT port='500' id-type='key_id' id='sess-1'/>
      <Exchange mode='main'/>
      <PSK key='test-preshared-key'/>
    </IKE>
    <PRIVATE-IP ip='10.70.0.5' ipv6='' addr='10.70.0.5' subnet='255.255.255.255'/>
    <TUNNEL tunnel-name='办公网' mapid='198.51.100.10' status='1'>
      <EXTENSIONS>
        <SECURED-ROUTE><ROUTE addr='198.51.100.0/24'/></SECURED-ROUTE>
        <SECURED-ROUTES name='邮件'><ROUTE addr='203.0.113.25/32'/></SECURED-ROUTES>
      </EXTENSIONS>
    </TUNNEL>
    <TUNNEL tunnel-name='服务器段' mapid='198.51.100.10' status='1'>
      <EXTENSIONS>
        <SECURED-ROUTE><ROUTE addr='198.51.124.0/24'/></SECURED-ROUTE>
      </EXTENSIONS>
    </TUNNEL>
    </NC_RESOURCE>
  </RESOURCE_LIST>
  <DNS_INFO><DOMAIN_HOST dnssrv="10.0.0.2"/></DNS_INFO>
</INTERGRATION_INFO>`

func TestParseNCResource(t *testing.T) {
	var info IntegrationInfo
	if err := xml.Unmarshal([]byte(ncPortalFixture), &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(info.ResourceList.TCPUDPResources) != 0 {
		t.Fatalf("fixture should have no TCP/UDP resources, got %d", len(info.ResourceList.TCPUDPResources))
	}
	if len(info.ResourceList.NCResources) != 1 {
		t.Fatalf("NCResource count = %d, want 1", len(info.ResourceList.NCResources))
	}

	nc := info.ResourceList.NCResources[0]
	if nc.Name != "nc" {
		t.Errorf("name = %q", nc.Name)
	}
	if nc.IKE.Server.IP != "198.51.100.10" || nc.IKE.Server.Port != 1194 {
		t.Errorf("server = %+v", nc.IKE.Server)
	}
	if nc.IKE.Client.IDType != "key_id" || nc.IKE.Client.ID != "sess-1" {
		t.Errorf("client = %+v", nc.IKE.Client)
	}
	if nc.IKE.Exchange.Mode != "main" {
		t.Errorf("exchange = %q", nc.IKE.Exchange)
	}
	if nc.IKE.PSK.Key != "test-preshared-key" {
		t.Errorf("PSK was not parsed")
	}
	if nc.PrivateIP.IP != "10.70.0.5" {
		t.Errorf("private ip = %q", nc.PrivateIP.IP)
	}
	if len(nc.Tunnels) != 2 {
		t.Fatalf("tunnel count = %d, want 2", len(nc.Tunnels))
	}
	if got := len(nc.Tunnels[0].Routes); got != 1 {
		t.Errorf("first tunnel routes = %d, want 1", got)
	}
	if got := len(nc.Tunnels[0].Named); got != 1 {
		t.Errorf("first tunnel named routes = %d, want 1", got)
	}
}

func TestSummarizeNCResourcesHidesPSK(t *testing.T) {
	var info IntegrationInfo
	if err := xml.Unmarshal([]byte(ncPortalFixture), &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	summary := SummarizeNCResources(info.ResourceList.NCResources)
	if len(summary) != 1 {
		t.Fatalf("summary count = %d, want 1", len(summary))
	}
	if summary[0].Server != "198.51.100.10:1194" {
		t.Errorf("server = %q", summary[0].Server)
	}
	if summary[0].PrivateIP != "10.70.0.5" {
		t.Errorf("private ip = %q", summary[0].PrivateIP)
	}
	if len(summary[0].Tunnels) != 2 || summary[0].Tunnels[0].Name != "办公网" {
		t.Fatalf("tunnels = %+v", summary[0].Tunnels)
	}
	wa := summary[0].Tunnels[0].Routes
	if len(wa) != 2 || wa[0] != "198.51.100.0/24" || wa[1] != "203.0.113.25/32" {
		t.Errorf("routes = %v", wa)
	}

	// The summary is what /api/status exposes; the pre-shared key must never
	// travel with it.
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "test-preshared-key") || strings.Contains(string(data), "PSK") {
		t.Fatalf("summary leaked key material: %s", data)
	}
}
