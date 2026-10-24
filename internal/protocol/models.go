package protocol

import (
	"encoding/xml"
	"fmt"
)

// VersionResponse represents /vpn/version.xml response
type VersionResponse struct {
	XMLName xml.Name `xml:"VERSION"`
	Major   string   `xml:"major,attr"`
	Minor   string   `xml:"minor,attr"`
}

// AuthResponse represents the XML response from /vpn/user/auth/password
type AuthResponse struct {
	XMLName xml.Name  `xml:"RESPONSE"`
	Result  ResultTag `xml:"RESULT"`

	// CertFactorUsed is not part of the gateway XML. AuthPasswordWithCert sets
	// it when the gateway's result code asked for the certificate factor and the
	// certificate step succeeded, so the caller can tell a real two-factor
	// session from one the gateway accepted on the password alone.
	CertFactorUsed bool `xml:"-"`
}

type ResultTag struct {
	Code    string `xml:"code,attr"`
	Msg     string `xml:"msg,attr"`
	SIDName string `xml:"sid_name,attr"`
}

// IntegrationInfo represents /vpn/user/portal/intergration.xml
type IntegrationInfo struct {
	XMLName      xml.Name     `xml:"INTERGRATION_INFO"`
	Version      VersionTag   `xml:"VERSION"`
	User         UserInfo     `xml:"USER"`
	Session      SessionInfo  `xml:"SESSION"`
	Gateway      GatewayInfo  `xml:"GATEWAY"`
	ResourceList ResourceList `xml:"RESOURCE_LIST"`
	DNSInfo      DNSInfo      `xml:"DNS_INFO"`
}

type VersionTag struct {
	Major string `xml:"major,attr"`
	Minor string `xml:"minor,attr"`
}

type UserInfo struct {
	Name         string `xml:"name,attr"`
	Group        string `xml:"group,attr"`
	Type         string `xml:"type,attr"`
	AccessType   string `xml:"access_type,attr"`
	LogoutPolicy string `xml:"logout_policy,attr"`
	SSLSM2       string `xml:"ssl_sm2,attr"`
	PSKey        string `xml:"client_jump_pskey,attr"`
	// PwdOvertime 是网关给出的口令剩余有效天数（0 表示无过期策略或已取不到）。
	PwdOvertime int `xml:"pwd_overtime,attr"`
}

type SessionInfo struct {
	SIDName        string `xml:"sid_name,attr"`
	ID             string `xml:"id,attr"`
	LoginAddr      string `xml:"login-addr,attr"`
	LoginTime      string `xml:"login-time,attr"`
	CurrentTime    string `xml:"current-time,attr"`
	DetectInterval int    `xml:"detect_interval,attr"` // Seconds, e.g. 180
}

type GatewayInfo struct {
	Version string `xml:"version,attr"`
}

type ResourceList struct {
	TCPUDPResources []TCPUDPResource `xml:"TCPUDP_RESOURCE"`
	// NCResources are Network Connect / IPsec profiles. The SSL CONNECT tunnel
	// path cannot carry them; they are parsed so the UI can explain what the
	// gateway granted instead of reporting a bare "0 resources".
	NCResources []NCResource `xml:"NC_RESOURCE"`
}

// NCResource is one Network Connect profile: IKE parameters, the virtual IP
// assigned to this session, and the tunnels (subnets) it protects.
type NCResource struct {
	Name      string     `xml:"name,attr" json:"name"`
	IKE       IKEParams  `xml:"IKE" json:"ike"`
	PrivateIP PrivateIP  `xml:"PRIVATE-IP" json:"privateIp"`
	Tunnels   []NCTunnel `xml:"TUNNEL" json:"tunnels"`
}

type IKEParams struct {
	Version  string      `xml:"version,attr" json:"version"`
	Server   IKEEndpoint `xml:"SERVER" json:"server"`
	Client   IKEEndpoint `xml:"CLIENT" json:"client"`
	Exchange IKEExchange `xml:"Exchange" json:"exchange"`
	// PSK is the pre-shared key from the portal response. It is deliberately
	// never serialized: nothing outside the (future) IPsec engine needs it.
	PSK IKEPSK `xml:"PSK" json:"-"`
}

type IKEExchange struct {
	Mode string `xml:"mode,attr" json:"mode"`
}

type IKEPSK struct {
	Key string `xml:"key,attr" json:"-"`
}

type IKEEndpoint struct {
	IP     string `xml:"ip,attr" json:"ip,omitempty"`
	Port   int    `xml:"port,attr" json:"port,omitempty"`
	IDType string `xml:"id-type,attr" json:"idType,omitempty"`
	ID     string `xml:"id,attr" json:"id,omitempty"`
}

type PrivateIP struct {
	IP     string `xml:"ip,attr" json:"ip"`
	Subnet string `xml:"subnet,attr" json:"subnet,omitempty"`
}

type NCTunnel struct {
	Name   string    `xml:"tunnel-name,attr" json:"name"`
	MapID  string    `xml:"mapid,attr" json:"mapId,omitempty"`
	Status string    `xml:"status,attr" json:"status,omitempty"`
	Routes []NCRoute `xml:"EXTENSIONS>SECURED-ROUTE>ROUTE" json:"routes,omitempty"`
	Named  []NCRoute `xml:"EXTENSIONS>SECURED-ROUTES>ROUTE" json:"namedRoutes,omitempty"`
}

type NCRoute struct {
	Addr    string `xml:"addr,attr" json:"addr"`
	Exclude string `xml:"exclude,attr" json:"exclude,omitempty"`
}

// IPsecResource is the UI-facing summary of an NC profile. It carries no key
// material and is safe to expose through the HTTP API.
type IPsecResource struct {
	Name      string        `json:"name"`
	Server    string        `json:"server"`
	PrivateIP string        `json:"privateIp"`
	Tunnels   []IPsecTunnel `json:"tunnels"`
}

type IPsecTunnel struct {
	Name   string   `json:"name"`
	Routes []string `json:"routes"`
}

// SummarizeNCResources flattens NC profiles into the summary the connected
// view shows when there are no TCP/UDP resources to proxy.
func SummarizeNCResources(list []NCResource) []IPsecResource {
	if len(list) == 0 {
		return nil
	}
	out := make([]IPsecResource, 0, len(list))
	for _, nc := range list {
		srv := nc.IKE.Server.IP
		if nc.IKE.Server.Port > 0 {
			srv = fmt.Sprintf("%s:%d", nc.IKE.Server.IP, nc.IKE.Server.Port)
		}
		summary := IPsecResource{
			Name:      nc.Name,
			Server:    srv,
			PrivateIP: nc.PrivateIP.IP,
		}
		for _, tun := range nc.Tunnels {
			routes := make([]string, 0, len(tun.Routes)+len(tun.Named))
			for _, r := range tun.Routes {
				if r.Addr != "" {
					routes = append(routes, r.Addr)
				}
			}
			for _, r := range tun.Named {
				if r.Addr != "" {
					routes = append(routes, r.Addr)
				}
			}
			summary.Tunnels = append(summary.Tunnels, IPsecTunnel{Name: tun.Name, Routes: routes})
		}
		out = append(out, summary)
	}
	return out
}

type TCPUDPResource struct {
	Name     string `xml:"name,attr" json:"name"`
	Protocol string `xml:"protocol,attr" json:"protocol"`
	MapID    string `xml:"mapid,attr" json:"mapId"`
	Port     string `xml:"port,attr" json:"port"` // can be "24390" or "443;24390"
	Status   string `xml:"status,attr" json:"status"`
	IsTCP    string `xml:"istcp,attr" json:"isTcp"`
	// Addr 是网关直接写在资源节点上的目标地址（真实网关常见形态，例如
	// 堡垒机 addr="10.10.20.15"），与子节点 TCPUDP_IP 二选一。
	Addr      string     `xml:"addr,attr" json:"addr"`
	IPConfigs []TCPUDPIp `xml:"TCPUDP_IP" json:"ipConfigs"`
	LocalPort int        `xml:"-" json:"localPort"` // Local forwarding port assigned by client
}

type TCPUDPIp struct {
	Addr string `xml:"addr,attr" json:"addr"` // e.g. "172.19.52.4-172.19.52.4"
}

type DNSInfo struct {
	DomainHost DomainHost `xml:"DOMAIN_HOST"`
}

type DomainHost struct {
	DNSSrv   string `xml:"dnssrv,attr"`
	DNSSrvV6 string `xml:"dnssrv_v6,attr"`
}

// VPNResource represents mapped resource for UI display and proxying
type VPNResource struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	RemoteIP   string `json:"remoteIp"`
	RemotePort string `json:"remotePort"`
	LocalProxy string `json:"localProxy"`
	Status     string `json:"status"`
	MapID      string `json:"mapId,omitempty"`
	AccessURL  string `json:"accessUrl,omitempty"`
}
