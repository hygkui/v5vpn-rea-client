# 总体架构与关键链路（图示）

本文是 `docs/` 各设计文档的**图形化入口**：一张总架构图 + 一条登录主链路的
端到端时序。各机制细节（认证状态机、协议交互、网页代理、IPsec 数据面）
仍以对应文档为准，本文只回答「组件怎么拼起来、一次登录经历了什么」。

| 想看什么 | 去哪 |
|:---|:---|
| 认证状态机与挑战模态 | [`auth-flow.md`](auth-flow.md) |
| 网关 HTTP 协议逐条端点 | [`protocol.md`](protocol.md) |
| 端口区间资源代理与系统 PAC | [`web-proxy.md`](web-proxy.md) |
| NC 资源 IPsec 数据面 | [`ipsec.md`](ipsec.md) |

图中出现的组件名即真实包名 / 路由名，与代码一一对应。

---

## 1. 总架构：单进程、双后端、本地桥

客户端是**一个 Go 桌面进程**（mygo 框架承载原生 WebView），前后端之间
没有跨进程 IPC——前端就是本地 HTTP 服务上的静态页面，`fetch /api/*`
即"IPC"：

```mermaid
flowchart TB
    subgraph shell["窗口壳 mygo（internal/cmd）"]
        webview["原生 WebView<br/>(WebView2 / WKWebView / WebKitGTK)"]
        tray["系统托盘 + 退出钩子<br/>(backends：谁活动就关谁)"]
    end

    subgraph ui["嵌入式前端 internal/cmd/ui（两套物理分家）"]
        v5ui["/v5vpn/ 前端 (app.js)"]
        atui["/atrust/ 前端"]
    end

    subgraph bridge["UI Bridge —— 本地 HTTP 服务 127.0.0.1:45678<br/>(端口被占时回退随机端口)"]
        api["newAPIRouter<br/>/api/login、/api/status、/api/sms-login …"]
        pacsrv["/proxy.pac"]
        uifs["静态 UI 资源 (embed.FS)"]
    end

    subgraph service["服务层 internal/service"]
        vpns["VPNService<br/>(V5VPN 后端)"]
        ats["ATrustService<br/>(aTrust 后端)"]
        syspx["systemproxy_*<br/>(HKCU AutoConfigURL)"]
    end

    subgraph protocollayer["协议层"]
        proto["internal/protocol<br/>V5VPN REST 客户端 + 心跳"]
        atp["internal/atrust<br/>aTrust 控制面 + 流式隧道"]
    end

    subgraph data["本地数据面"]
        pm["proxy.ProxyManager<br/>单端口资源 → 本地端口映射"]
        wp["proxy.WebProxy<br/>区间资源 → 回环 CONNECT"]
        ips["internal/ipsec<br/>WSL2/strongSwan 编排"]
    end

    subgraph support["支撑"]
        cfg["internal/config<br/>setting.xml / GatewayProfile"]
        certs["internal/certstore<br/>(.p12/.pfx 证书库)"]
        crypt["internal/crypto<br/>DES-CBC / AES-128-CBC"]
    end

    gw1["V5VPN 网关<br/>(HTTPS REST + SSL CONNECT)"]
    gw2["aTrust 网关"]
    wsl["WSL2 strongSwan<br/>(IKEv1/ESP)"]
    intranet["内网资源"]
    browser["系统浏览器"]

    webview -->|"按 lastUseGateway 协议选入口<br/>(ui_routes.go)"| ui
    v5ui -->|"fetch /api/*"| api
    atui -->|"fetch /api/atrust/*"| api
    api --> vpns
    api --> ats
    vpns --> proto
    ats --> atp
    proto -->|"HTTPS"| gw1
    atp -->|"HTTPS"| gw2
    vpns -->|"资源加载后"| pm
    vpns -->|"资源加载后"| wp
    vpns -->|"NC 资源，异步"| ips
    pm -->|"CONNECT (MapID + VSG_SESSIONID)"| gw1
    wp -->|"CONNECT (MapID + VSG_SESSIONID)"| gw1
    ips -->|"swanctl / 路由 / SNAT"| wsl
    wsl -->|"IKEv1 UDP 1194→4500 / ESP"| gw1
    pm & wp --> intranet
    wsl --> intranet
    vpns --> syspx
    syspx -->|"AutoConfigURL"| browser
    browser -->|"读 PAC + CONNECT"| wp
    vpns --- cfg
    vpns --- certs
    cfg --- crypt
```

阅读要点：

- **两个后端互不感知**（`backends.go` 的三条边界）：`VPNService` 与
  `ATrustService` 在 service 层并列，登录互不路由，UI 按网关 profile 的
  protocol 自己选入口；托盘与退出时由 cmd 层统一判断"谁活动"。
- **前端到后端只有一条路**：本地回环 HTTP。任何 UI 逻辑（挑战模态、
  状态轮询）最终都是 `/api/*` 请求；挑战会话（`VSG_SESSIONID`）永远
  留在 Go 侧，前端只拿 `gwId` + 结果码。
- **三条数据通路并存**：单端口资源走本地端口映射、端口区间资源走
  回环 CONNECT 代理 + 系统 PAC、NC 资源交给 WSL2 里的 strongSwan——
  分别对应 `web-proxy.md`、`ipsec.md` 的设计文档。
- mock 网关（`test/mock/v5vpn`、`test/mock/atrust`）扮演图中最右侧的
  两个网关，是集成与 UI E2E 的裁判。

## 2. 登录主链路：从点击到资源可用

一次口令登录在组件间的完整路径（认证挑战的多跳细节见
[`auth-flow.md`](auth-flow.md)，端点字段见 [`protocol.md`](protocol.md)）：

```mermaid
sequenceDiagram
    autonumber
    participant FE as 前端 app.js
    participant BR as UI Bridge /api/*
    participant SV as VPNService
    participant CL as protocol.Client
    participant GW as V5VPN 网关
    participant DP as 数据面 (Proxy/WebProxy/IPsec)

    FE->>BR: POST /api/login {gwId, username, password}
    BR->>SV: Login()
    SV->>CL: Handshake()
    CL->>GW: GET /vpn/version.xml
    GW-->>CL: VERSION 2.0
    SV->>CL: AuthOnly(username, password)
    CL->>GW: POST /vpn/user/auth/password (Base64, encode=1)

    alt 网关还要求其它因子 (RESULT code ≠ 0)
        GW-->>CL: 结果码 + VSG_SESSIONID
        CL-->>SV: AuthError(携带下一步因子)
        SV->>SV: keepChallengeLocked → authChallenge 槽位
        SV-->>BR: 200 {challenge: {type, next}}
        BR-->>FE: dispatchAuthError → 弹挑战模态
        Note over FE,GW: 后续因子经 /api/cert-factor、/api/sms-login…<br/>复用同一挑战会话，直到结果码 0 后同样进入 enterConnected
    else 认证通过
        GW-->>CL: RESULT code=0, Set-Cookie VSG_SESSIONID
        SV-->>BR: {status: Connected, resourceState: loading}
    end

    Note over SV: enterConnected：先报已连接，<br/>资源在后台异步拉取
    SV->>SV: go loadResources()（异步）
    SV->>CL: FetchIntegration()
    CL->>GW: GET /vpn/user/portal/intergration.xml?version=2.0
    GW-->>CL: 资源列表 (TCP/UDP + NC) + detect_interval
    CL->>CL: 心跳重定为 detect_interval

    par 三条数据通路各自就位
        SV->>DP: StartProxies —— 单端口资源本地映射
        SV->>DP: startWebResources —— 回环代理 + 系统 PAC
        SV->>DP: go startIPsec —— NC 资源交 WSL2
    end

    loop 状态轮询
        FE->>BR: GET /api/status
        BR-->>FE: resourceState / ipsecState / resources
    end

    loop 心跳 (period = detect_interval)
        CL->>GW: GET intergration.xml?period=…&version=2.0
    end
```

两个刻意的设计在图上体现为：

- **先连接、后资源**：`AuthOnly` 成功立刻返回 Connected 视图，
  `intergration.xml` 在后台拉取——portal 计算资源慢时用户不会被卡在
  登录页（`vpn_service.go` 的 `enterConnected` → `go loadResources`）。
- **资源失败不拆会话**：拉取失败停在「已连接但获取资源失败」，
  可重试而无需重新认证（`/api/resources/refresh`）。

登出链路（`/api/logout`，顺序即代码顺序）：状态**先**置 Disconnected
（`OnStatusChange` 立即翻转托盘与视图）→ 停 IPsec 与全部本地代理 →
还原系统 PAC → **最后** `Client.Logout()`（`GET /vpn/user/logout`）
告知网关拆会话。
