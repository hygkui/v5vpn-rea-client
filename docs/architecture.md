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
即"IPC"。两个协议后端（V5VPN / aTrust）在代码层互不感知、链路互不
纠缠，因此按后端分两张视图；共享部分（窗口壳、UI Bridge、支撑组件）
在两张图里重复出现，结构相同。

托盘与退出钩子横跨两个后端（`backends.go` 在 cmd 层回答"谁活动"、
退出时只关有会话的那个），不在单后端视图里展开。

两张视图为手绘 SVG（源文件在 `docs/diagrams/`），随浏览器浅色 /
深色主题自适应。

### 1.1 V5VPN 后端视图

认证与资源走 HTTPS REST；数据面有三条通路（单端口映射 / 回环
CONNECT 代理 / WSL2 IPsec）。前两条全平台可用；WSL2 IPsec 仅
Windows（macOS / Linux 上 NC 资源仅解析与展示，见
[`ipsec.md`](ipsec.md) §4）：

![V5VPN 后端视图](diagrams/v5vpn-backend.svg)

### 1.2 aTrust 后端视图

控制面是 HTTPS REST（登录、应用列表）；数据面是 TLS 441 上的二进制
流式隧道，由 `ATrustProxy` 在本地端口上按需建连——与 V5VPN 侧
ProxyManager「一条本地连接对应一条网关连接」的形态一致，只是隧道
协议不同（HTTP CONNECT vs 二进制帧）：

![aTrust 后端视图](diagrams/atrust-backend.svg)

aTrust 后端没有心跳保活与系统 PAC 接管，也不依赖证书库/加密组件；
状态机与 V5VPN 同套（Disconnected / Connecting / Connected / Error），
`/api/status` 以 `activeBackend` 合并两侧状态。

阅读要点：

- **两个后端互不感知**（`backends.go` 的三条边界）：`VPNService` 与
  `ATrustService` 在 service 层并列，登录互不路由，UI 按网关 profile 的
  protocol 自己选入口；托盘与退出时由 cmd 层统一判断"谁活动"。
- **前端到后端只有一条路**：本地回环 HTTP。任何 UI 逻辑（挑战模态、
  状态轮询）最终都是 `/api/*` 请求；挑战会话（`VSG_SESSIONID`）永远
  留在 Go 侧，前端只拿 `gwId` + 结果码。
- **V5VPN 三条数据通路并存**：单端口资源走本地端口映射、端口区间资源走
  回环 CONNECT 代理 + 系统 PAC、NC 资源交给 WSL2 里的 strongSwan——
  分别对应 `web-proxy.md`、`ipsec.md` 的设计文档。
- mock 网关（`test/mock/v5vpn`、`test/mock/atrust`）分别扮演两张图里
  的网关，是集成与 UI E2E 的裁判。

## 2. 登录主链路（V5VPN）：从点击到资源可用

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
