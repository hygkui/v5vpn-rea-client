# v5vpn-rea

借助 **REA** 分析研究工具与 **MyGo** 跨平台桌面技术架构，重新实现的现代化 V5VPN 客户端；v0.4.0 起同时支持深信服 **aTrust 零信任**网关，双协议并存、界面独立切换。

> [!WARNING]
> **免责声明**：本项目是独立的非官方技术研究项目，与网御星云（LeadSec）、
> 启明星辰、深信服等任何厂商均无关联，也未获得其授权或背书。它通过观察协议
> 行为重新实现客户端，仅供学习研究与互操作测试：请只在你自己拥有或被明确
> 授权管理的设备、网关与账号上使用，并在使用前确认你所在司法辖区及雇主 /
> 客户协议允许此类分析与互操作研究。软件按 Apache 2.0 许可「按原样」提供，
> 不附任何担保，因使用或滥用本软件造成的任何后果由使用者自行承担。
> 完整声明见 **[DISCLAIMER.md](DISCLAIMER.md)**。

---

## 1. 目标与技术参考

- **分析研究参考**：[morluto/rea](https://github.com/morluto/rea)
- **待分析目标软件**：(天清汉马 / 网御星云 / LeadSec 系列 VPN)
- **重新实现技术架构**：[egoist/mygo](https://github.com/egoist/mygo) (纯 Go 桌面开发框架，系统原生 WebView2 + 强类型 IPC)

---

## 2. 界面效果（新旧对比）

新旧客户端界面并排对比，**表格可左右滑动**查看全部截图，点击图片看大图：

<table>
  <tr>
    <td valign="middle"><b>新版本</b><br>(本项目 v0.1.0)</td>
    <td align="center"><a href="docs/references/v5vpn-rea/login.png"><img src="docs/references/v5vpn-rea/login.png" height="280" alt="新版本登录界面"></a></td>
    <td align="center"><a href="docs/references/v5vpn-rea/main.png"><img src="docs/references/v5vpn-rea/main.png" height="280" alt="新版本主界面"></a></td>
  </tr>
  <tr>
    <td valign="middle"><b>旧版本</b><br>(原厂客户端 5.3.3.x)</td>
    <td align="center"><a href="docs/references/启明星辰-天清汉马VPN/1.png"><img src="docs/references/启明星辰-天清汉马VPN/1.png" height="280" alt="原厂界面 1"></a></td>
    <td align="center"><a href="docs/references/启明星辰-天清汉马VPN/2.png"><img src="docs/references/启明星辰-天清汉马VPN/2.png" height="280" alt="原厂界面 2"></a></td>
    <td align="center"><a href="docs/references/启明星辰-天清汉马VPN/3.png"><img src="docs/references/启明星辰-天清汉马VPN/3.png" height="280" alt="原厂界面 3"></a></td>
    <td align="center"><a href="docs/references/启明星辰-天清汉马VPN/4.png"><img src="docs/references/启明星辰-天清汉马VPN/4.png" height="280" alt="原厂界面 4"></a></td>
    <td align="center"><a href="docs/references/启明星辰-天清汉马VPN/5.png"><img src="docs/references/启明星辰-天清汉马VPN/5.png" height="280" alt="原厂界面 5"></a></td>
  </tr>
</table>

---

## 3. 分析过程

通过对原厂客户端 `SecUI.exe`、`SecController.dll`、`SecLogin.dll`、`SecSSL.dll`、`VpnServ.exe` 的符号表、反汇编及内存映射观察分析，完整掌握了从本地凭证到隧道透传的关键机制。分析细节按主题沉淀在 docs，索引如下：

| 主题 | 结论速览 | 详细文档 |
|:---|:---|:---|
| 总体架构与登录主链路 | 单进程双后端；组件图 + 端到端时序图 | [`docs/architecture.md`](docs/architecture.md) |
| 政企 VPN 客户端生态 | 两代客户端并存；四大安全职责对标与项目边界 | [`docs/vendor-landscape.md`](docs/vendor-landscape.md) |
| 本地凭证 (setting.xml) | 用户名 Base64；口令 DES-CBC（PKCS5/7）；还原率 100% | [`docs/protocol.md`](docs/protocol.md) |
| 协议交互流程 | 版本探针 → 认证 → 资源拉取 → 隧道透传 → 心跳 → 登出 | [`docs/protocol.md`](docs/protocol.md) |
| 网关驱动的认证状态机 | `RESULT` 结果码按位分发因子，客户端不写死流程 | [`docs/auth-flow.md`](docs/auth-flow.md) |
| 网页类资源（端口区间） | 本地 CONNECT 代理 + 系统 PAC | [`docs/web-proxy.md`](docs/web-proxy.md) |
| IPsec（NC 资源） | WSL2 + strongSwan 数据面编排 | [`docs/ipsec.md`](docs/ipsec.md) |

---

## 4. 支持的认证方式与兼容性

### 4.1 认证因子矩阵（一眼判断能不能用）

对照你网关要求的认证方式，即可判断本客户端能否使用：

**V5VPN（网御星云 / 启明星辰天清汉马，协议 v2.0）**

| 网关要求的认证方式 | 挑战结果码 | 支持 | 界面表现（固定表单 + 挑战模态） |
|:---|:---|:---:|:---|
| 仅口令 | `0` | ✅ | 表单直接连接 |
| 口令 + 图形验证码 | `0x80` | ✅ | 弹出验证码模态，错码原地重试 |
| 口令 + 客户端证书（双因子） | `0x2` | ✅ | 弹出证书模态，在挑战会话上呈递 |
| 口令 + 短信验证码（MFA） | `0x8` | ✅ | 弹出短信模态（可重发倒计时） |
| 口令 + 证书 + 短信（三因素链） | `0x2`→`0x8` | ✅ | 证书模态 → 短信模态连续替换 |
| 证书 + 短信（免口令） | 证书步 `0x8` | ✅ | 证书登录入口 → 短信模态 |
| 仅客户端证书（mTLS 免密） | — | ✅ | 「🪪 证书登录」入口按钮，本地 `.p12/.pfx` 导入 |
| 口令过期强制改密 | `0x100` | ✅ | 弹出改密模态，改密后自动续连 |
| 口令 + 动态令牌（OTP） | `0x4` | ✅ | 弹出令牌模态（码由用户令牌生成，无发送步骤），错码原地重试 |
| 全链：验证码 + 证书 + 短信 + 令牌 | `0x80`→`0x2`→`0x8`→`0x4` | ✅ | 四个模态在同一挑战会话上连续替换 |
| USB Key 智能卡硬件认证 | — | ❌ | 开发中 |
| 匿名登录 / 国密(SM2/SM3/SM4) / IPsec | — | ❌ | 不在实现范围 |

> 登录框固定为「网关 + 账号 + 口令」表单与两个平级入口按钮（口令登录 / 证书登录），高度恒定；
> 所有网关挑战以模态窗口弹出，多跳链表现为模态的连续替换。因子链由网关
> 动态编排（见 `docs/auth-flow.md`）：
> 上表组合均已在 mock 网关全链对撞与 UI 端到端中覆盖，真实网关若给出其他
> 因子顺序，客户端按结果码分发，无需改代码。

**aTrust（深信服零信任）**

| 网关要求的认证方式 | 支持 | 界面入口 |
|:---|:---:|:---|
| 账号口令（`authConfig` → `psw` → `authCheck`） | ✅ | 界面顶部「切换到 aTrust 零信任」 |
| TCP 流式隧道与内网资源访问 | ✅ | 同上 |
| 多因素 `nextService` 链（短信 / 令牌 / 二次确认） | ❌ | 尚未支持，界面会明确提示 |

### 4.2 版本兼容性

| 项目 | 版本 / 范围 |
|:---|:---|
| 已在其中完成端到端验证的原厂客户端 | 5.3.3.x 系列 |
| 网关协议版本 | v2.0 (`/vpn/version.xml` 返回 `major=2 minor=0`) |

本项目仅实现「SSL VPN 门户 + HTTP CONNECT 隧道透传」这条路径，
不实现原客户端的内核态虚拟网卡（SecTap.sys / ndislwf.sys）与 IPsec 功能，
因此**不能替代**原厂客户端用于全网状路由场景。
其他 5.x 版本未经验证，可能因协议字段变化而不可用。

端到端连通性已在两套生产网关上验证完成（具体网关地址、账号、密码等
细节不在仓库内公开，请勿在 issue、PR、截图或日志中粘贴）。

---

## 5. 快速运行与使用

### 5.1 编译客户端
```bash
go build -o v5vpn-rea.exe ./internal/cmd
```

### 5.2 图形界面 (GUI) 模式
直接运行可启动 MyGo 现代桌面客户端，系统托盘自启：
```bash
.\v5vpn-rea.exe
```
V5VPN 与 aTrust 两套界面按协议独立（`/v5vpn/` 与 `/atrust/`），启动时按上次
使用的网关协议自动进入对应界面，顶部可整页切换：
```
http://127.0.0.1:45678
```

#### 网页类资源（端口区间，如堡垒机）：

网关把这类资源下发为 `port="1-65535"` + 节点 `addr` 属性，无法映射固定本地
端口。客户端为每条资源启动仅监听 `127.0.0.1` 的 HTTP CONNECT 代理，浏览器
经它访问内网地址；Windows 下登录后自动设置系统 PAC（仅资源地址走代理，
NAS / 外网一律直连，断开即还原）。设计取舍与安全边界见
**[docs/web-proxy.md](docs/web-proxy.md)**。双因子账号的「修改密码」也已修复
（口令步不再预装证书，收到 `0x2` 后补呈证书再改密）。

### 5.3 命令行 (CLI) 快速工具

#### 一键提取并解密系统 V5VPN 本地已存的所有账号密码：
```bash
.\v5vpn-rea.exe -dump-passwords
```

#### 查看已配置网关：
```bash
.\v5vpn-rea.exe -cli
```

#### 命令行直连网关：
```bash
.\v5vpn-rea.exe -cli -connect "<gateway-name>" -user "<username>" -pwd "<password>"
```

口令过期时带上新密码：

```bash
.\v5vpn-rea.exe -cli -connect "<gateway-name>" -user "<username>" -pwd "<old-password>" -new-pwd "<new-password>"
```

客户端会先用旧密码登录；只有网关返回 `0x100`（口令过期）时才执行改密。若密码未过期，则按旧密码正常连接，`-new-pwd` 不生效。

#### 证书登录与证书管理：

```bash
# 查看本地已导入的所有可用证书：
.\v5vpn-rea.exe -list-certs

# 导入 .p12 或 .pfx 客户端证书文件：
.\v5vpn-rea.exe -import-cert "path/to/cert.p12" -cert-alias "我的生产证书" -cert-pwd "证书密码"

# 使用已导入证书直连网关（支持指定证书 ID 或别名）：
.\v5vpn-rea.exe -cli -connect "<gateway-name>" -cert "<cert-id-or-alias>"

# 使用外部未导入证书文件直连网关：
.\v5vpn-rea.exe -cli -connect "<gateway-name>" -cert "path/to/cert.p12" -cert-pwd "证书密码"
```

#### 口令 + 证书双因子登录：

网关同时要求口令与客户端证书时，加 `-pwd-cert`：口令先提交到
`/vpn/user/auth/password`；网关在结果码中要求证书因子（`0x2`）后，
再于同一会话上把客户端证书经 `/vpn/user/auth/cert` 呈递（两步串行，
证书经 TLS 握手上送、请求无正文）。界面上无需任何预选：固定表单提交
口令后，客户端弹出证书模态，选中证书呈递即可（见 `docs/auth-flow.md`）。

```bash
# 已导入证书（ID 或别名）+ 账号口令：
.\v5vpn-rea.exe -cli -connect "<gateway-name>" -pwd-cert -cert "<cert-id-or-alias>" -user "<username>" -pwd "<password>"

# 外部 .p12 文件 + 账号口令：
.\v5vpn-rea.exe -cli -connect "<gateway-name>" -pwd-cert -cert "path/to/cert.p12" -cert-pwd "<证书口令>" -user "<username>" -pwd "<password>"
```

---

## 6. 项目目录结构

```
v5vpn-rea/
├── internal/             # 内部 Go 源码（不对外暴露 import 路径）
│   ├── atrust/           # 深信服 aTrust 零信任协议客户端（登录链、流式隧道、资源）
│   ├── certstore/        # 客户端证书存储（.p12/.pfx 导入、解析与管理）
│   ├── cmd/              # 入口程序 (MyGo 桌面窗口生命周期、系统托盘、CLI分发)
│   │   └── ui/           # 嵌入式响应式前端界面 (HTML5 / CSS3 / ES6，v5vpn/ 与 atrust/ 两套)
│   ├── config/           # 配置文件解析与本地凭证导入 (setting.xml)
│   ├── crypto/           # DES-CBC / AES-128-CBC 编解码核心算法实现
│   ├── protocol/         # V5VPN 网关 REST/HTTPS 协议客户端与心跳管理器
│   ├── proxy/            # 本地 TCP 端口映射与 SSL HTTP CONNECT 隧道代理引擎
│   └── service/          # 供 MyGo 前端调用的强类型 IPC 业务服务
├── configs/              # 本地运行配置（含保存凭证，已移出版本控制）
├── assets/               # 原创多分辨率盾牌图标与静态资源
├── docs/                 # 分析研究参考资料与发布检查清单
├── test/                 # 测试与 mock 网关（v5vpn / atrust），UI E2E 脚本
├── build.bat             # Windows 一键构建脚本
├── go.mod
└── README.md
```

## 7. 平台支持矩阵

| 平台 | WebView 后端 | 运行时依赖 | 实测状态 |
|:---|:---|:---|:---|
| Windows x64 / arm64 | WebView2 | WebView2 Runtime（Win11 自带；Win10 需安装） | 已实测（开发环境） |
| Linux amd64 / arm64 | WebKitGTK | `libwebkit2gtk-4.1-0`（Debian/Ubuntu） | 仅编译通过，未实测 |
| macOS amd64 / arm64 | WKWebView | 系统自带；分发需签名 + 公证 | 仅编译通过，未实测 |

mygo 在 Linux 各桌面环境下系统托盘 (`mygo.NewTray`) 的可用性差异较大，
如果托盘失败主功能仍可工作，直接用浏览器访问 `http://127.0.0.1:45678`
进入控制台即可。

## 8. 构建与发布

`build.bat` 走 `go build`，产出的 `v5vpn-rea.exe` 是「开发者构建」：

- 没有版本号、图标以外的资源节；
- `mygo.App.Version()` 返回空串，`updater.Enabled()` 始终为假，因此
  **该二进制永远无法自更新**；
- 适用于本地调试、CI 跑测试，但不适合直接分发给最终用户。

发布产物必须由 `go tool mygo build` 产出：

```bash
go tool mygo keygen                                    # 一次性生成 mygo-update.key / .pub
gh secret set MYGO_UPDATER_PRIVATE_KEY < mygo-update.key   # 把私钥存进 CI secrets
go tool mygo build -platform windows/amd64,linux/amd64,darwin/arm64 -upload
```

产物命名由 `mygo.json` 的 `name` 决定（当前是 `v5vpn-rea`），会得到
`v5vpn-rea.exe` / `v5vpn-rea Setup <version> amd64.exe` / `v5vpn-rea.app`
/ `.deb` 等。`.gitignore` 已把 `mygo-update.key`、`mygo-update.pub` 与
`/build/` 排除，私钥不会入库。

### 8.1 发版流程

日常开发 merge 到 `master` **不会**产生 Release：`.github/workflows/release.yml`
只在推送 `v*` tag 时触发。正式发版需要同步版本号（`mygo.json`、
`internal/cmd/main.go`、两套界面 `internal/cmd/ui/{v5vpn,atrust}/index.html`、
`CHANGELOG.md`），
提交后推送 tag：

```bash
git tag -a v0.2.1 -m "v0.2.1 - 简要说明"
git push origin v0.2.1
```

workflow 会自动创建 draft、构建三平台产物，全部通过后转为正式发布，
发布说明取自 `CHANGELOG.md` 对应段落（中文）。

完整步骤、发布后验证命令、修改历史 Release 说明的方法以及常见问题，
见 **[docs/RELEASING.md](docs/RELEASING.md)**。

## 9. 自更新与签名

mygo 内建了 ed25519 签名的自更新机制。`mygo.json` 的 `updates.publicKey`
必须在第一次 `go tool mygo keygen` 之后替换为 `mygo-update.pub` 的内容；
私钥 `mygo-update.key` 仅存放在 GitHub Secrets（变量名
`MYGO_UPDATER_PRIVATE_KEY`），任何泄露都意味着任意代码可推送给用户。

应用启动后约 10 秒进行首检（后台线程），托盘菜单新增「检查更新...」
由 `updater.MenuItem()` 提供。`OnBeforeQuit` 钩子保证任何 quit 路径
（包括 updater 触发的 relaunch）都会先调用 `vpnService.Logout()`，
避免网关侧留下孤儿 `VSG_SESSIONID`。

## 10. 用户数据位置

| 平台 | setting.xml 实际存储位置 |
|:---|:---|
| Windows | `%APPDATA%\v5vpn-rea\setting.xml` |
| Linux | `~/.config/v5vpn-rea/setting.xml`（或 `$XDG_CONFIG_HOME/v5vpn-rea/setting.xml`） |
| macOS | `~/Library/Application Support/v5vpn-rea/setting.xml` |

这些目录由 `mygo.App.Path(PathUserData)` 解析（`os.UserConfigDir()` 拼上
应用名）。`mygo build` 从 `mygo.json` 的 `name` 取得应用名；`go build`
开发者构建没有版本资源，因此 `main` 里通过 `mygo.App.SetName(AppName)`
显式设置为同一个名字，两种构建读写同一份 `setting.xml`
（`TestAppNameMatchesMygoJSON` 保证 `mygo.json` 与常量不漂移）。
**自更新不会擦掉用户配置**，
因为 mygo build 把应用目录整体替换，而 setting.xml 不再放在那里。

如果想使用旧版「exe 同目录」的布局（例如便携式部署），把 `setting.xml`
放在可执行文件旁边即可——`config.LoadSettingXML` 会按以下顺序回退：

1. 用户数据目录（生产构建默认）
2. 当前工作目录
3. 可执行文件目录
4. `configs/`（源码树布局）

## 11. 本地模拟服务端（Mock Server）

仓库内置了针对网御星云 / 启明星辰 V5VPN 网关的独立 HTTPS 模拟测试服务，方便在无真实网关环境下做双因素、改密等全流程断网调试：

```bash
# 启动 V5VPN 模拟服务端（默认 127.0.0.1:8443，模式为口令+证书双因素）
go run ./cmd/mock-v5vpn

# 可选模式：pwd-cert (双因素), pwd-cert-sms (口令+证书+短信三因素链), pwd-only (单口令), pwd-change (改密挑战), err-auth (认证失败), token (令牌), sms (口令+短信)
go run ./cmd/mock-v5vpn -mode pwd-only

# 启动 aTrust 模拟服务端
go run ./cmd/mock-atrust -addr 127.0.0.1:8443

# 客户端协议级端到端测试工具（对撞模拟服务端）
go run ./cmd/e2e-v5vpn -gw 127.0.0.1 -port 8443 -user admin -pwd admin123
go run ./cmd/e2e-atrust -gw https://127.0.0.1:8443 -user user1@local -pass any
```

启动后可在浏览器打开 `https://127.0.0.1:8443/` 仪表盘实时观察请求流量或动态切换模式。

## 12. 贡献

- 在 issue、PR、commit message 中**不要**粘贴真实网关地址、账号或密码
  （DES 密文同样不应粘贴，凭证扫描器会批量尝试）；
- 修改协议相关代码前先在私有分支跑通两套测试：单元测试 + `go test
  -short` 跳过的集成测试需要自行提供 `GATEWAY_IP / GATEWAY_PORT /
  GATEWAY_USER / GATEWAY_PASSWORD` 环境变量；
- **提交/推送前的完整测试清单（`go test` ≠ 测完，UI E2E 不进 CI 必须本机跑）
  见 [`AGENTS.md`](AGENTS.md)**：改动登录链 / 认证 / 资源代理时加跑
  `bash test/run.sh ui v5vpn` 或 `v5vpn-multi`，报告与截图可作 PR 证据；
- UI 改动请附前后对比截图，CSS 改动请确认在 1280x800 与 1920x1080
  两个分辨率下都不破布局。

详见 `DISCLAIMER.md` 与 `NOTICE`。
