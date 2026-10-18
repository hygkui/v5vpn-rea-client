# v5vpn-rea

基于 **REA (Reverse Engineer Anything)** 逆向分析技术与 **MyGo** 跨平台桌面技术架构，重新实现的现代化 V5VPN 客户端。

---

## 1. 目标与技术参考

- **逆向分析参考**：[morluto/rea](https://github.com/morluto/rea)
- **待逆向目标软件**：`C:\Program Files (x86)\V5VPN` (网御星云 / LeadSec 系列 VPN)
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

通过对 `SecUI.exe`、`SecController.dll`、`SecLogin.dll`、`SecSSL.dll`、`VpnServ.exe` 进行符号表、反汇编及内存映射分析，完全破解了以下关键机制：

### 3.1 本地凭证解密 (setting.xml)
- **用户名**：标准 Base64 编码。
- **密码**：DES-CBC，PKCS5/PKCS7 填充
- 解密还原率 100%，支持自动导入或反向导出。

### 3.2 协议交互流程 (Network Protocol)
1. **版本探针**：`GET /vpn/version.xml` $\rightarrow$ `<VERSION major="2" minor="0"/>`。
2. **加密口令认证**：`POST /vpn/user/auth/password`
   - 加密算法：AES-128-CBC，PKCS7 填充，Raw 字符串拼接（避免 URL 转义 Base64 尾部字符）
   - **关键参数 `encode`**：
     - `encode=2`：**2.0 网关标准**，指示网关使用 AES-128-CBC 解密。若误填 `encode=1`，网关会按 v1.0 纯 Base64 解码，导致解密密文为乱码并报 `0x8000001A (用户名或密码错误)`。
     - `encode=1`：v1.0 旧版网关模式，仅对明文口令做 Base64 编码。
   - 字段：`username={EncUser}&password={EncPwd}&encode=2&verifycode={code}`。
   - 登录成功返回 Session Cookie：`VSG_SESSIONID`。
   - **口令过期**：结果码 `0x00000100`（十进制 256），或提示语含「口令过期 / 密码已过期 / 请修改密码」。网关有时仍回 `0x8000001A`，但正文是过期而不是账密错误；响应若是 GBK，先转成 UTF-8 再判断。过期后，本客户端在同一接口上额外提交 `newpassword={EncNew}`，成功则用新密码继续登录。这个字段还没有在原厂客户端或生产网关上确认。
3. **获取授权资源**：`GET /vpn/user/portal/intergration.xml?version=2.0`
   - 获得 TCP/UDP 内网资源列表与端口、策略及 DNS。
4. **隧道建立与数据透传**：
   - 本地自动分配代理端口监听。
   - 建立 SSL 连接并发送 `CONNECT {TargetIP}:{TargetPort} HTTP/1.1\r\nCookie: VSG_SESSIONID={SessionID}` 进行全双工透传。
5. **保活心跳**：`GET /vpn/user/portal/intergration.xml?period={interval}&version=2.0`。
6. **安全登出**：`GET /vpn/user/logout`。

---

## 4. 兼容性

| 项目 | 版本 / 范围 |
|:---|:---|
| 已在其中完成端到端验证的原厂客户端 | 5.3.3.x 系列 |
| 网关协议版本 | v2.0 (`/vpn/version.xml` 返回 `major=2 minor=0`) |
| 支持的登录方式 | 口令登录 (`/vpn/user/auth/password`) |
| 未支持 | 证书登录、匿名登录、国密(SM2/SM3/SM4)套件、IPsec/NDIS 虚拟网卡模式 |

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
也可在任意浏览器中访问本地 Web 管理控制台：
```
http://127.0.0.1:45678
```

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

---

## 6. 项目目录结构

```
v5vpn-rea/
├── internal/             # 内部 Go 源码（不对外暴露 import 路径）
│   ├── cmd/              # 入口程序 (MyGo 桌面窗口生命周期、系统托盘、CLI分发)
│   │   └── ui/           # 嵌入式响应式前端界面 (HTML5 / CSS3 / ES6)
│   ├── config/           # 配置文件解析与本地凭证导入 (setting.xml)
│   ├── crypto/           # DES-CBC / AES-128-CBC 编解码核心算法实现
│   ├── protocol/         # V5VPN 网关 REST/HTTPS 协议客户端与心跳管理器
│   ├── proxy/            # 本地 TCP 端口映射与 SSL HTTP CONNECT 隧道代理引擎
│   └── service/          # 供 MyGo 前端调用的强类型 IPC 业务服务
├── configs/              # 本地运行配置（含保存凭证，已移出版本控制）
├── assets/               # 原创多分辨率盾牌图标与静态资源
├── docs/                 # 逆向分析参考资料与发布检查清单
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
| Linux | `~/.local/share/v5vpn-rea/setting.xml` |
| macOS | `~/Library/Application Support/v5vpn-rea/setting.xml` |

这些目录由 `mygo.App.Path(PathUserData)` 解析。**自更新不会擦掉用户配置**，
因为 mygo build 把应用目录整体替换，而 setting.xml 不再放在那里。

如果想使用旧版「exe 同目录」的布局（例如便携式部署），把 `setting.xml`
放在可执行文件旁边即可——`config.LoadSettingXML` 会按以下顺序回退：

1. 用户数据目录（生产构建默认）
2. 当前工作目录
3. 可执行文件目录
4. `configs/`（源码树布局）

## 11. 贡献

- 在 issue、PR、commit message 中**不要**粘贴真实网关地址、账号或密码
  （DES 密文同样不应粘贴，凭证扫描器会批量尝试）；
- 修改协议相关代码前先在私有分支跑通两套测试：单元测试 + `go test
  -short` 跳过的集成测试需要自行提供 `GATEWAY_IP / GATEWAY_PORT /
  GATEWAY_USER / GATEWAY_PASSWORD` 环境变量；
- UI 改动请附前后对比截图，CSS 改动请确认在 1280x800 与 1920x1080
  两个分辨率下都不破布局。

详见 `DISCLAIMER.md` 与 `NOTICE`。
