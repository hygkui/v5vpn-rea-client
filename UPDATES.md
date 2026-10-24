# 更新弹窗说明（update-*.json 的 notes 来源）

这个文件只服务客户端「检查更新」弹窗：`mygo build` 从这里提取 `## <版本号>`
段落写入 `update-<os>-<arch>.json` 的 `notes` 字段。GitHub Release 页面的完整
发布说明仍然来自 `CHANGELOG.md`，两者不要混写。

写法约束（弹窗是原生对话框，不渲染 Markdown）：

- 每个版本 **10 行以内**，一段导语 + 若干条一句话要点；
- 不用 `###` 小标题、表格、代码块、链接；
- 详细内容留给 `CHANGELOG.md`，结尾可提示「详细说明见 GitHub Release 页面」。

## 0.6.0

新增 V5VPN NC/IPsec 数据面支持（WSL2 + strongSwan 编排）。

- 支持网关下发的 NC 资源，通过 WSL2 strongSwan 建立 IKEv1 IPsec 隧道
- 管理员身份运行时自动配置 Windows 路由，原生应用无感访问内网子网
- 新增 scripts/setup-ipsec-wsl.ps1 一键初始化 WSL2 运行环境
- 界面增加 IPsec 隧道运行状态与网段列表展示
- 修复 Windows 路由网关解析、并发登出回滚及重连会话清理

详细说明见 GitHub Release 页面。

## 0.5.0

新增网页类资源（堡垒机等端口区间资源）本地代理访问，修复双因子账号改密。

- 端口区间资源自动启用本地 CONNECT 代理，浏览器即可访问内网页面
- Windows 登录后接管系统 PAC：仅资源地址走代理，NAS/外网直连，断开即还原
- 修复「口令 + 证书」双因子账号修改密码失败（先补呈证书再改密，编码自动回退）
- 新增短信验证码、动态令牌等多因素登录与挑战模态界面
- 网关链路抖动时握手自动重试；窗口尺寸按登录/已连接/设置分别记忆
- 安全加固：PAC 地址白名单与代理隧道目标白名单，防注入与借道

详细说明见 GitHub Release 页面。

## 0.4.0

支持深信服 aTrust 零信任网关，与 V5VPN 双协议并存。

- 新增 aTrust 零信任登录、流式隧道与内网资源访问
- 新增「口令 + 证书」双因子登录（界面新标签页与 -pwd-cert 命令行）
- V5VPN 与 aTrust 界面按协议独立，启动自动进入上次使用的协议
- 口令登录编码对齐原厂（Base64 + encode=1）
- 证书登录仅支持本地 .p12/.pfx 文件，移除 Windows 系统证书库
- 测试与 mock 网关收进仓库，新增协议集成测试与 UI 端到端测试

详细说明见 GitHub Release 页面。
