# AGENTS.md — 给 AI 编码代理与本仓库贡献者的工作约定

> 人类贡献者也适用；本文件与 `README.md` §12 互补，冲突时以更严格者为准。

## 提交 / 推送前必须跑的测试

`go test` **不等于**测完了。本仓库的测试分两层，CI 只覆盖第一层：

| 层 | 命令 | 进 CI？ | 验什么 |
|:---|:---|:---:|:---|
| Go 集成 | `go test -race ./...` | ✅（`-short`） | 协议、服务、代理、路由（含自拉起 mock 网关） |
| UI 端到端 | `bash test/run.sh e2e` | ❌ 仅本机 | 真实浏览器驱动 UI：全部套件（V5VPN 主链路 + NC/IPsec 资源 + 11 合 1 深度 + aTrust 主链路）聚合一份报告 |

**最低门槛（任何改动）：**

```bash
gofmt -l .                 # 必须无输出（CI 会挡）
go vet ./...
go test -race ./...        # 本机跑全量，比 CI 的 -short 更严
```

**触发条件加跑 UI E2E（只跑 go test 就推送是本仓库明确禁止的）：**

改动 `internal/cmd/ui/**`、登录链、认证状态机、资源/代理逻辑、**或任何
用户可见行为** → `bash test/run.sh e2e`（统一入口，一个命令跑全部套件并
聚合 `test/results/report.html`，不会漏）；赶时间或调试单套用
`bash test/run.sh ui v5vpn` / `ui multi` / `ui atrust`。

E2E 每套独立沙盒：自己构建 app 与 mock 网关、用隔离的用户数据目录
（跨平台：`APPDATA` + `HOME` 重定向）启动、随机端口，跑完即清理；需要
本机装有 Edge 或 Chrome（`EDGE_PATH` 可指定路径）。产物在 `test/results/`：
统一报告（含逐步截图）、各套件摘要 `suite-*.json`、日志，可作 PR 证据。

## 测试约定速查

- mock 网关是**裁判**：实现与原厂行为冲突时改实现，不改 mock 去迁就实现
  （`test/README.md` 三条约定）；
- 真实网关的集成测试默认 skip（占位凭据），用 `GATEWAY_IP / GATEWAY_PORT /
  GATEWAY_USER / GATEWAY_PASSWORD` 环境变量启用；
- UI E2E 断言的是用户可见行为，不要在 UI 测试里重复断言后端单元已覆盖的细节。

## 提交与发版

- commit message 中文、conventional 前缀（`feat(protocol): …`），
  不要在 issue / PR / commit 里粘贴真实网关地址、账号或密码；
- merge 不会发版：发版 = 版本号 5 处同步 + `CHANGELOG.md` 段落 +
  `UPDATES.md` 短摘要 + 打 tag 推送，完整步骤见 `docs/RELEASING.md`；
- 新机制沉淀设计决策文档到 `docs/`（参照 `docs/auth-flow.md`、
  `docs/web-proxy.md` 的写法：决策、反面案例、守卫测试引用）。
