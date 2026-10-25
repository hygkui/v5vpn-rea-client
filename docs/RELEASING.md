# 发版与 Release 流程

本文说明如何把一次改动发布为 GitHub Release，以及发布说明、版本号、自动更新清单之间的关系。适用于 `hygkui/v5vpn-rea-client`。

---

## 1. 核心规则：merge 不会发版

`.github/workflows/release.yml` 的触发条件只有 **tag push**：

```yaml
on:
  push:
    tags: ["v*"]
```

把 PR merge 进 `master` 只会触发 `.github/workflows/ci.yml`（测试 + 交叉编译），**不会产生 Release**。需要发版时必须手动打并推送 tag。

---

## 2. 发版前的版本号同步

版本号在仓库中有 **5 处**（界面按协议分成两套，各有一份 index.html），必须保持一致：

| 文件 | 位置 | 说明 |
|:---|:---|:---|
| `mygo.json` | `"version": "0.2.1"` | 不带 `v`；workflow 用它校验 tag |
| `internal/cmd/main.go` | `var AppVersion = "v0.2.1"` | 带 `v`；运行时版本与更新检查基准 |
| `internal/cmd/ui/v5vpn/index.html` | 4 处 `version-badge` / `app-version-text` | V5VPN 界面显示的版本徽标 |
| `internal/cmd/ui/atrust/index.html` | 4 处 `version-badge` / `app-version-text` | aTrust 界面显示的版本徽标 |
| `CHANGELOG.md` | `## 0.2.1` 标题 | 发布说明来源 |

`internal/cmd/version_test.go` 会替 CI 校验这些副本：`TestAppVersionMatchesMygoJSON` 比较 mygo.json 与 main.go，`TestUIVersionBadgesMatchAppVersion` 检查两套 index.html 的全部版本徽标，任何一处漂移都会让 CI 失败。

> `AppVersion` 与网关协议版本 `"2.0"` 无关，不要混用。

---

## 3. CHANGELOG 约定（发布说明是中文）

`CHANGELOG.md` 是**唯一的发布说明来源**。约定：

- 一级标题 `# 更新日志`；
- 每个版本一个二级标题，精确匹配版本号：`## 0.2.1`；也兼容 Keep a Changelog 的 `## [0.2.1] - 2026-10-19` 写法（workflow 会去掉方括号）；
- 开发中的改动先写在 `## Unreleased` 下，发版时改名为 `## <版本号>`；
- **内容用中文书写**。

发布说明会被写到两个地方，所以必须是中文：

1. GitHub Release 的正文（`release.yml` 的 `Draft release` job 用 awk 提取对应段落）；
2. `update-<os>-<arch>.json` 清单的 `notes` 字段——客户端「检查更新」弹窗直接展示它。

如果 CHANGELOG 里找不到对应版本段落，workflow 会回退到 `gh release create --generate-notes`（英文自动生成），因此务必先写好段落。

### 弹窗短摘要：UPDATES.md

更新弹窗是原生对话框，**不渲染 Markdown**，且不适合长文。因此 manifest 的 `notes` 不取自 CHANGELOG，而是取自根目录 `UPDATES.md`（`mygo.json` 里 `updates.changelog` 指定）：每个版本一段导语 + 若干条一句话要点，**10 行以内**，不用 `###` 小标题、表格、代码块。发版时与 CHANGELOG 同步新增 `## <版本号>` 段落；详细内容只写进 CHANGELOG。

---

## 4. 发版步骤

```bash
# 1) 确认在 master 且工作区干净
git checkout master
git pull
git status

# 2) 版本号同步（见第 2 节）：mygo.json / main.go / 两套 index.html
#    CHANGELOG.md 的 ## Unreleased 改为 ## <版本号>（完整发布说明）
#    UPDATES.md 新增 ## <版本号> 短摘要（弹窗用，10 行以内）
#    提交
git add mygo.json internal/cmd/main.go CHANGELOG.md UPDATES.md \
        internal/cmd/ui/v5vpn/index.html internal/cmd/ui/atrust/index.html
git commit -m "chore(release): bump to v0.2.1"
git push origin master

# 3) 打带注释的 tag（说明也建议中文）并推送
git tag -a v0.2.1 -m "v0.2.1 - 简要说明"
git push origin v0.2.1
```

推送 tag 后 `Release` workflow 自动执行，依次为：

1. **Draft release**：校验 tag 与 `mygo.json` 版本一致，创建 draft，写入 CHANGELOG 对应段落；
2. **mygo build**：macOS / Windows / Linux 三平台（amd64 + arm64）构建并上传全量包与增量 delta 到该 draft；
3. **Publish release**：全部构建通过后 `gh release edit --draft=false` 转为正式发布。

任一平台构建失败则不会发布，draft 保留在 Releases 页面可排查。

版本号选择遵循语义化版本：新功能升次版本号（`0.1.x → 0.2.0`），修复升补丁号（`0.2.0 → 0.2.1`）。

---

## 5. 发布后验证

```bash
# 最新 release 的 tag 与时间
gh release list -L 5

# 产物是否齐全（含全量包、Setup exe、dmg、deb、delta、update-*.json）
gh release view v0.2.1 --json assets --jq '.assets[].name'

# 发布说明是否为中文
gh release view v0.2.1 --json body --jq .body

# releases/latest 是否指向新版本
curl -sS -o /dev/null -w '%{redirect_url}\n' \
  https://github.com/hygkui/v5vpn-rea-client/releases/latest

# 自动更新清单是否指向新版本、notes 是否为中文
curl -sSL https://github.com/hygkui/v5vpn-rea-client/releases/latest/download/update-windows-amd64.json
```

客户端更新检查逻辑（`internal/service/vpn_service.go` 的 `CheckForUpdates`）按顺序尝试：清单 `update-*.json` → `releases/latest` 的 302 → GitHub REST API。前两条不受 API 限流影响。

---

## 6. 修改已发布版本的说明

Release 正文与 tag 无关，可以随时用 `gh` 改写历史版本（仓库写权限即可）：

```bash
gh release edit v0.1.0 --notes-file path/to/notes.md
```

适用场景：修正错误的发布说明、把英文说明改为中文。注意：

- 只改 Release 正文，**不会**同步修改已上传的 `update-*.json` 里的 `notes`；
- 已发布版本的 tag 与产物不要改动，否则签名与更新链路可能失效。

---

## 7. 常见问题

**Q: merge 了 PR，为什么没有新 Release？** A: 设计如此，只有 tag push 会触发发布（见第 1 节）。

**Q: workflow 报 tag 与 `mygo.json` 不一致？** A: 第 2 节的四处版本号没同步，或 tag 打在了错误提交上。

**Q: Release 正文是英文？** A: `CHANGELOG.md` 没有对应版本的中文段落，走了 `--generate-notes` 回退。补好段落重新推送 tag（先删远端 tag：`git push origin :refs/tags/vX.Y.Z`），或直接 `gh release edit` 修正正文。

**Q: 小改动需要发版吗？** A: 不需要。修复合并进 `master` 后，在下一次正常发版时随版本发布即可。

**Q: 更新检查测试失败？** A: `TestLiveVPNServiceCheckForUpdates` 会真实联网。它不硬编码最新版本，而是先探测线上最新版再断言。本地不想联网时用 `go test -short ./...` 跳过。
