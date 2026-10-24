#!/usr/bin/env bash
# run.sh — v5vpn-rea 测试总入口。
#
# 两层测试：
#   go    协议级集成测试（快、可进 CI）：测试自己构建并拉起 mock 子进程。
#   ui    浏览器端到端（慢、需本机 Edge/Chrome）：e2e_run.js 是统一入口，
#         一个命令跑全部 UI 套件（V5VPN 主链路 + 11 合 1 深度场景 + aTrust
#         主链路），每套独立沙盒、子进程隔离，最后聚合一份
#         results/report.html。此前两个 E2E 脚本割裂（一个自拉起、一个
#         要手工先起 app@45678 + mock@8443），run.sh all 会漏跑深度场景
#         ——已合并，不会再漏。
#
# 用法：
#   ./test/run.sh              # go + 全部 UI E2E（默认全量）
#   ./test/run.sh go           # 只跑 go 集成测试
#   ./test/run.sh e2e          # 全部 UI E2E（聚合一份报告）
#   ./test/run.sh ui           # 同 e2e
#   ./test/run.sh ui v5vpn     # 只跑 V5VPN 主链路（单套调试）
#   ./test/run.sh ui v5vpn-nc  # 只跑 NC/IPsec 资源场景（单套调试）
#   ./test/run.sh ui atrust    # 只跑 aTrust 主链路
#   ./test/run.sh ui multi     # 只跑 11 合 1 深度场景
#   ./test/run.sh all          # go + 全部 UI E2E

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/.." && pwd)"

WHAT="${1:-all}"
SCENARIO="${2:-all}"

run_go() {
  echo "=== Go 集成测试（含自拉起 mock） ==="
  cd "$REPO_ROOT"
  go test -short ./internal/atrust/... ./internal/service/... ./test/... "$@"
}

ensure_node_deps() {
  cd "$DIR"
  if [ ! -d node_modules ]; then
    echo "安装依赖: npm install"
    npm install --no-audit --no-fund
  fi
}

# run_e2e 统一入口：全部套件、聚合报告。
run_e2e() {
  echo "=== UI E2E 统一入口（V5VPN 主链路 + 11 合 1 深度 + aTrust 主链路） ==="
  ensure_node_deps
  node e2e_run.js
  echo ""
  echo "报告: $DIR/results/report.html"
}

# run_ui_single 单套调试：保留按场景直跑旧脚本的能力。
run_ui_single() {
  local scenario="$1"
  echo "=== UI E2E 单套（场景: ${scenario}） ==="
  ensure_node_deps
  case "$scenario" in
    v5vpn)   node e2e_ui_test.js --scenario=v5vpn ;;
    v5vpn-nc) node e2e_ui_test.js --scenario=v5vpn-nc ;;
    atrust)  node e2e_ui_test.js --scenario=atrust ;;
    multi|v5vpn-multi) node e2e_v5vpn_multi_test.js ;;
    *)
      echo "未知场景: $scenario（可选: v5vpn | v5vpn-nc | multi | atrust）" >&2
      exit 2
      ;;
  esac
}

case "$WHAT" in
  go)          run_go ;;
  e2e|ui)
    if [ -n "$SCENARIO" ] && [ "$SCENARIO" != "all" ]; then
      run_ui_single "$SCENARIO"
    else
      run_e2e
    fi
    ;;
  all|"")      run_go; run_e2e ;;
  *)
    echo "用法: $0 [go|e2e|ui|all] [v5vpn|v5vpn-nc|multi|atrust]" >&2
    exit 2
    ;;
esac
