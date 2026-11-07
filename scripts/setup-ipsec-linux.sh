#!/usr/bin/env bash
set -euo pipefail

helper_path=/usr/local/libexec/v5vpn-rea-ipsec-helper
policy_path=/usr/share/polkit-1/actions/org.v5vpn-rea.ipsec.policy
runtime_path=/run/v5vpn-native-ipsec

case "${1:---check}" in
  --check)
    for tool in ip iptables swanctl pkexec; do
      command -v "$tool" >/dev/null || { echo "缺少运行依赖：$tool" >&2; exit 1; }
    done
    test -x /usr/lib/ipsec/charon || { echo '缺少 strongSwan charon' >&2; exit 1; }
    test -x "$helper_path" || { echo '原生内网 helper 尚未安装，请先构建并执行 --install' >&2; exit 1; }
    "$helper_path" --check
    ;;
  --install)
    test "$(id -u)" -eq 0 || { echo '--install 需要管理员权限' >&2; exit 1; }
    test "$#" -eq 2 && test -f "$2" && test -x "$2" || { echo '用法：--install /绝对路径/已审查的helper' >&2; exit 2; }
    case "$2" in /*) ;; *) echo 'helper 路径必须为绝对路径' >&2; exit 2;; esac
    test ! -e "$runtime_path" || { echo '已有内网会话或遗留状态，请先断开或核对恢复' >&2; exit 1; }
    test ! -L "$helper_path" && test ! -L "$policy_path" || { echo '拒绝覆盖符号链接' >&2; exit 1; }
    install -d -o root -g root -m 755 /usr/local/libexec
    install -o root -g root -m 755 "$2" "$helper_path"
    "$helper_path" --check
    if test -w /usr/share/polkit-1/actions; then
    install -d -o root -g root -m 755 /usr/share/polkit-1/actions
    policy_tmp=$(mktemp)
    trap 'rm -f "$policy_tmp"' EXIT
    cat > "$policy_tmp" <<'POLICY'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>V5VPN REA</vendor>
  <action id="org.v5vpn-rea.ipsec">
    <description>Configure V5VPN intranet connection</description>
    <description xml:lang="zh_CN">配置 V5VPN 内网连接</description>
    <message>Administrator authorization is required to connect V5VPN intranet resources.</message>
    <message xml:lang="zh_CN">V5VPN 需要管理员授权来建立内网连接。</message>
    <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin</allow_active></defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/local/libexec/v5vpn-rea-ipsec-helper</annotate>
  </action>
</policyconfig>
POLICY
    install -o root -g root -m 644 "$policy_tmp" "$policy_path"
    else
      pkaction --action-id org.freedesktop.policykit.exec >/dev/null
      echo "系统策略目录只读，使用现有 pkexec 管理员授权策略。"
    fi
    echo '原生内网 helper 已安装。桌面客户端按普通用户运行，连接时由系统申请授权。'
    ;;
  --uninstall)
    test "$(id -u)" -eq 0 || { echo '--uninstall 需要管理员权限' >&2; exit 1; }
    test ! -e "$runtime_path" || { echo '请先断开内网会话并核对清理' >&2; exit 1; }
    rm -f "$helper_path"
    if test -w /usr/share/polkit-1/actions; then rm -f "$policy_path"; fi
    echo '已移除本产品 helper 和授权策略；共享 strongSwan 软件包保留。'
    ;;
  *) echo '用法：--check | --install /绝对路径/helper | --uninstall' >&2; exit 2;;
esac
