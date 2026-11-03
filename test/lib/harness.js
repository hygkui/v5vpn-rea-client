// lib/harness.js — UI E2E 的自拉起沙盒。
//
// 构建并拉起 mock 网关与客户端、用隔离的用户数据目录（跨平台：Windows
// 读 APPDATA，macOS/Linux 由 HOME 派生）、随机端口，跑完清理。原本只有
// e2e_ui_test.js 有这套生命周期，e2e_v5vpn_multi_test.js 靠「手工先起
// app@45678 + mock@8443」的前置——两个入口两种形态，导致 run.sh all
// 漏跑深度场景。现在统一从这里拿沙盒，任何 E2E 套件单独可跑。
'use strict';

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// goBuild 构建一个仓库内包到指定路径。
function goBuild(tag, outPath, pkg) {
  tag(`构建 ${pkg} → ${outPath}`);
  const buildTags = process.platform === 'linux' && pkg.endsWith('/internal/cmd') ? ['-tags', 'ipsectest'] : [];
  execFileSync('go', ['build', ...buildTags, '-o', outPath, pkg], {
    cwd: REPO_ROOT,
    stdio: 'inherit',
    env: { ...process.env },
  });
}

// findFreePort 用 net 模块实际 bind 一次拿端口，避免和正在跑的 mock 抢 8443。
function findFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function waitForPort(port, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => { sock.destroy(); resolve(); });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) reject(new Error(`${label} 在 ${timeoutMs}ms 内未监听 ${port}`));
        else setTimeout(attempt, 200);
      });
    };
    attempt();
  });
}

// startSandbox 建一个隔离沙盒并拉起 mock 与客户端。
//   spec: { entryPkg|mockPkg, mockArgs(addr, mockDataDir), uiPath, tag, keep }
// 返回 { appURL, appPort, mockURL, mockPort, appDataDir, workDir, kill }。
//
// kill() 幂等：杀子进程并（除非 keep）删除整个工作目录。app 的用户数据
// 目录、mock 的数据目录、二进制都落在里面，删目录即完成清理。
async function startSandbox(spec) {
  const tag = spec.tag || (() => {});
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-sandbox-'));
  const binDir = path.join(workDir, 'bin');
  const appDataDir = path.join(workDir, 'appdata');
  const mockDataDir = path.join(workDir, 'mock-data');
  fs.mkdirSync(binDir, { recursive: true });
  fs.mkdirSync(appDataDir, { recursive: true });
  fs.mkdirSync(mockDataDir, { recursive: true });

  const exeSuffix = os.platform() === 'win32' ? '.exe' : '';
  const mockExe = path.join(binDir, `mock${exeSuffix}`);
  const appExe = path.join(binDir, `app${exeSuffix}`);

  const children = [];
  let killed = false;
  const kill = () => {
    if (killed) return;
    killed = true;
    for (const c of children.reverse()) {
      try { c.kill('SIGKILL'); } catch { /* 已退出 */ }
    }
    if (!spec.keep) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch { /* Windows 句柄未释放 */ }
    } else {
      tag(`保留沙盒目录: ${workDir}`);
    }
  };

  // 1. 构建 mock 与 app。
  goBuild(tag, mockExe, spec.entryPkg || spec.mockPkg);
  goBuild(tag, appExe, 'github.com/hygkui/v5vpn-rea-client/internal/cmd');

  // 2. 拉起 mock（随机端口）。
  const mockPort = await findFreePort();
  const mockAddr = `127.0.0.1:${mockPort}`;
  const mockProc = spawn(mockExe, spec.mockArgs(mockAddr, mockDataDir), {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(mockProc);
  pipeTo(procLog(tag, 'mock'), mockProc);
  await waitForPort(mockPort, 20000, 'mock');
  tag(`mock 已就绪: https://${mockAddr}`);

  // 3. 拉起 app（隔离用户数据目录，跨平台：Windows 读 APPDATA，
  //    macOS/Linux 的 mygo PathUserData / os.UserConfigDir 均由 HOME 派生。
  //    cwd 落在只含二进制的 bin 目录，堵住「工作目录 setting.xml」这条
  //    候选路径读到开发机真实配置。
  const appPort = await findFreePort();
  const appEnv = { ...process.env, APPDATA: appDataDir };
  if (process.platform === 'linux') appEnv.V5VPN_IPSEC_TEST_STATE = process.env.V5VPN_E2E_IPSEC_STATE || 'up';
  if (process.platform !== 'win32') {
    appEnv.HOME = appDataDir;
    // os.UserConfigDir 优先读 XDG_CONFIG_HOME，仅重定向 HOME 挡不住它：
    // 深度/Ubuntu 等发行版把它设成全局的 $HOME/.config，开发机真实的
    // setting.xml（真实网关与账号）会漏进沙盒——下拉里出现真实网关、
    // 演示网关不再注入，E2E 断言随之失败。
    appEnv.XDG_CONFIG_HOME = path.join(appDataDir, '.config');
  }
  const appProc = spawn(appExe, ['-port', String(appPort)], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: appEnv,
    cwd: binDir,
  });
  children.push(appProc);
  pipeTo(procLog(tag, 'app'), appProc);
  await waitForPort(appPort, 30000, 'app');
  tag(`客户端已就绪: http://127.0.0.1:${appPort}（配置目录 ${appDataDir}）`);

  return {
    appURL: `http://127.0.0.1:${appPort}${spec.uiPath || '/'}`,
    appPort,
    mockURL: `https://${mockAddr}`,
    mockPort,
    appDataDir,
    workDir,
    kill,
  };
}

// procLog 生成把子进程 stdout/stderr 转发到 tag 的函数。
function procLog(tag, name) {
  return (line) => tag(`[${name}] ${String(line).trim()}`);
}

function pipeTo(sink, proc) {
  proc.stdout.on('data', d => sink(d));
  proc.stderr.on('data', d => sink(d));
}

module.exports = { goBuild, findFreePort, waitForPort, startSandbox, REPO_ROOT };
