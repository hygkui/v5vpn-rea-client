// e2e_ui_test.js — 驱动真实 Web UI 连 in-repo mock 网关的端到端测试。
//
// 与 internal/atrust/e2e_mock_test.go 的分工：
//   - Go 测试验协议层（登录链、资源解析、隧道帧），跑在 CI 里；
//   - 这个脚本验 UI 层（表单→API→渲染→断开），需要真实浏览器与桌面进程，
//     不进 CI，由 test/run.sh 在本机跑。
//
// 它自己负责三件事，不需要人工先启动任何进程：
//   1. 构建并拉起 mock 网关（test/mock/atrust 或 test/mock/v5vpn），随机端口；
//   2. 在**隔离的 APPDATA** 下启动 app，避免把测试网关写进用户的真实
//      setting.xml（那里存着真实账号口令）；
//   3. 用 puppeteer-core 驱动本机 Edge 走完场景，逐步截图并生成 HTML 报告。
//
// 为什么必须隔离 APPDATA：app 的配置与设备标识都在 %APPDATA%\v5vpn-rea\ 下。
// 不隔离就会污染开发机上的真实配置——这是测试工具最不该犯的错。
//
// 用法：
//   node e2e_ui_test.js                       # 默认跑 aTrust 场景
//   node e2e_ui_test.js --scenario=atrust
//   node e2e_ui_test.js --scenario=v5vpn
//   node e2e_ui_test.js --keep                # 保留临时目录，便于排查

'use strict';

const puppeteer = require('puppeteer-core');
const fs = require('fs');
const path = require('path');
const { findBrowser } = require('./lib/find-browser');
const { startSandbox } = require('./lib/harness');

const TEST_DIR = __dirname;
const RESULTS_DIR = path.join(TEST_DIR, 'results');

// ---------------------------------------------------------------------------
// 参数
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = { scenario: 'atrust', keep: false };
  for (const a of argv.slice(2)) {
    const m = /^--([a-z-]+)=(.*)$/.exec(a);
    if (m) out[m[1]] = m[2];
    else if (a === '--keep') out.keep = true;
  }
  return out;
}

const ARGS = parseArgs(process.argv);

// REPORT_PATH 是本套件的单套报告；套件摘要（suite-*.json）供 e2e_run.js
// 聚合成统一报告。
const REPORT_PATH = path.join(RESULTS_DIR, `report-${ARGS.scenario}.html`);

// 场景定义：协议、mock 包路径、网关表单值、期望在界面上看到的资源名。
//
// 资源名取自 mock 的固定夹具（test/mock/atrust/endpoints.go 的 mockAppInfo，
// test/mock/v5vpn/server.go 的 intergration.xml），改夹具时这里要同步。
const SCENARIOS = {
  atrust: {
    name: 'aTrust 零信任',
    mockPkg: 'github.com/hygkui/v5vpn-rea-client/test/mock/atrust',
    mockArgs: (addr, dir) => ['-addr', addr, '-dir', dir, '-v=false'],
    protocol: 'atrust',
    // 两套前端物理分家：aTrust 在 /atrust/，V5VPN 在 /v5vpn/。
    uiPath: '/atrust/',
    statusPath: '/api/atrust/status',
    gateway: { name: 'aTrust 测试网关(Mock)', username: 'e2e-user@local', password: 'e2e-password' },
    expectedResources: ['Mock 控制台 (本机 8443)', '内网 Web (域名+IP)', '办公网段 10.20.0.0/16'],
  },
  v5vpn: {
    name: 'V5VPN (网御)',
    mockPkg: 'github.com/hygkui/v5vpn-rea-client/test/mock/v5vpn',
    // v5vpn mock 是 library 包，需要 cmd/mockserver 这个入口。
    entryPkg: 'github.com/hygkui/v5vpn-rea-client/cmd/mockserver',
    mockArgs: (addr) => ['-addr', addr, '-mode', 'pwd-only'],
    protocol: 'v5vpn',
    uiPath: '/v5vpn/',
    statusPath: '/api/status',
    gateway: { name: 'V5VPN 测试网关(Mock)', username: 'admin', password: 'admin123' },
    expectedResources: ['内网OA协同办公', '研发代码仓库 (GitLab)'],
  },
  // NC（IPsec 全路由）账号：mock 用 -nc only 下发 <NC_RESOURCE>、0 个
  // TCP/UDP 资源。这一场景驱动 PR #13 的完整链路：service 拉起 IPsec
  // 数据面（本机无 WSL 时状态机落到 unavailable）、/api/status 暴露
  // ipsecResources/ipsecState、资源表进入 NC 分支、状态条渲染。这也是
  // PSK 不泄漏到 API 的端到端守卫。
  'v5vpn-nc': {
    name: 'V5VPN NC/IPsec 资源',
    mockPkg: 'github.com/hygkui/v5vpn-rea-client/test/mock/v5vpn',
    entryPkg: 'github.com/hygkui/v5vpn-rea-client/cmd/mockserver',
    mockArgs: (addr) => ['-addr', addr, '-mode', 'pwd-only', '-nc', 'only'],
    protocol: 'v5vpn',
    uiPath: '/v5vpn/',
    statusPath: '/api/status',
    gateway: { name: 'V5VPN NC 测试网关(Mock)', username: 'admin', password: 'admin123' },
    expectedResources: [],
    nc: true,
  },
};

const SCENARIO = SCENARIOS[ARGS.scenario];
if (!SCENARIO) {
  console.error(`未知场景: ${ARGS.scenario}（可选: ${Object.keys(SCENARIOS).join(', ')}）`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// 日志与结果
// ---------------------------------------------------------------------------

fs.mkdirSync(RESULTS_DIR, { recursive: true });
const SCREENSHOTS_DIR = path.join(RESULTS_DIR, 'screenshots');
fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

const LOG_FILE = path.join(RESULTS_DIR, `test-${ARGS.scenario}.log`);
fs.writeFileSync(LOG_FILE, `=== ${SCENARIO.name} UI E2E started at ${new Date().toISOString()} ===\n`);

function log(msg) {
  const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const line = `[${ts}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

const steps = [];

// meta 在 main 与 runScenario 之间共享的运行期信息（报告头部也用它）。
const meta = { mockURL: '-', appURL: '-', browser: '-', appDataDir: '-' };

// recordStep 执行一步，成功失败都截图并落盘，失败继续往下跑还是立刻停？
// 立刻停：后续步骤都依赖前一步的界面状态，继续跑只会产生误导性的截图。
async function recordStep(page, { id, title, desc, screenshotName, action }) {
  const t0 = Date.now();
  log(`>>> [Step ${id}] ${title}`);
  let status = 'PASS';
  let details = '';
  let error = null;

  try {
    details = (await action()) || '';
  } catch (err) {
    status = 'FAIL';
    error = err.message;
    log(`!!! Step ${id} failed: ${err.message}`);
  }

  const durationMs = Date.now() - t0;
  const file = path.join(SCREENSHOTS_DIR, `${ARGS.scenario}-${screenshotName}`);
  try {
    await page.screenshot({ path: file, fullPage: false });
  } catch {
    /* 页面已崩时截图会失败，不该盖掉真正的错误 */
  }

  steps.push({
    id, title, desc, status, durationMs, details, error,
    screenshotFile: fs.existsSync(file) ? `screenshots/${path.basename(file)}` : null,
    screenshotBase64: fs.existsSync(file) ? fs.readFileSync(file).toString('base64') : null,
  });

  log(`<<< [Step ${id}] ${status} (${durationMs}ms)`);
  if (error) throw new Error(`Step ${id} (${title}) 失败: ${error}`);
}

// ---------------------------------------------------------------------------
// 进程编排（构建/端口/沙盒拉起统一在 lib/harness.js，与 multi 套件共用）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 报告
// ---------------------------------------------------------------------------

function generateHtmlReport(meta) {
  const passCount = steps.filter(s => s.status === 'PASS').length;
  const failCount = steps.filter(s => s.status === 'FAIL').length;
  const totalMs = steps.reduce((a, s) => a + s.durationMs, 0);
  const reportPath = REPORT_PATH;
  const logText = fs.existsSync(LOG_FILE) ? fs.readFileSync(LOG_FILE, 'utf-8') : '';
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${SCENARIO.name} UI E2E 测试报告</title>
<style>
  :root {
    --bg:#0f172a; --card:#1e293b; --border:#334155; --text:#f1f5f9; --muted:#94a3b8;
    --primary:#38bdf8; --ok:#10b981; --bad:#ef4444; --accent:#6366f1;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
       background:var(--bg);color:var(--text);line-height:1.6;padding:30px 20px}
  .container{max-width:1100px;margin:0 auto}
  header{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid var(--border);
         border-radius:12px;padding:24px 32px;margin-bottom:24px}
  .header-top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;margin-bottom:16px}
  h1{font-size:23px;color:#fff}
  .badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:13px;font-weight:600}
  .badge-pass{background:rgba(16,185,129,.2);color:#34d399;border:1px solid var(--ok)}
  .badge-fail{background:rgba(239,68,68,.2);color:#f87171;border:1px solid var(--bad)}
  .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;
        padding-top:16px;border-top:1px solid var(--border)}
  .meta-item{display:flex;flex-direction:column}
  .meta-label{font-size:12px;color:var(--muted);text-transform:uppercase}
  .meta-value{font-size:15px;font-weight:600;color:#fff;margin-top:4px;word-break:break-all}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin-bottom:24px}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}
  .stat-num{font-size:27px;font-weight:700;color:var(--primary)}
  .stat-num.ok{color:var(--ok)} .stat-num.bad{color:var(--bad)}
  .stat-title{font-size:13px;color:var(--muted);margin-top:4px}
  h2{font-size:19px;margin:32px 0 16px;color:#fff}
  .step{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:22px}
  .step-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:10px}
  .step-title-wrap{display:flex;align-items:center;gap:12px}
  .step-num{background:var(--accent);color:#fff;width:28px;height:28px;border-radius:50%;
            display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex:0 0 auto}
  .step-title{font-size:16px;font-weight:600;color:#fff}
  .step-desc{color:var(--muted);font-size:14px;margin-bottom:10px}
  .step-details{background:#0f172a;border-left:3px solid var(--primary);padding:10px 14px;font-size:13px;
                color:#cbd5e1;border-radius:0 6px 6px 0;margin-bottom:14px;
                font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
  .step-err{border-left-color:var(--bad);color:#fca5a5}
  .shot{background:#090d16;border:1px solid #1e293b;border-radius:8px;padding:12px;text-align:center}
  .shot img{max-width:100%;height:auto;border-radius:6px;border:1px solid var(--border);cursor:zoom-in}
  .shot-label{font-size:12px;color:var(--muted);margin-top:8px}
  .logs{background:#0b0f19;border:1px solid var(--border);border-radius:8px;padding:16px;max-height:420px;
        overflow-y:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
        color:#94a3b8;white-space:pre-wrap;word-break:break-all}
  footer{text-align:center;color:var(--muted);font-size:13px;margin-top:40px;padding-top:20px;border-top:1px solid var(--border)}
  .lightbox{display:none;position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:9999;
            align-items:center;justify-content:center;cursor:zoom-out}
  .lightbox.active{display:flex}
  .lightbox img{max-width:95%;max-height:95%;border-radius:8px}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-top">
      <h1>🛡️ ${SCENARIO.name} UI 端到端测试</h1>
      <span class="badge ${failCount === 0 ? 'badge-pass' : 'badge-fail'}">
        ${failCount === 0 ? '✓ 全部通过' : '✕ 存在失败项'}
      </span>
    </div>
    <div class="meta">
      <div class="meta-item"><span class="meta-label">Mock 网关</span><span class="meta-value">${esc(meta.mockURL)}</span></div>
      <div class="meta-item"><span class="meta-label">客户端 UI</span><span class="meta-value">${esc(meta.appURL)}</span></div>
      <div class="meta-item"><span class="meta-label">浏览器</span><span class="meta-value">${esc(meta.browser)}</span></div>
      <div class="meta-item"><span class="meta-label">配置文件隔离</span><span class="meta-value">${esc(meta.appDataDir)}</span></div>
      <div class="meta-item"><span class="meta-label">执行时间</span><span class="meta-value">${new Date().toLocaleString('zh-CN')}</span></div>
    </div>
  </header>

  <div class="stats">
    <div class="stat"><div class="stat-num">${steps.length}</div><div class="stat-title">总步骤</div></div>
    <div class="stat"><div class="stat-num ok">${passCount}</div><div class="stat-title">通过</div></div>
    <div class="stat"><div class="stat-num ${failCount ? 'bad' : ''}">${failCount}</div><div class="stat-title">失败</div></div>
    <div class="stat"><div class="stat-num">${(totalMs / 1000).toFixed(2)}s</div><div class="stat-title">总耗时</div></div>
  </div>

  <h2>📸 操作步骤</h2>
  ${steps.map(s => `
  <div class="step">
    <div class="step-head">
      <div class="step-title-wrap"><div class="step-num">${s.id}</div><div class="step-title">${esc(s.title)}</div></div>
      <div>
        <span class="badge ${s.status === 'PASS' ? 'badge-pass' : 'badge-fail'}">${s.status}</span>
        <span style="font-size:13px;color:var(--muted);margin-left:8px">${s.durationMs}ms</span>
      </div>
    </div>
    <p class="step-desc">${esc(s.desc)}</p>
    <div class="step-details${s.error ? ' step-err' : ''}"><strong>${s.error ? '错误：' : '结果：'}</strong>${esc(s.error || s.details)}</div>
    ${s.screenshotBase64 ? `<div class="shot">
      <img src="data:image/png;base64,${s.screenshotBase64}" onclick="openLB(this.src)" alt="${esc(s.screenshotFile)}">
      <div class="shot-label">📷 <code>results/${esc(s.screenshotFile)}</code>（点击放大）</div>
    </div>` : ''}
  </div>`).join('')}

  <h2>📋 完整日志</h2>
  <div class="logs">${esc(logText)}</div>

  <footer>Generated by v5vpn-rea test suite • ${new Date().toISOString()}</footer>
</div>
<div id="lb" class="lightbox" onclick="this.classList.remove('active')"><img id="lb-img" src="" alt=""></div>
<script>
  function openLB(src){document.getElementById('lb-img').src=src;document.getElementById('lb').classList.add('active');}
</script>
</body>
</html>`;

  fs.writeFileSync(reportPath, html);
  return reportPath;
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------
// 浏览器探测在 lib/find-browser.js：跨平台候选列表，EDGE_PATH 优先。

async function main() {
  let browser = null;
  let reportPath = null;
  let sandbox = null;

  try {
    // 1-3. 沙盒：构建 mock 与客户端、隔离用户数据目录、随机端口拉起。
    //   生命周期统一在 lib/harness.js，与 e2e_v5vpn_multi_test.js 共用，
    //   任何 E2E 套件单独可跑，不再有「手工先起服务」的前置。
    log(`=== [1/5] 构建沙盒（场景: ${SCENARIO.name}） ===`);
    sandbox = await startSandbox({
      entryPkg: SCENARIO.entryPkg,
      mockPkg: SCENARIO.mockPkg,
      mockArgs: SCENARIO.mockArgs,
      uiPath: SCENARIO.uiPath,
      keep: ARGS.keep,
      tag: (msg) => { fs.appendFileSync(LOG_FILE, `${msg}\n`); log(msg); },
    });
    meta.mockURL = sandbox.mockURL;
    meta.appURL = sandbox.appURL;
    meta.appDataDir = sandbox.appDataDir;

    // 4. 浏览器
    const browserPath = findBrowser();
    if (!browserPath) throw new Error('未找到 Edge/Chrome；可用 EDGE_PATH 环境变量指定');
    meta.browser = browserPath;
    log(`使用浏览器: ${browserPath}`);

    browser = await puppeteer.launch({
      executablePath: browserPath,
      headless: 'new',
      defaultViewport: { width: 1280, height: 900 },
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors'],
    });
    const page = await browser.newPage();
    page.on('console', m => log(`[browser ${m.type()}] ${m.text()}`));
    page.on('pageerror', e => log(`[browser error] ${e.message}`));
    page.on('response', r => {
      if (r.url().includes('/api/')) log(`[api] ${r.status()} ${r.url()}`);
    });

    // 5. 场景步骤
    log('=== [4/5] 执行场景步骤 ===');
    await runScenario(page);

    log('=== [5/5] 生成报告 ===');
  } catch (err) {
    log(`FATAL: ${err.stack || err.message}`);
    // 失败也要出报告——里面的截图和日志是排障的唯一线索。
  } finally {
    if (browser) await browser.close().catch(() => {});
    if (sandbox) sandbox.kill();
    reportPath = generateHtmlReport(meta);
    log(`报告: ${reportPath}`);
    writeSuiteSummary();
  }

  const failed = steps.filter(s => s.status === 'FAIL').length;
  const crashed = steps.length === 0;
  process.exit(failed || crashed ? 1 : 0);
}

// writeSuiteSummary 导出一份机器可读的套件摘要（results/suite-*.json），
// 供 e2e_run.js 聚合成统一报告：一个入口、一份报告，避免漏跑。
function writeSuiteSummary() {
  const summary = {
    suite: `ui:${ARGS.scenario}`,
    title: `${SCENARIO.name} 主链路 UI E2E`,
    logFile: path.basename(LOG_FILE),
    reportFile: path.basename(REPORT_PATH),
    scenarios: [{
      id: 1,
      title: `${SCENARIO.name} 主链路（登录 → 资源 → 断开）`,
      desc: '表单 → API → 渲染 → 断开的完整回归。',
      status: steps.some(s => s.status === 'FAIL') ? 'FAIL' : 'PASS',
      steps: steps.map(s => ({
        stepId: s.id,
        title: s.title,
        desc: s.desc,
        status: s.status,
        details: s.details || '',
        durationMs: s.durationMs || 0,
        screenshot: s.screenshotFile || null,
      })),
    }],
  };
  try {
    fs.writeFileSync(
      path.join(RESULTS_DIR, `suite-ui-${ARGS.scenario}.json`),
      JSON.stringify(summary, null, 2));
  } catch (err) {
    log(`写套件摘要失败: ${err.message}`);
  }
}

// runScenario 是场景步骤的主体。
//
// 两套界面不是同一页面按协议裁剪，而是各自独立的一页：aTrust 的网关表单
// 没有加密算法下拉、没有验证码输入框、没有改密按钮，这些元素在 V5VPN
// 场景里才有。步骤里按 SCENARIO.protocol 分支，而不是"先查元素在不在
// 再决定断言" —— 后者会让"元素被误删"和"本来就不该有"混为一谈。
async function runScenario(page) {
  const gw = SCENARIO.gateway;
  const isATrust = SCENARIO.protocol === 'atrust';

  await recordStep(page, {
    id: 1,
    title: '加载客户端主界面',
    desc: '打开本协议的界面目录，确认登录视图与网关选择框已渲染。',
    screenshotName: '01-login-view.png',
    action: async () => {
      await page.goto(meta.appURL, { waitUntil: 'networkidle0', timeout: 20000 });
      await page.waitForSelector('#view-login', { visible: true });
      const title = await page.title();
      // 界面必须确实是本协议那一套：分家后仍可能因为跳错目录跑成
      // 另一套，页面标题和切换链接是最直接的证据。
      const switchHref = await page.$eval('.proto-switch-link', el => el.getAttribute('href'));
      const wantHref = isATrust ? '/v5vpn/' : '/atrust/';
      if (switchHref !== wantHref) {
        throw new Error(`界面切换链接指向 ${switchHref}，期望 ${wantHref}（可能打开错了界面）`);
      }
      // 网关下拉只列本协议的网关。默认配置带两台 V5VPN 演示网关：
      // aTrust 界面必须看不到它们；V5VPN 界面必须看得到（protocol
      // 零值 = V5VPN，旧的演示网关没有任何 protocol 字段）。
      const optionTexts = await page.$$eval('#gateway-select option', els => els.map(e => e.textContent.trim()));
      const demoVisible = optionTexts.some(t => t.includes('demo-gateway'));
      if (isATrust && demoVisible) {
        throw new Error(`aTrust 界面下拉里出现了 V5VPN 演示网关: ${optionTexts.join(' | ')}`);
      }
      if (!isATrust && !demoVisible) {
        throw new Error(`V5VPN 界面下拉里应有演示网关（零值 protocol 属于 V5VPN）: ${optionTexts.join(' | ')}`);
      }
      return `页面标题: ${title}；切换到另一协议: ${switchHref}；下拉网关数=${optionTexts.length}（含演示网关=${demoVisible}）`;
    },
  });

  await recordStep(page, {
    id: 2,
    title: `添加 ${SCENARIO.name} 测试网关`,
    desc: `在网关管理里新增 ${meta.mockURL}，并切换为当前网关。`,
    screenshotName: '02-add-gateway.png',
    action: async () => {
      await page.click('#open-settings-btn');
      await page.waitForSelector('#settings-modal', { visible: true });

      await fill(page, '#new-gw-name', gw.name);
      // app 把网关地址拆成 IP + 端口两个输入框。
      await fill(page, '#new-gw-ip', '127.0.0.1');
      await fill(page, '#new-gw-port', String(new URL(meta.mockURL).port));
      // 协议在分家后是"由哪套界面提交"决定的：两套表单各自写死自己的
      // protocol，界面上没有可选的下拉。加密算法只有 V5VPN 有。
      if (!isATrust) {
        await page.select('#new-gw-algo', '0');
      }
      await page.click('#add-gw-btn');

      // 等新行出现再点「切换」，避免保存未落库时点空。
      await page.waitForFunction(
        (name) => Array.from(document.querySelectorAll('#gateways-tbody tr'))
          .some(r => r.textContent.includes(name)),
        { timeout: 10000 }, gw.name,
      );
      // 行内按钮由选中状态决定，两条分支都要被真实覆盖：
      //   - 已选中的网关显示「✓ 当前选中」——aTrust 场景里这是第一台
      //     本协议网关，界面自动选中了它，没有可点的「切换」；
      //   - 未选中的显示「切换」——v5vpn 场景里演示网关还在列表里。
      const switchResult = await page.evaluate((name) => {
        for (const row of document.querySelectorAll('#gateways-tbody tr')) {
          if (!row.textContent.includes(name)) continue;
          const btn = row.querySelector('.select-gw-btn');
          if (btn) { btn.click(); return 'clicked'; }
          if (row.querySelector('.badge-current-gw')) return 'already-current';
          return 'no-button';
        }
        return 'row-missing';
      }, gw.name);

      if (switchResult === 'row-missing') throw new Error('网关表格里没有新添加的行');
      if (switchResult === 'no-button') throw new Error('新网关行里既没有「切换」按钮，也不是当前选中');
      if (switchResult === 'already-current') {
        // 已经自动选中：手动关弹窗，后续断言与点了「切换」一致。
        await page.click('#modal-done-btn');
      }

      await page.waitForFunction(() => {
        const m = document.getElementById('settings-modal');
        return !m || m.style.display === 'none';
      }, { timeout: 10000 });

      const pill = await page.$eval('#gw-ip-port', el => el.textContent.trim());
      const protoTag = await page.$eval('#gateway-info-bar', el => el.textContent.trim());
      if (!pill.includes('127.0.0.1')) {
        throw new Error(`信息栏未显示 mock 地址（switchResult=${switchResult}）: ${pill}`);
      }
      return `已切换到 ${gw.name}（方式=${switchResult}）；地址栏: ${pill}；信息条: ${protoTag}`;
    },
  });

  await recordStep(page, {
    id: 3,
    title: '填写凭据并点击连接',
    desc: `输入 ${gw.username} / ${gw.password}，走 ${SCENARIO.name} 的登录链。`,
    screenshotName: '03-credentials.png',
    action: async () => {
      await fill(page, '#username-input', gw.username);
      await fill(page, '#password-input', gw.password);
      // PR #10 界面重构（固定表单 + 挑战模态）后，验证码不再是表单常驻
      // 元素：网关要验证码时以模态弹出，由 e2e_v5vpn_multi_test.js 的
      // 验证码场景专门覆盖。这里 mock 用 pwd-only 模式，提交后直接进
      // 认证链，无需断言任何挑战组件。
      await page.click('#connect-btn');
      return isATrust
        ? '凭据已填写（aTrust 界面无验证码输入框）'
        : '凭据已提交（pwd-only 模式无挑战，等待认证链）';
    },
  });

  await recordStep(page, {
    id: 4,
    title: '等待认证通过并进入已连接视图',
    desc: `${SCENARIO.name} 的认证链完成后，界面切到已连接工作台。`,
    screenshotName: '04-connected.png',
    action: async () => {
      // 用轮询而不是一次性 waitForFunction：连接失败时登录表单会显示错误，
      // 直接等 45 秒超时会把真正的原因（比如网关拒了凭据）埋掉。
      const deadline = Date.now() + 45000;
      while (Date.now() < deadline) {
        const state = await page.evaluate(() => ({
          connected: (() => {
            const v = document.getElementById('view-connected');
            return !!(v && v.style.display !== 'none');
          })(),
          alert: (() => {
            const a = document.getElementById('login-alert');
            return a && a.offsetParent !== null ? a.textContent.trim() : '';
          })(),
        }));

        if (state.connected) break;
        if (state.alert) {
          throw new Error(`登录被拒，界面提示: ${state.alert}`);
        }
        await new Promise(r => setTimeout(r, 200));
      }

      const connected = await page.evaluate(() => {
        const v = document.getElementById('view-connected');
        return !!(v && v.style.display !== 'none');
      });
      if (!connected) throw new Error('45 秒内未进入已连接视图，且界面没有给出错误提示');

      const user = await page.$eval('#session-user-val', el => el.textContent.trim());
      const sid = await page.$eval('#session-id-val', el => el.textContent.trim());
      const gwName = await page.$eval('#connected-gw-name', el => el.textContent.trim());

      // 改密入口只属于 V5VPN：aTrust 后端没有改密端点，它那套界面里
      // 根本没有这个按钮。V5VPN 口令会话里它必须可见。
      let changePwdVisible = null;
      if (!isATrust) {
        changePwdVisible = await page.$eval('#connected-change-pwd-btn', el => el.offsetParent !== null);
        if (!changePwdVisible) {
          throw new Error('V5VPN 口令会话下"修改密码"按钮应可见');
        }
      } else {
        const hasBtn = await page.$('#connected-change-pwd-btn');
        if (hasBtn) {
          throw new Error('aTrust 界面里不应存在"修改密码"按钮');
        }
      }
      return `已连接；用户=${user}；会话=${sid.slice(0, 12)}…；网关=${gwName}` +
        (isATrust ? '' : `；改密按钮可见=${changePwdVisible}`);
    },
  });

  await recordStep(page, {
    id: 5,
    title: SCENARIO.nc ? 'NC/IPsec 资源已拉取并渲染' : '资源列表已从 mock 拉取并渲染',
    desc: SCENARIO.nc
      ? '0 个 TCP/UDP 资源时，资源表进入 NC 分支并列出隧道与路由，状态条渲染数据面状态。'
      : `等待表格里出现 mock 夹具下发的资源（${SCENARIO.expectedResources.join('、')}）。`,
    screenshotName: '05-resources.png',
    action: async () => {
      await page.waitForFunction(() => {
        const rows = document.querySelectorAll('#resources-tbody tr');
        if (!rows.length) return false;
        return !rows[0].textContent.includes('正在从网关拉取');
      }, { timeout: 30000 });

      if (SCENARIO.nc) {
        return await assertNCView(page);
      }

      const names = await page.$$eval('#resources-tbody tr', rows =>
        rows.map(r => (r.querySelector('strong') || r).textContent.trim()));
      const count = await page.$eval('#res-count', el => el.textContent.trim());

      const missing = SCENARIO.expectedResources.filter(n => !names.some(got => got.includes(n)));
      if (missing.length) {
        throw new Error(`资源列表缺少期望项: ${missing.join('、')}；实际: ${names.join(' | ')}`);
      }
      return `共 ${count} 行；含期望资源；实际: ${names.join(' | ')}`;
    },
  });

  await recordStep(page, {
    id: 6,
    title: '断开连接并回到登录视图',
    desc: '点击断开，确认后端登出且界面平滑退回登录页。',
    screenshotName: '06-disconnected.png',
    action: async () => {
      // 直接在元素上派发 click：头部每秒轮询刷新会引起布局抖动，
      // 坐标点击可能落空（偶发 Step 6 超时的根因）。
      await page.$eval('#disconnect-btn', el => el.click());
      await page.waitForFunction(() => {
        const v = document.getElementById('view-login');
        return v && v.style.display !== 'none';
      }, { timeout: 20000 });

      const status = await page.evaluate(async (statusPath) => {
        const res = await fetch(statusPath);
        return res.json();
      }, SCENARIO.statusPath);
      return `已断开；后端状态=${status.status || status.Status || '未知'}`;
    },
  });
}

// assertNCView 验证 NC（IPsec 全路由）账号在界面上的完整呈现。后端先把
// /api/status 备齐：ipsecResources 带隧道与路由、ipsecState 离开 pending
// 落到终态（无 WSL 的机器上是 unavailable，装了 WSL 的是 error/up——
// 三者都算「状态机跑完了」，本套不绑死机器形态）。再核对 DOM：状态条
// 可见、资源表进入 NC 分支。最后是安全不变量：整个 status 响应不得
// 含 mock PSK——这是 PR #13「PSK 不进入任何 JSON 输出」的端到端守卫。
async function assertNCView(page) {
  const fetchStatus = () => page.evaluate(async (p) => {
    const res = await fetch(p);
    return res.json();
  }, SCENARIO.statusPath);

  const deadline = Date.now() + 30000;
  let status = null;
  while (Date.now() < deadline) {
    status = await fetchStatus();
    if (['unavailable', 'error', 'up'].includes(status.ipsecState)) break;
    await new Promise(r => setTimeout(r, 200));
  }
  if (!status || !['unavailable', 'error', 'up'].includes(status.ipsecState)) {
    throw new Error(`30 秒内 ipsecState 未到达终态: ${JSON.stringify(status).slice(0, 300)}`);
  }

  const profiles = status.ipsecResources || [];
  if (!profiles.length) {
    throw new Error(`/api/status 未返回 ipsecResources: ${JSON.stringify(status).slice(0, 300)}`);
  }
  const tunnels = profiles.flatMap(p => p.tunnels || []);
  if (!tunnels.some(t => (t.name || '').includes('Mock 办公网'))) {
    throw new Error(`ipsecResources 缺少 mock 隧道: ${JSON.stringify(tunnels)}`);
  }
  const routesBlob = JSON.stringify(tunnels);
  if (!routesBlob.includes('198.51.100.0/24') || !routesBlob.includes('203.0.113.0/24')) {
    throw new Error(`隧道缺少 mock 路由: ${routesBlob}`);
  }
  const statusBlob = JSON.stringify(status);
  if (statusBlob.includes('mock-psk-fixture')) {
    throw new Error('PSK 泄漏进 /api/status 响应');
  }

  // 状态条：由头部每秒轮询刷新，等它出现并带上隧道信息。
  await page.waitForFunction(() => {
    const el = document.getElementById('ipsec-status');
    return !!(el && el.offsetParent !== null && /IPsec/.test(el.textContent));
  }, { timeout: 15000 });
  const barText = (await page.$eval('#ipsec-status', el => el.textContent.trim()));

  // 资源表 NC 分支：0 TCP/UDP 时的说明文案 + 已下发隧道列表。
  const tableText = await page.$eval('#resources-tbody', tb => tb.textContent);
  if (!tableText.includes('IPsec')) {
    throw new Error(`资源表未进入 NC 分支: ${tableText.slice(0, 200)}`);
  }
  if (!tableText.includes('Mock 办公网') || !tableText.includes('198.51.100.0/24')) {
    throw new Error(`资源表缺少隧道/路由信息: ${tableText.slice(0, 300)}`);
  }

  return `ipsecState=${status.ipsecState}；状态条: ${barText}；资源表: ${tableText.replace(/\s+/g, ' ').slice(0, 120)}…`;
}

// fill 清空并输入。复制来的输入框常有预填值（例如默认网关 IP），
// 直接 type 会拼成 127.0.0.10.0.0.1 这类脏值。
async function fill(page, selector, value) {
  await page.click(selector, { clickCount: 3 });
  await page.keyboard.press('Backspace');
  await page.type(selector, value);
}

main();
