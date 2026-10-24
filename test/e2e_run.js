// e2e_run.js — UI E2E 的统一入口：一个命令跑全部套件，聚合一份报告。
//
// 背景：此前 e2e_ui_test.js（自拉起、主链路）与 e2e_v5vpn_multi_test.js
// （深度场景、需手工先起 app@45678 + mock@8443）是两个割裂的入口，
// run.sh all 只包含前者——深度场景要靠记得单独跑，漏跑就是漏测。本脚本
// 顺序执行全部套件（每套独立沙盒、子进程隔离、互不影响），读取各套件
// 落盘的 suite-*.json 摘要，聚合渲染 results/report.html。
//
// 用法：
//   node e2e_run.js            # 全部：V5VPN 主链路 + 11 合 1 深度 + aTrust 主链路
//   node e2e_run.js --only=v5vpn,multi   # 只跑部分套件（v5vpn|multi|atrust）
//
// 退出码：任一套件失败（或崩溃未产出摘要）即非 0，可直接进 CI 判定。
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const TEST_DIR = __dirname;
const RESULTS_DIR = path.join(TEST_DIR, 'results');
const REPORT_FILE = path.join(RESULTS_DIR, 'report.html');

function parseArgs(argv) {
  const out = { only: null };
  for (const a of argv.slice(2)) {
    const m = /^--([a-z-]+)=(.*)$/.exec(a);
    if (m) out[m[1]] = m[2];
  }
  return out;
}
const ARGS = parseArgs(process.argv);

// 套件定义：子命令 + 单套摘要文件。顺序即执行顺序。
const SUITES = [
  { key: 'v5vpn', title: 'V5VPN 主链路（登录 → 资源 → 断开）', cmd: ['node', 'e2e_ui_test.js', '--scenario=v5vpn'], summary: 'suite-ui-v5vpn.json' },
  { key: 'v5vpn-nc', title: 'V5VPN NC/IPsec 资源（0 TCP/UDP → 状态条 + NC 资源表）', cmd: ['node', 'e2e_ui_test.js', '--scenario=v5vpn-nc'], summary: 'suite-ui-v5vpn-nc.json' },
  { key: 'multi', title: 'V5VPN 11 合 1 深度场景（2FA / 三因素 / 全链 / 改密 / 验证码 / 短信 / 令牌）', cmd: ['node', 'e2e_v5vpn_multi_test.js'], summary: 'suite-multi.json' },
  { key: 'atrust', title: 'aTrust 主链路（登录 → 资源 → 断开）', cmd: ['node', 'e2e_ui_test.js', '--scenario=atrust'], summary: 'suite-ui-atrust.json' },
];

function log(msg) {
  const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
  console.log(`[${ts}] ${msg}`);
}

const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// runSuite 以子进程跑一个套件：崩溃互不传染，stdout 透传到终端。
function runSuite(suite) {
  return new Promise((resolve) => {
    log(`>>> [套件 ${suite.key}] ${suite.title}`);
    const t0 = Date.now();
    const proc = spawn(suite.cmd[0], suite.cmd.slice(1), {
      cwd: TEST_DIR,
      stdio: 'inherit',
      env: { ...process.env },
    });
    proc.on('close', (code) => {
      const ms = Date.now() - t0;
      const summaryPath = path.join(RESULTS_DIR, suite.summary);
      const summary = fs.existsSync(summaryPath)
        ? JSON.parse(fs.readFileSync(summaryPath, 'utf-8'))
        : { suite: suite.key, title: suite.title, scenarios: [], crash: true };
      const failed = code !== 0;
      log(`<<< [套件 ${suite.key}] ${failed ? 'FAIL' : 'PASS'}（${(ms / 1000).toFixed(1)}s，exit ${code}）`);
      resolve({ suite, ok: !failed, summary, durationMs: ms });
    });
  });
}

async function main() {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const selected = ARGS.only
    ? SUITES.filter(s => ARGS.only.split(',').includes(s.key))
    : SUITES;
  if (selected.length === 0) {
    console.error(`未知套件: ${ARGS.only}（可选: ${SUITES.map(s => s.key).join(', ')}）`);
    process.exit(2);
  }

  const results = [];
  for (const suite of selected) {
    // 前一套件的摘要文件先清掉：崩溃的套件不应顶替上一轮的结果。
    const p = path.join(RESULTS_DIR, suite.summary);
    if (fs.existsSync(p)) fs.rmSync(p);
    results.push(await runSuite(suite));
  }

  writeAggregatedReport(results, selected);

  const failed = results.filter(r => !r.ok);
  log(`=== E2E 汇总：${results.length - failed.length}/${results.length} 套件通过，报告: ${REPORT_FILE} ===`);
  process.exit(failed.length ? 1 : 0);
}

// writeAggregatedReport 渲染统一报告：每个套件一张卡片（场景 → 步骤 → 截图）。
function writeAggregatedReport(results, selected) {
  const now = new Date();
  const suitesHtml = results.map(r => {
    const scs = r.summary.scenarios || [];
    const scHtml = scs.map(sc => `
      <div class="scenario">
        <div class="scenario-header">
          <span class="scenario-title">${esc(sc.title)}</span>
          <span class="badge ${sc.status === 'PASS' ? 'b-pass' : 'b-fail'}">${sc.status}</span>
        </div>
        ${sc.desc ? `<p class="scenario-desc">${esc(sc.desc)}</p>` : ''}
        <div class="steps">
          ${(sc.steps || []).map(st => `
            <div class="step">
              <div class="step-head">
                <span>${esc(st.title)}</span>
                <span class="badge ${st.status === 'PASS' ? 'b-pass' : 'b-fail'}">${st.status}</span>
              </div>
              ${st.details ? `<p class="step-details">${esc(st.details)}</p>` : ''}
              ${screenshotImg(st.screenshot)}
            </div>`).join('')}
        </div>
      </div>`).join('') || '<p>（套件崩溃，未产出任何场景结果——见终端/日志）</p>';

    return `
    <section class="suite ${r.ok ? 'ok' : 'fail'}">
      <h2>${esc(r.suite.title)} <span class="badge ${r.ok ? 'b-pass' : 'b-fail'}">${r.ok ? 'PASS' : 'FAIL'}</span></h2>
      <p class="suite-meta">套件: ${esc(r.suite.key)} · 耗时 ${(r.durationMs / 1000).toFixed(1)}s
        · 摘要: ${esc(r.suite.summary)}${r.summary.logFile ? ` · 日志: results/${esc(r.summary.logFile)}` : ''}</p>
      ${scHtml}
    </section>`;
  }).join('');

  const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>V5VPN UI E2E 统一报告</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font: 14px/1.6 -apple-system, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 22px; }
  .suite { background: #1e293b; border-radius: 12px; padding: 16px 20px; margin: 24px 0; }
  .suite.fail { outline: 2px solid #ef4444; }
  h2 { font-size: 17px; margin: 0 0 4px; }
  .suite-meta { color: #94a3b8; font-size: 12px; margin: 0 0 12px; }
  .badge { font-size: 11px; padding: 2px 10px; border-radius: 999px; }
  .b-pass { background: #065f46; color: #a7f3d0; }
  .b-fail { background: #7f1d1d; color: #fecaca; }
  .scenario { border-top: 1px solid #334155; padding: 12px 0; }
  .scenario-header { display: flex; gap: 10px; align-items: baseline; }
  .scenario-title { font-weight: 600; }
  .scenario-desc, .step-details { color: #94a3b8; font-size: 12px; margin: 4px 0; }
  .steps { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; margin-top: 10px; }
  .step { background: #0f172a; border-radius: 8px; padding: 10px 12px; }
  .step-head { display: flex; justify-content: space-between; gap: 8px; font-size: 13px; }
  .step img { width: 100%; border-radius: 6px; margin-top: 8px; cursor: zoom-in; }
  .lightbox { position: fixed; inset: 0; background: rgba(0,0,0,.85); display: none; align-items: center; justify-content: center; cursor: zoom-out; }
  .lightbox img { max-width: 96vw; max-height: 96vh; }
</style>
</head>
<body>
<div class="wrap">
  <h1>V5VPN UI E2E 统一报告</h1>
  <p>${esc(selected.map(s => s.key).join(' + '))} · ${now.toLocaleString('zh-CN')} ·
     ${results.length - results.filter(r => !r.ok).length}/${results.length} 套件通过</p>
  ${suitesHtml}
</div>
<div id="lb" class="lightbox" onclick="this.style.display='none'"><img id="lb-img" src=""></div>
<script>
  document.addEventListener('click', e => {
    if (e.target.tagName === 'IMG' && e.target.closest('.step')) {
      document.getElementById('lb-img').src = e.target.src;
      document.getElementById('lb').style.display = 'flex';
    }
  });
</script>
</body>
</html>`;
  fs.writeFileSync(REPORT_FILE, html);
}

// screenshotImg 把套件摘要里的截图路径转成内嵌 base64（报告单文件可分发）。
function screenshotImg(name) {
  if (!name) return '';
  // 摘要里的截图是文件名或相对路径，统一落到 results/screenshots/。
  const base = path.basename(name);
  for (const dir of [path.join(RESULTS_DIR, 'screenshots'), RESULTS_DIR]) {
    const p = path.join(dir, base);
    if (fs.existsSync(p)) {
      const data = fs.readFileSync(p).toString('base64');
      return `<img src="data:image/png;base64,${data}" alt="${esc(base)}" title="点击放大">`;
    }
  }
  return `<p class="step-details">（截图缺失: ${esc(base)}）</p>`;
}

main().catch(err => {
  console.error(`FATAL: ${err.stack || err.message}`);
  process.exit(1);
});
