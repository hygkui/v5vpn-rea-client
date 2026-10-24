// V5VPN Client Frontend Controller
(function() {
  // Application State
  let config = null;
  let currentGateway = null;
  let isConnected = false;
  let logPollTimer = null;
  let selectedCertId = '';
  // Last IPsec (NC) profiles from /api/status. They have no local proxy; the
  // table shows them instead of a bare "no resources" line.
  let lastIPsec = [];
  let lastIPsecState = '';
  let lastIPsecError = '';
  let certs = [];

  // ==================== 网关驱动的挑战状态 ====================
  // 登录表单只负责起点（网关 + 账号 + 口令）。每个因子提交后由网关结果码
  // 决定下一步，跳数不定；四种挑战（图形验证码 / 客户端证书 / 短信 / 改密）
  // 都在同一个模态窗口里弹出。challengeKind 记录当前模态承载的挑战类型，
  // certStandalone 区分「链中证书挑战」与「证书免密登录」两种提交方式。
  let challengeKind = null;         // 'verifycode' | 'cert' | 'sms' | 'pwd-change'
  let certStandalone = false;       // cert 模态：true = 证书直接登录（非链中挑战）
  let modalVerifycode = '';         // 验证码模态录入的图形验证码，一次性带给下一次登录
  let pwdChangeVoluntary = false;   // 改密模态：主动改密 vs 网关 0x100 强制改密

  // ==================== 协议过滤 ====================
  // 界面按协议完全分开：这一套只列出 V5VPN 网关，aTrust 网关在另一套界面里管理。
  function isV5VPNGateway(gw) {
    return !gw || gw.protocol !== 'atrust';
  }


  // DOM Elements - Views
  const viewLogin = document.getElementById('view-login');
  const viewConnected = document.getElementById('view-connected');
  const loginAlert = document.getElementById('login-alert');

  // DOM Elements - Login View
  const loginForm = document.getElementById('login-form');
  const gatewaySelect = document.getElementById('gateway-select');
  const openSettingsBtn = document.getElementById('open-settings-btn');
  const gwIpPort = document.getElementById('gw-ip-port');
  const gwAlgoTag = document.getElementById('gw-algo-tag');
  const usernameInput = document.getElementById('username-input');
  const passwordInput = document.getElementById('password-input');
  const togglePwdBtn = document.getElementById('toggle-pwd-btn');
  const rememberPwdCheckbox = document.getElementById('remember-pwd-checkbox');
  const autoLoginCheckbox = document.getElementById('auto-login-checkbox');
  const connectBtn = document.getElementById('connect-btn');
  const connectBtnText = document.getElementById('connect-btn-text');
  const connectSpinner = connectBtn.querySelector('.btn-spinner');
  const voluntaryChangePwdLink = document.getElementById('voluntary-change-pwd-link');
  const certLoginBtn = document.getElementById('cert-login-btn');

  // DOM Elements - Challenge Modal (gateway-driven, body is rebuilt per kind)
  const challengeModal = document.getElementById('challenge-modal');
  const challengeTitle = document.getElementById('challenge-title');
  const challengeCloseBtn = document.getElementById('challenge-close-btn');
  const challengeBody = document.getElementById('challenge-body');

  // DOM Elements - Connected View
  const connectedGwName = document.getElementById('connected-gw-name');
  const connectedChangePwdBtn = document.getElementById('connected-change-pwd-btn');
  const sessionUserVal = document.getElementById('session-user-val');
  const sessionIpVal = document.getElementById('session-ip-val');
  const sessionIdVal = document.getElementById('session-id-val');
  const resCount = document.getElementById('res-count');
  const resLoadingBadge = document.getElementById('res-loading-badge');
  const refreshResourcesBtn = document.getElementById('refresh-resources-btn');
  const resourceErrorBanner = document.getElementById('resource-error-banner');
  const resourceErrorText = document.getElementById('resource-error-text');
  const resourcesTbody = document.getElementById('resources-tbody');
  const disconnectBtn = document.getElementById('disconnect-btn');
  const toggleLogsBtn = document.getElementById('toggle-logs-btn');
  const logsPanel = document.getElementById('logs-panel');
  const closeLogsBtn = document.getElementById('close-logs-btn');
  const clearLogsBtn = document.getElementById('clear-logs-btn');
  const logConsole = document.getElementById('log-console');

  // DOM Elements - Settings Modal
  const settingsModal = document.getElementById('settings-modal');
  const closeModalBtn = document.getElementById('close-modal-btn');
  const modalDoneBtn = document.getElementById('modal-done-btn');
  const gatewaysTbody = document.getElementById('gateways-tbody');
  const addGwBtn = document.getElementById('add-gw-btn');

  // Backend Bridge API (HTTP API or IPC)
  const api = {
    async getConfig() {
      if (window.VPNService && window.VPNService.getConfig) {
        return await window.VPNService.getConfig();
      }
      const res = await fetch('/api/config');
      return await res.json();
    },
    async login(gwId, username, password, verifycode, remember, auto) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000); // 12s timeout safeguard

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId, username, password, verifycode, remember, auto }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || '登录失败');
          error.code = data.code || '';
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('网关响应超时(12s)，请检查网络与网关端口连通性');
        }
        throw err;
      }
    },
    async logout() {
      if (window.VPNService && window.VPNService.logout) {
        return await window.VPNService.logout();
      }
      const res = await fetch('/api/logout', { method: 'POST' });
      return await res.json();
    },
    async getStatus() {
      if (window.VPNService && window.VPNService.getStatus) {
        return await window.VPNService.getStatus();
      }
      const res = await fetch('/api/status');
      return await res.json();
    },
    async getLogs() {
      if (window.VPNService && window.VPNService.getLogs) {
        return await window.VPNService.getLogs();
      }
      const res = await fetch('/api/logs');
      return await res.json();
    },
    async clearLogs() {
      if (window.VPNService && window.VPNService.clearLogs) {
        return await window.VPNService.clearLogs();
      }
      await fetch('/api/logs', { method: 'DELETE' });
    },
    async saveGateway(gw) {
      if (window.VPNService && window.VPNService.saveGateway) {
        return await window.VPNService.saveGateway(gw);
      }
      const res = await fetch('/api/gateways', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(gw)
      });
      return await res.json();
    },
    async deleteGateway(id) {
      if (window.VPNService && window.VPNService.deleteGateway) {
        return await window.VPNService.deleteGateway(id);
      }
      const res = await fetch(`/api/gateways/${encodeURIComponent(id)}`, { method: 'DELETE' });
      return await res.json();
    },
    async openURL(url) {
      if (window.VPNService && window.VPNService.openURL) {
        return await window.VPNService.openURL(url);
      }
      try {
        await fetch('/api/open-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
      } catch (e) {
        window.open(url, '_blank');
      }
    },
    async setWindowSize(mode) {
      try {
        await fetch('/api/window-size', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode })
        });
      } catch (_) {}
    },
    async changePassword(gwId, username, password, newPassword, verifycode, remember, auto) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);
      try {
        const res = await fetch('/api/change-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId, username, password, newPassword, verifycode, remember, auto }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || '修改密码失败');
          error.code = data.code || '';
          error.passwordChanged = data.passwordChanged === true;
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('网关响应超时(20s)，请检查网络与网关端口连通性');
        }
        throw err;
      }
    },
    async checkUpdates() {
      if (window.VPNService && window.VPNService.checkForUpdates) {
        return await window.VPNService.checkForUpdates();
      }
      const res = await fetch('/api/check-updates', { method: 'POST' });
      return await res.json();
    },
    async refreshResources() {
      if (window.VPNService && window.VPNService.refreshResources) {
        return await window.VPNService.refreshResources();
      }
      const res = await fetch('/api/resources/refresh', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '重新拉取资源失败');
      return data;
    },
    async listCerts(source) {
      if (window.VPNService && window.VPNService.listCertificates) {
        return await window.VPNService.listCertificates(source);
      }
      const res = await fetch(`/api/certs?source=${encodeURIComponent(source)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '读取证书列表失败');
      return data;
    },
    async importCert(path, alias, password) {
      if (window.VPNService && window.VPNService.importCertificate) {
        return await window.VPNService.importCertificate(path, alias, password);
      }
      const res = await fetch('/api/certs/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path, alias, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '导入证书失败');
      return data;
    },
    async deleteCert(id) {
      if (window.VPNService && window.VPNService.deleteCertificate) {
        return await window.VPNService.deleteCertificate(id);
      }
      const res = await fetch(`/api/certs/${encodeURIComponent(id)}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '删除证书失败');
      return data;
    },
    async pickCertFile() {
      const res = await fetch('/api/cert/pick', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '无法打开文件选择对话框');
      return data.path || '';
    },
    async loginWithCert(gwId, source, certId, verifycode, auto) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);
      try {
        const res = await fetch('/api/login-cert', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId, source, certId, verifycode, auto }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || '证书登录失败');
          error.code = data.code || '';
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('网关响应超时(20s)，请检查网络与网关端口连通性');
        }
        throw err;
      }
    },
    // Ask the gateway to text the SMS verification code for a challenged
    // login. The challenged session is held by the backend; only the gateway
    // id travels with the request.
    async sendSMSCode(gwId) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);
      try {
        const res = await fetch('/api/sms-send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || '发送短信失败');
          error.code = data.code || '';
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('网关响应超时(20s)，请检查网络与网关端口连通性');
        }
        throw err;
      }
    },
    // Submit the SMS verification code and finish the challenged login.
    async smsLogin(gwId, code) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);
      try {
        const res = await fetch('/api/sms-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId, code }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || '短信认证失败');
          error.code = data.code || '';
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('网关响应超时(20s)，请检查网络与网关端口连通性');
        }
        throw err;
      }
    },
    // Submit the dynamic-token (OTP) code and finish the challenged login.
    async tokenLogin(gwId, code) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);
      try {
        const res = await fetch('/api/token-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId, code }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || '动态令牌认证失败');
          error.code = data.code || '';
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('网关响应超时(20s)，请检查网络与网关端口连通性');
        }
        throw err;
      }
    },
    // Present the client certificate on a password login the gateway answered
    // with the certificate challenge (code 2). The challenged session is held
    // by the backend; the chain continues with whatever the gateway asks next.
    async submitCertFactor(gwId, source, certId, verifycode) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);
      try {
        const res = await fetch('/api/cert-factor', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId, source, certId, verifycode }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || '证书认证失败');
          error.code = data.code || '';
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('网关响应超时(20s)，请检查网络与网关端口连通性');
        }
        throw err;
      }
    }
  };

  // Password visibility toggle
  togglePwdBtn.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
      passwordInput.type = 'text';
      togglePwdBtn.textContent = '🔒';
    } else {
      passwordInput.type = 'password';
      togglePwdBtn.textContent = '👁';
    }
  });

  // External links (GitHub footer etc.): open in system browser, not WebView
  document.querySelectorAll('.js-open-external').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const url = a.dataset.url || a.href;
      if (url) api.openURL(url);
    });
  });

  // Footer update buttons: trigger the update check with clear UI feedback
  document.querySelectorAll('.js-check-updates').forEach(btn => {
    btn.addEventListener('click', async () => {
      const original = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '⏳ 正在检查…';
      try {
        const res = await api.checkUpdates();
        if (res && res.error) {
          btn.innerHTML = '❌ 检查失败';
          alert('检查更新失败：\n' + res.error + '\n\n您可以手动前往 GitHub Releases 页面查看。');
        } else if (res && res.hasUpdate) {
          btn.innerHTML = '🎉 发现新版 ' + res.latestVersion;
          const notes = res.releaseNotes ? ('\n\n更新说明：\n' + res.releaseNotes) : '';
          const msg = `发现新版本 ${res.latestVersion}（当前版本: ${res.currentVersion}）${notes}\n\n是否打开浏览器前往下载？`;
          if (confirm(msg)) {
            await api.openURL(res.releaseURL || 'https://github.com/hygkui/v5vpn-rea-client/releases');
          }
        } else if (res) {
          btn.innerHTML = '✔ 已是最新版 (' + res.currentVersion + ')';
        } else {
          btn.innerHTML = '✔ 已是最新版本';
        }
      } catch (e) {
        btn.innerHTML = '❌ 检查异常';
        alert('检查更新异常：' + (e.message || e));
      } finally {
        setTimeout(() => {
          btn.innerHTML = original;
          btn.disabled = false;
        }, 3000);
      }
    });
  });

  // Modal Controls
  openSettingsBtn.addEventListener('click', () => {
    renderGatewayManagerTable();
    settingsModal.style.display = 'flex';
    api.setWindowSize('settings');
  });

  function closeSettingsModal() {
    settingsModal.style.display = 'none';
    api.setWindowSize(isConnected ? 'connected' : 'login');
  }

  closeModalBtn.addEventListener('click', closeSettingsModal);
  modalDoneBtn.addEventListener('click', closeSettingsModal);
  settingsModal.addEventListener('click', (e) => {
    if (e.target === settingsModal) closeSettingsModal();
  });

  // Logs Panel Toggle
  toggleLogsBtn.addEventListener('click', () => {
    const isVisible = logsPanel.style.display !== 'none';
    logsPanel.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) {
      logConsole.scrollTop = logConsole.scrollHeight;
    }
  });

  closeLogsBtn.addEventListener('click', () => {
    logsPanel.style.display = 'none';
  });

  clearLogsBtn.addEventListener('click', async () => {
    await api.clearLogs();
    logConsole.innerHTML = '';
  });

  // Gateway Selection & Population
  function populateGateways(gateways, lastUsed) {
    gatewaySelect.innerHTML = '';
    if (!gateways || gateways.length === 0) {
      gatewaySelect.innerHTML = '<option value="">(暂无网关配置，请在设置中添加)</option>';
      gwIpPort.textContent = '--';
      gwAlgoTag.textContent = '--';
      return;
    }

    gateways.forEach(gw => {
      const opt = document.createElement('option');
      opt.value = gw.id || gw.name;
      opt.textContent = `${gw.name} (${gw.ip}:${gw.port})`;
      if (gw.name === lastUsed || gw.id === lastUsed) {
        opt.selected = true;
      }
      gatewaySelect.appendChild(opt);
    });

    onGatewayChanged();
  }

  function onGatewayChanged() {
    closeChallengeModal();
    modalVerifycode = '';
    const selectedVal = gatewaySelect.value;
    if (!config || !config.gateways) return;
    currentGateway = config.gateways.find(g => (g.id === selectedVal || g.name === selectedVal));
    if (!currentGateway && config.gateways.length > 0) {
      currentGateway = config.gateways[0];
    }

    if (currentGateway) {
      gwIpPort.textContent = `${currentGateway.ip}:${currentGateway.port}`;
      gwAlgoTag.textContent = currentGateway.algo === 1 ? '国密 GM/SM' : '国际标准 TLS';

      // Auto-fill remembered accounts
      if (currentGateway.savedAccounts && currentGateway.savedAccounts.length > 0) {
        const lastUser = currentGateway.lastUserName || currentGateway.savedAccounts[0].username;
        const acc = currentGateway.savedAccounts.find(a => a.username === lastUser) || currentGateway.savedAccounts[0];
        usernameInput.value = acc.username || '';
        passwordInput.value = acc.password || '';
        rememberPwdCheckbox.checked = acc.remember !== false;
        autoLoginCheckbox.checked = acc.auto === true;
      } else {
        usernameInput.value = '';
        passwordInput.value = '';
      }

      restoreAuthPreferences();
    }
  }

  gatewaySelect.addEventListener('change', onGatewayChanged);

  // Reload gateway configuration and re-render without resetting active modal or window size
  async function reloadGatewaysData() {
    try {
      config = await api.getConfig();
      populateGateways(config.gateways, config.lastUseGateway);
      renderGatewayManagerTable();
    } catch (err) {
      console.error('Failed to reload gateways:', err);
    }
  }

  // Render Gateways Table in Settings Modal
  function renderGatewayManagerTable() {
    if (!config || !config.gateways) return;
    gatewaysTbody.innerHTML = '';
    const own = config.gateways.filter(isV5VPNGateway);
    if (own.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="5" class="empty-state" style="padding:24px; text-align:center; color:var(--text-dim);">暂无网关配置，请在下方添加</td>`;
      gatewaysTbody.appendChild(tr);
      return;
    }
    own.forEach(gw => {
      const tr = document.createElement('tr');
      const users = (gw.savedAccounts || []).map(a => a.username).join(', ') || '-';
      const isSelected = currentGateway && (currentGateway.id === gw.id || currentGateway.name === gw.name);

      tr.className = isSelected ? 'gw-row is-selected-row' : 'gw-row';
      tr.innerHTML = `
        <td title="${escapeHtml(gw.name)}">
          <div class="gw-name-cell">
            <span class="gw-dot ${isSelected ? 'dot-active' : ''}"></span>
            <strong class="gw-name-text">${escapeHtml(gw.name)}</strong>
          </div>
        </td>
        <td class="gw-ip-cell" title="${escapeHtml(gw.ip)}:${gw.port}">
          <code class="gw-code">${escapeHtml(gw.ip)}:${gw.port}</code>
        </td>
        <td><span class="algo-pill ${gw.algo === 1 ? 'algo-gm' : 'algo-tls'}">${gw.algo === 1 ? '国密 GM' : '国际标准'}</span></td>
        <td class="gw-users-cell" title="${escapeHtml(users)}">${escapeHtml(users)}</td>
        <td>
          <div class="action-btn-cell">
            ${isSelected 
              ? '<span class="badge-current-gw">✓ 当前选中</span>' 
              : `<button class="btn btn-select btn-sm select-gw-btn" data-id="${gw.id || gw.name}">切换</button>`}
            <button class="btn btn-delete btn-sm delete-gw-btn" data-id="${gw.id || gw.name}" title="删除此网关配置">删除</button>
          </div>
        </td>
      `;
      gatewaysTbody.appendChild(tr);
    });

    // Select Gateway
    gatewaysTbody.querySelectorAll('.select-gw-btn').forEach(b => {
      b.addEventListener('click', (e) => {
        const id = e.target.dataset.id;
        gatewaySelect.value = id;
        onGatewayChanged();
        closeSettingsModal();
      });
    });

    // Delete Gateway
    gatewaysTbody.querySelectorAll('.delete-gw-btn').forEach(b => {
      b.addEventListener('click', async (e) => {
        const id = e.target.dataset.id;
        if (confirm(`确定删除网关 ${id} 吗？`)) {
          await api.deleteGateway(id);
          await reloadGatewaysData();
        }
      });
    });
  }

  // Add Gateway
  addGwBtn.addEventListener('click', async () => {
    const name = document.getElementById('new-gw-name').value.trim();
    const ip = document.getElementById('new-gw-ip').value.trim();
    const port = parseInt(document.getElementById('new-gw-port').value, 10) || 443;
    const algo = parseInt(document.getElementById('new-gw-algo').value, 10) || 0;

    if (!name || !ip) {
      alert('请填写网关名称和 IP 地址');
      return;
    }
    if (name.length > 20) {
      alert('网关名称过长，请控制在 20 个字符以内');
      return;
    }

    await api.saveGateway({ name, ip, port, algo });
    document.getElementById('new-gw-name').value = '';
    document.getElementById('new-gw-ip').value = '';
    await reloadGatewaysData();
  });

  // ==================== 网关驱动的认证状态机 ====================
  // 每个因子提交后读网关结果码：成功进连接视图；挑战（改密 / 短信 / 证书 /
  // 图形验证码）打开对应模态，在同一挑战会话上继续；其他错误回到表单提示。
  // 跳数由网关决定，客户端只循环到 code 0，界面不枚举流程。

  function isPasswordExpired(err) {
    // Only the backend's 0x100 challenge may open the change-password modal.
    return !!(err && err.code === 'password_expired');
  }

  function isSMSChallenge(err) {
    // Only the backend's 0x8 challenge may open the SMS modal.
    return !!(err && err.code === 'sms_challenge');
  }

  function isCertChallenge(err) {
    // The gateway asked for the client-certificate factor (code 2).
    return !!(err && err.code === 'cert_challenge');
  }

  function isTokenChallenge(err) {
    // The gateway asked for the dynamic-token (OTP) factor (code 4).
    return !!(err && err.code === 'token_challenge');
  }

  // handleAuthOutcome runs one factor submission and dispatches the result.
  // Every modal submit handler reuses it; a follow-up challenge simply
  // replaces the open modal with the next one.
  async function handleAuthOutcome(promise) {
    setConnectingState(true);
    try {
      const res = await promise;
      closeChallengeModal();
      showConnectedView(res);
      return true;
    } catch (err) {
      setConnectingState(false);
      dispatchAuthError(err);
      return false;
    }
  }

  // dispatchAuthError maps a backend result code to the next UI hop. Codes
  // that keep a modal open (sms_code_error, certificate retries) are handled
  // by the modal's own submit handler and never reach here.
  function dispatchAuthError(err) {
    if (isPasswordExpired(err)) {
      openChallengeModal('pwd-change', { voluntary: false });
      return;
    }
    if (isSMSChallenge(err)) {
      openChallengeModal('sms');
      return;
    }
    if (isCertChallenge(err)) {
      openChallengeModal('cert', { standalone: false });
      return;
    }
    if (isTokenChallenge(err)) {
      openChallengeModal('token');
      return;
    }
    if (err && err.code === 'verify_code') {
      // Re-open the captcha modal with the gateway's reason: a wrong code
      // re-runs the login and lands here again, and a bare re-open would
      // leave the user guessing why.
      openChallengeModal('verifycode', { error: friendlyLoginError(err) });
      return;
    }
    closeChallengeModal();
    showLoginAlert(friendlyLoginError(err), 'error');
  }

  // Login Form Submission: the fixed form is always the password entry.
  async function handleLogin() {
    const gwId = gatewaySelect.value;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const remember = rememberPwdCheckbox.checked;
    const auto = autoLoginCheckbox.checked;

    if (!gwId || !username || !password) {
      showLoginAlert('请输入网关、用户名和登录密码', 'error');
      return;
    }

    hideLoginAlert();
    // The captcha modal hands its code to exactly one login attempt.
    const verifycode = modalVerifycode;
    modalVerifycode = '';
    await handleAuthOutcome(api.login(gwId, username, password, verifycode, remember, auto));
  }

  // ==================== 挑战模态 ====================
  // 四种挑战共用一个模态壳：openChallengeModal 按类型重建 body。模态内的
  // 提交永远走「提交因子 → dispatchAuthError」的同一分发，所以链中挑战
  // （口令→证书→短信）只是模态内容的连续替换。

  function openChallengeModal(kind, opts) {
    challengeKind = kind;
    stopSmsCountdown();
    challengeBody.innerHTML = '';
    if (kind === 'verifycode') {
      challengeTitle.textContent = '图形验证码';
      buildVerifycodeBody();
    } else if (kind === 'cert') {
      certStandalone = !!(opts && opts.standalone);
      challengeTitle.textContent = certStandalone ? '证书直接登录' : '网关要求客户端证书';
      buildCertBody();
    } else if (kind === 'sms') {
      challengeTitle.textContent = '短信认证';
      buildSMSBody();
    } else if (kind === 'token') {
      challengeTitle.textContent = '动态令牌认证';
      buildTokenBody();
    } else if (kind === 'pwd-change') {
      pwdChangeVoluntary = !!(opts && opts.voluntary);
      challengeTitle.textContent = '修改密码';
      buildPwdChangeBody();
    }
    challengeModal.style.display = 'flex';
    // A re-open after a rejected factor carries the gateway's reason; the
    // builder has rendered #modal-alert by now, so the message lands inside
    // the modal instead of behind it.
    if (opts && opts.error) {
      modalAlert(opts.error, 'error');
    }
  }

  function closeChallengeModal() {
    challengeKind = null;
    challengeModal.style.display = 'none';
    challengeBody.innerHTML = '';
    stopSmsCountdown();
  }

  challengeCloseBtn.addEventListener('click', () => {
    closeChallengeModal();
    hideLoginAlert();
  });
  challengeModal.addEventListener('click', (e) => {
    if (e.target === challengeModal) {
      closeChallengeModal();
      hideLoginAlert();
    }
  });

  // modalAlert shows a message inside the open modal; every builder renders
  // one #modal-alert element for retry hints.
  function modalAlert(msg, type) {
    const el = document.getElementById('modal-alert');
    if (!el) return;
    el.textContent = cleanErrorMessage(msg);
    el.className = `alert-box alert-${type}`;
    el.style.display = 'block';
  }

  // ==================== 短信认证（多因素挑战） ====================
  // 网关在口令校验通过后要求短信因子（RESULT code 0x8）。「发送短信」带
  // 60 秒重发倒计时，与原厂客户端的 Btn_SendSMS 行为一致。
  const SMS_RESEND_SECONDS = 60;
  let smsCountdownTimer = null;
  let smsCountdownLeft = 0;

  function stopSmsCountdown() {
    if (smsCountdownTimer) {
      clearInterval(smsCountdownTimer);
      smsCountdownTimer = null;
    }
    smsCountdownLeft = 0;
    const sendBtn = document.getElementById('modal-sms-send');
    if (sendBtn) {
      sendBtn.disabled = false;
      sendBtn.textContent = '📱 发送短信';
    }
  }

  function startSmsCountdown() {
    stopSmsCountdown();
    const sendBtn = document.getElementById('modal-sms-send');
    if (!sendBtn) return;
    smsCountdownLeft = SMS_RESEND_SECONDS;
    sendBtn.disabled = true;
    sendBtn.textContent = `重新发送 (${smsCountdownLeft}秒)`;
    smsCountdownTimer = setInterval(() => {
      smsCountdownLeft--;
      if (smsCountdownLeft <= 0) {
        stopSmsCountdown();
        return;
      }
      sendBtn.textContent = `重新发送 (${smsCountdownLeft}秒)`;
    }, 1000);
  }

  function buildSMSBody() {
    challengeBody.innerHTML = `
      <p class="challenge-hint">网关要求短信认证（多因素认证）。点击「发送短信」，输入手机收到的验证码后继续连接。</p>
      <div class="alert-box alert-error" id="modal-alert" style="display:none;"></div>
      <div class="form-group">
        <label for="modal-sms-input">短信验证码：</label>
        <div class="sms-input-row">
          <input type="text" id="modal-sms-input" class="form-control" placeholder="请输入手机短信验证码" maxlength="8" autocomplete="one-time-code" inputmode="numeric">
          <button type="button" id="modal-sms-send" class="btn btn-secondary sms-send-btn">📱 发送短信</button>
        </div>
      </div>
      <div class="challenge-actions">
        <button type="button" id="modal-sms-submit" class="btn btn-primary">验证并连接</button>
      </div>
    `;
    const input = document.getElementById('modal-sms-input');
    document.getElementById('modal-sms-send').addEventListener('click', handleSendSMS);
    document.getElementById('modal-sms-submit').addEventListener('click', (e) => {
      e.preventDefault();
      handleSMSLogin();
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleSMSLogin();
      }
    });
    input.focus();
  }

  async function handleSendSMS() {
    const gwId = gatewaySelect.value;
    if (!gwId) {
      modalAlert('请选择网关节点', 'error');
      return;
    }
    const sendBtn = document.getElementById('modal-sms-send');
    sendBtn.disabled = true;
    sendBtn.textContent = '正在发送...';
    try {
      await api.sendSMSCode(gwId);
      modalAlert('短信验证码已发送，请查看手机短信并输入。', 'info');
      startSmsCountdown();
    } catch (err) {
      modalAlert((err && err.message) || '发送短信失败', 'error');
      stopSmsCountdown();
    }
  }

  async function handleSMSLogin() {
    const gwId = gatewaySelect.value;
    const input = document.getElementById('modal-sms-input');
    const code = input ? input.value.trim() : '';
    const submitBtn = document.getElementById('modal-sms-submit');
    if (!gwId) {
      modalAlert('请选择网关节点', 'error');
      return;
    }
    if (!code) {
      modalAlert('请输入手机收到的短信验证码', 'error');
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = '正在验证...';
    setConnectingState(true);
    try {
      const res = await api.smsLogin(gwId, code);
      closeChallengeModal();
      showConnectedView(res);
      return;
    } catch (err) {
      setConnectingState(false);
      if (err && err.code === 'sms_code_error') {
        // 网关只拒绝了这一个码，挑战仍然有效：留在模态里让用户重输。
        modalAlert('网关提示：短信验证码错误，请核对后重新输入。', 'error');
        input.value = '';
        input.focus();
      } else {
        // 其余结果交给统一分发：可能是下一个挑战模态，也可能是硬错误。
        dispatchAuthError(err);
      }
    } finally {
      // 模态被替换或关闭后这些元素已不在文档里，无需恢复。
      if (submitBtn.isConnected) {
        submitBtn.disabled = false;
        submitBtn.textContent = '验证并连接';
      }
    }
  }

  // ==================== 动态令牌（OTP 挑战） ====================
  // 网关要求动态令牌因子（RESULT code 0x4）。与短信不同，令牌码由用户
  // 手里的硬件/软件令牌自行生成，没有「发送」步骤：输入即提交。
  function buildTokenBody() {
    challengeBody.innerHTML = `
      <p class="challenge-hint">网关要求动态令牌认证（多因素认证）。输入硬件或软件令牌当前显示的动态口令后继续连接。</p>
      <div class="alert-box alert-error" id="modal-alert" style="display:none;"></div>
      <div class="form-group">
        <label for="modal-token-input">动态口令：</label>
        <div class="sms-input-row">
          <input type="text" id="modal-token-input" class="form-control" placeholder="请输入令牌上的动态口令" maxlength="8" autocomplete="one-time-code" inputmode="numeric">
        </div>
      </div>
      <div class="challenge-actions">
        <button type="button" id="modal-token-submit" class="btn btn-primary">验证并连接</button>
      </div>
    `;
    const input = document.getElementById('modal-token-input');
    document.getElementById('modal-token-submit').addEventListener('click', (e) => {
      e.preventDefault();
      handleTokenLogin();
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleTokenLogin();
      }
    });
    input.focus();
  }

  async function handleTokenLogin() {
    const gwId = gatewaySelect.value;
    const input = document.getElementById('modal-token-input');
    const code = input ? input.value.trim() : '';
    const submitBtn = document.getElementById('modal-token-submit');
    if (!gwId) {
      modalAlert('请选择网关节点', 'error');
      return;
    }
    if (!code) {
      modalAlert('请输入令牌上的动态口令', 'error');
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = '正在验证...';
    setConnectingState(true);
    try {
      const res = await api.tokenLogin(gwId, code);
      closeChallengeModal();
      showConnectedView(res);
      return;
    } catch (err) {
      setConnectingState(false);
      if (err && err.code === 'token_code_error') {
        // 网关只拒绝了这一个码，挑战仍然有效：留在模态里让用户重输。
        modalAlert('网关提示：动态令牌码错误，请核对令牌当前显示后重新输入。', 'error');
        input.value = '';
        input.focus();
      } else {
        // 其余结果交给统一分发：可能是下一个挑战模态，也可能是硬错误。
        dispatchAuthError(err);
      }
    } finally {
      if (submitBtn.isConnected) {
        submitBtn.disabled = false;
        submitBtn.textContent = '验证并连接';
      }
    }
  }

  // ==================== 图形验证码挑战 ====================
  // The image is fetched on the backend's pre-auth session; the code the user
  // types travels with the next login attempt over that same session.
  function buildVerifycodeBody() {
    challengeBody.innerHTML = `
      <p class="challenge-hint">网关要求输入图形验证码。输入下图中字符后点击「继续连接」，将携带验证码重新提交登录。</p>
      <div class="alert-box alert-error" id="modal-alert" style="display:none;"></div>
      <div class="form-group">
        <label for="modal-verifycode-input">图形验证码：</label>
        <div class="verifycode-container">
          <input type="text" id="modal-verifycode-input" class="form-control" placeholder="请输入验证码" maxlength="6" autocomplete="off">
          <div class="verifycode-img-wrapper" id="modal-verifycode-img-wrapper" title="看不清？点击换一张">
            <img id="modal-verifycode-img" src="" alt="验证码" style="display: none;">
            <span id="modal-verifycode-loading" class="verifycode-loading" style="display: none;">加载中...</span>
          </div>
          <button type="button" id="modal-verifycode-refresh" class="btn btn-secondary btn-sm refresh-vc-btn" title="点击刷新验证码">🔄</button>
        </div>
      </div>
      <div class="challenge-actions">
        <button type="button" id="modal-verifycode-submit" class="btn btn-primary">继续连接</button>
      </div>
    `;
    const input = document.getElementById('modal-verifycode-input');
    document.getElementById('modal-verifycode-img-wrapper').addEventListener('click', () => loadVerifyCodeImage());
    document.getElementById('modal-verifycode-refresh').addEventListener('click', () => loadVerifyCodeImage());
    document.getElementById('modal-verifycode-submit').addEventListener('click', submitVerifycode);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        submitVerifycode();
      }
    });
    loadVerifyCodeImage();
    input.focus();
  }

  // submitVerifycode hands the code to exactly one login attempt and re-runs
  // the password submission; the gateway decides what happens next.
  async function submitVerifycode() {
    const code = document.getElementById('modal-verifycode-input').value.trim();
    if (!code) {
      modalAlert('请输入图形验证码', 'error');
      return;
    }
    modalVerifycode = code;
    closeChallengeModal();
    hideLoginAlert();
    await handleLogin();
  }

  async function loadVerifyCodeImage() {
    const gwId = gatewaySelect.value;
    const img = document.getElementById('modal-verifycode-img');
    const loading = document.getElementById('modal-verifycode-loading');
    if (!gwId || !img) return;
    if (loading) {
      loading.style.display = 'inline';
      loading.textContent = '加载中...';
    }
    img.style.display = 'none';
    try {
      const res = await fetch(`/api/verifycode-image?gwId=${encodeURIComponent(gwId)}`);
      const data = await res.json();
      if (data && data.dataUrl) {
        img.src = data.dataUrl;
        img.style.display = 'block';
        if (loading) loading.style.display = 'none';
      } else if (data && data.error) {
        if (loading) loading.textContent = '加载失败';
      }
    } catch (err) {
      console.error('Failed to load verifycode image:', err);
      if (loading) loading.textContent = '加载失败';
    }
  }

  function cleanErrorMessage(msg) {
    if (!msg) return '';
    let text = String(msg)
      .replace(/\s*[\(（](?:错误代码|错误码|code)[:：]?\s*[^）\)]*[\)）]/gi, '')
      .trim();
    if (text.startsWith('登录失败: ') && text.length > 5) {
      text = text.substring(5).trim();
    } else if (text.startsWith('登录失败：') && text.length > 5) {
      text = text.substring(5).trim();
    }
    return text;
  }

  function friendlyLoginError(err) {
    if (isPasswordExpired(err)) {
      return '网关提示：账号口令已过期，请在下方设置新密码。';
    }
    if (isSMSChallenge(err)) {
      // 因子链可以是口令→短信、口令+证书→短信或证书→短信，文案不指名前置因子。
      return '网关提示：还需短信验证码完成多因素认证。请点击「发送短信」并输入手机收到的验证码。';
    }
    if (err && err.code === 'bad_credentials') {
      return '网关提示：用户名或密码错误，请检查输入的账号或密码！';
    }
    if (err && err.code === 'verify_code') {
      // The verifycode modal opens itself via dispatchAuthError; this text
      // only surfaces when the code is quoted elsewhere (e.g. a failed
      // automatic sign-in after a password change).
      const rawMsg = err && err.message ? cleanErrorMessage(err.message) : '';
      if (rawMsg && !rawMsg.includes('需要图形验证码') && !rawMsg.includes('0x80')) {
        return rawMsg.startsWith('网关提示') ? rawMsg : ('网关提示：' + rawMsg);
      }
      return '网关提示：需要输入图形验证码，请在弹窗中输入验证码后继续连接。';
    }
    if (err && err.code) {
      const certMsg = friendlyCertError(err.code);
      if (certMsg) return certMsg;
    }
    const clean = cleanErrorMessage((err && err.message) || '未知错误');
    // Only a gateway result code earns the 网关提示 prefix. A local failure
    // (missing certificate directory, the request timing out) never reached the
    // gateway, and labelling it as one sends the user looking in the wrong place.
    if (err && err.code) {
      return clean.startsWith('网关提示') ? clean : ('网关提示：' + clean);
    }
    return clean;
  }

  // friendlyCertError maps the backend's stable certificate codes to text.
  function friendlyCertError(code) {
    switch (code) {
      case 'cert_invalid':
        return '网关提示：证书验证失败，请重新选择证书或确认网关已信任该证书。';
      case 'cert_unavailable':
        return '网关提示：该用户或网关未启用证书认证方式。';
      case 'cert_expired':
        return '网关提示：证书已过期，请更换证书或联系管理员续期。';
      case 'cert_revoked':
        return '网关提示：证书已被注销，请重新选择证书进行认证。';
      case 'cert_signature':
        return '网关提示：证书签名错误，请重新选择证书进行认证。';
      default:
        return '';
    }
  }

  // ==================== 修改密码（0x100 强制 / 主动改密） ====================
  function buildPwdChangeBody() {
    const hint = pwdChangeVoluntary
      ? '您已确认修改密码，请设置新密码。修改成功后将自动使用新密码连接。'
      : '网关要求先修改已过期的登录密码。修改成功后会用新密码继续连接。';
    challengeBody.innerHTML = `
      <p class="challenge-hint">${hint}</p>
      <div class="alert-box alert-error" id="modal-alert" style="display:none;"></div>
      <div class="form-group">
        <label for="modal-new-password">新密码：</label>
        <input type="password" id="modal-new-password" class="form-control" placeholder="请输入新密码" autocomplete="new-password">
      </div>
      <div class="form-group">
        <label for="modal-confirm-password">确认新密码：</label>
        <input type="password" id="modal-confirm-password" class="form-control" placeholder="再次输入新密码" autocomplete="new-password">
      </div>
      <div class="challenge-actions">
        <button type="button" id="modal-pwd-submit" class="btn btn-primary">修改密码并连接</button>
      </div>
    `;
    const input = document.getElementById('modal-new-password');
    document.getElementById('modal-pwd-submit').addEventListener('click', (e) => {
      e.preventDefault();
      handleChangePassword();
    });
    input.focus();
  }

  async function handleChangePassword() {
    const gwId = gatewaySelect.value;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const newPassword = document.getElementById('modal-new-password').value;
    const confirmPassword = document.getElementById('modal-confirm-password').value;
    // A captcha accepted earlier in the chain may still be required by the
    // change endpoint; it is consumed with this one submission.
    const verifycode = modalVerifycode;
    const remember = rememberPwdCheckbox.checked;
    const auto = autoLoginCheckbox.checked;
    const submitBtn = document.getElementById('modal-pwd-submit');

    if (!gwId || !username || !password) {
      modalAlert('请输入网关、用户名和当前登录密码', 'error');
      return;
    }
    if (!newPassword) {
      modalAlert('请输入新密码', 'error');
      return;
    }
    if (newPassword !== confirmPassword) {
      modalAlert('两次输入的新密码不一致', 'error');
      return;
    }
    if (newPassword === password) {
      modalAlert('新密码不能与当前密码相同', 'error');
      return;
    }

    modalVerifycode = '';
    submitBtn.disabled = true;
    submitBtn.textContent = '正在修改密码...';
    try {
      const res = await api.changePassword(gwId, username, password, newPassword, verifycode, remember, auto);
      passwordInput.value = newPassword;
      closeChallengeModal();
      showConnectedView(res);
    } catch (err) {
      const baseMsg = friendlyLoginError(err);
      if (err && err.passwordChanged) {
        // The gateway accepted the new password; only the automatic sign-in
        // failed. Move the form back to the login state with the new password
        // so a captcha (or a plain retry) can finish the connection.
        passwordInput.value = newPassword;
        closeChallengeModal();
        if (err.code === 'verify_code') {
          showLoginAlert('密码已修改，但自动登录需要图形验证码：请点击「口令登录」完成验证。', 'error');
        } else {
          showLoginAlert('密码已修改，但自动登录未完成：' + baseMsg + ' 请使用新密码重新连接。', 'error');
        }
      } else {
        modalAlert(baseMsg, 'error');
      }
    } finally {
      if (submitBtn.isConnected) {
        submitBtn.disabled = false;
        submitBtn.textContent = '修改密码并连接';
      }
    }
  }

  // ==================== 客户端证书（链中挑战 / 免密登录） ====================
  // rememberedCertId returns the selection to restore: the in-memory choice
  // first, then the gateway's last successful choice.
  function rememberedCertId(preferred) {
    return preferred || (currentGateway && currentGateway.selectedCertId) || '';
  }

  // buildCertBody renders the certificate modal. Two modes share one body:
  //   chain      — the gateway asked for the certificate factor after the
  //                password (code 2); submit presents the certificate on the
  //                challenged session via /api/cert-factor.
  //   standalone — the「使用证书直接登录」entry; identity is proven by the
  //                certificate alone (原厂 Opt_Cert), submit calls /api/login-cert.
  function buildCertBody() {
    const hint = certStandalone
      ? '身份完全由客户端证书证明（免口令）。选择一张证书直接连接；若网关还要求短信等因子，会继续弹出。'
      : '口令校验已通过，网关要求客户端证书因子。选择一张证书呈递给网关；若还有后续因子，会继续弹出。';
    challengeBody.innerHTML = `
      <p class="challenge-hint">${hint}</p>
      <div class="alert-box alert-error" id="modal-alert" style="display:none;"></div>
      <div class="form-group">
        <div class="label-row">
          <label>选择证书：</label>
          <button type="button" id="modal-cert-import-toggle" class="settings-trigger-btn" title="从 .p12/.pfx 文件导入证书">＋ 导入证书</button>
        </div>
        <div id="modal-cert-list" class="cert-list">
          <p class="cert-empty">正在检测证书...</p>
        </div>
      </div>
      <div id="modal-cert-import-panel" class="import-panel" style="display: none;">
        <div class="form-group">
          <label for="modal-import-path">证书文件：</label>
          <div class="import-path-row">
            <input type="text" id="modal-import-path" class="form-control" placeholder="选择或输入 .p12/.pfx 文件路径">
            <button type="button" id="modal-import-browse" class="btn btn-secondary btn-sm">浏览...</button>
          </div>
        </div>
        <div class="form-group">
          <label for="modal-import-alias">显示名称（可选）：</label>
          <input type="text" id="modal-import-alias" class="form-control" placeholder="默认使用证书名称">
        </div>
        <div class="form-group">
          <label for="modal-import-pwd">证书口令：</label>
          <input type="password" id="modal-import-pwd" class="form-control" placeholder="无口令可留空" autocomplete="off">
        </div>
        <div class="challenge-actions">
          <button type="button" id="modal-import-confirm" class="btn btn-primary">导入</button>
          <button type="button" id="modal-import-cancel" class="btn btn-secondary">取消</button>
        </div>
      </div>
      <div class="form-options" id="modal-cert-auto-row">
        <label class="checkbox-label">
          <input type="checkbox" id="modal-cert-auto-login">
          <span>证书自动登录</span>
        </label>
      </div>
      <div class="challenge-actions">
        <button type="button" id="modal-cert-submit" class="btn btn-primary"></button>
      </div>
    `;
    if (!certStandalone) {
      document.getElementById('modal-cert-auto-row').style.display = 'none';
    } else if (currentGateway) {
      document.getElementById('modal-cert-auto-login').checked = currentGateway.certAutoLogin === true;
    }
    const submitBtn = document.getElementById('modal-cert-submit');
    submitBtn.textContent = certStandalone ? '证书安全连接' : '呈递证书并连接';
    submitBtn.addEventListener('click', (e) => {
      e.preventDefault();
      handleCertModalSubmit();
    });
    document.getElementById('modal-cert-import-toggle').addEventListener('click', () => {
      const panel = document.getElementById('modal-cert-import-panel');
      const list = document.getElementById('modal-cert-list');
      const visible = panel.style.display !== 'none';
      panel.style.display = visible ? 'none' : 'block';
      list.style.display = visible ? '' : 'none';
    });
    document.getElementById('modal-import-cancel').addEventListener('click', () => {
      document.getElementById('modal-cert-import-panel').style.display = 'none';
      document.getElementById('modal-cert-list').style.display = '';
      document.getElementById('modal-import-path').value = '';
      document.getElementById('modal-import-alias').value = '';
      document.getElementById('modal-import-pwd').value = '';
    });
    document.getElementById('modal-import-browse').addEventListener('click', async () => {
      try {
        const path = await api.pickCertFile();
        if (path) {
          document.getElementById('modal-import-path').value = path;
        } else {
          modalAlert('未选择证书文件', 'info');
        }
      } catch (err) {
        modalAlert((err && err.message) || '无法打开文件选择对话框，请手动输入路径', 'error');
      }
    });
    document.getElementById('modal-import-confirm').addEventListener('click', async () => {
      const path = document.getElementById('modal-import-path').value.trim();
      if (!path) {
        modalAlert('请选择证书文件', 'error');
        return;
      }
      const confirmBtn = document.getElementById('modal-import-confirm');
      confirmBtn.disabled = true;
      confirmBtn.textContent = '正在导入...';
      try {
        const info = await api.importCert(
          path,
          document.getElementById('modal-import-alias').value.trim(),
          document.getElementById('modal-import-pwd').value
        );
        document.getElementById('modal-import-cancel').click();
        selectedCertId = info.id || '';
        await loadCertificates();
        modalAlert(`证书「${info.name || info.id}」导入成功`, 'info');
      } catch (err) {
        modalAlert((err && err.message) || '导入证书失败', 'error');
      } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = '导入';
      }
    });
    loadCertificates();
  }

  // loadCertificates renders the certificate list into the modal container.
  async function loadCertificates() {
    const listEl = document.getElementById('modal-cert-list');
    if (!listEl) return;
    listEl.innerHTML = '<p class="cert-empty">正在检测证书...</p>';
    try {
      const list = await api.listCerts(0);
      certs = Array.isArray(list) ? list : [];
    } catch (err) {
      certs = [];
      listEl.innerHTML = `<p class="cert-empty">${escapeHtml(err.message || '读取证书列表失败')}</p>`;
      return;
    }

    if (certs.length === 0) {
      listEl.innerHTML = '<p class="cert-empty">未找到已导入的证书。点击「导入证书」添加 .p12/.pfx 文件。</p>';
      return;
    }

    // A remembered certificate that is no longer in the store must not silently
    // become another identity: clear the selection and let the user choose again.
    const remembered = rememberedCertId(selectedCertId);
    const missing = remembered && !certs.some(c => c.id === remembered);
    selectedCertId = missing ? '' : (remembered || certs[0].id);

    listEl.innerHTML = '';
    if (missing) {
      const notice = document.createElement('p');
      notice.className = 'cert-empty';
      notice.textContent = '上次使用的证书不可用，请重新选择';
      listEl.appendChild(notice);
    }
    certs.forEach(cert => {
      const item = document.createElement('div');
      item.className = 'cert-item' + (cert.isExpired ? ' cert-item-expired' : '') +
        (cert.id === selectedCertId ? ' is-selected' : '');
      item.dataset.id = cert.id;

      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = 'cert-choice';
      radio.checked = cert.id === selectedCertId;
      radio.addEventListener('change', () => {
        selectedCertId = cert.id;
        listEl.querySelectorAll('.cert-item').forEach(el => {
          el.classList.toggle('is-selected', el.dataset.id === cert.id);
        });
      });
      item.appendChild(radio);

      const main = document.createElement('div');
      main.className = 'cert-main';
      main.innerHTML =
        `<div class="cert-name">${escapeHtml(cert.name || cert.id)}` +
        (cert.isExpired ? '<span class="cert-badge-expired">已过期</span>' : '') +
        `</div>` +
        `<div class="cert-meta">颁发者：${escapeHtml(cert.issuer || '-')}</div>` +
        `<div class="cert-meta">有效期：${escapeHtml(cert.validFrom || '-')} 到 ${escapeHtml(cert.validTo || '-')}</div>`;
      item.appendChild(main);

      if (cert.source === 0) {
        const del = document.createElement('button');
        del.type = 'button';
        del.className = 'cert-delete-btn';
        del.textContent = '删除';
        del.addEventListener('click', async (e) => {
          e.stopPropagation();
          if (!confirm(`确定删除证书「${cert.name || cert.id}」吗？`)) return;
          try {
            await api.deleteCert(cert.id);
            modalAlert('证书已删除', 'info');
          } catch (err) {
            modalAlert(err.message || '删除证书失败', 'error');
          }
          await loadCertificates();
        });
        item.appendChild(del);
      }

      item.addEventListener('click', () => {
        radio.checked = true;
        radio.dispatchEvent(new Event('change'));
      });

      listEl.appendChild(item);
    });
  }

  // handleCertModalSubmit presents the chosen certificate. In chain mode the
  // challenged session lives in the backend; in standalone mode this is a
  // fresh certificate login. Either way the gateway decides the next hop.
  async function handleCertModalSubmit() {
    const gwId = gatewaySelect.value;
    const submitBtn = document.getElementById('modal-cert-submit');
    if (!gwId) {
      modalAlert('请选择网关节点', 'error');
      return;
    }
    if (!selectedCertId) {
      modalAlert('请先选择一张证书', 'error');
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = '正在连接...';
    setConnectingState(true);
    try {
      let res;
      if (certStandalone) {
        const autoEl = document.getElementById('modal-cert-auto-login');
        const auto = autoEl ? autoEl.checked : false;
        res = await api.loginWithCert(gwId, 0, selectedCertId, '', auto);
      } else {
        res = await api.submitCertFactor(gwId, 0, selectedCertId, '');
      }
      closeChallengeModal();
      showConnectedView(res);
      return;
    } catch (err) {
      setConnectingState(false);
      if (err && (err.code === 'cert_expired' || err.code === 'cert_invalid' ||
                  err.code === 'cert_revoked' || err.code === 'cert_signature' ||
                  err.code === 'cert_unavailable')) {
        // The certificate itself was rejected; the challenge stays alive.
        // Keep the modal open so the user can pick another certificate.
        modalAlert(friendlyCertError(err.code) || (err.message || '证书认证失败'), 'error');
        loadCertificates();
      } else {
        dispatchAuthError(err);
      }
    } finally {
      if (submitBtn.isConnected) {
        submitBtn.disabled = false;
        submitBtn.textContent = certStandalone ? '证书安全连接' : '呈递证书并连接';
      }
    }
  }

  // Restore the gateway's remembered certificate. With the fixed form there
  // are no tabs to switch: the remembered certificate preselects inside the
  // certificate modal, and every login starts from the password form — the
  // gateway's challenges drive the rest.
  function restoreAuthPreferences() {
    if (!currentGateway) return;
    // certType 1 is the system certificate store, which this client no longer
    // supports. Both login paths submit source 0, so leaving the selection in
    // place would fail later as a plain "certificate not found".
    if (currentGateway.certType === 1 && currentGateway.selectedCertId) {
      showLoginAlert('此网关上次使用的是系统证书库中的证书，当前版本已不再支持系统证书库。请点击「使用客户端证书直接登录」，在弹窗中导入 .p12/.pfx 文件后重新选择。', 'info');
      currentGateway.selectedCertId = '';
    }
    if (currentGateway.selectedCertId) {
      selectedCertId = currentGateway.selectedCertId;
    }
  }

  loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    handleLogin();
  });
  voluntaryChangePwdLink?.addEventListener('click', (e) => {
    e.preventDefault();
    const gwId = gatewaySelect.value;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (!gwId || !username || !password) {
      showLoginAlert('请先选择网关并输入账号与当前密码', 'error');
      return;
    }
    if (!confirm('当前密码有效（未过期），是否确认修改密码？')) {
      return;
    }
    hideLoginAlert();
    openChallengeModal('pwd-change', { voluntary: true });
  });

  // 证书登录入口（原厂 Opt_Cert）：与口令登录平级的独立起点，身份完全由
  // mTLS 证书证明，不经过口令步；网关若还要求短信等因子，入口之后走模态。
  certLoginBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    if (!gatewaySelect.value) {
      showLoginAlert('请选择网关节点', 'error');
      return;
    }
    hideLoginAlert();
    openChallengeModal('cert', { standalone: true });
  });

  connectedChangePwdBtn?.addEventListener('click', async (e) => {
    e.preventDefault();
    if (!confirm('当前处于正常连接状态，是否确认修改密码？\n确认后将断开当前连接并进入修改密码界面。')) {
      return;
    }
    try {
      await api.logout();
    } catch (_) {}
    showLoginView();
    openChallengeModal('pwd-change', { voluntary: true });
  });

  connectBtn.addEventListener('click', (e) => {
    e.preventDefault();
    handleLogin();
  });

  function setConnectingState(connecting) {
    if (connecting) {
      connectBtn.disabled = true;
      connectSpinner.style.display = 'inline-block';
      connectBtnText.textContent = '正在连接网关...';
    } else {
      connectBtn.disabled = false;
      connectSpinner.style.display = 'none';
      connectBtnText.textContent = '🔑 口令登录';
    }
  }

  function showLoginAlert(msg, type) {
    loginAlert.textContent = cleanErrorMessage(msg);
    loginAlert.className = `alert-box alert-${type}`;
    loginAlert.style.display = 'block';
  }

  function hideLoginAlert() {
    loginAlert.style.display = 'none';
  }

  // Switch to Connected View
  function showConnectedView(info) {
    isConnected = true;
    viewLogin.style.display = 'none';
    viewConnected.style.display = 'flex';
    api.setWindowSize('connected');

    if (currentGateway) {
      connectedGwName.textContent = `${currentGateway.name} (${currentGateway.ip}:${currentGateway.port})`;
    }
    sessionUserVal.textContent = (info && info.username) || usernameInput.value.trim() || '-';
    if (info) {
      sessionIdVal.textContent = info.sessionId || '-';
      sessionIpVal.textContent = info.loginAddress || (currentGateway ? `${currentGateway.ip}:${currentGateway.port}` : '-');
      renderResources(info.resources || [], info.ipsecResources || []);
      // Certificate sessions have no password to change; hide the shortcut.
      if (connectedChangePwdBtn) {
        connectedChangePwdBtn.style.display = info.authType === 'certificate' ? 'none' : '';
      }
      setResourceState(info.resourceState || 'ready', info.resourceError || '');
    }
    startResourcePolling();
    startStatusPolling();
  }

  // setResourceState drives the "loading / ready / failed" affordances in the
  // resource card. A failed fetch keeps the session connected and offers a
  // retry instead of forcing the user back to the login form.
  function setResourceState(state, message) {
    if (resLoadingBadge) {
      resLoadingBadge.style.display = state === 'loading' ? '' : 'none';
    }
    if (refreshResourcesBtn) {
      refreshResourcesBtn.style.display = state === 'error' ? '' : 'none';
    }
    if (resourceErrorBanner) {
      resourceErrorBanner.style.display = state === 'error' ? 'flex' : 'none';
    }
    if (resourceErrorText && state === 'error') {
      resourceErrorText.textContent = message || '网关未在超时时间内返回资源列表。';
    }
    if (state === 'loading') {
      resourcesTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">
            <span class="mini-spinner" style="display:inline-block;vertical-align:middle;margin-right:8px;"></span>
            正在从网关拉取受保护的内网资源，请稍候...
          </td>
        </tr>
      `;
    } else if (state === 'error' && (!resourcesTbody.children.length || resCount.textContent === '0')) {
      resourcesTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">资源列表获取失败，VPN 已连接。请点击「重新拉取资源」重试。</td>
        </tr>
      `;
    }
  }

  // Resource polling: while loading, poll the status endpoint until the
  // background fetch finishes or fails.
  let resourcePollTimer = null;
  let statusPollTimer = null;

  function startResourcePolling() {
    stopResourcePolling();
    let attempts = 0;
    resourcePollTimer = setInterval(async () => {
      attempts++;
      try {
        const st = await api.getStatus();
        updateIPsecStatus(st);
        if (st && st.status === 'Disconnected') {
          stopResourcePolling();
          showLoginView();
          return;
        }
        if (!st) {
          return;
        }
        const state = st.resourceState || 'ready';
        if (state === 'loading') {
          setResourceState('loading', '');
          return;
        }
        stopResourcePolling();
        setResourceState(state, st.resourceError || '');
        if (state === 'ready') {
          renderResources(st.resources || [], st.ipsecResources || []);
        }
      } catch (_) {
        if (attempts > 40) stopResourcePolling();
      }
    }, 1000);
  }

  function stopResourcePolling() {
    if (resourcePollTimer) {
      clearInterval(resourcePollTimer);
      resourcePollTimer = null;
    }
  }

  function startStatusPolling() {
    stopStatusPolling();
    let disconnectedCount = 0;
    statusPollTimer = setInterval(async () => {
      if (!isConnected) {
        stopStatusPolling();
        return;
      }
      try {
        const st = await api.getStatus();
        updateIPsecStatus(st);
        if (st && st.status === 'Disconnected') {
          disconnectedCount++;
          if (disconnectedCount >= 2) {
            showLoginView();
          }
        } else {
          disconnectedCount = 0;
        }
      } catch (_) {}
    }, 1500);
  }

  function stopStatusPolling() {
    if (statusPollTimer) {
      clearInterval(statusPollTimer);
      statusPollTimer = null;
    }
  }

  // Reactive push hook called from Go runtime (e.g. system tray "Disconnect" click)
  window.onVPNDisconnected = function() {
    if (isConnected) {
      showLoginView();
    }
  };

  refreshResourcesBtn?.addEventListener('click', async () => {
    refreshResourcesBtn.disabled = true;
    refreshResourcesBtn.textContent = '正在重新拉取...';
    setResourceState('loading', '');
    try {
      const res = await api.refreshResources();
      setResourceState('ready', '');
      renderResources((res && res.resources) || []);
    } catch (err) {
      setResourceState('error', (err && err.message) || '重新拉取资源失败');
    } finally {
      refreshResourcesBtn.disabled = false;
      refreshResourcesBtn.textContent = '🔄 重新拉取资源';
    }
  });

  // Switch to Login View
  function showLoginView() {
    isConnected = false;
    stopResourcePolling();
    stopStatusPolling();
    viewConnected.style.display = 'none';
    viewLogin.style.display = 'flex';
    setConnectingState(false);
    closeChallengeModal();
    modalVerifycode = '';
    lastIPsec = [];
    renderResources([]);
    setResourceState('ready', '');
    api.setWindowSize('login');
  }

  // Disconnect Handler
  disconnectBtn.addEventListener('click', async () => {
    try {
      await api.logout();
    } finally {
      showLoginView();
    }
  });

  // Render Protected Resources Table
  // updateIPsecStatus renders the NC/IPsec state line. The tunnel is brought up
  // by the backend (WSL + strongSwan); this only reports what it did.
  function updateIPsecStatus(st) {
    const el = document.getElementById('ipsec-status');
    if (!el) return;
    const ipsec = (st && st.ipsecResources) || [];
    if (!ipsec.length) {
      el.style.display = 'none';
      return;
    }
    lastIPsecState = (st && st.ipsecState) || '';
    lastIPsecError = (st && st.ipsecError) || '';
    const tunnels = ipsec.flatMap(p => p.tunnels || []);
    const names = tunnels.map(t => t.name).filter(Boolean).join('、') || 'NC';
    let msg;
    if (lastIPsecState === 'up') {
      msg = `IPsec 隧道已建立：${names}。Windows 应用若无法访问内网，请以管理员权限运行客户端（自动添加路由），或手动添加路由。`;
    } else if (lastIPsecState === 'starting') {
      msg = `正在通过 WSL/strongSwan 建立 IPsec 隧道（${names}）...`;
    } else if (lastIPsecState === 'error') {
      msg = `IPsec 隧道建立失败：${lastIPsecError || '未知错误'}`;
    } else if (lastIPsecState === 'unavailable') {
      msg = `IPsec 数据面不可用：${lastIPsecError || 'WSL 发行版未安装'}`;
    } else {
      msg = `网关下发了 IPsec 隧道（${names}），等待建立。`;
    }
    el.textContent = msg;
    el.className = 'ipsec-status ipsec-' + (lastIPsecState || 'pending');
    el.style.display = 'block';
  }

  function renderResources(resources, ipsec) {
    if (ipsec) lastIPsec = ipsec;
    resCount.textContent = resources.length;
    resourcesTbody.innerHTML = '';

    if (!resources || resources.length === 0) {
      // An NC/IPsec profile produces no local proxy: the SSL tunnel path this
      // client implements cannot carry it. Say so instead of "no resources".
      const tunnels = (lastIPsec || []).flatMap(p => (p.tunnels || []).map(t => ({
        name: t.name,
        routes: (t.routes || []).join('、'),
      })));
      if (tunnels.length) {
        const rows = tunnels.map(t =>
          `<li><strong>${escapeHtml(t.name)}</strong>${t.routes ? '：' + escapeHtml(t.routes) : ''}</li>`
        ).join('');
        const stateText = lastIPsecState === 'up'
          ? 'IPsec 隧道已建立，内网网段通过 WSL/strongSwan 承载（状态见上方）。本表只列出 TCP/UDP 代理资源。'
          : '网关为该账号下发的是 <strong>IPsec 全路由（NC 资源）</strong>，没有 TCP/UDP 代理资源。';
        resourcesTbody.innerHTML = `
          <tr>
            <td colspan="6" class="empty-state" style="text-align:left; line-height:1.8;">
              ${stateText}<br>
              已下发的隧道：
              <ul style="margin:8px 0 0 18px;">${rows}</ul>
            </td>
          </tr>
        `;
        return;
      }
      resourcesTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">VPN 隧道中未发现受保护的 TCP 映射资源。</td>
        </tr>
      `;
      return;
    }

    resources.forEach(r => {
      const parts = (r.localProxy || '').split(':');
      const localPort = parts[parts.length - 1] || '';
      let accessUrl = r.accessUrl;
      if (!accessUrl) {
        const isHttps = r.remotePort === '443' || r.remotePort === '8443' || (r.name && (r.name.toLowerCase().includes('https') || r.name.includes('堡垒')));
        accessUrl = (isHttps ? 'https://127.0.0.1:' : 'http://127.0.0.1:') + localPort;
      }

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${escapeHtml(r.name)}</strong></td>
        <td><span class="algo-pill">${escapeHtml(r.protocol)}</span></td>
        <td><code>${escapeHtml(r.remoteIp)}:${escapeHtml(r.remotePort)}</code></td>
        <td>
          <a href="${escapeHtml(accessUrl)}" class="proxy-link open-url-btn" data-url="${escapeHtml(accessUrl)}" title="点击在浏览器中打开">${escapeHtml(r.localProxy)}</a>
          <div class="proxy-subtext">${escapeHtml(accessUrl)}</div>
        </td>
        <td><span class="status-pill status-connected"><span class="status-dot"></span>${escapeHtml(r.status)}</span></td>
        <td>
          <div class="action-btn-cell">
            <button class="btn btn-primary btn-sm open-url-btn" data-url="${escapeHtml(accessUrl)}">🌐 在浏览器打开</button>
            <button class="btn btn-secondary btn-sm copy-proxy-btn" data-url="${escapeHtml(accessUrl)}">📋 复制</button>
          </div>
        </td>
      `;
      resourcesTbody.appendChild(tr);
    });

    resourcesTbody.querySelectorAll('.open-url-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const url = btn.dataset.url;
        if (url) api.openURL(url);
      });
    });

    resourcesTbody.querySelectorAll('.copy-proxy-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const url = btn.dataset.url;
        navigator.clipboard.writeText(url);
        const originalText = btn.textContent;
        btn.textContent = '已复制!';
        setTimeout(() => { btn.textContent = originalText; }, 1500);
      });
    });
  }

  // Live Logs Poller
  async function pollLogs() {
    try {
      const logs = await api.getLogs();
      if (logs && logs.length > 0) {
        logConsole.innerHTML = '';
        logs.forEach(line => {
          const div = document.createElement('div');
          div.className = 'log-line';
          if (line.includes('[SUCCESS]')) div.className += ' log-success';
          else if (line.includes('[WARN]')) div.className += ' log-warn';
          else if (line.includes('[ERROR]')) div.className += ' log-error';
          else if (line.includes('[DEBUG]')) div.className += ' log-debug';
          else div.className += ' log-info';
          div.textContent = line;
          logConsole.appendChild(div);
        });
        logConsole.scrollTop = logConsole.scrollHeight;
      }
    } catch (_) {}
  }

  // App Initialization
  async function loadAppConfig() {
    try {
      config = await api.getConfig();
      populateGateways(config.gateways, config.lastUseGateway);
      rememberPwdCheckbox.checked = config.remember !== false;
      if (config.appVersion) {
        document.querySelectorAll('.version-badge').forEach(el => {
          el.textContent = config.appVersion;
        });
        document.querySelectorAll('.app-version-text').forEach(el => {
          el.textContent = config.appVersion;
        });
      }

      // Check current connection status in case app was already connected
      const st = await api.getStatus();
      if (st && st.status === 'Connected') {
        showConnectedView(st);
      } else if (settingsModal.style.display !== 'flex') {
        showLoginView();
      }
    } catch (err) {
      console.error('Failed to load app config:', err);
      if (settingsModal.style.display !== 'flex') {
        showLoginView();
      }
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Boot
  loadAppConfig().then(() => {
    logPollTimer = setInterval(pollLogs, 1500);
    pollLogs();
  });
})();
