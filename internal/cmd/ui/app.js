// V5VPN Client Frontend Controller
(function() {
  // Application State
  let config = null;
  let currentGateway = null;
  let isConnected = false;
  let logPollTimer = null;

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
  const verifycodeGroup = document.getElementById('verifycode-group');
  const verifycodeInput = document.getElementById('verifycode-input');
  const rememberPwdCheckbox = document.getElementById('remember-pwd-checkbox');
  const autoLoginCheckbox = document.getElementById('auto-login-checkbox');
  const connectBtn = document.getElementById('connect-btn');
  const connectBtnText = document.getElementById('connect-btn-text');
  const connectSpinner = connectBtn.querySelector('.btn-spinner');
  const passwordChangePanel = document.getElementById('password-change-panel');
  const newPasswordInput = document.getElementById('new-password-input');
  const confirmPasswordInput = document.getElementById('confirm-password-input');
  const changePasswordBtn = document.getElementById('change-password-btn');
  const cancelChangePasswordBtn = document.getElementById('cancel-change-password-btn');

  // DOM Elements - Connected View
  const connectedGwName = document.getElementById('connected-gw-name');
  const sessionUserVal = document.getElementById('session-user-val');
  const sessionIpVal = document.getElementById('session-ip-val');
  const sessionIdVal = document.getElementById('session-id-val');
  const resCount = document.getElementById('res-count');
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
  const reloadOrigBtn = document.getElementById('reload-orig-btn');
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
    if (passwordChangePanel) hidePasswordChangePanel();
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
    }
  }

  gatewaySelect.addEventListener('change', onGatewayChanged);

  // Render Gateways Table in Settings Modal
  function renderGatewayManagerTable() {
    if (!config || !config.gateways) return;
    gatewaysTbody.innerHTML = '';
    config.gateways.forEach(gw => {
      const tr = document.createElement('tr');
      const users = (gw.savedAccounts || []).map(a => a.username).join(', ') || '-';
      const isSelected = currentGateway && (currentGateway.id === gw.id || currentGateway.name === gw.name);

      tr.innerHTML = `
        <td><strong>${escapeHtml(gw.name)}</strong> ${isSelected ? '<span class="algo-pill" style="margin-left:4px;">当前选中</span>' : ''}</td>
        <td><code>${escapeHtml(gw.ip)}:${gw.port}</code></td>
        <td><span class="algo-pill">${gw.algo === 1 ? '国密' : '国际标准'}</span></td>
        <td>${escapeHtml(users)}</td>
        <td>
          <div class="action-btn-cell">
            <button class="btn btn-secondary btn-sm select-gw-btn" data-id="${gw.id || gw.name}">使用此网关</button>
            <button class="btn btn-danger btn-sm delete-gw-btn" data-id="${gw.id || gw.name}">删除</button>
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
          await loadAppConfig();
          renderGatewayManagerTable();
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

    await api.saveGateway({ name, ip, port, algo });
    document.getElementById('new-gw-name').value = '';
    document.getElementById('new-gw-ip').value = '';
    await loadAppConfig();
    renderGatewayManagerTable();
  });

  // Reload Local Config from setting.xml
  reloadOrigBtn.addEventListener('click', async () => {
    await loadAppConfig();
    renderGatewayManagerTable();
    alert('已成功从本地 setting.xml 重新同步网关与密码！');
  });

  // Login Form Submission
  async function handleLogin() {
    const gwId = gatewaySelect.value;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const verifycode = verifycodeInput.value.trim();
    const remember = rememberPwdCheckbox.checked;
    const auto = autoLoginCheckbox.checked;

    if (!gwId || !username || !password) {
      showLoginAlert('请输入网关、用户名和登录密码', 'error');
      return;
    }

    hideLoginAlert();
    setConnectingState(true);

    try {
      const res = await api.login(gwId, username, password, verifycode, remember, auto);
      showConnectedView(res);
    } catch (err) {
      const msg = friendlyLoginError(err);
      if (isPasswordExpired(err)) {
        showPasswordChangePanel();
      }
      showLoginAlert(msg, 'error');
      setConnectingState(false);
    }
  }

  function isPasswordExpired(err) {
    // Only the backend's 0x100 challenge may open the change-password panel.
    return !!(err && err.code === 'password_expired');
  }

  function friendlyLoginError(err) {
    if (isPasswordExpired(err)) {
      return '网关提示：账号口令已过期，请在下方设置新密码。';
    }
    if (err && err.code === 'bad_credentials') {
      return '网关提示：用户名或密码错误，请检查输入的账号或密码！';
    }
    return (err && err.message) || '未知错误';
  }

  function showPasswordChangePanel() {
    passwordChangePanel.style.display = 'block';
    connectBtn.style.display = 'none';
    newPasswordInput.focus();
  }

  function hidePasswordChangePanel() {
    passwordChangePanel.style.display = 'none';
    connectBtn.style.display = '';
    newPasswordInput.value = '';
    confirmPasswordInput.value = '';
  }

  async function handleChangePassword() {
    const gwId = gatewaySelect.value;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const newPassword = newPasswordInput.value;
    const verifycode = verifycodeInput.value.trim();
    const remember = rememberPwdCheckbox.checked;
    const auto = autoLoginCheckbox.checked;

    if (!gwId || !username || !password) {
      showLoginAlert('请输入网关、用户名和当前登录密码', 'error');
      return;
    }
    if (!newPassword) {
      showLoginAlert('请输入新密码', 'error');
      return;
    }
    if (newPassword !== confirmPasswordInput.value) {
      showLoginAlert('两次输入的新密码不一致', 'error');
      return;
    }
    if (newPassword === password) {
      showLoginAlert('新密码不能与当前密码相同', 'error');
      return;
    }

    hideLoginAlert();
    changePasswordBtn.disabled = true;
    changePasswordBtn.textContent = '正在修改密码...';
    try {
      const res = await api.changePassword(gwId, username, password, newPassword, verifycode, remember, auto);
      passwordInput.value = newPassword;
      hidePasswordChangePanel();
      showConnectedView(res);
    } catch (err) {
      showLoginAlert(err.message || '修改密码失败', 'error');
    } finally {
      changePasswordBtn.disabled = false;
      changePasswordBtn.textContent = '修改密码并连接';
    }
  }

  loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (passwordChangePanel.style.display !== 'none') {
      handleChangePassword();
      return;
    }
    handleLogin();
  });

  changePasswordBtn.addEventListener('click', (e) => {
    e.preventDefault();
    handleChangePassword();
  });

  cancelChangePasswordBtn.addEventListener('click', () => {
    hidePasswordChangePanel();
    hideLoginAlert();
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
      connectBtnText.textContent = '立即连接';
    }
  }

  function showLoginAlert(msg, type) {
    loginAlert.textContent = msg;
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
    sessionUserVal.textContent = usernameInput.value.trim() || '-';
    if (info) {
      sessionIdVal.textContent = info.sessionId || '-';
      sessionIpVal.textContent = info.loginAddress || (currentGateway ? `${currentGateway.ip}:${currentGateway.port}` : '-');
      renderResources(info.resources || []);
    }
  }

  // Switch to Login View
  function showLoginView() {
    isConnected = false;
    viewConnected.style.display = 'none';
    viewLogin.style.display = 'flex';
    setConnectingState(false);
    renderResources([]);
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
  function renderResources(resources) {
    resCount.textContent = resources.length;
    resourcesTbody.innerHTML = '';

    if (!resources || resources.length === 0) {
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
      } else {
        showLoginView();
      }
    } catch (err) {
      console.error('Failed to load app config:', err);
      showLoginView();
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
