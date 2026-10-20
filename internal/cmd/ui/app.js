// V5VPN Client Frontend Controller
(function() {
  // Application State
  let config = null;
  let currentGateway = null;
  let isConnected = false;
  let logPollTimer = null;
  let authMode = 'password';       // 'password' | 'cert'
  let selectedCertId = '';
  let certs = [];

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
  const passwordChangeHint = document.querySelector('.password-change-hint');
  const voluntaryChangePwdLink = document.getElementById('voluntary-change-pwd-link');
  const newPasswordInput = document.getElementById('new-password-input');
  const confirmPasswordInput = document.getElementById('confirm-password-input');
  const changePasswordBtn = document.getElementById('change-password-btn');
  const cancelChangePasswordBtn = document.getElementById('cancel-change-password-btn');

  // DOM Elements - Authentication Tabs and Certificate Panel
  const passwordPanel = document.getElementById('password-panel');
  const certPanel = document.getElementById('cert-panel');
  const authTabs = Array.from(document.querySelectorAll('.auth-tab'));
  const certList = document.getElementById('cert-list');
  const certRefreshBtn = document.getElementById('cert-refresh-btn');
  const importCertBtn = document.getElementById('import-cert-btn');
  const importCertPanel = document.getElementById('import-cert-panel');
  const importCertPath = document.getElementById('import-cert-path');
  const importCertAlias = document.getElementById('import-cert-alias');
  const importCertPwd = document.getElementById('import-cert-pwd');
  const importCertConfirmBtn = document.getElementById('import-cert-confirm-btn');
  const importCertCancelBtn = document.getElementById('import-cert-cancel-btn');
  const browseCertBtn = document.getElementById('browse-cert-btn');
  const certAutoLoginCheckbox = document.getElementById('cert-auto-login-checkbox');

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
    if (config.gateways.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="5" class="empty-state" style="padding:24px; text-align:center; color:var(--text-dim);">暂无网关配置，请在下方添加</td>`;
      gatewaysTbody.appendChild(tr);
      return;
    }
    config.gateways.forEach(gw => {
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

  // Login Form Submission
  async function handleLogin() {
    if (authMode === 'cert') {
      await handleCertLogin();
      return;
    }
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
    if (err && err.code) {
      const certMsg = friendlyCertError(err.code);
      if (certMsg) return certMsg;
    }
    return (err && err.message) || '未知错误';
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

  function showPasswordChangePanel(isVoluntary = false) {
    if (passwordChangeHint) {
      if (isVoluntary) {
        passwordChangeHint.textContent = '您已确认修改密码，请在下方设置新密码。修改成功后将自动使用新密码连接。';
      } else {
        passwordChangeHint.textContent = '网关要求先修改已过期的登录密码。修改成功后会用新密码继续连接。';
      }
    }
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

  // ==================== 证书登录 ====================
  function setAuthMode(mode) {
    authMode = mode === 'cert' ? 'cert' : 'password';
    authTabs.forEach(tab => {
      const active = tab.dataset.mode === authMode;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    passwordPanel.style.display = authMode === 'password' ? '' : 'none';
    certPanel.style.display = authMode === 'cert' ? '' : 'none';
    hidePasswordChangePanel();
    hideLoginAlert();
    updateConnectButtonLabel();
    if (authMode === 'cert') {
      loadCertificates();
    }
  }

  function updateConnectButtonLabel() {
    if (connectBtn.disabled) return;
    connectBtnText.textContent = authMode === 'cert' ? '证书安全连接' : '立即连接';
  }

  authTabs.forEach(tab => {
    tab.addEventListener('click', () => setAuthMode(tab.dataset.mode));
  });

  async function loadCertificates() {
    certList.innerHTML = '<p class="cert-empty">正在检测证书...</p>';
    try {
      const list = await api.listCerts(0);
      certs = Array.isArray(list) ? list : [];
    } catch (err) {
      certs = [];
      certList.innerHTML = `<p class="cert-empty">${escapeHtml(err.message || '读取证书列表失败')}</p>`;
      return;
    }

    if (certs.length === 0) {
      certList.innerHTML = '<p class="cert-empty">未找到已导入的证书。点击「导入证书」添加 .p12/.pfx 文件。</p>';
      return;
    }

    // Keep the selection stable across refreshes, else preselect the first.
    if (!certs.some(c => c.id === selectedCertId)) {
      selectedCertId = certs[0].id;
    }

    certList.innerHTML = '';
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
        certList.querySelectorAll('.cert-item').forEach(el => {
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
            showLoginAlert('证书已删除', 'info');
          } catch (err) {
            showLoginAlert(err.message || '删除证书失败', 'error');
          }
          await loadCertificates();
        });
        item.appendChild(del);
      }

      item.addEventListener('click', () => {
        radio.checked = true;
        radio.dispatchEvent(new Event('change'));
      });

      certList.appendChild(item);
    });
  }

  async function handleCertLogin() {
    const gwId = gatewaySelect.value;
    const verifycode = verifycodeInput.value.trim();
    const auto = certAutoLoginCheckbox.checked;

    if (!gwId) {
      showLoginAlert('请选择网关节点', 'error');
      return;
    }
    if (!selectedCertId) {
      showLoginAlert('请先选择一张证书', 'error');
      return;
    }

    hideLoginAlert();
    setConnectingState(true);
    try {
      const res = await api.loginWithCert(gwId, 0, selectedCertId, verifycode, auto);
      showConnectedView(res);
    } catch (err) {
      showLoginAlert(friendlyLoginError(err), 'error');
      setConnectingState(false);
      if (err && (err.code === 'cert_expired' || err.code === 'cert_invalid' || err.code === 'cert_revoked')) {
        loadCertificates();
      }
    }
  }

  certRefreshBtn.addEventListener('click', () => loadCertificates());

  importCertBtn.addEventListener('click', () => {
    const visible = importCertPanel.style.display !== 'none';
    importCertPanel.style.display = visible ? 'none' : 'block';
    certList.style.display = visible ? '' : 'none';
  });

  importCertCancelBtn.addEventListener('click', () => {
    importCertPanel.style.display = 'none';
    certList.style.display = '';
    importCertPath.value = '';
    importCertAlias.value = '';
    importCertPwd.value = '';
  });

  browseCertBtn.addEventListener('click', async () => {
    try {
      const path = await api.pickCertFile();
      if (path) {
        importCertPath.value = path;
      } else {
        showLoginAlert('未选择证书文件', 'info');
      }
    } catch (err) {
      showLoginAlert((err && err.message) || '无法打开文件选择对话框，请手动输入路径', 'error');
    }
  });

  importCertConfirmBtn.addEventListener('click', async () => {
    const path = importCertPath.value.trim();
    if (!path) {
      showLoginAlert('请选择证书文件', 'error');
      return;
    }
    importCertConfirmBtn.disabled = true;
    importCertConfirmBtn.textContent = '正在导入...';
    try {
      const info = await api.importCert(path, importCertAlias.value.trim(), importCertPwd.value);
      importCertCancelBtn.click();
      selectedCertId = info.id || '';
      await loadCertificates();
      showLoginAlert(`证书「${info.name || info.id}」导入成功`, 'info');
    } catch (err) {
      showLoginAlert((err && err.message) || '导入证书失败', 'error');
    } finally {
      importCertConfirmBtn.disabled = false;
      importCertConfirmBtn.textContent = '导入';
    }
  });

  // Restore the gateway's remembered authentication mode and certificate.
  function restoreAuthPreferences() {
    if (!currentGateway) {
      setAuthMode('password');
      return;
    }
    if (currentGateway.authType === 1) {
      selectedCertId = currentGateway.selectedCertId || '';
      certAutoLoginCheckbox.checked = currentGateway.certAutoLogin === true;
      setAuthMode('cert');
    } else {
      setAuthMode('password');
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
    showPasswordChangePanel(true);
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
    showPasswordChangePanel(true);
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
      updateConnectButtonLabel();
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
    sessionUserVal.textContent = (info && info.username) || usernameInput.value.trim() || '-';
    if (info) {
      sessionIdVal.textContent = info.sessionId || '-';
      sessionIpVal.textContent = info.loginAddress || (currentGateway ? `${currentGateway.ip}:${currentGateway.port}` : '-');
      renderResources(info.resources || []);
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
          renderResources(st.resources || []);
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
