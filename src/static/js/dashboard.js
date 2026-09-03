// ─── State Management ─── 
let currentTab = 'system'; // Global state for active tab
let currentWizardStep = 1;
let pendingConfirmAction = null;
let currentPage = 1;
let perPage = 100;
let totalPages = 1;

async function parseJsonResponse(response) {
  try {
    return await response.json();
  } catch (error) {
    return null;
  }
}

function getResponseErrorMessage(payload, fallbackMessage) {
  if (!payload || typeof payload !== 'object') {
    return fallbackMessage;
  }
  return payload.error || payload.message || fallbackMessage;
}

function setTextIfPresent(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

// ─── Tab Navigation ───
function showHelpToolkit() {
  const toolkitModal = document.getElementById('toolkitModal');
  const toolkitTitle = document.getElementById('toolkitTitle');
  const toolkitContent = document.getElementById('toolkitContent');

  toolkitModal.classList.add('active');

  switch (currentTab) {
    case 'system':
      toolkitTitle.innerText = "System Help";
      toolkitContent.innerHTML = "Here you can view <strong>hardware diagnostics</strong> (CPU/RAM out of 8GB, storage), <strong>interface throughput</strong>, and <strong>service states</strong>.";
      break;
    case 'device-management':
      toolkitTitle.innerText = "Device Management Help";
      toolkitContent.innerHTML = "Here you can track <strong>physical network clients</strong>, view <strong>lease bindings</strong>, and manually trigger <strong>IP-based bandwidth shaping (throttling)</strong>.";
      break;
    case 'traffic-logs':
      toolkitTitle.innerText = "Traffic Logs Help";
      toolkitContent.innerHTML = "This section displays how <strong>decrypted payloads are logged</strong>, their <strong>category classification</strong>, and allows <strong>CSV exporting</strong> of historical network events.";
      break;
    case 'filtering':
      toolkitTitle.innerText = "Content Filtering Help";
      toolkitContent.innerHTML = "This section manages <strong>Natural Language Processing (NLP)</strong> parameters, <strong>entity classification</strong> (Educational, Harmful, etc.), and configuration for <strong>keyword triggers</strong>.";
      break;
    case 'behavioral-control':
      toolkitTitle.innerText = "Behavioral Control Help";
      toolkitContent.innerHTML = "Understand the difference between <strong>Network Request Velocity</strong> (algorithmic parsing of background traffic) and <strong>Physical Scroll Telemetry</strong> (active user doomscrolling). This section also handles <strong>SNI fallback scanning</strong> for encrypted apps.";
      break;
    case 'sni-monitoring':
      toolkitTitle.innerText = "SNI Monitoring Help";
      toolkitContent.innerHTML = "Monitor <strong>encrypted app traffic patterns</strong> via Server Name Indication (SNI). View <strong>scroll velocity rates</strong>, <strong>domain request counts</strong>, and <strong>client-level telemetry</strong> for apps that block full SSL inspection.";
      break;
    case 'settings':
      toolkitTitle.innerText = "Setup Help";
      toolkitContent.innerHTML = "Manage system <strong>backups</strong>, perform <strong>configuration restorations</strong>, and configure <strong>edge interface bindings</strong>.";
      break;
    default:
      toolkitTitle.innerText = "Help Toolkit";
      toolkitContent.innerHTML = "Context-aware help is available here depending on your active tab.";
  }
}

function switchTab(tabId, triggerElement = null) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

  document.getElementById(`tab-${tabId}`)?.classList.add('active');
  const navItem = triggerElement
    || window.event?.currentTarget
    || Array.from(document.querySelectorAll('.nav-item')).find(el => el.getAttribute('onclick')?.includes(`'${tabId}'`));
  navItem?.classList.add('active');

  currentTab = tabId;

  if (tabId === 'system') {
    loadPinnedDisplay();
    loadCircuitBreakerState();
  }
  if (tabId === 'device-management') {
    loadThrottledDevices();
    loadActiveDevices();
    loadLeasedDevices();
  }
  if (tabId === 'traffic-logs') {
    loadTrafficLogs();
  }
  if (tabId === 'settings') loadUnifiedConfig();
  if (tabId === 'filtering') {
    loadCategoryHints();
    loadKeywords();
  }
  if (tabId === 'traffic-policy') {
    loadTPWhitelist();
    loadTPBypass();
    loadTPPending();
  }
  if (tabId === 'behavioral-control') {
    loadBehavioralSettings();
    loadBehavioralPolicies();
  }
  if (tabId === 'sni-monitoring') {
    // Wait for DOM layout before rendering charts (charts in hidden tabs have zero dimensions)
    requestAnimationFrame(() => {
      setTimeout(() => loadSNIDashboard(), 100);
    });
  }
}

// ─── Device Management ───
window.loadThrottledDevices = async function () {
  const tableBody = document.getElementById('throttled-tbody');

  try {
    const response = await fetch('/api/devices/throttled');
    const data = await response.json();
    const throttledDevices = data.throttled_devices || [];

    if (throttledDevices.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No throttled devices</td></tr>';
      return;
    }

    tableBody.innerHTML = throttledDevices.map(device => {
      const hostname = device.hostname || device.custom_name || 'Unknown Device';
      const ip = device.client_ip || device.ip_address || '—';
      const throttleState = device.throttle_state || 'unknown';
      const throttleStateClass = getThrottleStateClass(throttleState);

      return `
        <tr>
          <td style="font-weight: 500;">${hostname}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${ip}</td>
          <td><span class="category-badge ${throttleStateClass}">${throttleState}</span></td>
          <td>
            <button class="btn-secondary" style="padding: 0.25rem 0.75rem; font-size: 0.85rem;" onclick="releaseThrottle('${ip}')">Release</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    console.error('Error loading throttled devices:', error);
    tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 2rem;">Error loading throttled devices</td></tr>';
  }
};

function getThrottleStateClass(state) {
  const stateMap = {
    'throttled': 'danger',
    'recovering': 'warning',
    'released': 'success'
  };
  return stateMap[state] || 'secondary';
}

async function releaseThrottle(ipAddress) {
  if (!confirm(`Release throttle for ${ipAddress}?`)) {
    return;
  }

  try {
    const response = await fetch('/api/devices/release-throttle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ipAddress })
    });

    if (response.ok) {
      showToast('Throttle released successfully', 'success');
      loadThrottledDevices();
    } else {
      const data = await response.json();
      showToast(data.error || 'Failed to release throttle', 'danger');
    }
  } catch (error) {
    console.error('Error releasing throttle:', error);
    showToast('Error releasing throttle', 'danger');
  }
}

window.loadActiveDevices = async function () {
  const tableBody = document.getElementById('active-tbody');

  try {
    const response = await fetch('/api/devices/active');
    const data = await response.json();
    const devices = data.devices || [];

    if (devices.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No active devices</td></tr>';
      return;
    }

    tableBody.innerHTML = devices.map(device => {
      const hostname = device.hostname || 'Unknown Device';
      const ip = device.ip_address || '—';

      return `
        <tr>
          <td style="font-weight: 500;">${hostname}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${ip}</td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    console.error('Error loading active devices:', error);
    tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">Error loading active devices</td></tr>';
  }
};

window.loadLeasedDevices = async function () {
  const tableBody = document.getElementById('leased-tbody');

  try {
    const response = await fetch('/api/devices');
    const data = await response.json();
    const devices = data.devices || [];

    // Filter to include valid managed LAN network devices
    const leasedDevices = devices.filter(device => {
      const ip = device.ip_address || '';
      return Boolean(ip && !ip.startsWith('127.'));
    });

    if (leasedDevices.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No leased devices</td></tr>';
      return;
    }

    tableBody.innerHTML = leasedDevices.map(device => {
      const policy = device.policy || 'none';
      const stateClass = policy === 'blacklist' ? 'danger' : (policy === 'whitelist' ? 'success' : 'secondary');
      const stateLabel = policy === 'blacklist' ? 'Blacklisted' : (policy === 'whitelist' ? 'Whitelisted' : 'Default');

      return `
        <tr>
          <td style="font-weight: 500;">${device.hostname || device.custom_name || 'Unknown Device'}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${device.ip_address || '—'}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${device.mac_address || '—'}</td>
          <td><span class="category-badge ${stateClass}">${stateLabel}</span></td>
          <td>
            <div class="device-filter-pills">
              <button class="filter-pill whitelist ${policy === 'whitelist' ? 'active' : ''}" onclick="setDeviceFilter('${device.mac_address}', 'whitelist', this)">Whitelist</button>
              <button class="filter-pill blacklist ${policy === 'blacklist' ? 'active' : ''}" onclick="setDeviceFilter('${device.mac_address}', 'blacklist', this)">Blacklist</button>
              <button class="filter-pill none ${policy === 'none' ? 'active' : ''}" onclick="setDeviceFilter('${device.mac_address}', 'none', this)">Default</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    console.error('Error loading leased devices:', error);
    tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 2rem;">Error loading leased devices</td></tr>';
  }
};

window.setDeviceFilter = async function (macAddress, action, buttonElement) {
  try {
    const response = await fetch('/api/devices/policy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac_address: macAddress, policy: action })
    });

    if (response.ok) {
      const data = await response.json();
      if (data.status === 'success') {
        showToast(`Device ${action === 'whitelist' ? 'whitelisted' : action === 'blacklist' ? 'blacklisted' : 'reset to default'} successfully`, 'success');

        // Update UI to reflect the new state
        const row = buttonElement.closest('tr');
        const pills = row.querySelectorAll('.filter-pill');
        pills.forEach(pill => pill.classList.remove('active'));
        buttonElement.classList.add('active');

        // Update status badge
        const statusBadge = row.querySelector('.category-badge');
        if (statusBadge) {
          statusBadge.className = `category-badge ${action === 'blacklist' ? 'danger' : action === 'whitelist' ? 'success' : 'secondary'}`;
          statusBadge.textContent = action === 'blacklist' ? 'Blacklisted' : action === 'whitelist' ? 'Whitelisted' : 'Default';
        }

        loadLeasedDevices(); // Refresh to ensure consistency
      } else {
        showToast('Failed to update device filter: ' + (data.message || 'Unknown error'), 'danger');
      }
    } else {
      showToast('Failed to update device filter', 'danger');
    }
  } catch (error) {
    showToast('Error updating device filter', 'danger');
  }
};

// ─── Active Restraints Registry ───
async function loadRestraintsRegistry() {
  const tableBody = document.getElementById('restraints-tbody');

  try {
    const response = await fetch('/api/restraints/registry');
    const data = await response.json();
    const restraints = Array.isArray(data.restraints) ? data.restraints : [];

    if (restraints.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No active restraints</td></tr>';
      return;
    }

    tableBody.innerHTML = restraints.map(restraint => {
      return `
        <tr>
          <td style="font-weight: 500;">${restraint.hostname || restraint.custom_name || 'Unknown Device'}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${restraint.ip_address || '—'}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${restraint.mac_address || '—'}</td>
          <td><span class="category-badge danger">Blacklisted</span></td>
          <td>
            <button class="btn btn-danger" onclick="releaseRestraint('${restraint.ip_address}')" style="padding: 0.5rem 1rem; font-size: 0.85rem;">Release</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary); padding: 2rem;">Error loading restraints</td></tr>';
  }
}

async function releaseRestraint(ipAddress) {
  if (!confirm(`Release restraint for IP ${ipAddress}?`)) {
    return;
  }

  try {
    const response = await fetch('/api/restraints/release', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ipAddress })
    });

    const data = await response.json();
    if (response.ok) {
      showToast(data.message || 'Restraint released successfully', 'success');
      loadRestraintsRegistry();
    } else {
      showToast(data.error || 'Failed to release restraint', 'danger');
    }
  } catch (error) {
    showToast('Error releasing restraint', 'danger');
  }
}

// ─── Advanced Settings Toggle ───
function toggleAdvancedSettings() {
  const advancedToggle = document.getElementById('advanced-toggle');
  const advancedSettings = document.getElementById('advanced-settings');

  if (advancedToggle.checked) {
    advancedSettings.classList.remove('d-none');
  } else {
    advancedSettings.classList.add('d-none');
  }
}

function switchSettings(section) {
  document.querySelectorAll('.settings-panel').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.tabs .tab').forEach(el => el.classList.remove('active'));
  document.getElementById(`settings-${section}`).classList.remove('hidden');
  window.event?.currentTarget?.classList.add('active');
}

// ─── Mobile Sidebar ─── 
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
}

// ─── API Calls ─── 
async function refreshStats() {
  try {
    const response = await fetch('/api/stats');
    if (!response.ok) {
      throw new Error(`Failed to fetch stats: ${response.status}`);
    }
    const data = await parseJsonResponse(response) || {};
    const systemMetrics = data.system_metrics || {};
    const networkConfig = data.network_config || {};
    const recentRows = Array.isArray(data.recent) ? data.recent : [];
    const counts = Array.isArray(data.counts) ? data.counts : [];

    setTextIfPresent('stat-total', data.total ?? 0);
    setTextIfPresent('stat-flagged', data.flagged ?? 0);
    setTextIfPresent('stat-clients', data.clients ?? 0);
    setTextIfPresent('stat-throttled', data.throttles?.length || 0);

    let html = '';
    counts.forEach(c => {
      const count = c.count ?? 0;
      const category = c.category ?? 'Unknown';
      const percent = data.total > 0 ? Math.round((count / data.total) * 100) : 0;
      html += `
        <div style="text-align: center; padding: 1rem; background: var(--surface); border-radius: 8px;">
          <div style="font-size: 1.5rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem;">${count}</div>
          <div style="font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase;">${category}</div>
          <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">${percent}%</div>
        </div>
      `;
    });
    const categoryBreakdown = document.getElementById('category-breakdown');
    if (categoryBreakdown) {
      categoryBreakdown.innerHTML = html;
    }

    let recentHtml = '';
    recentRows.slice(0, 10).forEach(r => {
      const categoryClass = `category-badge ${String(r.category || 'unclassified').toLowerCase()}`;
      recentHtml += `
        <tr>
          <td>${r.time}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${r.client_ip}</td>
          <td>${r.host}</td>
          <td><span class="${categoryClass}">${r.category}</span></td>
          <td>${r.flagged ? '🚫 Blocked' : '✓'}</td>
        </tr>
      `;
    });
    const recentTableBody = document.getElementById('recent-tbody');
    if (recentTableBody) {
      recentTableBody.innerHTML = recentHtml || '<tr><td colspan="5" class="text-center" style="color: var(--text-secondary); padding: 2rem;">No traffic data yet</td></tr>';
    }

    // Throughput display removed per requirements

    const sysCpu = document.getElementById('sys-cpu');
    if (sysCpu) {
      sysCpu.textContent = `${systemMetrics.cpu_percent ?? 0}%`;
    }

    const sysMemory = document.getElementById('sys-memory');
    if (sysMemory) {
      sysMemory.textContent = `${systemMetrics.memory_percent ?? 0}%`;
    }

    const sysDisk = document.getElementById('sys-disk');
    if (sysDisk) {
      sysDisk.textContent = `${systemMetrics.disk_percent ?? 0}%`;
    }

    // Update service statuses
    const services = data.statuses || {};
    ['mitmproxy', 'dnsmasq'].forEach(svc => {
      const badge = document.getElementById(`status-${svc}`);
      if (badge) {
        const isActive = services[svc] === 'active' || services[svc] === 'running';
        badge.textContent = isActive ? 'Active' : 'Inactive';
        badge.className = `category-badge ${isActive ? 'success' : 'danger'}`;
      }
    });

    // Update network configuration displays if on settings or wizard tab
    if (currentTab === 'settings' || currentTab === 'wizard') {
      syncConfigInputs(['setting-upstream-interface'], networkConfig.upstream_interface);
      syncConfigInputs(['setting-distribution-interface'], networkConfig.distribution_interface);
      syncConfigInputs(['setting-gateway-ip', 'wizard-gateway-ip'], networkConfig.gateway_ip);
      syncConfigInputs(['wizard-dhcp-start'], networkConfig.dhcp_start);
      syncConfigInputs(['wizard-dhcp-end'], networkConfig.dhcp_end);

      const dnsServersEl = document.getElementById('setting-dns-servers');
      if (dnsServersEl && networkConfig.dns_servers) {
        dnsServersEl.value = networkConfig.dns_servers;
      }

      updateInterfaceDropdowns(networkConfig.upstream_interface, networkConfig.distribution_interface);
    }
  } catch (e) {
    showToast('Failed to load statistics', 'error');
  }
}

function getConfigInput(ids) {
  for (const id of ids) {
    const element = document.getElementById(id);
    if (element) {
      return element;
    }
  }
  return null;
}

function syncConfigInputs(ids, value) {
  ids.forEach(id => {
    const element = document.getElementById(id);
    if (!element) {
      return;
    }

    if (element.type === 'checkbox') {
      element.checked = Boolean(value);
    } else {
      element.value = value ?? '';
    }
  });
}

async function loadUnifiedConfig() {
  try {
    const response = await fetch('/api/config');
    if (!response.ok) {
      throw new Error('Failed to fetch configuration');
    }

    const config = await parseJsonResponse(response) || {};

    // Populate network interface dropdowns with available interfaces
    if (config.available_interfaces && Array.isArray(config.available_interfaces)) {
      populateInterfaceDropdowns(config.available_interfaces);
    }

    // Sync filtering settings
    syncConfigInputs(['block-harmful'], config.block_harmful);
    syncConfigInputs(['block-distracting'], config.block_distracting);
    syncConfigInputs(['throttle-enabled'], config.throttle_enabled);

    // Sync network settings
    syncConfigInputs(['upstream-interface'], config.upstream_interface);
    syncConfigInputs(['distribution-interface'], config.distribution_interface);
    syncConfigInputs(['gateway-ip'], config.gateway_ip);
    syncConfigInputs(['dhcp-start'], config.dhcp_start);
    syncConfigInputs(['dhcp-end'], config.dhcp_end);

    // Sync DNS servers
    const dnsServersEl = document.getElementById('dns-servers');
    if (dnsServersEl && config.upstream_dns) {
      dnsServersEl.value = config.upstream_dns;
    }

    // Sync advanced settings
    syncConfigInputs(['nlp-accuracy'], config.nlp_accuracy);
    syncConfigInputs(['nlp-enabled'], config.nlp_enabled);
    syncConfigInputs(['throttle-rate'], config.throttle_rate);
    syncConfigInputs(['throttle-duration'], config.throttle_duration);
    syncConfigInputs(['https-enabled'], config.enable_https);
    syncConfigInputs(['log-retention'], config.log_retention);
    syncConfigInputs(['tfidf-page-threshold'], config.tfidf_classification_threshold);
    syncConfigInputs(['tfidf-url-threshold'], config.tfidf_url_threshold);
    syncConfigInputs(['tfidf-body-threshold'], config.tfidf_body_threshold);

    // Update NLP status label
    const nlpCheck = document.getElementById('nlp-enabled');
    const nlpLabel = document.getElementById('nlp-status-label');
    if (nlpCheck && nlpLabel) {
      const enabled = config.nlp_enabled === true || config.nlp_enabled === 'true';
      nlpCheck.checked = enabled;
      nlpLabel.textContent = enabled ? 'Enabled' : 'Disabled';
      nlpLabel.style.color = enabled ? 'var(--success)' : 'var(--danger)';
    }

    // Update throttle status label
    const throttleCheck = document.getElementById('throttle-enabled');
    const throttleLabel = document.getElementById('throttle-status-label');
    if (throttleCheck && throttleLabel) {
      const enabled = config.throttle_enabled === true || config.throttle_enabled === 'true';
      throttleCheck.checked = enabled;
      throttleLabel.textContent = enabled ? 'Enabled' : 'Disabled';
    }

    // Update network interface dropdowns with actual values
    updateInterfaceDropdowns(config.upstream_interface, config.distribution_interface);

    // Populate pinned domains editor dropdown in Setup tab
    loadPinnedEditor().catch(() => { });

  } catch (error) {
    showToast('Failed to load configuration', 'danger');
  }
}

async function loadConfigToUI() {
  return loadUnifiedConfig();
}

function populateInterfaceDropdowns(interfaces) {
  const upstreamSelect = document.getElementById('upstream-interface');
  const distributionSelect = document.getElementById('distribution-interface');

  if (!upstreamSelect || !distributionSelect) return;

  // Clear existing options
  upstreamSelect.innerHTML = '';
  distributionSelect.innerHTML = '';

  // Add default option
  const defaultOption = document.createElement('option');
  defaultOption.value = '';
  defaultOption.textContent = 'Select interface...';
  upstreamSelect.appendChild(defaultOption.cloneNode(true));
  distributionSelect.appendChild(defaultOption);

  // Add available interfaces
  interfaces.forEach(iface => {
    const upstreamOption = document.createElement('option');
    upstreamOption.value = iface;
    upstreamOption.textContent = iface;
    upstreamSelect.appendChild(upstreamOption);

    const distributionOption = document.createElement('option');
    distributionOption.value = iface;
    distributionOption.textContent = iface;
    distributionSelect.appendChild(distributionOption);
  });
}

function updateInterfaceDropdowns(upstreamIface, distributionIface) {
  // Update upstream interface dropdown
  const upstreamSelect = document.getElementById('upstream-interface');
  if (upstreamSelect) {
    let optionExists = false;
    for (let opt of upstreamSelect.options) {
      if (opt.value === upstreamIface) {
        optionExists = true;
        opt.selected = true;
        break;
      }
    }
    if (!optionExists && upstreamIface) {
      const newOption = document.createElement('option');
      newOption.value = upstreamIface;
      newOption.textContent = upstreamIface;
      newOption.selected = true;
      upstreamSelect.appendChild(newOption);
    }
  }

  // Update distribution interface dropdown
  const distributionSelect = document.getElementById('distribution-interface');
  if (distributionSelect) {
    let optionExists = false;
    for (let opt of distributionSelect.options) {
      if (opt.value === distributionIface) {
        optionExists = true;
        opt.selected = true;
        break;
      }
    }
    if (!optionExists && distributionIface) {
      const newOption = document.createElement('option');
      newOption.value = distributionIface;
      newOption.textContent = distributionIface;
      newOption.selected = true;
      distributionSelect.appendChild(newOption);
    }
  }
}

async function saveUnifiedConfig(e) {
  e.preventDefault();

  const blockHarmfulEl = document.getElementById('block-harmful');
  const blockDistractingEl = document.getElementById('block-distracting');
  const throttleEnabledEl = document.getElementById('throttle-enabled');

  // Network settings
  const upstreamInterfaceEl = document.getElementById('upstream-interface');
  const distributionInterfaceEl = document.getElementById('distribution-interface');
  const gatewayIpEl = document.getElementById('gateway-ip');
  const dhcpStartEl = document.getElementById('dhcp-start');
  const dhcpEndEl = document.getElementById('dhcp-end');
  const dnsServersEl = document.getElementById('dns-servers');

  // Advanced settings
  const nlpAccuracyEl = document.getElementById('nlp-accuracy');
  const nlpEnabledEl = document.getElementById('nlp-enabled');
  const throttleRateEl = document.getElementById('throttle-rate');
  const throttleDurationEl = document.getElementById('throttle-duration');
  const httpsEnabledEl = document.getElementById('https-enabled');
  const logRetentionEl = document.getElementById('log-retention');
  const tfidfPageEl = document.getElementById('tfidf-page-threshold');
  const tfidfUrlEl = document.getElementById('tfidf-url-threshold');
  const tfidfBodyEl = document.getElementById('tfidf-body-threshold');

  const payload = {
    block_harmful: Boolean(blockHarmfulEl?.checked),
    block_distracting: Boolean(blockDistractingEl?.checked),
    throttle_enabled: Boolean(throttleEnabledEl?.checked),
    // Network configuration
    upstream_interface: upstreamInterfaceEl?.value || 'enp0s31f6',
    distribution_interface: distributionInterfaceEl?.value || 'wlp1s0',
    gateway_ip: gatewayIpEl?.value || '172.20.10.1',
    dhcp_start: dhcpStartEl?.value || '172.20.10.10',
    dhcp_end: dhcpEndEl?.value || '172.20.10.50',
    upstream_dns: dnsServersEl?.value || '8.8.8.8\n8.8.4.4',
    // Advanced configuration
    nlp_accuracy: nlpAccuracyEl?.value || 'balanced',
    nlp_enabled: String(Boolean(nlpEnabledEl?.checked)),
    throttle_rate: throttleRateEl?.value || '256',
    throttle_duration: throttleDurationEl?.value || '600',
    enable_https: Boolean(httpsEnabledEl?.checked),
    log_retention: logRetentionEl?.value || '30',
    tfidf_classification_threshold: tfidfPageEl?.value || '0.05',
    tfidf_url_threshold: tfidfUrlEl?.value || '0.3',
    tfidf_body_threshold: tfidfBodyEl?.value || '0.15'
  };

  try {
    const response = await fetch('/api/config/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Server returned HTTP status ${response.status}`);
    }

    const data = await response.json();
    if (data.status === 'success') {
      showToast('Configuration applied and saved!', 'success');
      await loadConfigToUI();
    } else {
      showToast('Save failed: ' + (data.message || 'Unknown error'), 'danger');
    }
  } catch (e) {
    console.error('Configuration save error:', e);
    showToast('Network error: Could not reach backend data layer.', 'danger');
  }
}

async function loadBehavioralSettings() {
  try {
    const response = await fetch('/api/config/behavioral');
    if (!response.ok) return;
    const data = await parseJsonResponse(response) || {};

    const l1 = data.engagement_l1_minutes || 3;
    const l2 = data.engagement_l2_minutes || 6;
    const l3 = data.engagement_l3_minutes || 12;
    const reset = data.engagement_reset_idle || 120;
    const l1Rate = data.engagement_l1_rate || '128kbit';
    const l2Rate = data.engagement_l2_rate || '32kbit';
    const l3Rate = data.engagement_l3_rate || '4kbit';
    const checkInterval = data.engagement_check_interval || 30;
    const minRequests = data.engagement_min_requests || 10;

    // Determine mode
    let mode = 'custom';
    for (const [key, preset] of Object.entries(BEHAVIORAL_PRESETS)) {
      if (preset.l1_minutes == l1 && preset.l2_minutes == l2 &&
        preset.l3_minutes == l3 && preset.l1_rate == l1Rate &&
        preset.l2_rate == l2Rate && preset.l3_rate == l3Rate) {
        mode = key;
        break;
      }
    }
    selectBehavioralMode(mode);

    const elL1 = document.getElementById('adv-engagement-l1');
    const elL2 = document.getElementById('adv-engagement-l2');
    const elL3 = document.getElementById('adv-engagement-l3');
    const elReset = document.getElementById('adv-engagement-reset');
    const elL1Rate = document.getElementById('adv-engagement-l1-rate');
    const elL2Rate = document.getElementById('adv-engagement-l2-rate');
    const elL3Rate = document.getElementById('adv-engagement-l3-rate');
    const elCheckInterval = document.getElementById('adv-engagement-check-interval');
    const elMinRequests = document.getElementById('adv-engagement-min-requests');
    if (elL1) elL1.value = String(l1);
    if (elL2) elL2.value = String(l2);
    if (elL3) elL3.value = String(l3);
    if (elReset) elReset.value = String(reset);
    if (elL1Rate) elL1Rate.value = String(l1Rate);
    if (elL2Rate) elL2Rate.value = String(l2Rate);
    if (elL3Rate) elL3Rate.value = String(l3Rate);
    if (elCheckInterval) elCheckInterval.value = String(checkInterval);
    if (elMinRequests) elMinRequests.value = String(minRequests);

    // Update timeline if in custom mode
    if (mode === 'custom') updateBehavioralTimeline();
  } catch (e) {
    console.error('loadBehavioralSettings:', e);
  }
}

// ─── Behavioral Control (Redesigned) ───

const BEHAVIORAL_PRESETS = {
  relaxed: {
    l1_minutes: 30, l2_minutes: 60, l3_minutes: 90, idle_reset: 1200,
    l1_rate: '256kbit', l2_rate: '64kbit', l3_rate: '8kbit',
    description: 'L1 at 30min (256kbit), L2 at 60min (64kbit), L3 at 90min (8kbit). 20min idle reset.'
  },
  balanced: {
    l1_minutes: 15, l2_minutes: 30, l3_minutes: 45, idle_reset: 900,
    l1_rate: '128kbit', l2_rate: '32kbit', l3_rate: '4kbit',
    description: 'L1 at 15min (128kbit), L2 at 30min (32kbit), L3 at 45min (4kbit). 15min idle reset.'
  },
  strict: {
    l1_minutes: 5, l2_minutes: 10, l3_minutes: 15, idle_reset: 300,
    l1_rate: '64kbit', l2_rate: '16kbit', l3_rate: '2kbit',
    description: 'L1 at 5min (64kbit), L2 at 10min (16kbit), L3 at 15min (2kbit). 5min idle reset.'
  }
};

function selectBehavioralMode(mode) {
  document.querySelectorAll('.mode-card').forEach(el => el.style.borderColor = 'transparent');
  const card = document.getElementById('mode-card-' + mode);
  if (card) {
    card.style.borderColor = 'var(--primary)';
    card.querySelector('input[type="radio"]').checked = true;
  }
  const advSection = document.getElementById('behavioral-advanced');
  if (mode === 'custom') {
    advSection.classList.remove('d-none');
    updateBehavioralTimeline();
  } else {
    advSection.classList.add('d-none');
    const preset = BEHAVIORAL_PRESETS[mode] || BEHAVIORAL_PRESETS.balanced;
    const elL1 = document.getElementById('adv-engagement-l1');
    const elL2 = document.getElementById('adv-engagement-l2');
    const elL3 = document.getElementById('adv-engagement-l3');
    const elL1Rate = document.getElementById('adv-engagement-l1-rate');
    const elL2Rate = document.getElementById('adv-engagement-l2-rate');
    const elL3Rate = document.getElementById('adv-engagement-l3-rate');
    if (elL1) elL1.value = String(preset.l1_minutes);
    if (elL2) elL2.value = String(preset.l2_minutes);
    if (elL3) elL3.value = String(preset.l3_minutes);
    if (elL1Rate) elL1Rate.value = String(preset.l1_rate);
    if (elL2Rate) elL2Rate.value = String(preset.l2_rate);
    if (elL3Rate) elL3Rate.value = String(preset.l3_rate);
  }
}

function updateBehavioralTimeline() {
  // Read current custom values and update the timeline display
  const l1 = document.getElementById('adv-engagement-l1')?.value || '3';
  const l2 = document.getElementById('adv-engagement-l2')?.value || '6';
  const l3 = document.getElementById('adv-engagement-l3')?.value || '12';
  const l1Rate = document.getElementById('adv-engagement-l1-rate')?.value || '128kbit';
  const l2Rate = document.getElementById('adv-engagement-l2-rate')?.value || '32kbit';
  const l3Rate = document.getElementById('adv-engagement-l3-rate')?.value || '4kbit';
  const reset = document.getElementById('adv-engagement-reset')?.value || '120';

  const setText = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
  setText('tl-l1-time', l1 + ' min');
  setText('tl-l2-time', l2 + ' min');
  setText('tl-l3-time', l3 + ' min');
  setText('tl-l1-rate', l1Rate);
  setText('tl-l2-rate', l2Rate);
  setText('tl-l3-rate', l3Rate);

  // Format reset: convert seconds to minutes
  const resetMin = Math.floor(parseInt(reset) / 60);
  setText('tl-reset', (resetMin === 1 ? '1 min idle' : resetMin + ' min idle'));
}

async function saveBehavioralSettings(event) {
  event.preventDefault();
  let mode = 'balanced';
  document.querySelectorAll('.mode-card input[type="radio"]').forEach(el => {
    if (el.checked) mode = el.value;
  });

  let payload = {};
  if (mode === 'custom') {
    payload = {
      engagement_l1_minutes: document.getElementById('adv-engagement-l1')?.value || '3',
      engagement_l2_minutes: document.getElementById('adv-engagement-l2')?.value || '6',
      engagement_l3_minutes: document.getElementById('adv-engagement-l3')?.value || '12',
      engagement_reset_idle: document.getElementById('adv-engagement-reset')?.value || '120',
      engagement_l1_rate: document.getElementById('adv-engagement-l1-rate')?.value || '128kbit',
      engagement_l2_rate: document.getElementById('adv-engagement-l2-rate')?.value || '32kbit',
      engagement_l3_rate: document.getElementById('adv-engagement-l3-rate')?.value || '4kbit',
      engagement_check_interval: document.getElementById('adv-engagement-check-interval')?.value || '30',
      engagement_min_requests: document.getElementById('adv-engagement-min-requests')?.value || '10'
    };
  } else {
    const preset = BEHAVIORAL_PRESETS[mode] || BEHAVIORAL_PRESETS.balanced;
    payload = {
      engagement_l1_minutes: String(preset.l1_minutes),
      engagement_l2_minutes: String(preset.l2_minutes),
      engagement_l3_minutes: String(preset.l3_minutes),
      engagement_reset_idle: String(preset.idle_reset),
      engagement_l1_rate: String(preset.l1_rate),
      engagement_l2_rate: String(preset.l2_rate),
      engagement_l3_rate: String(preset.l3_rate)
    };
  }

  try {
    const resp = await fetch('/api/config/behavioral', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (resp.ok) showToast('Settings saved', 'success');
    else showToast('Failed to save', 'danger');
  } catch (e) {
    showToast('Error saving', 'danger');
  }
}

// ─── Domain Behavior Policies (PFR overrides) ───

async function loadBehavioralPolicies() {
  const tbody = document.getElementById('behavioral-policies-tbody');
  if (!tbody) return;
  try {
    const r = await fetch('/api/behavioral-policies');
    const d = await r.json();
    const policies = d.policies || {};
    const entries = Object.entries(policies);
    if (entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-secondary);padding:2rem;">No domain overrides — using auto profiling</td></tr>';
      return;
    }
    const label = { auto: 'Auto', enforce_doomscroll: 'Enforce Doomscroll', exempt_media: 'Exempt Media' };
    const cls = { auto: 'secondary', enforce_doomscroll: 'danger', exempt_media: 'success' };
    tbody.innerHTML = entries.map(([domain, policy]) => `
      <tr>
        <td style="font-family:monospace;">${domain}</td>
        <td><span class="category-badge ${cls[policy] || 'secondary'}">${label[policy] || policy}</span></td>
        <td style="text-align:right;">
          <a href="#" onclick="setBehavioralPolicy('${domain}','auto');return false;" style="color:var(--danger);">[Revert to Auto]</a>
        </td>
      </tr>
    `).join('');
  } catch (_) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-secondary);">Error loading policies</td></tr>';
  }
}

async function setBehavioralPolicy(domain, policyType) {
  const domainInput = document.getElementById('bp-domain-input');
  const policySelect = document.getElementById('bp-policy-select');
  if (domain === undefined) {
    domain = domainInput?.value?.trim().toLowerCase() || '';
    policyType = policySelect?.value || 'auto';
  }
  if (!domain) { showToast('Enter a domain', 'danger'); return; }
  try {
    const r = await fetch('/api/behavioral-policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, policy_type: policyType })
    });
    const d = await r.json();
    if (r.ok) {
      showToast(`${domain} → ${policyType}`, 'success');
      if (domainInput) domainInput.value = '';
      loadBehavioralPolicies();
    } else {
      showToast(d.error || 'Failed', 'danger');
    }
  } catch (_) {
    showToast('Error setting policy', 'danger');
  }
}

// ─── Password Management ───
async function handlePasswordChange() {
  const current = document.getElementById('pwd-current');
  const newPwd = document.getElementById('pwd-new');
  const confirm = document.getElementById('pwd-confirm');
  const feedback = document.getElementById('pwd-feedback');

  if (!current || !newPwd || !confirm) return;

  if (!newPwd.value || newPwd.value.length < 6) {
    feedback.innerHTML = '<span style="color: var(--danger);">Password must be at least 6 characters</span>';
    return;
  }
  if (newPwd.value !== confirm.value) {
    feedback.innerHTML = '<span style="color: var(--danger);">Passwords do not match</span>';
    return;
  }

  feedback.innerHTML = '<span style="color: var(--text-secondary);">Changing password...</span>';

  try {
    const resp = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_password: current.value,
        new_password: newPwd.value,
        confirm: confirm.value
      })
    });
    const data = await resp.json();

    if (resp.ok) {
      feedback.innerHTML = '<span style="color: var(--success);">Password changed successfully</span>';
      current.value = '';
      newPwd.value = '';
      confirm.value = '';
      setTimeout(() => { feedback.innerHTML = ''; }, 3000);
    } else {
      feedback.innerHTML = '<span style="color: var(--danger);">' + (data.error || 'Failed to change password') + '</span>';
    }
  } catch (err) {
    feedback.innerHTML = '<span style="color: var(--danger);">Connection error</span>';
  }
}

// ─── Keyword Filtering ───
window.loadKeywords = async function () {
  const tableBody = document.getElementById('keywords-table-body');
  if (!tableBody) return;

  try {
    const response = await fetch('/api/keywords');
    const keywords = await response.json();

    if (!keywords || keywords.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No constraints active</td></tr>';
      return;
    }

    tableBody.innerHTML = keywords.map(kw => `
      <tr>
        <td>${kw.keyword}</td>
        <td style="text-align: right;">
          <a href="#" onclick="deleteKeyword(${kw.id}); return false;" style="color: var(--danger);">[Delete]</a>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading keywords:', error);
    tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">Error loading keywords</td></tr>';
  }
};

window.deleteKeyword = async function (keywordId) {
  if (!confirm('Are you sure you want to delete this keyword?')) {
    return;
  }

  try {
    const response = await fetch(`/api/keywords/${keywordId}`, {
      method: 'DELETE'
    });

    if (response.ok) {
      showToast('Keyword deleted successfully', 'success');
      loadKeywords();
    } else {
      const data = await response.json();
      showToast(data.error || 'Failed to delete keyword', 'danger');
    }
  } catch (error) {
    showToast('Error deleting keyword', 'danger');
  }
};

// ─── Category Hints Management ───

// ─── Bypass Domain List ───
async function loadBypassDomains() {
  const tableBody = document.getElementById("bypass-domains-table-body");
  if (!tableBody) return;

  try {
    const response = await fetch("/api/config");
    const config = await response.json();
    const domainsStr = config.custom_bypass_domains || "";
    const domains = domainsStr ? domainsStr.split(",").map(d => d.trim()).filter(Boolean) : [];

    if (domains.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No bypass domains configured</td></tr>';
      return;
    }

    tableBody.innerHTML = domains.map(d => `
      <tr>
        <td style="font-family: monospace;">${d}</td>
        <td style="text-align: right;">
          <a href="#" onclick="removeBypassDomain('${d}'); return false;" style="color: var(--danger);">[Remove]</a>
        </td>
      </tr>
    `).join("");
  } catch (error) {
    showToast("Failed to load bypass domains", "danger");
  }
}

async function addBypassDomain() {
  const input = document.getElementById("bypass-domain-input");
  if (!input) return;

  const domain = input.value.trim().toLowerCase();
  if (!domain) {
    showToast("Enter a domain to bypass", "danger");
    return;
  }

  try {
    const resp = await fetch("/api/config");
    const config = await resp.json();
    const existing = config.custom_bypass_domains || "";
    const domains = existing ? existing.split(",").map(d => d.trim()).filter(Boolean) : [];

    if (domains.includes(domain)) {
      showToast("Domain already in bypass list", "warning");
      return;
    }

    domains.push(domain);

    const saveResp = await fetch("/api/config/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ custom_bypass_domains: domains.join(",") })
    });

    if (saveResp.ok) {
      showToast("Domain added to bypass list", "success");
      input.value = "";
      loadBypassDomains();
    } else {
      showToast("Failed to save bypass list", "danger");
    }
  } catch (error) {
    showToast("Error adding bypass domain", "danger");
  }
}

async function removeBypassDomain(domain) {
  if (!confirm("Remove " + domain + " from the bypass list?")) return;

  try {
    const resp = await fetch("/api/config");
    const config = await resp.json();
    const existing = config.custom_bypass_domains || "";
    const domains = existing ? existing.split(",").map(d => d.trim()).filter(Boolean) : [];
    const filtered = domains.filter(d => d !== domain);

    const saveResp = await fetch("/api/config/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ custom_bypass_domains: filtered.join(",") })
    });

    if (saveResp.ok) {
      showToast("Domain removed from bypass list", "success");
      loadBypassDomains();
    } else {
      showToast("Failed to save bypass list", "danger");
    }
  } catch (error) {
    showToast("Error removing bypass domain", "danger");
  }
}

// ─── Pending Bypass Waitlist (SSL Pinning) ───

async function loadPendingBypasses() {
  const tableBody = document.getElementById("pending-bypass-table-body");
  const table = document.getElementById("pending-bypass-table");
  const empty = document.getElementById("pending-bypass-empty");
  const badge = document.getElementById("pending-bypass-count");
  if (!tableBody) return;

  try {
    const response = await fetch("/api/pending-bypasses");
    const data = await response.json();
    const bypasses = data.pending || [];

    if (badge) {
      badge.textContent = bypasses.length + " pending";
      badge.style.display = bypasses.length > 0 ? "inline-block" : "none";
    }

    if (bypasses.length === 0) {
      if (table) table.style.display = "none";
      if (empty) empty.style.display = "";
      return;
    }

    if (table) table.style.display = "";
    if (empty) empty.style.display = "none";

    tableBody.innerHTML = bypasses.map(b => {
      const seen = b.last_seen ? new Date(b.last_seen * 1000).toLocaleString() : "—";
      const errShort = (b.error_msg || "").substring(0, 40);
      return `
        <tr>
          <td style="font-family: monospace;">${b.domain}</td>
          <td>${b.client_ip || "—"}</td>
          <td style="font-size: 0.8rem; color: var(--text-secondary);">${errShort}</td>
          <td style="font-size: 0.8rem;">${seen}</td>
          <td>${b.occurrence_count}</td>
          <td style="text-align: right; white-space: nowrap;">
            <button class="btn-primary" style="padding: 0.25rem 0.6rem; font-size: 0.8rem;" onclick="approvePendingBypass('${b.domain}')">Approve</button>
            <button class="btn-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.8rem; margin-left: 0.25rem;" onclick="rejectPendingBypass('${b.domain}')">Reject</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (error) {
    if (tableBody) tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">Error loading pending bypasses</td></tr>';
  }
}

async function approvePendingBypass(domain, scope) {
  scope = scope || "exact";
  const warning = scope === "all"
    ? "\n\nWARNING: Approving the whole registrable domain also bypasses WEB versions and any other service on " + domain + ". Continue?"
    : "";
  if (!confirm("Approve " + domain + (scope === "all" ? " (whole domain)" : " (exact failing domains)") + "?" + warning)) return;
  try {
    const resp = await fetch("/api/pending-bypasses/" + encodeURIComponent(domain) + "/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope: scope })
    });
    const data = await resp.json();
    if (resp.ok) {
      showToast(domain + " approved", "success");
      loadTPPending();
      loadTPBypass(tpBypassPage);
    } else {
      showToast(data.error || "Failed to approve", "danger");
    }
  } catch (error) {
    showToast("Error approving bypass", "danger");
  }
}

async function rejectPendingBypass(domain) {
  if (!confirm("Reject " + domain + "? Its observations will be removed and nothing will be bypassed.")) return;
  try {
    const resp = await fetch("/api/pending-bypasses/" + encodeURIComponent(domain) + "/reject", { method: "POST" });
    const data = await resp.json();
    if (resp.ok) {
      showToast(domain + " rejected", "success");
      loadTPPending();
    } else {
      showToast(data.error || "Failed to reject", "danger");
    }
  } catch (error) {
    showToast("Error rejecting bypass", "danger");
  }
}

// ─── Global Whitelist Management ───

async function loadWhitelist() {
  const tableBody = document.getElementById("whitelist-table-body");
  if (!tableBody) return;

  try {
    const response = await fetch("/api/whitelist");
    const domains = await response.json();

    if (!domains || domains.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No whitelist domains configured</td></tr>';
      return;
    }

    tableBody.innerHTML = domains.map(d => `
      <tr>
        <td style="font-family: monospace;">${d}</td>
        <td style="text-align: right;">
          <a href="#" onclick="removeWhitelistDomain('${d}'); return false;" style="color: var(--danger);">[Remove]</a>
        </td>
      </tr>
    `).join("");
  } catch (error) {
    tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary);">Error loading whitelist</td></tr>';
  }
}

async function addWhitelistDomain() {
  const input = document.getElementById("whitelist-domain-input");
  if (!input) return;

  const domain = input.value.trim().toLowerCase();
  if (!domain) {
    showToast("Enter a domain to whitelist", "danger");
    return;
  }

  try {
    const resp = await fetch("/api/whitelist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: domain })
    });

    if (resp.ok) {
      showToast(domain + " added to whitelist", "success");
      input.value = "";
      loadWhitelist();
    } else {
      const data = await resp.json();
      showToast(data.error || "Failed to add domain", "danger");
    }
  } catch (error) {
    showToast("Error adding whitelist domain", "danger");
  }
}

async function removeWhitelistDomain(domain) {
  if (!confirm("Remove " + domain + " from the global whitelist?")) return;

  try {
    const resp = await fetch("/api/whitelist/" + encodeURIComponent(domain), { method: "DELETE" });
    if (resp.ok) {
      showToast(domain + " removed from whitelist", "success");
      loadWhitelist();
    } else {
      const data = await resp.json();
      showToast(data.error || "Failed to remove", "danger");
    }
  } catch (error) {
    showToast("Error removing whitelist domain", "danger");
  }
}

// ─── Traffic Policy Tab — paginated versions ───

let tpWhitelistPage = 1;
let tpBypassPage = 1;
let tpPendingPage = 1;
const TP_PER_PAGE = 20;

function refreshTrafficPolicy() {
  loadTPWhitelist(tpWhitelistPage);
  loadTPBypass(tpBypassPage);
  loadTPPending(tpPendingPage);
  showToast("Traffic policy refreshed", "success");
}

async function clearPendingBypasses() {
  if (!confirm("Clear ALL pending SSL pinning bypass entries? This cannot be undone.")) return;
  try {
    const r = await fetch("/api/pending-bypasses/clear", { method: "POST" });
    const d = await r.json();
    if (r.ok) {
      showToast(d.message || "Pending list cleared", "success");
      loadTPPending();
    } else {
      showToast(d.error || "Failed to clear", "danger");
    }
  } catch (_) {
    showToast("Error clearing pending bypasses", "danger");
  }
}

function renderPagination(containerId, page, totalPages, loadFunc) {
  const container = document.getElementById(containerId);
  if (!container || totalPages <= 1) { if (container) container.innerHTML = ''; return; }
  let html = '<button class="btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.8rem;" ';
  html += page > 1 ? `onclick="${loadFunc}(${page - 1})"` : 'disabled';
  html += '><i class="fa-solid fa-chevron-left"></i></button>';
  html += `<span>Page ${page} of ${totalPages}</span>`;
  html += '<button class="btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.8rem;" ';
  html += page < totalPages ? `onclick="${loadFunc}(${page + 1})"` : 'disabled';
  html += '><i class="fa-solid fa-chevron-right"></i></button>';
  container.innerHTML = html;
}

// ── Traffic Policy — Whitelist ──

async function loadTPWhitelist(page = 1) {
  tpWhitelistPage = page;
  const tbody = document.getElementById("wl-table-body");
  if (!tbody) return;
  try {
    const r = await fetch(`/api/whitelist?page=${page}&per_page=${TP_PER_PAGE}`);
    const d = await r.json();
    if (!d.domains || d.domains.length === 0) {
      tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--text-secondary);padding:2rem;">No whitelist domains</td></tr>';
    } else {
      tbody.innerHTML = d.domains.map(dn => `<tr><td style="font-family:monospace;">${dn}</td><td style="text-align:right;"><a href="#" onclick="removeWhitelistDomain('${dn}');return false;" style="color:var(--danger);">[Remove]</a></td></tr>`).join('');
    }
    renderPagination("wl-pagination", page, d.total_pages || 1, "loadTPWhitelist");
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--text-secondary);">Error</td></tr>';
  }
}

async function addWhitelistDomain() {
  const input = document.getElementById("wl-domain-input");
  if (!input) return;
  const domain = input.value.trim().toLowerCase();
  if (!domain) { showToast("Enter a domain", "danger"); return; }
  try {
    const r = await fetch("/api/whitelist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }) });
    if (r.ok) { showToast(domain + " added", "success"); input.value = ""; loadTPWhitelist(1); }
    else { const e = await r.json(); showToast(e.error || "Failed", "danger"); }
  } catch (_) { showToast("Error", "danger"); }
}

async function removeWhitelistDomain(domain) {
  if (!confirm("Remove " + domain + "?")) return;
  try {
    const r = await fetch("/api/whitelist/" + encodeURIComponent(domain), { method: "DELETE" });
    if (r.ok) { showToast(domain + " removed", "success"); loadTPWhitelist(tpWhitelistPage); }
    else { const e = await r.json(); showToast(e.error || "Failed", "danger"); }
  } catch (_) { showToast("Error", "danger"); }
}

// ── Traffic Policy — Bypass List ──

async function loadTPBypass(page = 1) {
  tpBypassPage = page;
  const tbody = document.getElementById("bypass-table-body");
  if (!tbody) return;
  try {
    const r = await fetch("/api/config");
    const cfg = await r.json();
    const raw = cfg.custom_bypass_domains || "";
    const allDomains = raw ? raw.split(",").map(d => d.trim()).filter(Boolean) : [];
    const total = allDomains.length;
    const totalPages = Math.max(1, Math.ceil(total / TP_PER_PAGE));
    const start = (page - 1) * TP_PER_PAGE;
    const pageDomains = allDomains.slice(start, start + TP_PER_PAGE);
    if (pageDomains.length === 0) {
      tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--text-secondary);padding:2rem;">No bypass domains</td></tr>';
    } else {
      tbody.innerHTML = pageDomains.map(d => `<tr><td style="font-family:monospace;">${d}</td><td style="text-align:right;"><a href="#" onclick="removeBypassDomain('${d}');return false;" style="color:var(--danger);">[Remove]</a></td></tr>`).join('');
    }
    renderPagination("bypass-pagination", page, totalPages, "loadTPBypass");
  } catch (_) {
    tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--text-secondary);">Error</td></tr>';
  }
}

// ── Traffic Policy — Pending Bypass Waitlist ──

async function loadTPPending() {
  const tbody = document.getElementById("pending-bypass-table-body");
  const badge = document.getElementById("pending-bypass-count");
  if (!tbody) return;
  try {
    const r = await fetch(`/api/pending-bypasses`);
    const d = await r.json();
    const clusters = d.pending || [];
    const threshold = d.threshold || 3;
    const thresholdLabel = document.getElementById("pb-threshold-label");
    const thresholdSelect = document.getElementById("pb-threshold");
    if (thresholdLabel) thresholdLabel.textContent = threshold;
    if (thresholdSelect && String(thresholdSelect.value) !== String(threshold)) thresholdSelect.value = String(threshold);
    if (badge) {
      badge.textContent = clusters.length + " pending";
      badge.style.display = clusters.length > 0 ? "inline-block" : "none";
    }
    if (clusters.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);padding:2rem;">No pinning clusters above the detection threshold</td></tr>';
    } else {
      tbody.innerHTML = clusters.map(b => {
        const seen = b.last_seen ? new Date(b.last_seen * 1000).toLocaleString() : "—";
        const observed = (b.observed_domains || []).map(o =>
          `<span style="display:inline-block;background:var(--surface);padding:0.1rem 0.4rem;margin:0.1rem;border-radius:4px;font-family:monospace;font-size:0.72rem;">${o.domain} <span style="color:var(--text-secondary);">x${o.count}</span></span>`
        ).join('');
        return `<tr>
          <td style="font-family:monospace;font-weight:600;">${b.base_domain}</td>
          <td>${b.total_occurrences}</td>
          <td style="max-width:420px;">${observed || "—"}</td>
          <td style="font-size:0.8rem;">${seen}</td>
          <td style="text-align:right;white-space:nowrap;">
            <button class="btn-primary" style="padding:0.2rem 0.5rem;font-size:0.78rem;" title="Persists only the exact failing SNI domains (web versions stay inspectable)" onclick="approvePendingBypass('${b.base_domain}','exact')">Approve Exact</button>
            <button class="btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.78rem;margin-left:0.2rem;" title="Persists the whole registrable domain — also bypasses web traffic on it" onclick="approvePendingBypass('${b.base_domain}','all')">Approve All</button>
            <button class="btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.78rem;margin-left:0.2rem;color:var(--danger);" onclick="rejectPendingBypass('${b.base_domain}')">Reject</button>
          </td>
        </tr>`;
      }).join('');
    }
    renderPagination("pb-pagination", 1, 1, "loadTPPending");
  } catch (_) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);">Error</td></tr>';
  }
}

async function setPinningThreshold(value) {
  const v = parseInt(value, 10);
  if (!v || v < 2 || v > 7) { showToast("Threshold must be 2-7", "danger"); loadTPPending(); return; }
  try {
    const r = await fetch("/api/config/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ pinning_min_occurrences: String(v) }) });
    if (r.ok) { showToast("Threshold set to " + v, "success"); loadTPPending(); }
    else { showToast("Failed to save threshold", "danger"); loadTPPending(); }
  } catch (_) { showToast("Error saving threshold", "danger"); loadTPPending(); }
}

async function exportPendingBypasses() {
  try {
    const r = await fetch("/api/pending-bypasses/export");
    if (!r.ok) { showToast("Export failed", "danger"); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "pinning_waitlist_export.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast("Export downloaded", "success");
  } catch (_) {
    showToast("Error exporting", "danger");
  }
}

async function addBypassDomain() {
  const input = document.getElementById("bypass-domain-input");
  if (!input) return;
  const domain = input.value.trim().toLowerCase();
  if (!domain) { showToast("Enter a domain", "danger"); return; }
  try {
    const r = await fetch("/api/config");
    const cfg = await r.json();
    const raw = cfg.custom_bypass_domains || "";
    const domains = raw ? raw.split(",").map(d => d.trim()).filter(Boolean) : [];
    if (domains.includes(domain)) { showToast("Already in list", "warning"); return; }
    domains.push(domain);
    const s = await fetch("/api/config/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ custom_bypass_domains: domains.join(",") }) });
    if (s.ok) { showToast(domain + " added", "success"); input.value = ""; loadTPBypass(1); }
    else { showToast("Failed to save", "danger"); }
  } catch (_) { showToast("Error", "danger"); }
}

async function removeBypassDomain(domain) {
  if (!confirm("Remove " + domain + "?")) return;
  try {
    const r = await fetch("/api/config");
    const cfg = await r.json();
    const raw = cfg.custom_bypass_domains || "";
    const domains = raw ? raw.split(",").map(d => d.trim()).filter(Boolean) : [];
    const filtered = domains.filter(d => d !== domain);
    const s = await fetch("/api/config/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ custom_bypass_domains: filtered.join(",") }) });
    if (s.ok) { showToast(domain + " removed", "success"); loadTPBypass(tpBypassPage); }
    else { showToast("Failed", "danger"); }
  } catch (_) { showToast("Error", "danger"); }
}

// ─── Category Hints ───

async function loadCategoryHints() {
  const tableBody = document.getElementById('category-hints-table-body');

  try {
    const response = await fetch('/api/categories/hints');
    const hints = await response.json();

    if (hints.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No category mappings configured</td></tr>';
      return;
    }

    tableBody.innerHTML = hints.map(hint => `
      <tr>
        <td><span class="category-badge ${hint.category.toLowerCase()}">${hint.category}</span></td>
        <td>${hint.domain}</td>
        <td style="text-align: right;">
          <a href="#" onclick="deleteCategoryHint(${hint.id}); return false;" style="color: var(--danger);">[Delete]</a>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    tableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-secondary); padding: 2rem;">Error loading category hints</td></tr>';
  }
}

// ─── Global Network Speedometer ───
function toggleMetricsToolkit() {
  const content = document.getElementById('metrics-toolkit-content');
  const toggle = document.getElementById('metrics-toolkit-toggle');

  if (content.style.display === 'none') {
    content.style.display = 'block';
    toggle.textContent = '▲';
  } else {
    content.style.display = 'none';
    toggle.textContent = '▼';
  }
}

async function updateGlobalThroughput() {
  try {
    const response = await fetch('/api/interface/throughput');
    const data = await response.json();

    const rxElement = document.getElementById('global-rx-mbps');
    const txElement = document.getElementById('global-tx-mbps');

    if (rxElement) rxElement.textContent = data.rx_mbps.toFixed(2);
    if (txElement) txElement.textContent = data.tx_mbps.toFixed(2);

    // Also update nerve center display
    const nerveLoad = document.getElementById('nerve-network-load');
    if (nerveLoad) {
      nerveLoad.textContent = `${data.rx_mbps.toFixed(2)} / ${data.tx_mbps.toFixed(2)} Mbps`;
    }
  } catch (error) {
    console.error('Failed to update throughput:', error);
  }
}

// Start periodic throughput polling (every 2 seconds)
setInterval(updateGlobalThroughput, 2000);

async function deleteCategoryHint(hintId) {
  if (!confirm('Are you sure you want to delete this category mapping?')) {
    return;
  }

  try {
    const response = await fetch(`/api/categories/hints/${hintId}`, {
      method: 'DELETE'
    });

    if (response.ok) {
      showToast('Category mapping deleted successfully', 'success');
      loadCategoryHints();
    } else {
      const data = await response.json();
      showToast(data.error || 'Failed to delete category mapping', 'danger');
    }
  } catch (error) {
    console.error('Error deleting category hint:', error);
    showToast('Error deleting category mapping', 'danger');
  }
}

// ─── SNI Status Indicator Update ───
function updateSNIStatusIndicator(checkbox) {
  // Works with both old (behavioral-sni-enabled) and new (adv-sni-enabled) toggles
  const statusText = document.getElementById('sni-status-text');
  if (statusText) {
    if (checkbox.checked) {
      statusText.textContent = 'ON';
      statusText.style.color = '#1A938A';
      statusText.style.fontWeight = 'bold';
    } else {
      statusText.textContent = 'OFF';
      statusText.style.color = '#ff3860';
      statusText.style.fontWeight = 'bold';
    }
  }
  // Also update the new advanced label
  const advStatus = document.getElementById('adv-sni-status');
  if (advStatus) {
    advStatus.textContent = checkbox.checked ? 'Enabled' : 'Disabled';
    advStatus.style.color = checkbox.checked ? 'var(--success)' : 'var(--danger)';
  }
}

// ─── Toast Notification Helper ───
function showToast(message, type = 'info') {
  const toastContainer = document.querySelector('.toast-container');
  if (!toastContainer) {
    // Create toast container if it doesn't exist
    const container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;

  const container = document.querySelector('.toast-container');
  container.appendChild(toast);

  // Remove toast after 3 seconds
  setTimeout(() => {
    toast.remove();
  }, 3000);
}

async function loadTrafficLogs() {
  const trafficTableBody = document.getElementById('traffic-tbody');
  if (!trafficTableBody) {
    return;
  }

  try {
    // Get filter values
    const categoryFilter = document.getElementById('traffic-filter-category')?.value || '';
    const clientFilter = document.getElementById('traffic-filter-client')?.value || '';
    const domainFilter = document.getElementById('traffic-filter-domain')?.value || '';
    const blockReasonFilter = document.getElementById('block-reason-filter')?.value || '';

    // Combine search filters (client IP or domain)
    const searchFilter = clientFilter || domainFilter;

    // Build URL with filter parameters
    const offset = (currentPage - 1) * perPage;
    let url = `/api/logs/traffic?limit=${perPage}&offset=${offset}`;
    if (categoryFilter) {
      url += `&category=${encodeURIComponent(categoryFilter)}`;
    }
    if (searchFilter) {
      url += `&search=${encodeURIComponent(searchFilter)}`;
    }
    if (blockReasonFilter) {
      url += `&block_reason=${encodeURIComponent(blockReasonFilter)}`;
    }

    const response = await fetch(url);
    if (!response.ok) {
      const errorPayload = await parseJsonResponse(response);
      throw new Error(getResponseErrorMessage(errorPayload, 'Failed to load traffic logs'));
    }
    const data = await parseJsonResponse(response) || {};
    const recentRows = Array.isArray(data.logs) ? data.logs : [];

    let trafficHtml = '';
    recentRows.forEach(r => {
      const categoryClass = `category-badge ${String(r.category || 'unclassified').toLowerCase()}`;

      // Generate block reason badges
      let blockReasonHtml = '';
      if (r.block_reasons && r.block_reasons.length > 0) {
        blockReasonHtml = r.block_reasons.map(reason => {
          const reasonClass = getBlockReasonClass(reason);
          return `<span class="badge ${reasonClass} me-1">${reason}</span>`;
        }).join('');
      } else {
        blockReasonHtml = '<span class="text-muted">-</span>';
      }

      trafficHtml += `
        <tr>
          <td>${r.formatted_time || r.time || 'N/A'}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${r.client_ip}</td>
          <td>${r.host}</td>
          <td><span class="${categoryClass}">${r.category}</span></td>
          <td>${blockReasonHtml}</td>
          <td>${r.flagged ? '🚫 Blocked' : '✓'}</td>
        </tr>
      `;
    });
    trafficTableBody.innerHTML = trafficHtml || '<tr><td colspan="6" class="text-center" style="color: var(--text-secondary); padding: 2rem;">No traffic data yet</td></tr>';

    // Update pagination controls
    if (data.pagination) {
      const totalItems = Math.max(0, Number(data.pagination.total_count) || 0);
      totalPages = Math.max(1, Math.ceil(totalItems / perPage));
      currentPage = Math.min(Math.max(1, currentPage), totalPages);
      setTextIfPresent('current-page', currentPage);
      setTextIfPresent('total-pages', totalPages);
      setTextIfPresent('total-items', totalItems);

      // Enable/disable buttons
      const prevButton = document.getElementById('prev-page');
      const nextButton = document.getElementById('next-page');
      if (prevButton) prevButton.disabled = currentPage <= 1;
      if (nextButton) nextButton.disabled = currentPage >= totalPages;
    }
  } catch (e) {
    console.error('Failed to load traffic logs:', e);
    trafficTableBody.innerHTML = '<tr><td colspan="6" class="text-center" style="color: var(--text-secondary); padding: 2rem;">Unable to load traffic logs right now</td></tr>';
    showToast('Failed to load traffic logs', 'error');
  }
}

function getBlockReasonClass(reason) {
  const reasonMap = {
    'KEYWORD_MATCH': 'bg-danger',
    'CATEGORY_BLOCKED': 'bg-danger',
    'DOMAIN_BLOCKED': 'bg-warning'
  };
  return reasonMap[reason] || 'bg-secondary';
}

function changePage(delta) {
  const newPage = currentPage + delta;
  if (newPage >= 1 && newPage <= totalPages) {
    currentPage = newPage;
    loadTrafficLogs();
  }
}

function applyFilters() {
  currentPage = 1; // Reset to first page when filters change
  loadTrafficLogs();
}

async function clearTrafficLogs() {
  pendingConfirmAction = async () => {
    const response = await fetch('/api/logs/clear', { method: 'POST' });
    if (response.ok) {
      showToast('Logs cleared successfully', 'success');
      refreshStats();
      loadTrafficLogs();
    } else {
      const errorData = await response.json().catch(() => ({}));
      showToast(errorData.error || 'Failed to clear logs', 'error');
    }
  };
  showConfirmDialog('Clear all traffic logs and throttle events? This cannot be undone.', 'Clear');
}

async function confirmReset() {
  pendingConfirmAction = factoryReset;
  showConfirmDialog('Reset all settings to factory defaults? This cannot be undone.', 'Reset');
}

function resetConfiguration() {
  confirmReset();
}

async function factoryReset() {
  try {
    const response = await fetch('/api/config/reset', { method: 'POST' });
    if (response.ok) {
      showToast('System reset to defaults', 'success');
      location.reload();
    } else {
      showToast('Failed to reset system', 'error');
    }
  } catch (error) {
    showToast('Factory reset request failed', 'error');
  }
}

function exportConfig() {
  showToast('Exporting configuration...', 'info');
  // Direct browser redirect to download the JSON payload attachment cleanly
  window.location.href = '/api/config/setup/export';
}

function importConfig() {
  // 1. Create a dynamic, hidden file input element
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = '.json';

  // 2. Listen for when the user selects a file
  fileInput.onchange = function (e) {
    const file = e.target.files[0];
    if (!file) return;

    showToast('Uploading configuration...', 'info');

    // 3. Package the file inside FormData
    const formData = new FormData();
    formData.append('config_file', file);

    // 4. Send the multi-part request to our backend API
    fetch('/api/config/setup/import', {
      method: 'POST',
      body: formData
    })
      .then(response => {
        if (response.redirected) {
          // If Flask redirects with flash messages, follow it
          window.location.href = response.url;
        } else {
          return response.json().then(data => {
            if (response.ok) {
              showToast('Configuration imported successfully!', 'success');
              setTimeout(() => window.location.reload(), 1500);
            } else {
              showToast(data.error || 'Import failed.', 'danger');
            }
          });
        }
      })
      .catch(err => {
        console.error(err);
        showToast('Network error during configuration import.', 'danger');
      });
  };

  // 5. Programmatically click it to trigger the OS file selector window
  fileInput.click();
}

async function executeSystemControl(action, buttonElement) {
  const originalText = buttonElement.textContent;
  const actionLabels = {
    'restart_proxy': '🔄 Restarting proxy...',
    'reload_config': '🔄 Restarting dashboard...',
    'reload_firewall': '🔄 Reloading firewall...',
    'restart_dnsmasq': '🔄 Reloading DNS...'
  };

  // Disable button and show loading state
  buttonElement.disabled = true;
  buttonElement.textContent = actionLabels[action] || '🔄 Processing...';

  try {
    const response = await fetch('/api/system/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    });

    const data = await response.json();

    if (response.ok && data.status === 'success') {
      showToast(data.message || 'Operation completed successfully', 'success');

      // Refresh stats after a short delay to show updated service status
      setTimeout(() => {
        refreshStats();
      }, 1000);
    } else if (response.ok && data.status === 'warning') {
      showToast(data.message || 'Operation completed with warnings', 'warning');

      setTimeout(() => {
        refreshStats();
      }, 1000);
    } else {
      showToast(data.error || data.message || 'Operation failed', 'error');
    }
  } catch (error) {
    console.error('System control error:', error);
    showToast('Network error: Could not execute command', 'error');
  } finally {
    // Restore button state after 2 seconds
    setTimeout(() => {
      buttonElement.disabled = false;
      buttonElement.textContent = originalText;
    }, 2000);
  }
}

function showConfirmDialog(message, action) {
  document.getElementById('modalMessage').textContent = message;
  document.getElementById('confirmBtn').textContent = action;
  document.getElementById('confirmModal').classList.add('active');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

function executeConfirm() {
  if (pendingConfirmAction) {
    pendingConfirmAction();
    closeModal('confirmModal');
    pendingConfirmAction = null;
  }
}

async function saveWizardConfig(e) {
  e?.preventDefault();

  // Gather all form inputs
  const blockHarmfulEl = getConfigInput(['block-harmful']);
  const blockDistractingEl = getConfigInput(['block-distracting']);
  const throttleEnabledEl = getConfigInput(['throttle-enabled']);
  const velocityThresholdEl = getConfigInput(['wizard-throttle-threshold']);

  // Network settings
  const upstreamInterfaceEl = document.getElementById('wizard-upstream-interface');
  const distributionInterfaceEl = document.getElementById('wizard-distribution-interface');
  const gatewayIpEl = document.getElementById('wizard-gateway-ip');
  const dhcpStartEl = document.getElementById('wizard-dhcp-start');
  const dhcpEndEl = document.getElementById('wizard-dhcp-end');
  const dnsServersEl = document.getElementById('wizard-dns-servers');
  const throttleRateEl = document.getElementById('wizard-throttle-rate');

  const payload = {
    block_harmful: Boolean(blockHarmfulEl?.checked),
    block_distracting: Boolean(blockDistractingEl?.checked),
    throttle_enabled: Boolean(throttleEnabledEl?.checked),
    velocity_threshold: Number.parseInt(velocityThresholdEl?.value || '30', 10) || 30,
    // Network configuration
    upstream_interface: upstreamInterfaceEl?.value || 'en0',
    distribution_interface: distributionInterfaceEl?.value || 'wlp1s0',
    gateway_ip: gatewayIpEl?.value || '172.20.10.1',
    dhcp_start: dhcpStartEl?.value || '172.20.10.10',
    dhcp_end: dhcpEndEl?.value || '172.20.10.50',
    dns_servers: dnsServersEl?.value || '8.8.8.8,8.8.4.4'
  };

  try {
    const response = await fetch('/api/config/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      showToast('Network settings applied successfully!', 'success');
      await loadWizardConfig();
    } else {
      const errorData = await response.json().catch(() => ({}));
      showToast(errorData.error || 'Failed to save configuration', 'danger');
    }
  } catch (error) {
    showToast('Error saving configuration: ' + error.message, 'danger');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  startDashboardPolling();
  loadConfigToUI();

  const settingsForm = document.getElementById('settingsForm');
  if (settingsForm && typeof saveConfig === 'function') settingsForm.addEventListener('submit', saveConfig);

  const wizardForm = document.getElementById('wizardForm');
  if (wizardForm) wizardForm.addEventListener('submit', saveWizardConfig);

  const sniCheckbox = document.getElementById('behavioral-sni-enabled');
  if (sniCheckbox) updateSNIStatusIndicator(sniCheckbox);

  const keywordForm = document.getElementById('keyword-form');
  if (keywordForm) {
    keywordForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      const keywordInput = document.getElementById('keyword-input');
      const keyword = keywordInput.value.trim();

      if (!keyword) {
        showToast('Please enter a keyword', 'danger');
        return;
      }

      try {
        const response = await fetch('/api/keywords', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ keyword: keyword })
        });

        const data = await response.json();

        if (response.ok) {
          showToast('Keyword added successfully', 'success');
          keywordInput.value = '';
          loadKeywords();
        } else {
          showToast(data.error || 'Failed to add keyword', 'danger');
        }
      } catch (error) {
        showToast('Error adding keyword', 'danger');
      }
    });
  }

  const categoryHintForm = document.getElementById('category-hint-form');
  if (categoryHintForm) {
    categoryHintForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      const categorySelect = document.getElementById('category-hint-category');
      const domainInput = document.getElementById('category-hint-domain');

      const category = categorySelect.value;
      const domain = domainInput.value.trim();

      if (!category) {
        showToast('Please select a category', 'danger');
        return;
      }

      if (!domain) {
        showToast('Please enter a domain', 'danger');
        return;
      }

      try {
        const response = await fetch('/api/categories/hints', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ category: category, domain: domain })
        });

        const data = await response.json();

        if (response.ok) {
          showToast('Category mapping added successfully', 'success');
          domainInput.value = '';
          categorySelect.value = '';
          loadCategoryHints();
        } else {
          showToast(data.error || 'Failed to add category mapping', 'danger');
        }
      } catch (error) {
        console.error('Error adding category hint:', error);
        showToast('Error adding category mapping', 'danger');
      }
    });
  }

  // SNI dashboard event listeners
  const sniTimeWindow = document.getElementById('sni-time-window');
  const sniClientFilter = document.getElementById('sni-client-filter');

  if (sniTimeWindow) {
    sniTimeWindow.addEventListener('change', loadSNIDashboard);
  }
  if (sniClientFilter) {
    sniClientFilter.addEventListener('change', loadSNIDashboard);
  }

  // Behavioral control timeline live update listeners
  const bSelectors = ['adv-engagement-l1', 'adv-engagement-l2', 'adv-engagement-l3',
    'adv-engagement-l1-rate', 'adv-engagement-l2-rate', 'adv-engagement-l3-rate',
    'adv-engagement-reset'];
  bSelectors.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', updateBehavioralTimeline);
  });

  // Initial circuit breaker load
  loadCircuitBreakerState();
});

// ─── Theme Management ───
function toggleTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  localStorage.setItem('ui-theme', mode);

  // Background fetch to backend
  fetch('/api/config/ui-theme', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ theme: mode })
  }).catch(e => console.log('Theme sync error:', e));
}

function initTheme() {
  const savedTheme = localStorage.getItem('ui-theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
  const themeSelect = document.getElementById('theme-preference');
  if (themeSelect) {
    themeSelect.value = savedTheme;
  }

  const themeToggleSwitch = document.getElementById('theme-toggle-switch');
  if (themeToggleSwitch) {
    themeToggleSwitch.checked = (savedTheme === 'dark');
    if (savedTheme === 'dark') {
      themeToggleSwitch.nextElementSibling.classList.add('active');
    } else {
      themeToggleSwitch.nextElementSibling.classList.remove('active');
    }
  }
}

function toggleThemeMode(isDark) {
  const mode = isDark ? 'dark' : 'light';
  toggleTheme(mode);
}

// ─── SNI Dashboard Functions ───
let sniDomainChart = null;

// ─── SNI Monitoring ───

let currentSniPage = 1;
const SNI_PAGE_SIZE = 20;

async function loadSNIDashboard() {
  const timeWindowSelect = document.getElementById('sni-time-window');
  const clientFilterSelect = document.getElementById('sni-client-filter');
  if (!timeWindowSelect || !clientFilterSelect) return;

  const timeWindow = timeWindowSelect.value;
  const clientIP = clientFilterSelect.value;

  try {
    // Load scroll rates for charts
    const scrollResponse = await fetch(`/api/sni/scroll-rates?time_window=${timeWindow}&client_ip=${clientIP}`);
    const scrollData = await parseJsonResponse(scrollResponse) || {};
    updateSNICharts(scrollResponse.ok && scrollData.status === 'success' ? scrollData.scroll_rates : []);

    // Load the first page of SNI logs
    currentSniPage = 1;
    await loadSNILogPage(1);

    // Load client filter dropdown
    await loadSNIClientFilter();
  } catch (error) {
    console.error('Error loading SNI dashboard:', error);
  }
}

async function loadSNILogPage(page) {
  const clientFilterSelect = document.getElementById('sni-client-filter');
  const searchInput = document.getElementById('sni-log-search');
  if (!clientFilterSelect) return;

  const clientIP = clientFilterSelect.value || '';
  const domain = searchInput ? searchInput.value.trim() : '';
  const offset = (page - 1) * SNI_PAGE_SIZE;

  try {
    let url = `/api/sni/requests?limit=${SNI_PAGE_SIZE}&offset=${offset}&client_ip=${encodeURIComponent(clientIP)}`;
    if (domain) url += `&domain=${encodeURIComponent(domain)}`;

    const response = await fetch(url);
    const data = await parseJsonResponse(response) || {};

    if (response.ok && data.status === 'success') {
      currentSniPage = page;
      updateSNILogTable(data.logs || []);
      updateSNIPagination(data.pagination || {});
    } else {
      updateSNILogTable([]);
      updateSNIPagination({});
    }
  } catch (error) {
    console.error('Error loading SNI log page:', error);
    updateSNILogTable([]);
  }
}

function updateSNIPagination(pagination) {
  const container = document.getElementById('sni-pagination');
  const pageInfo = document.getElementById('sni-page-info');
  const pageNums = document.getElementById('sni-page-nums');
  const prevBtn = document.getElementById('sni-prev-page');
  const nextBtn = document.getElementById('sni-next-page');

  if (!container || !pagination.total_count === undefined) { container.style.display = 'none'; return; }

  const total = pagination.total_count || 0;
  const limit = pagination.limit || SNI_PAGE_SIZE;
  const offset = pagination.offset || 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  if (total === 0) { container.style.display = 'none'; return; }

  container.style.display = 'flex';
  if (pageInfo) pageInfo.textContent = `${offset + 1}-${Math.min(offset + limit, total)} of ${total}`;
  if (pageNums) pageNums.textContent = `Page ${currentSniPage} of ${totalPages}`;
  if (prevBtn) prevBtn.disabled = currentSniPage <= 1;
  if (nextBtn) nextBtn.disabled = currentSniPage >= totalPages;
}

function renderSNIChartFallback(canvasId, items, labelFormatter) {
  const canvas = document.getElementById(canvasId);
  const container = canvas?.parentElement;
  if (!canvas || !container) {
    return;
  }

  let fallback = container.querySelector('.sni-chart-fallback');
  if (!fallback) {
    fallback = document.createElement('div');
    fallback.className = 'sni-chart-fallback';
    fallback.style.marginTop = '1rem';
    fallback.style.padding = '0.75rem 1rem';
    fallback.style.border = '1px solid var(--border)';
    fallback.style.borderRadius = '8px';
    fallback.style.background = 'var(--surface)';
    container.appendChild(fallback);
  }

  if (!items.length) {
    fallback.textContent = 'No SNI activity available for the selected filters.';
    return;
  }

  fallback.innerHTML = items.slice(0, 5).map(labelFormatter).join('<br>');
}

function updateSNICharts(scrollRates) {
  const safeRates = Array.isArray(scrollRates) ? scrollRates : [];
  const domains = safeRates.map(r => r.domain);
  const requestCounts = safeRates.map(r => r.total_requests);

  if (!window.Chart) {
    renderSNIChartFallback(
      'sni-domain-chart',
      safeRates,
      rate => `${rate.domain}: ${Number(rate.total_requests || 0)} requests`
    );
    return;
  }

  const domainCanvas = document.getElementById('sni-domain-chart');
  if (!domainCanvas) return;

  const parentWidth = domainCanvas.parentElement.clientWidth || 400;
  domainCanvas.width = parentWidth;
  domainCanvas.height = 280;

  // Domain Request Count Chart
  const domainCtx = domainCanvas.getContext('2d');
  if (sniDomainChart) {
    sniDomainChart.destroy();
    sniDomainChart = null;
  }
  sniDomainChart = new Chart(domainCtx, {
    type: 'bar',
    data: {
      labels: domains.length ? domains : ['No Data'],
      datasets: [{
        label: 'Request Count',
        data: requestCounts.length ? requestCounts : [0],
        backgroundColor: '#43B3AE'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true
        },
        x: {
          ticks: {
            maxRotation: 45,
            minRotation: 45
          }
        }
      }
    }
  });

  // Remove any stale fallbacks since Chart is working
  document.querySelectorAll('.sni-chart-fallback').forEach(el => el.remove());
}

function updateSNILogTable(logs) {
  const tableBody = document.getElementById('sni-log-table');
  const emptyState = document.getElementById('sni-empty-state');
  if (!tableBody) {
    return;
  }
  const safeLogs = Array.isArray(logs) ? logs : [];

  if (safeLogs.length === 0) {
    tableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-secondary);">No SNI requests found for the selected filters.</td></tr>';
    if (emptyState) emptyState.classList.remove('hidden');
    return;
  }

  if (emptyState) emptyState.classList.add('hidden');

  tableBody.innerHTML = safeLogs.map(log => `
    <tr>
      <td>${log.formatted_time || 'N/A'}</td>
      <td style="font-family: monospace;">${log.client_ip || '—'}</td>
      <td>${log.domain || 'Unknown domain'}</td>
    </tr>
  `).join('');
}

async function loadSNIClientFilter() {
  try {
    const response = await fetch('/api/sni/requests');
    const data = await parseJsonResponse(response) || {};

    if (response.ok && data.status === 'success') {
      const clientIPs = [...new Set(data.logs.map(log => log.client_ip))];
      const select = document.getElementById('sni-client-filter');
      if (!select) {
        return;
      }

      // Keep current selection
      const currentValue = select.value;

      select.innerHTML = '<option value="">All Clients</option>' +
        clientIPs.map(ip => `<option value="${ip}">${ip}</option>`).join('');

      select.value = currentValue;
    }
  } catch (error) {
    console.error('Error loading SNI client filter:', error);
  }
}

function exportSNI() {
  const timeWindowSelect = document.getElementById('sni-time-window');
  const clientFilterSelect = document.getElementById('sni-client-filter');

  const params = new URLSearchParams();

  // Apply client filter if selected
  if (clientFilterSelect && clientFilterSelect.value) {
    params.set('client_ip', clientFilterSelect.value);
  }

  // Convert time window to start_time
  if (timeWindowSelect && timeWindowSelect.value) {
    const now = Date.now() / 1000;
    const windowMap = { '1m': 60, '5m': 300, '15m': 900, '1h': 3600 };
    const seconds = windowMap[timeWindowSelect.value];
    if (seconds) {
      params.set('start_time', (now - seconds).toFixed(0));
    }
  }

  const queryString = params.toString();
  const url = '/api/sni/export' + (queryString ? '?' + queryString : '');
  window.location.href = url;
  showToast('Exporting SNI data to CSV...', 'success');
}



// ─── SNI Clear & Throttle Reset ───
async function clearSNILogs() {
  if (!confirm("Clear ALL SNI request logs? This cannot be undone.")) return;

  try {
    const resp = await fetch("/api/sni/clear", { method: "POST" });
    const data = await resp.json();

    if (resp.ok) {
      showToast(data.message || "SNI logs cleared", "success");
      currentSniPage = 1;
      loadSNIDashboard();
    } else {
      showToast(data.error || "Failed to clear SNI logs", "danger");
    }
  } catch (error) {
    showToast("Error clearing SNI logs", "danger");
  }
}

async function resetAllThrottles() {
  if (!confirm("Flush ALL tc rules and reset all throttle scores? Full speed restored.")) return;

  try {
    const resp = await fetch("/api/throttle/reset-all", { method: "POST" });
    const data = await resp.json();
    if (resp.ok) {
      showToast("All throttles reset — tc flushed, scores zeroed", "success");
    } else {
      showToast(data.error || "Reset failed", "danger");
    }
    if (typeof loadCircuitBreakerState === "function") loadCircuitBreakerState();
    currentSniPage = 1;
    loadSNIDashboard();
  } catch (error) {
    showToast("Error resetting throttles", "danger");
  }
}
function refreshSNI() {
  loadSNIDashboard();
  showToast('SNI dashboard refreshed', 'success');
}

// ─── Pinned Domains — System tab display + Setup tab editor ───

async function loadPinnedDisplay() {
  const container = document.getElementById("pinned-domains-display");
  if (!container) return;
  try {
    const r = await fetch("/api/config");
    const cfg = await r.json();
    const raw = cfg.proxy_pinned_domains || "facebook.com,twitter.com,x.com,tiktok.com,instagram.com,reddit.com,youtube.com";
    const domains = raw.split(",").map(d => d.trim()).filter(Boolean);
    if (domains.length === 0) {
      container.innerHTML = '<span style="color: var(--text-secondary);">(none)</span>';
      return;
    }
    container.innerHTML = domains.map(d =>
      `<span style="background: var(--surface); color: var(--text-primary); padding: 0.25rem 0.6rem; border-radius: 6px; font-size: 0.85rem; font-family: monospace;">${d}</span>`
    ).join('');
  } catch (_) {
    container.innerHTML = '<span style="color: var(--danger);">Error</span>';
  }
}

async function loadPinnedEditor() {
  const select = document.getElementById("pinned-domain-select");
  if (!select) return;
  try {
    const r = await fetch("/api/config");
    const cfg = await r.json();
    // Fall back to the effective default so the dropdown always shows data,
    // even before proxy_pinned_domains has been saved to config_settings.
    const raw = cfg.proxy_pinned_domains || "facebook.com,twitter.com,x.com,tiktok.com,instagram.com,reddit.com,youtube.com";
    const domains = raw ? raw.split(",").map(d => d.trim()).filter(Boolean) : [];
    select.innerHTML = '<option value="">Select to remove...</option>' +
      domains.map(d => `<option value="${d}">${d}</option>`).join('');
  } catch (_) { }
}

async function addPinnedDomain() {
  const input = document.getElementById("pinned-domain-input");
  if (!input) return;
  const domain = input.value.trim().toLowerCase();
  if (!domain) { showToast("Enter a domain", "danger"); return; }
  try {
    const r = await fetch("/api/config");
    const cfg = await r.json();
    const raw = cfg.proxy_pinned_domains || "";
    const domains = raw ? raw.split(",").map(d => d.trim()).filter(Boolean) : [];
    if (domains.includes(domain)) { showToast("Already in list", "warning"); return; }
    domains.push(domain);
    await fetch("/api/config/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ proxy_pinned_domains: domains.join(",") }) });
    showToast(domain + " added", "success"); input.value = "";
    loadPinnedEditor();
    loadPinnedDisplay();
  } catch (_) { showToast("Error", "danger"); }
}

async function removePinnedDomain() {
  const select = document.getElementById("pinned-domain-select");
  if (!select) return;
  const domain = select.value;
  if (!domain) return;
  if (!confirm("Remove " + domain + " from pinned domains?")) { select.value = ""; return; }
  try {
    const r = await fetch("/api/config");
    const cfg = await r.json();
    const raw = cfg.proxy_pinned_domains || "";
    const domains = raw ? raw.split(",").map(d => d.trim()).filter(Boolean) : [];
    const filtered = domains.filter(d => d !== domain);
    await fetch("/api/config/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ proxy_pinned_domains: filtered.join(",") }) });
    showToast(domain + " removed", "success");
    loadPinnedEditor();
    loadPinnedDisplay();
  } catch (_) { showToast("Error", "danger"); }
}

// ─── Unified Polling Engine ───
let dashboardPollInterval = null;

function startDashboardPolling() {
  if (dashboardPollInterval) clearInterval(dashboardPollInterval);

  const fetchSummary = async () => {
    try {
      const response = await fetch('/api/dashboard/summary');
      if (!response.ok) return;
      const data = await response.json();

      // 1. Update Nerve Center (Quick View)
      const healthIcon = document.getElementById('nerve-health-icon');
      const healthText = document.getElementById('nerve-health-text');

      const isOptimal = data.system.cpu_usage < 80 && data.system.ram_usage_gb < (data.system.ram_total_gb * 0.9);
      if (healthIcon && healthText) {
        healthIcon.style.color = isOptimal ? '#1A938A' : 'var(--danger)';
        healthText.textContent = isOptimal ? 'Optimal' : 'Degraded';
      }

      const interfaceThroughput = document.getElementById('nerve-interface-throughput');
      if (interfaceThroughput) {
        interfaceThroughput.textContent = `Rx: ${data.system.throughput_rx_mbps} Mbps / Tx: ${data.system.throughput_tx_mbps} Mbps`;
      }



      const sysThroughput = document.getElementById('sys-throughput');
      if (sysThroughput) {
        sysThroughput.textContent = `${data.system.throughput_rx_mbps} / ${data.system.throughput_tx_mbps}`;
      }

      const networkLoad = document.getElementById('nerve-network-load');
      if (networkLoad) {
        networkLoad.textContent = 'Network Active';
      }

      const shieldIntegrity = document.getElementById('nerve-shield-integrity');
      if (shieldIntegrity) {
        shieldIntegrity.textContent = `${data.devices.total_connected} Active / ${data.devices.throttled_count} Throttled`;
      }

      const nlpStatus = document.getElementById('nerve-nlp-status');
      if (nlpStatus) {
        nlpStatus.textContent = data.active_config?.nlp_enabled ? 'Active' : 'Idle';
      }

      // Fetch additional nerve center metrics when available
      try {
        const nerveResponse = await fetch('/api/nerve-center/metrics');
        if (nerveResponse.ok) {
          const nerveData = await nerveResponse.json();
          if (shieldIntegrity) {
            shieldIntegrity.textContent = `${nerveData.active_count} Active / ${nerveData.throttled_count} Throttled`;
          }
          if (nlpStatus && nerveData.nlp_status) {
            nlpStatus.textContent = nerveData.nlp_status;
          }
          // Use server uptime display instead of interface mode
          const serverUptime = document.getElementById('nerve-uptime');
          if (serverUptime && nerveData.uptime) {
            serverUptime.textContent = nerveData.uptime;
          }
        }
      } catch (error) {
        console.error('Failed to fetch nerve center metrics:', error);
      }

      // 2. Update System Gauges (throughput removed per requirements)
      const sysCpu = document.getElementById('sys-cpu');
      if (sysCpu) {
        sysCpu.textContent = `${data.system.cpu_usage}%`;
      }
      const sysMemory = document.getElementById('sys-memory');
      if (sysMemory) {
        const ramPercent = Math.round((data.system.ram_usage_gb / data.system.ram_total_gb) * 100);
        sysMemory.textContent = `${ramPercent}%`;
      }
      const sysDisk = document.getElementById('sys-disk');
      if (sysDisk) {
        sysDisk.textContent = `${data.system.disk_usage}%`;
      }

      ['mitmproxy', 'dnsmasq'].forEach(svc => {
        const badge = document.getElementById(`status-${svc}`);
        if (badge) {
          const isActive = data.system.services[svc] === 'active' || data.system.services[svc] === 'running';
          badge.textContent = isActive ? 'Active' : 'Inactive';
          badge.className = `category-badge ${isActive ? 'success' : 'danger'}`;
        }
      });

      // 3. Update active tab specifics without flickering
      if (currentTab === 'device-management' && data.dhcp_allocations) {
        const tableBody = document.getElementById('devices-tbody');
        if (tableBody && data.dhcp_allocations.length > 0) {
          tableBody.innerHTML = data.dhcp_allocations.map(device => {
            const policy = device.policy || 'none';
            const stateClass = policy === 'blacklist' ? 'danger' : (policy === 'whitelist' ? 'success' : 'secondary');
            const stateLabel = policy === 'blacklist' ? 'Blacklisted' : (policy === 'whitelist' ? 'Whitelisted' : 'Default');

            return `
              <tr>
                <td style="font-weight: 500;">${device.hostname || device.custom_name || 'Unknown Device'}</td>
                <td style="font-family: monospace; font-size: 0.9rem;">${device.ip_address || '—'}</td>
                <td style="font-family: monospace; font-size: 0.9rem;">${device.mac_address || '—'}</td>
                <td><span class="category-badge ${stateClass}">${stateLabel}</span></td>
                <td>
                  <div class="device-filter-pills">
                    <button class="filter-pill whitelist ${policy === 'whitelist' ? 'active' : ''}" onclick="setDeviceFilter('${device.mac_address}', 'whitelist', this)">Whitelist</button>
                    <button class="filter-pill blacklist ${policy === 'blacklist' ? 'active' : ''}" onclick="setDeviceFilter('${device.mac_address}', 'blacklist', this)">Blacklist</button>
                    <button class="filter-pill none ${policy === 'none' ? 'active' : ''}" onclick="setDeviceFilter('${device.mac_address}', 'none', this)">Default</button>
                  </div>
                </td>
              </tr>
            `;
          }).join('');
        }
      }
      // 4. Update Circuit Breaker status
      try {
        await loadCircuitBreakerState();
      } catch (e) { }
      // 5. Update pinned domains display on System tab
      loadPinnedDisplay().catch(() => { });
      // 5. Update pending bypass count badge (lightweight — only badge text)
      try {
        const pbResp = await fetch("/api/pending-bypasses");
        const pbData = await pbResp.json();
        const badge = document.getElementById("pending-bypass-count");
        if (badge) {
          const total = pbData.pending ? pbData.pending.length : 0;
          badge.textContent = total + " pending";
          badge.style.display = total > 0 ? "inline-block" : "none";
        }
      } catch (e) {
        // Non-critical
      }

    } catch (error) {
      console.error('Polling error:', error);
    }
  };

  fetchSummary();

  // Reduce polling frequency when tab is not visible
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (dashboardPollInterval) {
        clearInterval(dashboardPollInterval);
        dashboardPollInterval = setInterval(fetchSummary, 60000);
      }
    } else {
      if (dashboardPollInterval) {
        clearInterval(dashboardPollInterval);
        dashboardPollInterval = setInterval(fetchSummary, 15000);
      }
      fetchSummary(); // Immediate refresh when tab becomes visible
    }
  });

  dashboardPollInterval = setInterval(fetchSummary, 15000);
}

// ─── Circuit Breaker Status ───
async function loadCircuitBreakerState() {
  try {
    const response = await fetch('/api/circuit-breaker/state');
    const data = await response.json();

    const panel = document.getElementById('circuit-breaker-panel');
    const subtitle = document.getElementById('cb-subtitle');
    const badge = document.getElementById('cb-status-badge');
    const interventions = document.getElementById('cb-interventions');
    const empty = document.getElementById('cb-empty');

    if (!panel) return;

    const cbData = data.states || [];

    if (cbData.length === 0) {
      panel.style.display = 'none';
      return;
    }

    panel.style.display = 'block';

    // Update badge (3-level system: 1=Pause, 2=Friction, 3=Circuit Break)
    const highestLevel = Math.max(...cbData.map(s => s.level));
    if (highestLevel >= 3) {
      badge.textContent = 'Circuit Break';
      badge.style.background = '#ff3860';
    } else if (highestLevel >= 2) {
      badge.textContent = 'Friction';
      badge.style.background = '#ffa500';
    } else {
      badge.textContent = 'Pause';
      badge.style.background = '#1A938A';
    }

    subtitle.textContent = `${cbData.length} device(s) under intervention`;

    // Build intervention list — use actual engagement data from backend
    const levelColors = { 0: '#666', 1: '#1A938A', 2: '#ffa500', 3: '#ff3860' };
    const levelIcons = { 0: 'fa-circle', 1: 'fa-pause-circle', 2: 'fa-gauge-high', 3: 'fa-bolt' };

    interventions.innerHTML = cbData.map(s => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background: var(--surface); border-radius: 8px; margin-bottom: 0.5rem; border-left: 4px solid ${levelColors[s.level] || '#1A938A'};">
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <i class="fa-solid ${levelIcons[s.level] || 'fa-circle-info'}" style="color: ${levelColors[s.level] || '#1A938A'}; font-size: 1.2rem;"></i>
          <div>
            <div style="font-weight: 600; font-size: 0.95rem;">${s.client_ip}</div>
            <div style="font-size: 0.8rem; color: var(--text-secondary);">${s.engagement_minutes || 0}min engaged • ${s.throttle_rate || '?'} • idle ${Math.floor(s.idle_seconds || 0)}s</div>
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <span style="font-size: 0.85rem; font-weight: 600; color: ${levelColors[s.level] || '#1A938A'};">L${s.level}: ${s.level_name}</span>
          <button class="btn-secondary" onclick="releaseCircuitBreaker('${s.client_ip}')" style="padding: 0.25rem 0.75rem; font-size: 0.8rem;">Release</button>
        </div>
      </div>
    `).join('');

    if (empty) empty.style.display = 'none';
  } catch (error) {
    console.error('Error loading circuit breaker state:', error);
  }
}

async function releaseCircuitBreaker(clientIp) {
  if (!confirm(`Release circuit breaker for ${clientIp}?`)) return;

  try {
    const response = await fetch('/api/circuit-breaker/release', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_ip: clientIp })
    });

    if (response.ok) {
      showToast(`Circuit breaker released for ${clientIp}`, 'success');
      loadCircuitBreakerState();
    } else {
      const data = await response.json();
      showToast(data.error || 'Failed to release', 'danger');
    }
  } catch (error) {
    showToast('Error releasing circuit breaker', 'danger');
  }
}

// ─── Logout Handler ───
async function handleLogout() {
  if (!confirm('Sign out of the VIGILANT dashboard?')) return;

  try {
    const response = await fetch('/api/logout', { method: 'POST' });
    if (response.ok) {
      window.location.href = '/login';
    }
  } catch (error) {
    // Even if the request fails, redirect to login
    window.location.href = '/login';
  }
}
