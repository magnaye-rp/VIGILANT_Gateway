// ─── State Management ─── 
let currentTab = 'system'; // Global state for active tab
let currentWizardStep = 1;
let pendingConfirmAction = null;
let currentPage = 1;
let perPage = 100;
let totalPages = 1;

// ─── Tab Navigation ───
function showHelpToolkit() {
  const toolkitModal = document.getElementById('toolkitModal');
  const toolkitTitle = document.getElementById('toolkitTitle');
  const toolkitContent = document.getElementById('toolkitContent');
  
  toolkitModal.classList.add('active');
  
  switch(currentTab) {
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
    case 'settings':
      toolkitTitle.innerText = "Setup Help";
      toolkitContent.innerHTML = "Manage system <strong>backups</strong>, perform <strong>configuration restorations</strong>, and configure <strong>edge interface bindings</strong>.";
      break;
    default:
      toolkitTitle.innerText = "Help Toolkit";
      toolkitContent.innerHTML = "Context-aware help is available here depending on your active tab.";
  }
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  
  document.getElementById(`tab-${tabId}`)?.classList.add('active');
  event.currentTarget.classList.add('active');
  
  currentTab = tabId;
  
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
  }
  if (tabId === 'behavioral-control') {
    loadBehavioralSettings();
  }
  if (tabId === 'restraints') {
    loadRestraintsRegistry();
  }
}

// ─── Device Management ───
window.loadThrottledDevices = async function() {
  const tableBody = document.getElementById('throttled-tbody');

  try {
    const response = await fetch('/api/devices/throttled');
    const data = await response.json();
    const throttledDevices = data.throttled_devices || [];

    if (throttledDevices.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No throttled devices</td></tr>';
      return;
    }

    tableBody.innerHTML = throttledDevices.map(device => {
      const hostname = device.hostname || device.custom_name || 'Unknown Device';
      const ip = device.client_ip || device.ip_address || '—';
      
      return `
        <tr>
          <td style="font-weight: 500;">${hostname}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${ip}</td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    console.error('Error loading throttled devices:', error);
    tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">Error loading throttled devices</td></tr>';
  }
};

window.loadActiveDevices = async function() {
  const tableBody = document.getElementById('active-tbody');

  try {
    const response = await fetch('/api/devices');
    const data = await response.json();
    const devices = data.devices || [];

    // Filter for currently active devices (recently seen) and only include 192.168.10.0 network
    const now = Date.now() / 1000;
    const activeDevices = devices.filter(device => {
      const ip = device.ip_address || '';
      const lastSeen = device.last_seen || 0;
      // Consider device active if seen in last 5 minutes and in 192.168.10.0 network
      return ip.startsWith('192.168.10.') && (now - lastSeen) < 300;
    });

    if (activeDevices.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No active devices</td></tr>';
      return;
    }

    tableBody.innerHTML = activeDevices.map(device => {
      const hostname = device.hostname || device.custom_name || 'Unknown Device';
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

window.loadLeasedDevices = async function() {
  const tableBody = document.getElementById('leased-tbody');

  try {
    const response = await fetch('/api/devices');
    const data = await response.json();
    const devices = data.devices || [];

    // Filter to only include 192.168.10.0 network devices
    const leasedDevices = devices.filter(device => {
      const ip = device.ip_address || '';
      return ip.startsWith('192.168.10.');
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

window.setDeviceFilter = async function(macAddress, action, buttonElement) {
  try {
    const response = await fetch('/api/devices/filter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac: macAddress, action: action })
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
    const data = await response.json();
    const systemMetrics = data.system_metrics || {};
    const networkConfig = data.network_config || {};
    const recentRows = Array.isArray(data.recent) ? data.recent : [];
    const counts = Array.isArray(data.counts) ? data.counts : [];

    document.getElementById('stat-total').textContent = data.total;
    document.getElementById('stat-flagged').textContent = data.flagged;
    document.getElementById('stat-clients').textContent = data.clients;
    document.getElementById('stat-throttled').textContent = data.throttles?.length || 0;

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
    document.getElementById('category-breakdown').innerHTML = html;

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
    document.getElementById('recent-tbody').innerHTML = recentHtml || '<tr><td colspan="5" class="text-center" style="color: var(--text-secondary); padding: 2rem;">No traffic data yet</td></tr>';

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

    const config = await response.json();
    
    // Populate network interface dropdowns with available interfaces
    if (config.available_interfaces && Array.isArray(config.available_interfaces)) {
      populateInterfaceDropdowns(config.available_interfaces);
    }
    
    // Sync filtering settings
    syncConfigInputs(['block-harmful'], config.block_harmful);
    syncConfigInputs(['block-distracting'], config.block_distracting);
    syncConfigInputs(['throttle-enabled'], config.throttle_enabled);
    
    // Sync Behavioral Settings
    const netVelPreset = document.getElementById('network-velocity-preset');
    const netVelCustom = document.getElementById('network-velocity-custom');
    if (netVelPreset && config.proxy_velocity_threshold) {
      let val = String(config.proxy_velocity_threshold);
      if (['2.0', '1.5', '1.1'].includes(val)) {
        netVelPreset.value = val;
        document.getElementById('network-velocity-custom-container').style.display = 'none';
      } else {
        netVelPreset.value = 'custom';
        netVelCustom.value = val;
        document.getElementById('network-velocity-custom-container').style.display = 'block';
      }
    }
    
    const scrollVelPreset = document.getElementById('scroll-velocity-preset');
    const scrollVelCustom = document.getElementById('scroll-velocity-custom');
    if (scrollVelPreset && config.request_threshold) {
      let val = String(config.request_threshold);
      if (['120', '75', '40'].includes(val)) {
        scrollVelPreset.value = val;
        document.getElementById('scroll-velocity-custom-container').style.display = 'none';
      } else {
        scrollVelPreset.value = 'custom';
        scrollVelCustom.value = val;
        document.getElementById('scroll-velocity-custom-container').style.display = 'block';
      }
    }
    
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
    syncConfigInputs(['nlp-mode'], config.nlp_accuracy);
    syncConfigInputs(['throttle-rate'], config.throttle_rate);
    syncConfigInputs(['https-enabled'], config.enable_https);
    syncConfigInputs(['log-retention'], config.log_retention);
    
    // Update network interface dropdowns with actual values
    updateInterfaceDropdowns(config.upstream_interface, config.distribution_interface);
    
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
  const velocityThresholdEl = document.getElementById('throttle-threshold');
  
  // Network settings
  const upstreamInterfaceEl = document.getElementById('upstream-interface');
  const distributionInterfaceEl = document.getElementById('distribution-interface');
  const gatewayIpEl = document.getElementById('gateway-ip');
  const dhcpStartEl = document.getElementById('dhcp-start');
  const dhcpEndEl = document.getElementById('dhcp-end');
  const dnsServersEl = document.getElementById('dns-servers');
  
  // Advanced settings
  const nlpModeEl = document.getElementById('nlp-mode');
  const throttleRateEl = document.getElementById('throttle-rate');
  const httpsEnabledEl = document.getElementById('https-enabled');
  const logRetentionEl = document.getElementById('log-retention');

  const payload = {
    block_harmful: Boolean(blockHarmfulEl?.checked),
    block_distracting: Boolean(blockDistractingEl?.checked),
    throttle_enabled: Boolean(throttleEnabledEl?.checked),
    // Use behavioral logic for backward compatibility in unified form
    request_threshold: document.getElementById('scroll-velocity-preset')?.value === 'custom' 
                       ? Number.parseInt(document.getElementById('scroll-velocity-custom')?.value || '0', 10) 
                       : Number.parseInt(document.getElementById('scroll-velocity-preset')?.value || '0', 10),
    // Network configuration
    upstream_interface: upstreamInterfaceEl?.value || 'enp0s31f6',
    distribution_interface: distributionInterfaceEl?.value || 'wlp1s0',
    gateway_ip: gatewayIpEl?.value || '192.168.10.1',
    dhcp_start: dhcpStartEl?.value || '192.168.10.10',
    dhcp_end: dhcpEndEl?.value || '192.168.10.50',
    upstream_dns: dnsServersEl?.value || '8.8.8.8\n8.8.4.4',
    // Advanced configuration
    nlp_accuracy: nlpModeEl?.value || 'balanced',
    throttle_rate: Number.parseInt(throttleRateEl?.value || '256', 10) || 256,
    enable_https: Boolean(httpsEnabledEl?.checked),
    log_retention: Number.parseInt(logRetentionEl?.value || '30', 10) || 30
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
    const response = await fetch('/api/config');
    if (!response.ok) throw new Error('Failed to fetch configuration');
    const data = await response.json();
    
    const netPreset = document.getElementById('behavioral-network-preset');
    const netCustom = document.getElementById('behavioral-network-custom');
    if (netPreset) netPreset.value = data.network_velocity_preset || 'Medium';
    if (netCustom) netCustom.value = data.network_velocity_custom || 150;
    toggleBehavioralCustom('network');
    
    const scrollPreset = document.getElementById('behavioral-scroll-preset');
    const scrollCustom = document.getElementById('behavioral-scroll-custom');
    if (scrollPreset) scrollPreset.value = data.physical_scroll_preset || 'Medium';
    if (scrollCustom) scrollCustom.value = data.physical_scroll_custom || 75;
    toggleBehavioralCustom('scroll');
    
    const sniEnabled = document.getElementById('behavioral-sni-enabled');
    if (sniEnabled) sniEnabled.checked = data.sni_filtering_enabled;
    if (sniEnabled) {
      const slider = sniEnabled.nextElementSibling;
      if (data.sni_filtering_enabled) slider.classList.add('active');
      else slider.classList.remove('active');
      updateSNIStatusIndicator(sniEnabled);
    }
  } catch (e) {
    console.error(e);
    showToast('Error loading behavioral settings', 'danger');
  }
}

function toggleBehavioralCustom(type) {
  const preset = document.getElementById(`behavioral-${type}-preset`).value;
  const container = document.getElementById(`behavioral-${type}-custom-container`);
  if (preset === 'Custom') {
    container.classList.remove('hidden');
  } else {
    container.classList.add('hidden');
  }
}

async function saveBehavioralSettings(event) {
  event.preventDefault();
  
  const netPreset = document.getElementById('behavioral-network-preset').value;
  const netCustom = document.getElementById('behavioral-network-custom').value;
  const scrollPreset = document.getElementById('behavioral-scroll-preset').value;
  const scrollCustom = document.getElementById('behavioral-scroll-custom').value;
  const sniEnabled = document.getElementById('behavioral-sni-enabled')?.checked;
  
  const payload = {
    network_velocity_preset: netPreset,
    physical_scroll_preset: scrollPreset,
    sni_filtering_enabled: sniEnabled
  };
  
  // Read active values from DOM and cast to integers when Custom is selected
  if (netPreset === 'Custom') {
    const customValue = parseInt(netCustom, 10);
    if (isNaN(customValue) || customValue <= 0) {
      showToast('Network velocity custom value must be a positive integer', 'danger');
      return;
    }
    payload.network_velocity_custom = customValue;
  }
  
  if (scrollPreset === 'Custom') {
    const customValue = parseInt(scrollCustom, 10);
    if (isNaN(customValue) || customValue <= 0) {
      showToast('Physical scroll custom value must be a positive integer', 'danger');
      return;
    }
    payload.physical_scroll_custom = customValue;
  }
  
  try {
    const response = await fetch('/api/config/behavioral', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.status === 'success') {
        showToast('Behavioral settings saved successfully', 'success');
        loadBehavioralSettings(); // Reload to verify
      } else {
        showToast('Failed to save behavioral settings: ' + (data.message || 'Unknown error'), 'danger');
      }
    } else {
      showToast('Failed to save behavioral settings', 'danger');
    }
  } catch (error) {
    showToast('Error saving behavioral settings', 'danger');
  }
}

// ─── Category Hints Management ───
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

// ─── Category Hints Management ───
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

document.getElementById('category-hint-form').addEventListener('submit', async function(e) {
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
      headers: {
        'Content-Type': 'application/json'
      },
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
  const statusText = document.getElementById('sni-status-text');
  if (!statusText) return;
  
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
  try {
    // Get filter values
    const categoryFilter = document.getElementById('traffic-filter-category')?.value || '';
    const clientFilter = document.getElementById('traffic-filter-client')?.value || '';
    const domainFilter = document.getElementById('traffic-filter-domain')?.value || '';
    
    // Combine search filters (client IP or domain)
    const searchFilter = clientFilter || domainFilter;
    
    // Build URL with filter parameters
    let url = `/api/stats?page=${currentPage}&limit=100`;
    if (categoryFilter) {
      url += `&category=${encodeURIComponent(categoryFilter)}`;
    }
    if (searchFilter) {
      url += `&search=${encodeURIComponent(searchFilter)}`;
    }
    
    const response = await fetch(url);
    const data = await response.json();
    const recentRows = Array.isArray(data.recent) ? data.recent : [];

    let trafficHtml = '';
    recentRows.forEach(r => {
      const categoryClass = `category-badge ${String(r.category || 'unclassified').toLowerCase()}`;
      trafficHtml += `
        <tr>
          <td>${r.time}</td>
          <td style="font-family: monospace; font-size: 0.9rem;">${r.client_ip}</td>
          <td>${r.host}</td>
          <td><span class="${categoryClass}">${r.category}</span></td>
          <td>${r.flagged ? '🚫 Blocked' : '✓'}</td>
        </tr>
      `;
    });
    document.getElementById('traffic-tbody').innerHTML = trafficHtml || '<tr><td colspan="5" class="text-center" style="color: var(--text-secondary); padding: 2rem;">No traffic data yet</td></tr>';

    // Update pagination controls
    if (data.pagination) {
      currentPage = Math.max(1, Number(data.pagination.page) || 1);
      totalPages = Math.max(1, Number(data.pagination.total_pages) || 1);
      document.getElementById('current-page').textContent = currentPage;
      document.getElementById('total-pages').textContent = totalPages;
      document.getElementById('total-items').textContent = data.pagination.total_items;
      
      // Enable/disable buttons
      document.getElementById('prev-page').disabled = currentPage <= 1;
      document.getElementById('next-page').disabled = currentPage >= totalPages;
    }
  } catch (e) {
    showToast('Failed to load traffic logs', 'error');
  }
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
    window.location.href = '/api/config/export';
}

function importConfig() {
    // 1. Create a dynamic, hidden file input element
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json';
    
    // 2. Listen for when the user selects a file
    fileInput.onchange = function(e) {
        const file = e.target.files[0];
        if (!file) return;
        
        showToast('Uploading configuration...', 'info');
        
        // 3. Package the file inside FormData
        const formData = new FormData();
        formData.append('config_file', file);
        
        // 4. Send the multi-part request to our backend API
        fetch('/api/config/import', {
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

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.getElementById('toastContainer').appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
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
    gateway_ip: gatewayIpEl?.value || '192.168.10.1',
    dhcp_start: dhcpStartEl?.value || '192.168.10.10',
    dhcp_end: dhcpEndEl?.value || '192.168.10.50',
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
  startDashboardPolling();
  loadConfigToUI();

  const settingsForm = document.getElementById('settingsForm');
  if (settingsForm) settingsForm.addEventListener('submit', saveConfig);

  const wizardForm = document.getElementById('wizardForm');
  if (wizardForm) wizardForm.addEventListener('submit', saveWizardConfig);

  // Initialize SNI status indicator
  const sniCheckbox = document.getElementById('behavioral-sni-enabled');
  if (sniCheckbox) updateSNIStatusIndicator(sniCheckbox);
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

// ─── SNI Status Indicator ───
function updateSNIStatusIndicator(checkbox) {
  const textIndicator = document.getElementById('sni-status-text');
  if (!textIndicator) return;
  
  if (checkbox.checked) {
    textIndicator.textContent = "ON";
    textIndicator.style.color = "#1A938A";
  } else {
    textIndicator.textContent = "OFF";
    textIndicator.style.color = "rgba(128, 128, 128, 0.6)";
  }
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
      
      const networkLoad = document.getElementById('nerve-network-load');
      if (networkLoad) {
        networkLoad.textContent = 'Network Active';
      }
      
      const shieldIntegrity = document.getElementById('nerve-shield-integrity');
      if (shieldIntegrity) {
        const activeCount = data.devices?.total_connected || data.clients || 0;
        const throttledCount = data.devices?.throttled_count || data.throttles?.length || 0;
        shieldIntegrity.textContent = `${activeCount} Active / ${throttledCount} Throttled`;
      }
      
      // Fetch accurate nerve center metrics
      try {
        const nerveResponse = await fetch('/api/nerve-center/metrics');
        if (nerveResponse.ok) {
          const nerveData = await nerveResponse.json();
          const shieldIntegrity = document.getElementById('nerve-shield-integrity');
          if (shieldIntegrity) {
            shieldIntegrity.textContent = `${nerveData.active_count} Active / ${nerveData.throttled_count} Throttled`;
          }
          const nlpStatus = document.getElementById('nerve-nlp-status');
          if (nlpStatus) {
            nlpStatus.textContent = nerveData.nlp_status;
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
      
    } catch (error) {
      console.error('Polling error:', error);
    }
  };
  
  fetchSummary();
  dashboardPollInterval = setInterval(fetchSummary, 3000);
}

window.addEventListener('DOMContentLoaded', initTheme);
