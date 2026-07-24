// VIGILANT Dashboard JavaScript

// Theme Management
const themeToggle = document.getElementById('themeToggle');
const html = document.documentElement;

// Load saved theme
const savedTheme = localStorage.getItem('vigilant-theme') || 'light';
html.setAttribute('data-theme', savedTheme);
updateThemeIcon();

themeToggle.addEventListener('click', () => {
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('vigilant-theme', newTheme);
    updateThemeIcon();
});

function updateThemeIcon() {
    const theme = html.getAttribute('data-theme');
    themeToggle.textContent = theme === 'light' ? '🌙' : '☀️';
}

// Mobile Menu Toggle
const menuToggle = document.getElementById('menuToggle');
const sidebar = document.getElementById('sidebar');

menuToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
});

// Close sidebar when clicking outside on mobile
document.addEventListener('click', (e) => {
    if (window.innerWidth <= 1024) {
        if (!sidebar.contains(e.target) && !menuToggle.contains(e.target)) {
            sidebar.classList.remove('open');
        }
    }
});

// Toast Notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <span>${icons[type]}</span>
        <span>${message}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Modal Functions
function showModal(content) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = content;
    document.body.appendChild(overlay);
    
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            closeModal(overlay);
        }
    });
    
    const closeBtn = overlay.querySelector('.modal-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => closeModal(overlay));
    }
    
    return overlay;
}

function closeModal(overlay) {
    overlay.style.opacity = '0';
    setTimeout(() => overlay.remove(), 200);
}

// API Helper Functions
async function apiGet(endpoint) {
    try {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error('API request failed');
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        showToast('Failed to fetch data', 'error');
        return null;
    }
}

async function apiPost(endpoint, data) {
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!response.ok) throw new Error('API request failed');
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        showToast('Failed to save data', 'error');
        return null;
    }
}

// Format functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatDate(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

// Service Status Polling
async function updateServiceStatus() {
    const services = await apiGet('/api/services');
    if (services) {
        const proxyStatus = document.getElementById('proxyStatus');
        const firewallStatus = document.getElementById('firewallStatus');
        
        if (proxyStatus) {
            proxyStatus.className = 'status-dot ' + (services.proxy?.status === 'running' ? '' : 'error');
        }
        if (firewallStatus) {
            firewallStatus.className = 'status-dot ' + (services.firewall?.status === 'active' ? '' : 'error');
        }
    }
}

// Poll service status every 30 seconds
setInterval(updateServiceStatus, 30000);
updateServiceStatus();

// Tab Management
function setupTabs(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const tabs = container.querySelectorAll('.tab');
    const tabContents = container.querySelectorAll('.tab-content');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetId = tab.dataset.tab;
            
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            tab.classList.add('active');
            const targetContent = container.querySelector(`[data-tab-content="${targetId}"]`);
            if (targetContent) {
                targetContent.classList.add('active');
            }
        });
    });
}

// Form Validation
function validateForm(form) {
    const inputs = form.querySelectorAll('input[required], select[required]');
    let valid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.style.borderColor = 'var(--danger)';
            valid = false;
        } else {
            input.style.borderColor = '';
        }
    });
    
    return valid;
}

// Confirmation Dialog
function confirmAction(message, callback) {
    const modal = showModal(`
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Confirm Action</h3>
                <button class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <p>${message}</p>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary modal-close">Cancel</button>
                <button class="btn btn-danger" id="confirmBtn">Confirm</button>
            </div>
        </div>
    `);
    
    const confirmBtn = modal.querySelector('#confirmBtn');
    confirmBtn.addEventListener('click', () => {
        closeModal(modal);
        callback();
    });
}

// Auto-refresh for dashboard pages
let refreshInterval = null;

function startAutoRefresh(callback, interval = 5000) {
    if (refreshInterval) clearInterval(refreshInterval);
    callback();
    refreshInterval = setInterval(callback, interval);
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Setup any tabs on the page
    document.querySelectorAll('[id^="tabs-"]').forEach(setupTabs);
    
    // Add loading states to forms
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', async (e) => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner"></span> Saving...';
            }
        });
    });
});

// Tab Switching Function
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Remove active class from all nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Show selected tab content
    const tabContent = document.getElementById(`tab-${tabName}`);
    if (tabContent) {
        tabContent.classList.add('active');
    }
    
    // Add active class to selected nav item
    const navItem = document.querySelector(`.nav-item[onclick="switchTab('${tabName}')"]`);
    if (navItem) {
        navItem.classList.add('active');
    }
    
    // Load data for specific tabs
    if (tabName === 'device-management') {
        loadThrottledDevices();
        loadActiveDevices();
        loadLeasedDevices();
    } else if (tabName === 'traffic-logs') {
        loadTrafficLogs();
    } else if (tabName === 'sni-monitoring') {
        refreshSNI();
    }
}

// Sidebar Toggle Function
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.toggle('open');
    }
}

// Theme Toggle Function
function toggleThemeMode(isDark) {
    const html = document.documentElement;
    if (isDark) {
        html.setAttribute('data-theme', 'dark');
        localStorage.setItem('vigilant-theme', 'dark');
    } else {
        html.setAttribute('data-theme', 'light');
        localStorage.setItem('vigilant-theme', 'light');
    }
    
    // Save to server
    apiPost('/api/config/ui-theme', { theme: isDark ? 'dark' : 'light' });
}

// System Control Function
async function executeSystemControl(action, buttonElement) {
    if (!buttonElement) return;
    
    const originalText = buttonElement.textContent;
    buttonElement.disabled = true;
    buttonElement.innerHTML = '<span class="spinner"></span> Processing...';
    
    try {
        const result = await apiPost('/api/system/control', { action });
        if (result && result.status === 'success') {
            showToast(result.message || 'Action completed successfully', 'success');
        } else {
            showToast(result?.error || 'Action failed', 'error');
        }
    } catch (error) {
        showToast('Failed to execute system control', 'error');
    } finally {
        buttonElement.disabled = false;
        buttonElement.textContent = originalText;
    }
}

// Device Management Functions
async function loadThrottledDevices() {
    const tbody = document.getElementById('throttled-tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center;">Loading...</td></tr>';
    
    try {
        const result = await apiGet('/api/devices/throttled');
        if (result && result.devices) {
            if (result.devices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No throttled devices</td></tr>';
            } else {
                tbody.innerHTML = result.devices.map(device => `
                    <tr>
                        <td>${device.hostname || 'Unknown'}</td>
                        <td>${device.ip_address}</td>
                        <td><span class="category-badge distracting">Throttled</span></td>
                        <td>
                            <button class="btn-secondary" onclick="releaseThrottle('${device.ip_address}')" style="padding: 0.25rem 0.5rem; font-size: 0.8rem;">Release</button>
                        </td>
                    </tr>
                `).join('');
            }
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--danger);">Failed to load throttled devices</td></tr>';
    }
}

async function loadActiveDevices() {
    const tbody = document.getElementById('active-tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="2" style="text-align: center;">Loading...</td></tr>';
    
    try {
        const result = await apiGet('/api/devices/active');
        if (result && result.devices) {
            if (result.devices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary);">No active devices</td></tr>';
            } else {
                tbody.innerHTML = result.devices.map(device => `
                    <tr>
                        <td>${device.hostname || 'Unknown'}</td>
                        <td>${device.ip_address}</td>
                    </tr>
                `).join('');
            }
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--danger);">Failed to load active devices</td></tr>';
    }
}

async function loadLeasedDevices() {
    const tbody = document.getElementById('leased-tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center;">Loading...</td></tr>';
    
    try {
        const result = await apiGet('/api/devices');
        if (result && result.devices) {
            if (result.devices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No leased devices</td></tr>';
            } else {
                tbody.innerHTML = result.devices.map(device => `
                    <tr>
                        <td>${device.hostname || 'Unknown'}</td>
                        <td>${device.ip_address}</td>
                        <td>${device.mac_address || 'Unknown'}</td>
                        <td>${device.policy || 'none'}</td>
                    </tr>
                `).join('');
            }
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--danger);">Failed to load leased devices</td></tr>';
    }
}

async function releaseThrottle(ipAddress) {
    try {
        const result = await apiPost('/api/devices/release-throttle', { ip_address: ipAddress });
        if (result && result.status === 'success') {
            showToast(`Throttle released for ${ipAddress}`, 'success');
            loadThrottledDevices();
        } else {
            showToast(result?.error || 'Failed to release throttle', 'error');
        }
    } catch (error) {
        showToast('Failed to release throttle', 'error');
    }
}

// Traffic Logs Functions
async function loadTrafficLogs() {
    const tbody = document.getElementById('traffic-tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">Loading...</td></tr>';
    
    try {
        const clientFilter = document.getElementById('traffic-filter-client')?.value || '';
        const domainFilter = document.getElementById('traffic-filter-domain')?.value || '';
        const categoryFilter = document.getElementById('traffic-filter-category')?.value || '';
        const blockReasonFilter = document.getElementById('block-reason-filter')?.value || '';
        
        const params = new URLSearchParams();
        if (clientFilter) params.append('client_ip', clientFilter);
        if (domainFilter) params.append('host', domainFilter);
        if (categoryFilter) params.append('category', categoryFilter);
        if (blockReasonFilter) params.append('block_reason', blockReasonFilter);
        
        const result = await apiGet(`/api/logs/traffic?${params.toString()}`);
        if (result && result.logs) {
            if (result.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">No traffic logs found</td></tr>';
            } else {
                tbody.innerHTML = result.logs.map(log => `
                    <tr>
                        <td>${formatDate(log.timestamp)}</td>
                        <td>${log.client_ip}</td>
                        <td>${log.host}</td>
                        <td><span class="category-badge ${log.category?.toLowerCase()}">${log.category || 'Unclassified'}</span></td>
                        <td>${log.block_reason || '-'}</td>
                        <td>${log.flagged ? '<span style="color: var(--danger);">Blocked</span>' : '<span style="color: var(--success);">Allowed</span>'}</td>
                    </tr>
                `).join('');
            }
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--danger);">Failed to load traffic logs</td></tr>';
    }
}

function applyFilters() {
    loadTrafficLogs();
}

async function clearTrafficLogs() {
    if (!confirm('Are you sure you want to clear all traffic logs? This action cannot be undone.')) {
        return;
    }
    
    try {
        const result = await apiPost('/api/logs/clear');
        if (result && result.status === 'success') {
            showToast('Traffic logs cleared successfully', 'success');
            loadTrafficLogs();
        } else {
            showToast(result?.error || 'Failed to clear logs', 'error');
        }
    } catch (error) {
        showToast('Failed to clear traffic logs', 'error');
    }
}

// SNI Dashboard Functions
async function refreshSNI() {
    const tbody = document.getElementById('sni-log-table');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center;">Loading...</td></tr>';
    
    try {
        const result = await apiGet('/api/sni/requests');
        if (result && result.requests) {
            if (result.requests.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No SNI requests found</td></tr>';
            } else {
                tbody.innerHTML = result.requests.map(req => `
                    <tr>
                        <td>${formatDate(req.timestamp)}</td>
                        <td>${req.client_ip}</td>
                        <td>${req.domain}</td>
                        <td>${req.velocity_rps?.toFixed(2) || '0.00'}</td>
                    </tr>
                `).join('');
            }
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--danger);">Failed to load SNI requests</td></tr>';
    }
}

// Configuration Functions
async function exportConfig() {
    try {
        window.location.href = '/api/config/setup/export';
        showToast('Configuration export started', 'success');
    } catch (error) {
        showToast('Failed to export configuration', 'error');
    }
}

function importConfig() {
    // Trigger file upload dialog
    const fileInput = document.querySelector('input[type="file"][name="config_file"]');
    if (fileInput) {
        fileInput.click();
    } else {
        showToast('Import form not found', 'error');
    }
}

function confirmReset() {
    const modal = document.getElementById('confirmModal');
    const message = document.getElementById('modalMessage');
    const confirmBtn = document.getElementById('confirmBtn');
    
    if (modal && message && confirmBtn) {
        message.textContent = 'This will reset all settings to factory defaults. This action cannot be undone. Are you sure you want to continue?';
        modal.classList.add('active');
        
        confirmBtn.onclick = async function() {
            try {
                const result = await apiPost('/api/config/reset');
                if (result && result.status === 'success') {
                    showToast('Configuration reset successfully', 'success');
                    closeModal('confirmModal');
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showToast(result?.error || 'Failed to reset configuration', 'error');
                }
            } catch (error) {
                showToast('Failed to reset configuration', 'error');
            }
        };
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

function executeConfirm() {
    // This is a placeholder - actual implementation depends on context
    closeModal('confirmModal');
}

// Help Toolkit Function
function showHelpToolkit() {
    const modal = document.getElementById('toolkitModal');
    const title = document.getElementById('toolkitTitle');
    const content = document.getElementById('toolkitContent');
    
    if (modal && title && content) {
        title.textContent = 'VIGILANT Gateway Help';
        content.innerHTML = `
            <h4 style="margin-bottom: 0.5rem;">Quick Start Guide</h4>
            <ul style="margin-left: 1.5rem; margin-bottom: 1rem;">
                <li>Configure your network interfaces in the Setup tab</li>
                <li>Add keywords to block in the Content Filtering tab</li>
                <li>Set up behavioral controls in the Behavioral Control tab</li>
                <li>Monitor traffic and devices in the respective tabs</li>
            </ul>
            <h4 style="margin-bottom: 0.5rem;">Troubleshooting</h4>
            <ul style="margin-left: 1.5rem; margin-bottom: 1rem;">
                <li>If devices aren't connecting, check your DHCP settings</li>
                <li>If filtering isn't working, verify mitmproxy is running</li>
                <li>Check system logs for detailed error messages</li>
            </ul>
            <h4 style="margin-bottom: 0.5rem;">Support</h4>
            <p>For additional help, refer to the documentation or contact support.</p>
        `;
        modal.classList.add('active');
    }
}

// Behavioral Settings Functions
function toggleBehavioralCustom(type) {
    const presetSelect = document.getElementById(`behavioral-${type}-preset`);
    const customContainer = document.getElementById(`behavioral-${type}-custom-container`);
    
    if (presetSelect && customContainer) {
        if (presetSelect.value === 'Custom') {
            customContainer.classList.remove('hidden');
        } else {
            customContainer.classList.add('hidden');
        }
    }
}

function updateSNIStatusIndicator(checkbox) {
    const statusText = document.getElementById('sni-status-text');
    if (statusText) {
        if (checkbox.checked) {
            statusText.textContent = 'ON';
            statusText.style.color = '#1A938A';
        } else {
            statusText.textContent = 'OFF';
            statusText.style.color = 'var(--danger)';
        }
    }
}

async function saveBehavioralSettings(event) {
    event.preventDefault();
    
    const form = event.target;
    const saveBtn = document.getElementById('behavioral-save-btn');
    
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<span class="spinner"></span> Saving...';
    }
    
    try {
        const formData = {
            network_velocity_preset: document.getElementById('behavioral-network-preset')?.value,
            network_velocity_custom: document.getElementById('behavioral-network-custom')?.value,
            physical_scroll_preset: document.getElementById('behavioral-scroll-preset')?.value,
            physical_scroll_custom: document.getElementById('behavioral-scroll-custom')?.value,
            sni_filtering_enabled: document.getElementById('behavioral-sni-enabled')?.checked
        };
        
        const result = await apiPost('/api/config/behavioral', formData);
        if (result && result.status === 'success') {
            showToast('Behavioral settings saved successfully', 'success');
        } else {
            showToast(result?.error || 'Failed to save behavioral settings', 'error');
        }
    } catch (error) {
        showToast('Failed to save behavioral settings', 'error');
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.innerHTML = '<i class="fa-solid fa-save"></i> Save Settings';
        }
    }
}

// Settings Functions
function toggleAdvancedSettings() {
    const advancedSettings = document.getElementById('advanced-settings');
    const toggle = document.getElementById('advanced-toggle');
    
    if (advancedSettings && toggle) {
        if (toggle.checked) {
            advancedSettings.classList.remove('d-none');
        } else {
            advancedSettings.classList.add('d-none');
        }
    }
}

function toggleTheme(theme) {
    const html = document.documentElement;
    html.setAttribute('data-theme', theme);
    localStorage.setItem('vigilant-theme', theme);
}

async function saveUnifiedConfig(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    const config = {};
    
    formData.forEach((value, key) => {
        config[key] = value;
    });
    
    // Handle checkboxes
    const checkboxes = form.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        config[checkbox.id] = checkbox.checked;
    });
    
    try {
        const result = await apiPost('/api/config/setup', config);
        if (result && result.status === 'success') {
            showToast('Configuration saved successfully', 'success');
        } else {
            showToast(result?.error || 'Failed to save configuration', 'error');
        }
    } catch (error) {
        showToast('Failed to save configuration', 'error');
    }
}

function resetConfiguration() {
    confirmReset();
}

// Export for use in page-specific scripts
window.Vigilant = {
    showToast,
    showModal,
    closeModal,
    apiGet,
    apiPost,
    formatBytes,
    formatNumber,
    formatDate,
    confirmAction,
    startAutoRefresh,
    stopAutoRefresh,
    switchTab,
    toggleSidebar,
    toggleThemeMode,
    executeSystemControl,
    loadThrottledDevices,
    loadActiveDevices,
    loadLeasedDevices,
    loadTrafficLogs,
    applyFilters,
    clearTrafficLogs,
    refreshSNI,
    exportConfig,
    importConfig,
    confirmReset,
    showHelpToolkit,
    toggleBehavioralCustom,
    updateSNIStatusIndicator,
    saveBehavioralSettings,
    toggleAdvancedSettings,
    toggleTheme,
    saveUnifiedConfig
};
