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
    stopAutoRefresh
};
