// API Configuration
const API_BASE = 'http://localhost:8000';

// Cache Configuration
const CACHE_DURATION_MS = 30 * 60 * 1000; // 30 minutes

// State
let currentDomain = null;
let isScanning = false;
let lastScannedDomain = null;

// DOM Elements
const targetDomainEl = document.getElementById('targetDomain');
const loadingContainer = document.getElementById('loadingContainer');
const errorContainer = document.getElementById('errorContainer');
const resultsContainer = document.getElementById('resultsContainer');
const progressBar = document.getElementById('progressBar');
const errorMessage = document.getElementById('errorMessage');
const retryBtn = document.getElementById('retryBtn');
const scanTimeEl = document.getElementById('scanTime');
const rescanBtn = document.getElementById('rescanBtn');

// Initialize
document.addEventListener('DOMContentLoaded', initialize);
retryBtn.addEventListener('click', () => startScan(currentDomain, true));
if (rescanBtn) {
    rescanBtn.addEventListener('click', () => startScan(currentDomain, true));
}

/**
 * Get cached scan results for a domain
 */
async function getCachedResults(domain) {
    return new Promise((resolve) => {
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.get(['scanCache'], (result) => {
                const cache = result.scanCache || {};
                const cached = cache[domain];

                if (cached && (Date.now() - cached.timestamp < CACHE_DURATION_MS)) {
                    resolve(cached.data);
                } else {
                    resolve(null);
                }
            });
        } else {
            // Fallback for testing without chrome API
            resolve(null);
        }
    });
}

/**
 * Save scan results to cache
 */
async function saveCachedResults(domain, data) {
    return new Promise((resolve) => {
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.get(['scanCache'], (result) => {
                const cache = result.scanCache || {};
                cache[domain] = {
                    data: data,
                    timestamp: Date.now()
                };
                chrome.storage.local.set({ scanCache: cache }, resolve);
            });
        } else {
            resolve();
        }
    });
}

/**
 * Clear cache for a specific domain
 */
async function clearCacheForDomain(domain) {
    return new Promise((resolve) => {
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.get(['scanCache'], (result) => {
                const cache = result.scanCache || {};
                delete cache[domain];
                chrome.storage.local.set({ scanCache: cache }, resolve);
            });
        } else {
            resolve();
        }
    });
}

/**
 * Initialize the extension
 */
async function initialize() {
    try {
        // Get current tab URL
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.url) {
            showError('Unable to get current tab URL');
            return;
        }

        // Extract domain from URL
        const url = new URL(tab.url);

        // Check if it's a valid scannable URL
        if (!url.hostname || url.protocol === 'chrome:' || url.protocol === 'chrome-extension:') {
            targetDomainEl.textContent = 'N/A';
            showError('Cannot scan browser internal pages. Navigate to a website first.');
            return;
        }

        currentDomain = url.hostname;
        targetDomainEl.textContent = currentDomain;

        // Check for cached results
        const cachedData = await getCachedResults(currentDomain);
        if (cachedData) {
            lastScannedDomain = currentDomain;
            renderResults(cachedData, true);
            return;
        }

        // Start scanning
        startScan(currentDomain);

    } catch (error) {
        console.error('Initialization error:', error);
        showError('Failed to initialize: ' + error.message);
    }
}

/**
 * Start domain scan
 */
async function startScan(domain, forceRefresh = false) {
    if (isScanning) return;
    isScanning = true;

    // Clear cache if force refresh
    if (forceRefresh) {
        await clearCacheForDomain(domain);
    }

    // Reset UI
    showLoading();
    simulateProgress();

    try {
        const response = await fetch(`${API_BASE}/scan?domain=${encodeURIComponent(domain)}`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `HTTP ${response.status}`);
        }

        const data = await response.json();
        completeProgress();

        // Save to cache
        await saveCachedResults(domain, data);
        lastScannedDomain = domain;

        // Small delay for visual effect
        setTimeout(() => {
            renderResults(data, false);
        }, 300);

    } catch (error) {
        console.error('Scan error:', error);

        let errorMsg = error.message;
        if (error.message.includes('Failed to fetch')) {
            errorMsg = 'Cannot connect to Spectre backend. Please ensure the server is running on localhost:8000';
        }

        showError(errorMsg);
    } finally {
        isScanning = false;
    }
}

/**
 * Simulate progress bar animation
 */
function simulateProgress() {
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 90) {
            progress = 90;
            clearInterval(interval);
        }
        progressBar.style.width = `${progress}%`;
    }, 200);

    // Store interval ID for cleanup
    progressBar.dataset.intervalId = interval;
}

/**
 * Complete progress bar
 */
function completeProgress() {
    const intervalId = progressBar.dataset.intervalId;
    if (intervalId) {
        clearInterval(parseInt(intervalId));
    }
    progressBar.style.width = '100%';
}

/**
 * Show loading state
 */
function showLoading() {
    loadingContainer.style.display = 'flex';
    errorContainer.style.display = 'none';
    resultsContainer.style.display = 'none';
    progressBar.style.width = '0%';
}

/**
 * Show error state
 */
function showError(message) {
    loadingContainer.style.display = 'none';
    errorContainer.style.display = 'flex';
    resultsContainer.style.display = 'none';
    errorMessage.textContent = message;
}

/**
 * Show results
 */
function showResults() {
    loadingContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    resultsContainer.style.display = 'flex';
}

/**
 * Toggle section collapse
 */
function toggleSection(sectionId) {
    const section = document.getElementById(`${sectionId}Section`);
    if (section) {
        section.classList.toggle('collapsed');
    }
}

// Make toggleSection globally accessible
window.toggleSection = toggleSection;

/**
 * Render scan results
 */
function renderResults(data, fromCache = false) {
    showResults();

    // Update scan time with cache indicator
    if (fromCache) {
        scanTimeEl.textContent = `Cached • ${data.scan_duration_seconds}s`;
        scanTimeEl.classList.add('cached');
    } else {
        scanTimeEl.textContent = `Scanned in ${data.scan_duration_seconds}s`;
        scanTimeEl.classList.remove('cached');
    }

    // Render each section
    renderWhois(data.whois);
    renderIP(data.ip_hosting);
    renderSSL(data.ssl);
    renderTechStack(data.tech_stack);
    renderSubdomains(data.subdomains);
    renderHistorical(data.historical);
}

/**
 * Render Whois section
 */
function renderWhois(data) {
    const container = document.getElementById('whoisData');
    const status = document.getElementById('whoisStatus');

    if (!data.success) {
        status.textContent = 'ERROR';
        status.className = 'section-status error';
        container.innerHTML = `<div class="data-row"><span class="data-value danger">${data.error || 'Failed to fetch WHOIS data'}</span></div>`;
        return;
    }

    // Set status based on expiry warning
    if (data.expiry_warning) {
        status.textContent = 'EXPIRING';
        status.className = 'section-status warning';
    } else {
        status.textContent = 'OK';
        status.className = 'section-status success';
    }

    const rows = [
        { label: 'Registrar', value: data.registrar },
        { label: 'Organization', value: data.organization },
        { label: 'Created', value: data.creation_date },
        { label: 'Expires', value: data.expiration_date, class: data.expiry_warning ? 'danger' : '' },
        { label: 'Days Until Expiry', value: data.days_until_expiry !== null ? data.days_until_expiry : 'Unknown', class: data.expiry_warning ? 'danger' : 'highlight' },
        { label: 'Country', value: data.registrant_country },
    ];

    container.innerHTML = rows.map(row => `
        <div class="data-row">
            <span class="data-label">${row.label}</span>
            <span class="data-value ${row.class || ''}">${row.value}</span>
        </div>
    `).join('');

    // Add nameservers
    if (data.name_servers && data.name_servers.length > 0) {
        container.innerHTML += `
            <div class="data-row">
                <span class="data-label">Nameservers</span>
                <span class="data-value">${data.name_servers.slice(0, 3).join(', ')}</span>
            </div>
        `;
    }
}

/**
 * Render IP & Hosting section
 */
function renderIP(data) {
    const container = document.getElementById('ipData');
    const status = document.getElementById('ipStatus');

    if (!data.success) {
        status.textContent = 'ERROR';
        status.className = 'section-status error';
        container.innerHTML = `<div class="data-row"><span class="data-value danger">${data.error || 'Failed to resolve IP'}</span></div>`;
        return;
    }

    status.textContent = data.waf_detected ? 'WAF' : 'OK';
    status.className = data.waf_detected ? 'section-status warning' : 'section-status success';

    let html = `
        <div class="data-row">
            <span class="data-label">IP Address</span>
            <span class="data-value highlight">${data.ip_address}</span>
        </div>
        <div class="data-row">
            <span class="data-label">Location</span>
            <span class="data-value">${data.city}, ${data.country}</span>
        </div>
        <div class="data-row">
            <span class="data-label">ISP</span>
            <span class="data-value">${data.isp}</span>
        </div>
        <div class="data-row">
            <span class="data-label">ASN</span>
            <span class="data-value">${data.asn}</span>
        </div>
    `;

    if (data.waf_detected) {
        html += `
            <div class="data-row">
                <span class="data-label">WAF/CDN</span>
                <span class="data-value">
                    <span class="waf-badge">
                        <span class="waf-icon">🛡️</span>
                        <span class="waf-text">${data.waf_provider} Detected</span>
                    </span>
                </span>
            </div>
        `;
    }

    if (data.is_proxy) {
        html += `
            <div class="data-row">
                <span class="data-label">Proxy</span>
                <span class="data-value warning">Yes</span>
            </div>
        `;
    }

    container.innerHTML = html;
}

/**
 * Render SSL section
 */
function renderSSL(data) {
    const container = document.getElementById('sslData');
    const status = document.getElementById('sslStatus');

    if (!data.success) {
        status.textContent = 'ERROR';
        status.className = 'section-status error';
        container.innerHTML = `<div class="data-row"><span class="data-value danger">${data.error || 'Failed to fetch SSL certificate'}</span></div>`;
        return;
    }

    // Determine status
    if (data.is_expired) {
        status.textContent = 'EXPIRED';
        status.className = 'section-status error';
    } else if (data.expiring_soon) {
        status.textContent = 'EXPIRING';
        status.className = 'section-status warning';
    } else {
        status.textContent = 'VALID';
        status.className = 'section-status success';
    }

    const daysClass = data.is_expired ? 'danger' : (data.expiring_soon ? 'warning' : 'success');

    container.innerHTML = `
        <div class="data-row">
            <span class="data-label">Issuer</span>
            <span class="data-value">${data.issuer}</span>
        </div>
        <div class="data-row">
            <span class="data-label">Subject</span>
            <span class="data-value highlight">${data.subject}</span>
        </div>
        <div class="data-row">
            <span class="data-label">Valid From</span>
            <span class="data-value">${data.valid_from}</span>
        </div>
        <div class="data-row">
            <span class="data-label">Valid To</span>
            <span class="data-value">${data.valid_to}</span>
        </div>
        <div class="data-row">
            <span class="data-label">Days Remaining</span>
            <span class="data-value ${daysClass}">${data.days_remaining}</span>
        </div>
        <div class="data-row">
            <span class="data-label">Protocol</span>
            <span class="data-value">${data.protocol_version}</span>
        </div>
    `;
}

/**
 * Render Tech Stack section
 */
function renderTechStack(data) {
    const container = document.getElementById('techData');
    const status = document.getElementById('techStatus');

    if (!data.success) {
        status.textContent = 'ERROR';
        status.className = 'section-status error';
        container.innerHTML = `<div class="data-row"><span class="data-value danger">${data.error || 'Failed to analyze tech stack'}</span></div>`;
        return;
    }

    // Set status based on vulnerabilities
    if (data.has_vulnerabilities) {
        status.textContent = 'CVE';
        status.className = 'section-status error';
    } else {
        status.textContent = 'SAFE';
        status.className = 'section-status success';
    }

    let html = '';

    // Technologies
    if (data.technologies && data.technologies.length > 0) {
        data.technologies.forEach(tech => {
            html += `
                <div class="data-row">
                    <span class="data-label">${tech.name}</span>
                    <span class="data-value">${tech.value}</span>
                </div>
            `;
        });
    } else {
        html += `
            <div class="data-row">
                <span class="data-label">Technologies</span>
                <span class="data-value text-muted">No identifying headers found</span>
            </div>
        `;
    }

    // Vulnerabilities
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        html += `<div class="data-row" style="flex-direction: column; align-items: flex-start;">
            <span class="data-label" style="margin-bottom: 8px;">⚠️ Potential Vulnerabilities</span>
            <div style="display: flex; flex-wrap: wrap; gap: 4px;">`;

        data.vulnerabilities.forEach(vuln => {
            html += `
                <span class="cve-badge">
                    <span class="cve-icon">🔴</span>
                    <span class="cve-text">${vuln.cve}</span>
                </span>
            `;
        });

        html += `</div></div>`;
    }

    // Missing security headers
    if (data.missing_security_headers && data.missing_security_headers.length > 0) {
        html += `<div class="data-row" style="flex-direction: column; align-items: flex-start;">
            <span class="data-label" style="margin-bottom: 8px;">Missing Security Headers</span>
            <div style="display: flex; flex-wrap: wrap; gap: 4px;">`;

        data.missing_security_headers.forEach(header => {
            html += `<span class="missing-header-badge">${header}</span>`;
        });

        html += `</div></div>`;
    }

    container.innerHTML = html;
}

/**
 * Render Subdomains section
 */
function renderSubdomains(data) {
    const container = document.getElementById('subdomainsList');
    const status = document.getElementById('subdomainsStatus');

    if (!data.success) {
        status.textContent = 'ERROR';
        status.className = 'section-status error';
        container.innerHTML = `<div class="data-row"><span class="data-value danger">${data.error || 'Failed to discover subdomains'}</span></div>`;
        return;
    }

    status.textContent = data.total_found;
    status.className = 'section-status success';

    if (data.subdomains && data.subdomains.length > 0) {
        let html = data.subdomains.map(subdomain => `
            <div class="subdomain-item">
                <span class="subdomain-bullet"></span>
                <span class="subdomain-name">${subdomain}</span>
            </div>
        `).join('');

        if (data.total_found > data.displayed) {
            html += `<div class="subdomain-count">Showing ${data.displayed} of ${data.total_found} discovered</div>`;
        }

        container.innerHTML = html;
    } else {
        container.innerHTML = `<div class="subdomain-count">No subdomains discovered</div>`;
    }
}

/**
 * Render Historical section (Pro Feature)
 */
function renderHistorical(data) {
    const container = document.getElementById('historicalData');

    if (!data.success) {
        container.innerHTML = `<div class="data-row"><span class="data-value danger">Historical data unavailable</span></div>`;
        return;
    }

    let html = `
        <div class="data-row">
            <span class="data-label">Domain Age</span>
            <span class="data-value highlight">${data.total_age_years} years</span>
        </div>
        <div class="data-row">
            <span class="data-label">Ownership Changes</span>
            <span class="data-value">${data.ownership_changes}</span>
        </div>
    `;

    // Previous Registrars
    if (data.previous_registrars && data.previous_registrars.length > 0) {
        html += `<div class="data-row" style="flex-direction: column; align-items: flex-start;">
            <span class="data-label" style="margin-bottom: 8px;">Previous Registrars</span>`;

        data.previous_registrars.forEach(reg => {
            html += `
                <div style="width: 100%; display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <span style="color: var(--text-primary); font-size: 10px;">${reg.registrar}</span>
                    <span style="color: var(--text-muted); font-size: 10px;">${reg.period}</span>
                </div>
            `;
        });

        html += `</div>`;
    }

    // Drop History Timeline
    if (data.drop_history && data.drop_history.length > 0) {
        html += `<div style="margin-top: 12px;">
            <span class="data-label" style="display: block; margin-bottom: 8px;">History Timeline</span>
            <div class="timeline">`;

        data.drop_history.forEach(event => {
            html += `
                <div class="timeline-item">
                    <div class="timeline-date">${event.date}</div>
                    <div class="timeline-event">${event.event}</div>
                </div>
            `;
        });

        html += `</div></div>`;
    }

    // Mock data notice
    if (data.is_mock) {
        html += `
            <div style="margin-top: 12px; padding: 8px; background: rgba(255, 238, 0, 0.1); border-radius: 4px; text-align: center;">
                <span style="font-size: 9px; color: var(--accent-yellow);">Demo data - Upgrade to Pro for live historical records</span>
            </div>
        `;
    }

    container.innerHTML = html;
}
