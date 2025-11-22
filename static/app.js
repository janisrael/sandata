// Security Tester - Frontend Logic

let currentScanType = 'general';
let currentResult = null;

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initScanTypeSelector();
    initStartScan();
    initHistoryLoader();
    initExportButton();
});

// Scan Type Selector
function initScanTypeSelector() {
    const buttons = document.querySelectorAll('.scan-type-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentScanType = btn.dataset.type;
        });
    });
}

// Start Scan Button
function initStartScan() {
    const startBtn = document.getElementById('start-scan');
    startBtn.addEventListener('click', startScan);
    
    // Also allow Enter key in input
    document.getElementById('target').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            startScan();
        }
    });
}

// Start Scan Function
async function startScan() {
    let target = document.getElementById('target').value.trim();
    
    if (!target) {
        showNotification('Please enter a target URL', 'error');
        return;
    }
    
    // Auto-add https:// if no protocol specified
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
        target = 'https://' + target;
        // Update the input field to show the corrected URL
        document.getElementById('target').value = target;
        showNotification('Auto-added https:// to URL', 'info');
    }
    
    // Show status card
    const statusCard = document.getElementById('status');
    statusCard.classList.remove('hidden');
    
    const log = document.getElementById('log');
    log.textContent = `[${new Date().toLocaleTimeString()}] Starting ${currentScanType} scan...\n`;
    log.textContent += `[${new Date().toLocaleTimeString()}] Target: ${target}\n`;
    
    // Special warning for Advanced Scan mode
    if (currentScanType === 'advanced') {
        log.textContent += `[${new Date().toLocaleTimeString()}] ⚠️ ADVANCED SCAN MODE: Skipping all general checks\n`;
        log.textContent += `[${new Date().toLocaleTimeString()}] ℹ️ Only selected advanced tests will run\n`;
        showNotification('⚠️ Advanced Scan Mode: Only running selected advanced tests', 'warning');
    }
    
    // Load advanced scan options from localStorage
    const advancedOptions = loadAdvancedScanOptions();
    
    // Show warning if advanced scans are enabled
    const enabledTests = [];
    if (advancedOptions.sqlInjection) {
        enabledTests.push('SQL Injection');
    }
    if (advancedOptions.xssDetection) {
        enabledTests.push('XSS Detection');
    }
    if (advancedOptions.pluginVuln) {
        enabledTests.push('Plugin Vuln Check');
    }
    if (advancedOptions.subdomainEnum) {
        enabledTests.push('Subdomain Enum');
    }
    if (advancedOptions.portScan) {
        enabledTests.push('Port Scanning');
    }
    if (advancedOptions.directoryBruteforce) {
        enabledTests.push('Directory Bruteforce');
    }
    if (advancedOptions.apiDiscovery) {
        enabledTests.push('API Discovery');
    }
    if (advancedOptions.s3BucketCheck) {
        enabledTests.push('S3 Bucket Check');
    }
    
    // Only show advanced tests warning if scan type is actually 'advanced'
    if (enabledTests.length > 0 && currentScanType === 'advanced') {
        log.textContent += `[${new Date().toLocaleTimeString()}] ⚠️ ADVANCED TESTS: ${enabledTests.join(', ')} ENABLED\n`;
        showNotification(`⚠️ Running ${enabledTests.length} ADVANCED test(s) - May be invasive!`, 'warning');
    }
    
    // Hide previous report
    document.getElementById('report').classList.add('hidden');
    
    // Disable button during scan
    const startBtn = document.getElementById('start-scan');
    startBtn.disabled = true;
    startBtn.innerHTML = '<span class="material-icons-round scanning">sync</span> Scanning...';
    
    try {
        log.textContent += `[${new Date().toLocaleTimeString()}] Sending request to scanner...\n`;
        
        const endpoint = currentScanType === 'payment' ? '/api/scan/payment' : '/api/scan';
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin',
            body: JSON.stringify({ 
                target: target,
                async: false,  // Use synchronous scanning (Celery not required)
                options: {
                    scan_type: currentScanType,  // Pass the scan type to backend
                    advanced_sql_injection: advancedOptions.sqlInjection,
                    advanced_xss_detection: advancedOptions.xssDetection,
                    advanced_plugin_vuln: advancedOptions.pluginVuln,
                    advanced_subdomain_enum: advancedOptions.subdomainEnum,
                    advanced_port_scan: advancedOptions.portScan,
                    advanced_directory_bruteforce: advancedOptions.directoryBruteforce,
                    advanced_api_discovery: advancedOptions.apiDiscovery,
                    advanced_s3_bucket_check: advancedOptions.s3BucketCheck
                }
            })
        });
        
        // Check if redirected to login
        if (response.redirected || response.status === 401 || response.status === 302) {
            log.textContent += `[${new Date().toLocaleTimeString()}] Authentication required\n`;
            showNotification('Please login to start scanning', 'error');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
            return;
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Please login to use the scanner');
        }
        
        const data = await response.json();
        
        if (data.error) {
            log.textContent += `[${new Date().toLocaleTimeString()}] Error: ${data.error}\n`;
            showNotification(data.error, 'error');
            return;
        }
        
        log.textContent += `[${new Date().toLocaleTimeString()}] Scan completed. Fetching results...\n`;
        
        // Fetch result
        const resultResponse = await fetch(`/api/results/${data.result_id}`, {
            credentials: 'same-origin'
        });
        
        if (resultResponse.redirected || resultResponse.status === 401) {
            throw new Error('Session expired. Please login again');
        }
        
        const result = await resultResponse.json();
        
        log.textContent += `[${new Date().toLocaleTimeString()}] Results received. Score: ${result.score}/100\n`;
        log.textContent += `[${new Date().toLocaleTimeString()}] Found ${result.details.findings.length} findings\n`;
        
        // Add detailed scan progress logs to status log
        if (result.scan_logs && result.scan_logs.length > 0) {
            log.textContent += `\n━━━ Detailed Scan Progress ━━━\n`;
            result.scan_logs.forEach(logEntry => {
                const timestamp = new Date(logEntry.timestamp);
                const timeStr = timestamp.toLocaleTimeString();
                log.textContent += `[${timeStr}] ${logEntry.message}\n`;
            });
            log.textContent += `━━━ Scan Complete ━━━\n`;
            
            // Auto-scroll to bottom to show latest logs
            log.scrollTop = log.scrollHeight;
        }
        
        // Store current result
        currentResult = result;
        
        // Display report
        displayReport(result);
        
        showNotification('Scan completed successfully!', 'success');
        
    } catch (error) {
        log.textContent += `[${new Date().toLocaleTimeString()}] Fatal error: ${error.message}\n`;
        showNotification(`Scan failed: ${error.message}`, 'error');
    } finally {
        // Re-enable button
        startBtn.disabled = false;
        startBtn.innerHTML = '<span class="material-icons-round">play_arrow</span> Start Scan';
        
        // Stop the status card sync icon from spinning
        const statusIcon = document.querySelector('#status .material-icons-round.scanning');
        if (statusIcon) {
            statusIcon.classList.remove('scanning');
        }
    }
}

// Display Report
function displayReport(result) {
    const reportCard = document.getElementById('report');
    reportCard.classList.remove('hidden');
    
    const reportContent = document.getElementById('report-content');
    reportContent.innerHTML = '';
    
    // Score Display
    const scoreDiv = document.createElement('div');
    scoreDiv.className = 'score-display';
    
    if (result.score >= 85) {
        scoreDiv.classList.add('excellent');
    } else if (result.score >= 70) {
        scoreDiv.classList.add('good');
    } else if (result.score >= 50) {
        scoreDiv.classList.add('warning');
    } else {
        scoreDiv.classList.add('critical');
    }
    
    scoreDiv.innerHTML = `
        <div>${result.score}/100</div>
        <div style="font-size: 1rem; font-weight: 400; color: var(--text-secondary);">Security Score</div>
    `;
    reportContent.appendChild(scoreDiv);
    
    // Target and Scan Info
    const infoSection = document.createElement('div');
    infoSection.className = 'report-section';
    infoSection.innerHTML = `
        <h4><span class="material-icons-round">info</span> Scan Information</h4>
        <div class="meta-info">
            <p><strong>Target:</strong> ${result.target}</p>
            <p><strong>Scan Type:</strong> <span class="scan-type-badge ${result.scan_type}">${result.scan_type}</span></p>
            <p><strong>Scan Time:</strong> ${new Date(result.created_at).toLocaleString()}</p>
            <p><strong>Summary:</strong> ${result.summary}</p>
        </div>
    `;
    reportContent.appendChild(infoSection);
    
    // Scan Progress Logs (NEW!)
    if (result.scan_logs && result.scan_logs.length > 0) {
        const logsSection = document.createElement('div');
        logsSection.className = 'report-section scan-logs-section';
        
        logsSection.innerHTML = `
            <h4><span class="material-icons-round">list_alt</span> Scan Progress Log</h4>
            <div class="recommendations-accordion">
                <button class="accordion-toggle" id="scan-logs-toggle">
                    <span class="material-icons-round">info</span>
                    <span>All security checks performed during this scan. ✓ indicates passed checks, ⚠ indicates warnings, ❌ indicates critical issues.</span>
                    <span class="material-icons-round accordion-icon">expand_more</span>
                </button>
                <div class="accordion-content" id="scan-logs-accordion-content">
                    <div class="scan-logs-container">
                        ${result.scan_logs.map(log => {
                            const timestamp = new Date(log.timestamp);
                            const timeStr = timestamp.toLocaleTimeString();
                            const message = log.message;
                            
                            // Determine log type based on message content
                            let logClass = 'log-info';
                            if (message.includes('✓') || message.toLowerCase().includes('complete') || message.toLowerCase().includes('ok')) {
                                logClass = 'log-success';
                            } else if (message.includes('⚠') || message.toLowerCase().includes('warning') || message.toLowerCase().includes('missing')) {
                                logClass = 'log-warning';
                            } else if (message.includes('❌') || message.toLowerCase().includes('critical') || message.toLowerCase().includes('error')) {
                                logClass = 'log-error';
                            }
                            
                            return `
                                <div class="scan-log-entry ${logClass}">
                                    <span class="log-timestamp">${timeStr}</span>
                                    <span class="log-message">${message}</span>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            </div>
        `;
        
        reportContent.appendChild(logsSection);
    }
    
    // Findings
    const findingsSection = document.createElement('div');
    findingsSection.className = 'report-section';
    
    const findings = result.details.findings || [];
    
    if (findings.length > 0) {
        // Group findings by severity
        const critical = findings.filter(f => f.severity === 'critical');
        const high = findings.filter(f => f.severity === 'high');
        const medium = findings.filter(f => f.severity === 'medium');
        const low = findings.filter(f => f.severity === 'low');
        
        findingsSection.innerHTML = `
            <h4><span class="material-icons-round">bug_report</span> Findings (${findings.length})</h4>
            <div style="margin-bottom: 16px; color: var(--text-secondary);">
                ${critical.length > 0 ? `<span style="color: var(--critical);">● ${critical.length} Critical</span> ` : ''}
                ${high.length > 0 ? `<span style="color: var(--error);">● ${high.length} High</span> ` : ''}
                ${medium.length > 0 ? `<span style="color: var(--warning);">● ${medium.length} Medium</span> ` : ''}
                ${low.length > 0 ? `<span style="color: var(--accent-primary);">● ${low.length} Low</span>` : ''}
            </div>
        `;
        
        const findingsList = document.createElement('ul');
        findingsList.className = 'findings-list';
        
        // Sort by severity
        const sortedFindings = [...critical, ...high, ...medium, ...low];
        
        sortedFindings.forEach((finding, findingIdx) => {
            const li = document.createElement('li');
            li.className = `finding-item ${finding.severity}`;
            
            const hasRecommendations = finding.recommendations && finding.recommendations.length > 0;
            
            // Store finding data for modal
            li.dataset.finding = JSON.stringify(finding);
            
            li.innerHTML = `
                <div>
                    <span class="severity-badge ${finding.severity}">${finding.severity}</span>
                    <span class="finding-title">${finding.title}</span>
                </div>
                <div class="finding-detail" data-finding-idx="${findingIdx}">${finding.detail}</div>
                ${hasRecommendations ? `
                    <div class="recommendations-accordion">
                        <button class="accordion-toggle" data-finding-idx="${findingIdx}">
                            <span class="material-icons-round">construction</span>
                            <span>How to Fix This</span>
                            <span class="material-icons-round accordion-icon">expand_more</span>
                        </button>
                        <div class="accordion-content" id="recommendations-${findingIdx}">
                            <div class="recommendations-list">
                                <h5>Step-by-Step Remediation:</h5>
                                <ol>
                                    ${finding.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                                </ol>
                            </div>
                        </div>
                    </div>
                ` : ''}
            `;
            findingsList.appendChild(li);
        });
        
        findingsSection.appendChild(findingsList);
        
        // Add click handlers for finding details modal
        const findingDetails = findingsSection.querySelectorAll('.finding-detail');
        findingDetails.forEach((detailDiv) => {
            detailDiv.addEventListener('click', function() {
                const findingItem = this.closest('.finding-item');
                const findingData = JSON.parse(findingItem.dataset.finding);
                const targetUrl = result.target || '';
                openFindingModal(findingData, targetUrl);
            });
        });
    } else {
        findingsSection.innerHTML = `
            <h4><span class="material-icons-round">check_circle</span> Findings</h4>
            <div class="meta-info" style="text-align: center; padding: 30px;">
                <span class="material-icons-round" style="font-size: 48px; color: var(--success);">verified</span>
                <p style="margin-top: 16px; color: var(--success); font-size: 1.2rem; font-weight: 600;">
                    No security issues detected!
                </p>
                <p style="color: var(--text-secondary);">
                    This scan found no vulnerabilities. Continue monitoring regularly.
                </p>
            </div>
        `;
    }
    
    reportContent.appendChild(findingsSection);
    
    // Payment Scan Specific Details
    if (result.scan_type === 'payment') {
        displayPaymentDetails(result, reportContent);
    }
    
    // Technical Details
    if (result.details.meta) {
        displayTechnicalDetails(result.details.meta, reportContent);
    }
    
    // Initialize accordion functionality
    initializeAccordions();
    
    // Scroll to report
    reportCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Initialize Accordion Functionality
function initializeAccordions() {
    const accordionToggles = document.querySelectorAll('.accordion-toggle');
    
    accordionToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const icon = this.querySelector('.accordion-icon');
            let content;
            
            // Check if this is the scan logs accordion or a recommendations accordion
            if (this.id === 'scan-logs-toggle') {
                content = document.getElementById('scan-logs-accordion-content');
            } else {
                const findingIdx = this.getAttribute('data-finding-idx');
                content = document.getElementById(`recommendations-${findingIdx}`);
            }
            
            if (!content) return; // Safety check
            
            // Toggle active state
            const isActive = this.classList.contains('active');
            
            if (isActive) {
                // Close
                this.classList.remove('active');
                content.style.maxHeight = null;
                content.style.padding = '0 1rem';
                icon.textContent = 'expand_more';
            } else {
                // Open
                this.classList.add('active');
                content.style.maxHeight = content.scrollHeight + 40 + 'px';
                content.style.padding = '1rem';
                icon.textContent = 'expand_less';
            }
        });
    });
}

// Display Payment-Specific Details
function displayPaymentDetails(result, container) {
    const meta = result.details.meta;
    
    if (meta.payment_gateways && meta.payment_gateways.length > 0) {
        const gatewaySection = document.createElement('div');
        gatewaySection.className = 'report-section';
        gatewaySection.innerHTML = `
            <h4><span class="material-icons-round">account_balance</span> Payment Gateways Detected</h4>
            <div class="meta-info">
                <p>${meta.payment_gateways.join(', ')}</p>
            </div>
        `;
        container.appendChild(gatewaySection);
    }
    
    if (meta.pci_indicators && meta.pci_indicators.length > 0) {
        const pciSection = document.createElement('div');
        pciSection.className = 'report-section';
        pciSection.innerHTML = `
            <h4><span class="material-icons-round">verified_user</span> PCI DSS Indicators</h4>
            <div class="meta-info">
                <ul style="list-style: none; padding-left: 0;">
                    ${meta.pci_indicators.map(ind => `<li>✓ ${ind}</li>`).join('')}
                </ul>
            </div>
        `;
        container.appendChild(pciSection);
    }
    
    if (meta.forms && meta.forms.length > 0) {
        const formsSection = document.createElement('div');
        formsSection.className = 'report-section';
        formsSection.innerHTML = `
            <h4><span class="material-icons-round">web</span> Forms Analyzed</h4>
            <div class="meta-info">
                <p>${meta.forms.length} form(s) detected on page</p>
                ${meta.forms.map((form, idx) => `
                    <div style="margin-top: 12px; padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
                        <strong>Form ${idx + 1}:</strong><br>
                        Method: ${form.method || 'GET'}<br>
                        ${form.csrf_token ? 
                            '<span style="color: var(--success);">✓ CSRF Protection: Yes</span>' : 
                            '<span style="color: var(--error);">✗ CSRF Protection: No</span>'}<br>
                        ${form.payment_fields && form.payment_fields.length > 0 ? 
                            `Payment fields: ${form.payment_fields.length}` : 
                            'No payment fields detected'}
                    </div>
                `).join('')}
            </div>
        `;
        container.appendChild(formsSection);
    }
    
    // CAPTCHA/reCAPTCHA Information
    if (meta.captcha_info) {
        const captchaSection = document.createElement('div');
        captchaSection.className = 'report-section';
        const hasCaptcha = meta.captcha_info.detected;
        captchaSection.innerHTML = `
            <h4><span class="material-icons-round">${hasCaptcha ? 'verified_user' : 'warning'}</span> Bot Protection</h4>
            <div class="meta-info">
                ${hasCaptcha ? 
                    `<p style="color: var(--success);">✓ ${meta.captcha_info.type || 'CAPTCHA'} detected</p>` : 
                    '<p style="color: var(--warning);">⚠ No CAPTCHA/reCAPTCHA protection detected</p>'}
            </div>
        `;
        container.appendChild(captchaSection);
    }
    
    // Form Validation Information
    if (meta.form_validation && meta.form_validation.length > 0) {
        const validationSection = document.createElement('div');
        validationSection.className = 'report-section';
        validationSection.innerHTML = `
            <h4><span class="material-icons-round">rule</span> Form Validation</h4>
            <div class="meta-info">
                ${meta.form_validation.map((val, idx) => `
                    <div style="margin-top: 8px;">
                        <strong>Form ${idx + 1}:</strong><br>
                        ${val.has_required ? '✓' : '✗'} Required fields |
                        ${val.has_pattern ? '✓' : '✗'} Pattern validation |
                        ${val.has_maxlength ? '✓' : '✗'} Length limits |
                        ${val.has_type_validation ? '✓' : '✗'} Type validation
                    </div>
                `).join('')}
            </div>
        `;
        container.appendChild(validationSection);
    }
    
    // .htaccess Security Check
    if (meta.htaccess_info) {
        const htaccessSection = document.createElement('div');
        htaccessSection.className = 'report-section';
        const isExposed = meta.htaccess_info.exposed;
        const isProtected = meta.htaccess_info.protected;
        htaccessSection.innerHTML = `
            <h4><span class="material-icons-round">shield</span> .htaccess Security</h4>
            <div class="meta-info">
                ${isExposed ? 
                    '<p style="color: var(--critical);">✗ .htaccess file is EXPOSED - Critical vulnerability!</p>' :
                    isProtected ? 
                    '<p style="color: var(--success);">✓ .htaccess file is properly protected</p>' :
                    '<p style="color: var(--text-secondary);">○ .htaccess file not detected or not applicable</p>'}
            </div>
        `;
        container.appendChild(htaccessSection);
    }
}

// Display Technical Details
function displayTechnicalDetails(meta, container) {
    const techSection = document.createElement('div');
    techSection.className = 'report-section';
    techSection.innerHTML = '<h4><span class="material-icons-round">code</span> Technical Details</h4>';
    
    const techInfo = document.createElement('div');
    techInfo.className = 'meta-info';
    
    let techHtml = '';
    
    if (meta.status_code) {
        techHtml += `<p><strong>Status Code:</strong> ${meta.status_code}</p>`;
    }
    
    if (meta.response_time_ms) {
        techHtml += `<p><strong>Response Time:</strong> ${meta.response_time_ms}ms</p>`;
    }
    
    if (meta.final_url && meta.final_url !== meta.target) {
        techHtml += `<p><strong>Final URL:</strong> ${meta.final_url}</p>`;
    }
    
    if (meta.tls_info) {
        techHtml += `<p><strong>TLS Version:</strong> ${meta.tls_info.version || 'N/A'}</p>`;
        if (meta.tls_info.expires_days !== undefined) {
            techHtml += `<p><strong>Certificate Expires:</strong> ${meta.tls_info.expires_days} days</p>`;
        }
        if (meta.tls_info.cipher) {
            techHtml += `<p><strong>Cipher:</strong> ${meta.tls_info.cipher}</p>`;
        }
    }
    
    if (meta.tls_expires_days !== undefined) {
        techHtml += `<p><strong>TLS Certificate Expires:</strong> ${meta.tls_expires_days} days</p>`;
    }
    
    techInfo.innerHTML = techHtml;
    techSection.appendChild(techInfo);
    container.appendChild(techSection);
}

// Export to JSON
function initExportButton() {
    document.getElementById('export-btn').addEventListener('click', () => {
        if (!currentResult) {
            showNotification('No scan result to export', 'error');
            return;
        }
        
        const dataStr = JSON.stringify(currentResult, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `security-scan-${currentResult.id}.json`;
        link.click();
        
        URL.revokeObjectURL(url);
        showNotification('Report exported successfully', 'success');
    });
}

// Load History
function initHistoryLoader() {
    document.getElementById('load-history').addEventListener('click', loadHistory);
    // Load history on page load
    loadHistory();
}

async function loadHistory() {
    try {
        const response = await fetch('/api/results', {
            credentials: 'same-origin'
        });
        
        // Check if user needs to login
        if (response.redirected || response.status === 401 || response.status === 302) {
            const historyList = document.getElementById('history-list');
            historyList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">Please <a href="/login" style="color: var(--accent-primary); font-weight: 600;">login</a> to view scan history</p>';
            return;
        }
        
        // Check if response is JSON
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const historyList = document.getElementById('history-list');
            historyList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">Please <a href="/login" style="color: var(--accent-primary); font-weight: 600;">login</a> to view scan history</p>';
            return;
        }
        
        const results = await response.json();
        
        const historyList = document.getElementById('history-list');
        historyList.innerHTML = '';
        
        if (results.length === 0) {
            historyList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">No scan history yet</p>';
            return;
        }
        
        results.slice(0, 10).forEach(result => {
            const item = document.createElement('div');
            item.className = 'history-item';
            
            // Format date properly
            const scanDate = new Date(result.timestamp);
            const dateStr = scanDate.toLocaleDateString();
            const timeStr = scanDate.toLocaleTimeString();
            
            // Get scan type and score (with fallbacks)
            const scanType = result.type || 'general';
            const score = result.score !== null && result.score !== undefined ? result.score : 'N/A';
            
            item.innerHTML = `
                <div class="history-item-header">
                    <div class="history-item-url">${result.target || 'Unknown URL'}</div>
                    <span class="scan-type-badge ${scanType}">${scanType}</span>
                </div>
                <div class="history-item-meta">
                    Score: ${score}/100 • ${dateStr} ${timeStr}
                </div>
            `;
            
            item.addEventListener('click', () => loadResultById(result.id));
            historyList.appendChild(item);
        });
        
    } catch (error) {
        console.error('Failed to load history:', error);
        // Don't show error notification on page load
        const historyList = document.getElementById('history-list');
        if (historyList) {
            historyList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">Login to view scan history</p>';
        }
    }
}

async function loadResultById(id) {
    try {
        const response = await fetch(`/api/results/${id}`, {
            credentials: 'same-origin'
        });
        
        if (response.redirected || response.status === 401) {
            showNotification('Please login to view scan results', 'error');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
            return;
        }
        
        const result = await response.json();
        
        currentResult = result;
        displayReport(result);
        
        // Update target input
        document.getElementById('target').value = result.target;
        
    } catch (error) {
        console.error('Failed to load result:', error);
        showNotification('Failed to load scan result', 'error');
    }
}

// Notification System
function showNotification(message, type = 'info') {
    // Simple console notification for now
    // You can enhance this with a toast notification system
    const colors = {
        success: 'color: #00d4bd',
        error: 'color: #e85347',
        info: 'color: #0056b3',
        warning: 'color: #f0b400'
    };
    
    console.log(`%c${message}`, colors[type] || colors.info);
    
    // Optional: Show brief visual feedback in the log area
    const log = document.getElementById('log');
    if (log && type === 'info') {
        const currentTime = new Date().toLocaleTimeString();
        log.textContent = `[${currentTime}] ${message}\n`;
    }
}

// Load Advanced Scan Options from localStorage
function loadAdvancedScanOptions() {
    const defaultOptions = {
        sqlInjection: false,
        xssDetection: false,
        pluginVuln: false,
        subdomainEnum: false,
        portScan: false,
        directoryBruteforce: false,
        apiDiscovery: false,
        s3BucketCheck: false
    };
    
    try {
        const saved = localStorage.getItem('advancedScanOptions');
        if (saved) {
            return JSON.parse(saved);
        }
    } catch (e) {
        console.error('Error loading advanced scan options:', e);
    }
    
    return defaultOptions;
}

