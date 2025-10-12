/**
 * Finding Detail Modal - Show comprehensive verification details
 */

let currentFindingData = null;

// Open the finding detail modal
function openFindingModal(finding, targetUrl) {
    currentFindingData = { finding, targetUrl };
    
    const modal = document.getElementById('findingModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalSeverity = document.getElementById('modalSeverity');
    const modalWhatFound = document.getElementById('modalWhatFound');
    const modalTechnicalDetails = document.getElementById('modalTechnicalDetails');
    const modalVerification = document.getElementById('modalVerification');
    const modalWhyMatters = document.getElementById('modalWhyMatters');
    const modalCommands = document.getElementById('modalCommands');
    const modalRemediation = document.getElementById('modalRemediation');
    
    // Set title
    modalTitle.textContent = finding.title || 'Security Finding Details';
    
    // Set severity badge
    modalSeverity.textContent = `Severity: ${(finding.severity || 'info').toUpperCase()}`;
    modalSeverity.className = `severity-badge ${finding.severity || 'info'}`;
    
    // Generate detailed content based on finding type
    const details = generateDetailedExplanation(finding, targetUrl);
    
    // Populate sections
    modalWhatFound.innerHTML = details.whatFound;
    modalTechnicalDetails.innerHTML = details.technicalDetails;
    modalVerification.innerHTML = details.verification;
    modalWhyMatters.innerHTML = details.whyMatters;
    
    // Commands section
    if (details.commands && details.commands.length > 0) {
        document.getElementById('modalCommandsSection').style.display = 'block';
        modalCommands.innerHTML = details.commands;
    } else {
        document.getElementById('modalCommandsSection').style.display = 'none';
    }
    
    // Remediation section
    if (finding.recommendations && finding.recommendations.length > 0) {
        document.getElementById('modalRemediationSection').style.display = 'block';
        let remediationHTML = '<ul>';
        finding.recommendations.forEach(rec => {
            remediationHTML += `<li>${rec}</li>`;
        });
        remediationHTML += '</ul>';
        modalRemediation.innerHTML = remediationHTML;
    } else {
        document.getElementById('modalRemediationSection').style.display = 'none';
    }
    
    // Show modal
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden'; // Prevent background scrolling
}

// Close the finding detail modal
function closeFindingModal() {
    const modal = document.getElementById('findingModal');
    modal.classList.add('hidden');
    document.body.style.overflow = ''; // Restore scrolling
    currentFindingData = null;
}

// Copy all finding details to clipboard
function copyFindingDetails() {
    if (!currentFindingData) return;
    
    const { finding, targetUrl } = currentFindingData;
    const details = generateDetailedExplanation(finding, targetUrl);
    
    let text = `SECURITY FINDING REPORT\n`;
    text += `${'='.repeat(80)}\n\n`;
    text += `Title: ${finding.title}\n`;
    text += `Severity: ${finding.severity.toUpperCase()}\n`;
    text += `Target: ${targetUrl}\n`;
    text += `Date: ${new Date().toISOString()}\n\n`;
    
    text += `WHAT WAS FOUND:\n${'-'.repeat(80)}\n`;
    text += details.whatFound.replace(/<[^>]*>/g, '') + '\n\n';
    
    text += `TECHNICAL DETAILS:\n${'-'.repeat(80)}\n`;
    text += details.technicalDetails.replace(/<[^>]*>/g, '') + '\n\n';
    
    text += `HOW TO VERIFY:\n${'-'.repeat(80)}\n`;
    text += details.verification.replace(/<[^>]*>/g, '') + '\n\n';
    
    text += `WHY THIS MATTERS:\n${'-'.repeat(80)}\n`;
    text += details.whyMatters.replace(/<[^>]*>/g, '') + '\n\n';
    
    if (details.commands) {
        text += `TEST COMMANDS:\n${'-'.repeat(80)}\n`;
        text += details.commands.replace(/<[^>]*>/g, '') + '\n\n';
    }
    
    if (finding.recommendations && finding.recommendations.length > 0) {
        text += `REMEDIATION STEPS:\n${'-'.repeat(80)}\n`;
        finding.recommendations.forEach((rec, i) => {
            text += `${i + 1}. ${rec}\n`;
        });
    }
    
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Finding details copied to clipboard!', 'success');
    }).catch(() => {
        showNotification('Failed to copy details', 'error');
    });
}

// Generate detailed explanation based on finding type
function generateDetailedExplanation(finding, targetUrl) {
    const findingId = finding.id || '';
    const detail = finding.detail || '';
    const endpoints = finding.endpoints || [];
    const paths = finding.paths || [];
    const subdomains = finding.subdomains || [];
    
    let whatFound = '', technicalDetails = '', verification = '', whyMatters = '', commands = '';
    
    // Parse base URL
    const urlObj = new URL(targetUrl);
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`;
    
    // API Discovery findings
    if (findingId.includes('api-discovery')) {
        whatFound = `<p><strong>API endpoints were discovered</strong> that are publicly accessible.</p>`;
        whatFound += `<p>${detail}</p>`;
        
        if (endpoints.length > 0) {
            technicalDetails = '<ul>';
            endpoints.forEach(ep => {
                technicalDetails += `<li><strong>${ep.full_url || ep.path}</strong>`;
                technicalDetails += `<br/>Status: HTTP ${ep.status_code || 'Unknown'}`;
                if (ep.content_type) technicalDetails += `<br/>Type: ${ep.content_type}`;
                if (ep.format) technicalDetails += ` (${ep.format})`;
                if (ep.doc_type) technicalDetails += `<br/>Documentation: ${ep.doc_type}`;
                if (ep.note) technicalDetails += `<br/>Note: ${ep.note}`;
                technicalDetails += '</li>';
            });
            technicalDetails += '</ul>';
        } else {
            technicalDetails = `<p>${detail}</p>`;
        }
        
        verification = '<ol>';
        verification += '<li><strong>Open your browser</strong></li>';
        if (endpoints.length > 0) {
            endpoints.slice(0, 3).forEach(ep => {
                verification += `<li>Go to: <a href="${ep.full_url || ep.path}" target="_blank">${ep.full_url || ep.path}</a></li>`;
            });
        }
        verification += '<li><strong>You should see the API response or documentation</strong></li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Information Disclosure:</strong> Exposes API structure and available endpoints</li>';
        whyMatters += '<li><strong>Attack Surface:</strong> Helps attackers understand your system</li>';
        whyMatters += '<li><strong>User Enumeration:</strong> May expose user data or IDs</li>';
        whyMatters += '<li><strong>Reconnaissance:</strong> First step in planning an attack</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Verify with curl:</strong></p><pre>';
        if (endpoints.length > 0) {
            endpoints.slice(0, 3).forEach(ep => {
                commands += `curl -I "${ep.full_url || ep.path}"\n\n`;
            });
        }
        commands += '</pre>';
        
        // Check for WordPress API
        if (baseUrl) {
            commands += '<p><strong>Check WordPress API:</strong></p><pre>';
            commands += `curl -s "${baseUrl}/wp-json/" | python3 -m json.tool\n\n`;
            commands += `# Get all users:\n`;
            commands += `curl -s "${baseUrl}/wp-json/wp/v2/users" | python3 -m json.tool\n`;
            commands += '</pre>';
        }
    }
    
    // Directory Bruteforce findings
    else if (findingId.includes('dirbrute')) {
        whatFound = `<p><strong>Sensitive files or directories were found</strong> that should not be publicly accessible.</p>`;
        whatFound += `<p>${detail}</p>`;
        
        if (paths.length > 0) {
            technicalDetails = '<ul>';
            paths.forEach(p => {
                technicalDetails += `<li><strong>${p.full_url || p.path}</strong>`;
                technicalDetails += `<br/>Status: HTTP ${p.status_code || 'Unknown'}`;
                if (p.size) technicalDetails += `<br/>Size: ${p.size} bytes`;
                if (p.note) technicalDetails += `<br/>Risk: ${p.note}`;
                technicalDetails += '</li>';
            });
            technicalDetails += '</ul>';
        } else {
            technicalDetails = `<p>${detail}</p>`;
        }
        
        verification = '<ol>';
        verification += '<li><strong>Open your browser or use curl</strong></li>';
        if (paths.length > 0) {
            paths.slice(0, 3).forEach(p => {
                verification += `<li>Check: <a href="${p.full_url || p.path}" target="_blank">${p.full_url || p.path}</a></li>`;
            });
        }
        verification += '<li><strong>If you see content instead of a 403/404 error, the file is exposed!</strong></li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Configuration Leaks:</strong> .env, .git, config files expose sensitive data</li>';
        whyMatters += '<li><strong>Backup Files:</strong> May contain database credentials or API keys</li>';
        whyMatters += '<li><strong>Full System Compromise:</strong> .git directory allows downloading entire source code</li>';
        whyMatters += '<li><strong>Compliance Violation:</strong> Exposed files violate PCI DSS, GDPR requirements</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Verify with curl:</strong></p><pre>';
        if (paths.length > 0) {
            paths.slice(0, 3).forEach(p => {
                commands += `# Check ${p.path}:\n`;
                commands += `curl -I "${p.full_url || p.path}"\n`;
                commands += `# Expected: 403 Forbidden or 404 Not Found\n`;
                commands += `# DANGER: If you get 200 OK, the file is exposed!\n\n`;
            });
        }
        commands += '</pre>';
    }
    
    // Subdomain Enumeration findings
    else if (findingId.includes('subdomain')) {
        whatFound = `<p><strong>Subdomains were discovered</strong> that may expose additional attack surfaces.</p>`;
        whatFound += `<p>${detail}</p>`;
        
        if (subdomains.length > 0) {
            technicalDetails = '<ul>';
            subdomains.slice(0, 15).forEach(sd => {
                if (typeof sd === 'string') {
                    technicalDetails += `<li>${sd}</li>`;
                } else if (sd.subdomain) {
                    technicalDetails += `<li><strong>${sd.subdomain}</strong>`;
                    if (sd.ip) technicalDetails += ` → ${sd.ip}`;
                    if (sd.description) technicalDetails += ` (${sd.description})`;
                    technicalDetails += '</li>';
                }
            });
            if (subdomains.length > 15) {
                technicalDetails += `<li><em>... and ${subdomains.length - 15} more</em></li>`;
            }
            technicalDetails += '</ul>';
        } else {
            technicalDetails = `<p>${detail}</p>`;
        }
        
        verification = '<ol>';
        verification += '<li><strong>Open your browser</strong></li>';
        verification += '<li>Try visiting each subdomain to see if it loads</li>';
        verification += '<li><strong>Check for sensitive subdomains like:</strong></li>';
        verification += '<ul><li>dev.* - Development environments (should be internal only)</li>';
        verification += '<li>staging.* - Staging environments (should be internal)</li>';
        verification += '<li>admin.* - Admin panels (should have strong auth)</li>';
        verification += '<li>api.* - API endpoints (may expose data)</li></ul>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Expanded Attack Surface:</strong> More targets for attackers</li>';
        whyMatters += '<li><strong>Dev/Test Exposure:</strong> Staging environments often have weaker security</li>';
        whyMatters += '<li><strong>Information Leakage:</strong> Dev sites may show debug information</li>';
        whyMatters += '<li><strong>Forgotten Assets:</strong> Old subdomains may run outdated, vulnerable software</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Verify with DNS lookup:</strong></p><pre>';
        if (subdomains.length > 0) {
            subdomains.slice(0, 5).forEach(sd => {
                const subdomain = typeof sd === 'string' ? sd : sd.subdomain;
                if (subdomain) {
                    commands += `# Check ${subdomain}:\n`;
                    commands += `nslookup ${subdomain}\n`;
                    commands += `curl -I https://${subdomain}\n\n`;
                }
            });
        }
        commands += '</pre>';
    }
    
    // SQL Injection findings
    else if (findingId.includes('sql-injection')) {
        whatFound = `<p><strong>SQL Injection vulnerability detected!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        whatFound += `<p><strong>⚠️ CRITICAL:</strong> This allows attackers to manipulate database queries.</p>`;
        
        technicalDetails = '<p>The scanner detected that SQL injection payloads triggered unusual responses:</p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li><strong>Error-based detection:</strong> Database errors in response</li>';
        technicalDetails += '<li><strong>Time-based detection:</strong> Delays indicate SQL execution</li>';
        technicalDetails += '<li><strong>Boolean-based detection:</strong> Different responses for true/false conditions</li>';
        technicalDetails += '</ul>';
        
        verification = '<ol>';
        verification += '<li><strong>DO NOT attempt manual exploitation without authorization!</strong></li>';
        verification += '<li>Review the finding details for affected parameters</li>';
        verification += '<li>Use a professional tool like SQLMap (with permission)</li>';
        verification += '<li>Have a security professional verify the finding</li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Database Compromise:</strong> Attackers can read entire database</li>';
        whyMatters += '<li><strong>Data Theft:</strong> Customer data, passwords, credit cards exposed</li>';
        whyMatters += '<li><strong>Data Manipulation:</strong> Attackers can modify or delete data</li>';
        whyMatters += '<li><strong>Real-world Impact:</strong> Equifax breach (2017) - 147M records stolen via SQL injection</li>';
        whyMatters += '<li><strong>Compliance:</strong> Violates PCI DSS, GDPR, HIPAA</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>⚠️ Testing SQL injection requires authorization!</strong></p>';
        commands += '<p>Professional testing with SQLMap:</p><pre>';
        commands += `# Basic test (automated tool):\n`;
        commands += `sqlmap -u "${targetUrl}" --batch --risk=1 --level=1\n\n`;
        commands += `# Do NOT run this without written permission!\n`;
        commands += '</pre>';
    }
    
    // XSS findings
    else if (findingId.includes('xss')) {
        whatFound = `<p><strong>Cross-Site Scripting (XSS) vulnerability detected!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        whatFound += `<p><strong>⚠️ HIGH RISK:</strong> Allows attackers to inject malicious scripts.</p>`;
        
        technicalDetails = '<p>The scanner detected that user input is reflected without proper sanitization:</p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li><strong>Reflected XSS:</strong> Input immediately reflected in response</li>';
        technicalDetails += '<li><strong>DOM-based XSS:</strong> Client-side JavaScript manipulation</li>';
        technicalDetails += '<li><strong>Context-aware detection:</strong> Checks HTML, JavaScript, and attribute contexts</li>';
        technicalDetails += '</ul>';
        
        verification = '<ol>';
        verification += '<li><strong>DO NOT attempt exploitation in production!</strong></li>';
        verification += '<li>Review affected parameters in the finding</li>';
        verification += '<li>Check if user input appears in the HTML response</li>';
        verification += '<li>Have a security professional verify and test safely</li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Session Hijacking:</strong> Steal user cookies and sessions</li>';
        whyMatters += '<li><strong>Credential Theft:</strong> Capture login credentials</li>';
        whyMatters += '<li><strong>Malware Distribution:</strong> Redirect users to malicious sites</li>';
        whyMatters += '<li><strong>Real-world Impact:</strong> British Airways (2018) - 380K payment cards via XSS</li>';
        whyMatters += '<li><strong>Compliance:</strong> Violates OWASP Top 10, PCI DSS Req 6.5.7</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>⚠️ Testing XSS requires authorization!</strong></p>';
        commands += '<p>Safe verification (view source only):</p><pre>';
        commands += `# Check if input is reflected:\n`;
        commands += `curl "${targetUrl}?test=UNIQUESTRING" | grep "UNIQUESTRING"\n\n`;
        commands += `# If you see UNIQUESTRING in HTML, there may be XSS risk\n`;
        commands += '</pre>';
    }
    
    // Port Scan findings
    else if (findingId.includes('port-scan')) {
        whatFound = `<p><strong>Open network ports were discovered</strong> on the target system.</p>`;
        whatFound += `<p>${detail}</p>`;
        
        technicalDetails = `<p>${detail}</p>`;
        
        verification = '<ol>';
        verification += '<li><strong>Use an online port checker:</strong> <a href="https://www.yougetsignal.com/tools/open-ports/" target="_blank">YouGetSignal Port Scanner</a></li>';
        verification += '<li>Or use nmap: <code>nmap -p [port] [domain]</code></li>';
        verification += '<li><strong>Check if the ports should be publicly accessible</strong></li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Attack Vector:</strong> Each open port is a potential entry point</li>';
        whyMatters += '<li><strong>Service Exploitation:</strong> Outdated services can be compromised</li>';
        whyMatters += '<li><strong>Data Leakage:</strong> Database ports (3306, 5432) should never be public</li>';
        whyMatters += '<li><strong>Compliance:</strong> PCI DSS requires port scanning and restriction</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Verify with nmap:</strong></p><pre>';
        commands += `nmap -p 80,443,3306,5432,22,21 ${baseUrl.replace('https://', '').replace('http://', '')}\n`;
        commands += '</pre>';
    }
    
    // Generic/Other findings
    else {
        whatFound = `<p>${detail}</p>`;
        technicalDetails = `<p><strong>Details:</strong></p><p>${detail}</p>`;
        
        verification = '<ol>';
        verification += '<li>Review the finding details above</li>';
        verification += '<li>Check the affected resources manually</li>';
        verification += '<li>Consult with a security professional if needed</li>';
        verification += '</ol>';
        
        whyMatters = '<p>This finding may indicate a security weakness that could be exploited by attackers.</p>';
        
        commands = '';
    }
    
    return {
        whatFound,
        technicalDetails,
        verification,
        whyMatters,
        commands
    };
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeFindingModal();
    }
});

