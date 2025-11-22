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
    
    // Parse base URL safely
    let urlObj, baseUrl;
    try {
        urlObj = new URL(targetUrl);
        baseUrl = `${urlObj.protocol}//${urlObj.host}`;
    } catch (e) {
        // Fallback for invalid URLs
        urlObj = { protocol: 'http:', host: targetUrl, hostname: targetUrl };
        baseUrl = targetUrl;
    }
    
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
    
    // S3 Bucket Exposure findings
    else if (findingId.includes('s3')) {
        const buckets = finding.buckets || [];
        
        whatFound = `<p><strong>AWS S3 buckets were discovered</strong> associated with this domain.</p>`;
        whatFound += `<p>${detail}</p>`;
        
        if (buckets.length > 0) {
            technicalDetails = '<ul>';
            buckets.forEach(bucket => {
                technicalDetails += `<li><strong>${bucket.bucket_name}</strong>`;
                technicalDetails += `<br/>URL: <a href="${bucket.url}" target="_blank">${bucket.url}</a>`;
                technicalDetails += `<br/>Status: ${bucket.exists ? 'Bucket exists' : 'Not found'}`;
                if (bucket.public_read) {
                    technicalDetails += ' <span style="color: #ff4757;">[PUBLIC READ ACCESS]</span>';
                }
                if (bucket.list_enabled) {
                    technicalDetails += ' <span style="color: #ff6348;">[DIRECTORY LISTING ENABLED]</span>';
                }
                if (bucket.note) {
                    technicalDetails += `<br/><em>${bucket.note}</em>`;
                }
                technicalDetails += '</li>';
            });
            technicalDetails += '</ul>';
        } else {
            technicalDetails = `<p>${detail}</p>`;
        }
        
        verification = '<ol>';
        verification += '<li><strong>Test each S3 bucket with curl</strong> or open in browser</li>';
        if (buckets.length > 0) {
            buckets.slice(0, 3).forEach(bucket => {
                verification += `<li>Check: <a href="${bucket.url}" target="_blank">${bucket.bucket_name}</a></li>`;
            });
        }
        verification += '<li><strong>Status Codes:</strong></li>';
        verification += '<ul>';
        verification += '<li><strong>HTTP 200 OK:</strong> CRITICAL - Bucket is publicly readable!</li>';
        verification += '<li><strong>HTTP 403 Forbidden:</strong> Good - Bucket exists but access is denied</li>';
        verification += '<li><strong>HTTP 404 Not Found:</strong> Bucket does not exist</li>';
        verification += '</ul>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Data Exposure:</strong> Public S3 buckets can expose sensitive files, backups, customer data</li>';
        whyMatters += '<li><strong>Directory Listing:</strong> If enabled, attackers can enumerate ALL files in the bucket</li>';
        whyMatters += '<li><strong>Compliance Violations:</strong> Violates GDPR, HIPAA, PCI DSS requirements</li>';
        whyMatters += '<li><strong>Real-world Impact:</strong> Capital One breach (2019) - 100M records via S3 misconfiguration</li>';
        whyMatters += '<li><strong>Financial Impact:</strong> AWS data transfer costs from attackers downloading data</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>⚠️ Test S3 buckets with curl:</strong></p><pre>';
        if (buckets.length > 0) {
            buckets.slice(0, 5).forEach(bucket => {
                commands += `# Check ${bucket.bucket_name}:\n`;
                commands += `curl -I "${bucket.url}"\n`;
                commands += `# Expected: 403 Forbidden (secured) or 404 Not Found\n`;
                commands += `# DANGER: If you get 200 OK, the bucket is PUBLIC!\n\n`;
            });
        }
        commands += `\n# List bucket contents (if publicly readable):\n`;
        if (buckets.length > 0) {
            commands += `curl -s "${buckets[0].url}" | grep -o "<Key>[^<]*</Key>"\n\n`;
        }
        commands += `# AWS CLI commands (if you have credentials):\n`;
        if (buckets.length > 0) {
            commands += `aws s3 ls s3://${buckets[0].bucket_name}/\n`;
            commands += `aws s3api get-bucket-acl --bucket ${buckets[0].bucket_name}\n`;
            commands += `aws s3api get-public-access-block --bucket ${buckets[0].bucket_name}\n`;
        }
        commands += '</pre>';
    }
    
    // Payment: HTTPS Enforcement
    else if (findingId.includes('no-https') || findingId.includes('https-enforcement')) {
        whatFound = `<p><strong>Payment page is not using HTTPS!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        whatFound += `<p><strong>CRITICAL:</strong> All payment pages MUST use HTTPS for PCI DSS compliance.</p>`;
        
        technicalDetails = '<p>The page is accessed over <strong>HTTP (unencrypted)</strong> instead of HTTPS:</p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li><strong>Protocol:</strong> HTTP (port 80)</li>';
        technicalDetails += '<li><strong>Encryption:</strong> None - data transmitted in plain text</li>';
        technicalDetails += '<li><strong>PCI DSS Requirement:</strong> Requirement 4.1 - Use strong cryptography</li>';
        technicalDetails += '</ul>';
        
        verification = '<ol>';
        verification += '<li><strong>Check the URL bar</strong> - Look for the lock icon</li>';
        verification += '<li><strong>If the URL starts with "http://" (not "https://"), it is unencrypted</strong></li>';
        verification += `<li>Try accessing: <code>https://${urlObj.host}</code></li>`;
        verification += '<li><strong>Use SSL Labs to test:</strong> <a href="https://www.ssllabs.com/ssltest/" target="_blank">https://www.ssllabs.com/ssltest/</a></li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Credit Card Data Exposure:</strong> Card numbers, CVV, and personal data transmitted in plain text</li>';
        whyMatters += '<li><strong>Man-in-the-Middle Attacks:</strong> Attackers can intercept and steal payment information</li>';
        whyMatters += '<li><strong>PCI DSS Violation:</strong> Instant failure of PCI DSS Requirement 4.1</li>';
        whyMatters += '<li><strong>Customer Trust:</strong> Browsers show "Not Secure" warning, scaring away customers</li>';
        whyMatters += '<li><strong>Legal Liability:</strong> You are liable for data breaches due to lack of encryption</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Test with curl:</strong></p><pre>';
        commands += `# Check if HTTPS is available:\n`;
        commands += `curl -I https://${urlObj.host}\n\n`;
        commands += `# Check for HSTS header (forces HTTPS):\n`;
        commands += `curl -I https://${urlObj.host} | grep -i "strict-transport-security"\n\n`;
        commands += `# SSL/TLS test with openssl:\n`;
        commands += `openssl s_client -connect ${urlObj.host}:443 -servername ${urlObj.host}\n`;
        commands += '</pre>';
    }
    
    // Payment: Missing CSRF Token
    else if (findingId.includes('csrf')) {
        whatFound = `<p><strong>Payment form is missing CSRF protection!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        whatFound += `<p><strong>HIGH RISK:</strong> Attackers can trick users into submitting unauthorized payments.</p>`;
        
        technicalDetails = '<p>Cross-Site Request Forgery (CSRF) allows attackers to:</p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li>Submit forms on behalf of logged-in users without their knowledge</li>';
        technicalDetails += '<li>Change payment details, shipping addresses, or order quantities</li>';
        technicalDetails += '<li>Execute unauthorized transactions</li>';
        technicalDetails += '</ul>';
        technicalDetails += `<p><strong>No CSRF token found in the payment form!</strong></p>`;
        
        verification = '<ol>';
        verification += '<li><strong>View page source</strong> (right-click → View Page Source)</li>';
        verification += '<li><strong>Search for "csrf" or "token"</strong> in the HTML</li>';
        verification += '<li><strong>Check for hidden input fields</strong> like: <code>&lt;input type="hidden" name="csrf_token" value="..."&gt;</code></li>';
        verification += '<li><strong>If no token is found, CSRF protection is missing!</strong></li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Unauthorized Transactions:</strong> Attacker can force users to make unwanted purchases</li>';
        whyMatters += '<li><strong>Account Takeover:</strong> Change email, password, or payment methods</li>';
        whyMatters += '<li><strong>Financial Fraud:</strong> Submit payments to attacker-controlled accounts</li>';
        whyMatters += '<li><strong>OWASP Top 10:</strong> CSRF is a recognized critical web vulnerability</li>';
        whyMatters += '<li><strong>PCI DSS 6.5.9:</strong> Protect against CSRF attacks</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Test CSRF vulnerability:</strong></p><pre>';
        commands += `# Inspect the form HTML:\n`;
        commands += `curl -s "${targetUrl}" | grep -i "csrf\\|token\\|form"\n\n`;
        commands += `# Check for anti-CSRF headers:\n`;
        commands += `curl -I "${targetUrl}" | grep -i "x-csrf-token\\|x-xsrf-token"\n`;
        commands += '</pre>';
        commands += '<p><strong>WARNING: DO NOT attempt CSRF attacks without authorization!</strong></p>';
    }
    
    // Payment: Missing Security Headers
    else if (findingId.includes('security-headers') || findingId.includes('pci-security-headers')) {
        whatFound = `<p><strong>Missing critical security headers!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        
        technicalDetails = '<p><strong>Security headers protect against common attacks:</strong></p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li><strong>Content-Security-Policy (CSP):</strong> Prevents XSS attacks by controlling script sources</li>';
        technicalDetails += '<li><strong>X-Content-Type-Options:</strong> Prevents MIME type sniffing attacks</li>';
        technicalDetails += '<li><strong>X-Frame-Options:</strong> Prevents clickjacking attacks</li>';
        technicalDetails += '<li><strong>Strict-Transport-Security (HSTS):</strong> Forces HTTPS connections</li>';
        technicalDetails += '<li><strong>Referrer-Policy:</strong> Controls referrer information leakage</li>';
        technicalDetails += '</ul>';
        
        verification = '<ol>';
        verification += '<li><strong>Open browser DevTools</strong> (F12)</li>';
        verification += '<li><strong>Go to Network tab</strong></li>';
        verification += '<li><strong>Reload the page</strong></li>';
        verification += '<li><strong>Click on the main document request</strong></li>';
        verification += '<li><strong>Check Response Headers</strong> for the missing headers listed above</li>';
        verification += '<li><strong>Use online tool:</strong> <a href="https://securityheaders.com" target="_blank">https://securityheaders.com</a></li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>XSS Attacks:</strong> Missing CSP allows attackers to inject malicious scripts</li>';
        whyMatters += '<li><strong>Clickjacking:</strong> Missing X-Frame-Options allows embedding in malicious iframes</li>';
        whyMatters += '<li><strong>Protocol Downgrade:</strong> Missing HSTS allows man-in-the-middle attacks</li>';
        whyMatters += '<li><strong>PCI DSS Compliance:</strong> Security headers are part of secure coding practices (Req 6.5)</li>';
        whyMatters += '<li><strong>Defense in Depth:</strong> Multiple layers of security reduce attack success rate</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Check security headers with curl:</strong></p><pre>';
        commands += `# Check all response headers:\n`;
        commands += `curl -I "${targetUrl}"\n\n`;
        commands += `# Check specific security headers:\n`;
        commands += `curl -I "${targetUrl}" | grep -i "content-security-policy\\|x-frame-options\\|strict-transport\\|x-content-type"\n\n`;
        commands += `# Use securityheaders.com API:\n`;
        commands += `curl -s "https://securityheaders.com/?q=${encodeURIComponent(targetUrl)}&followRedirects=on"\n`;
        commands += '</pre>';
    }
    
    // Payment: Insecure Cookies
    else if (findingId.includes('insecure-cookies') || findingId.includes('cookie')) {
        whatFound = `<p><strong>Cookies are configured insecurely!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        
        technicalDetails = '<p><strong>Cookie security flags protect session data:</strong></p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li><strong>Secure flag:</strong> Ensures cookie is only sent over HTTPS</li>';
        technicalDetails += '<li><strong>HttpOnly flag:</strong> Prevents JavaScript from accessing the cookie (XSS protection)</li>';
        technicalDetails += '<li><strong>SameSite attribute:</strong> Prevents CSRF attacks by controlling cross-site cookie sending</li>';
        technicalDetails += '</ul>';
        technicalDetails += `<p>${detail}</p>`;
        
        verification = '<ol>';
        verification += '<li><strong>Open browser DevTools</strong> (F12)</li>';
        verification += '<li><strong>Go to Application tab</strong> (Chrome) or Storage tab (Firefox)</li>';
        verification += '<li><strong>Expand Cookies</strong> in the left sidebar</li>';
        verification += '<li><strong>Check each cookie\'s flags:</strong></li>';
        verification += '<ul>';
        verification += '<li>Secure should be checked</li>';
        verification += '<li>HttpOnly should be checked</li>';
        verification += '<li>SameSite should be "Strict" or "Lax"</li>';
        verification += '</ul>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Session Hijacking:</strong> Missing Secure flag allows cookie theft over HTTP</li>';
        whyMatters += '<li><strong>XSS Cookie Theft:</strong> Missing HttpOnly allows JavaScript to steal session cookies</li>';
        whyMatters += '<li><strong>CSRF Attacks:</strong> Missing/weak SameSite allows cross-site request attacks</li>';
        whyMatters += '<li><strong>PCI DSS 4.1:</strong> Protect cardholder data during transmission</li>';
        whyMatters += '<li><strong>Account Takeover:</strong> Stolen session cookies = full account access</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Check cookie attributes with curl:</strong></p><pre>';
        commands += `# Check Set-Cookie headers:\n`;
        commands += `curl -I "${targetUrl}" | grep -i "set-cookie"\n\n`;
        commands += `# Verbose cookie information:\n`;
        commands += `curl -v "${targetUrl}" 2>&1 | grep -i "cookie"\n`;
        commands += '</pre>';
    }
    
    // Payment: Direct Credit Card Input
    else if (findingId.includes('direct-card-input') || findingId.includes('credit-card') || findingId.includes('card-field')) {
        whatFound = `<p><strong>Direct credit card input detected!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        whatFound += `<p><strong>PCI DSS CONCERN:</strong> Direct card handling increases compliance scope.</p>`;
        
        technicalDetails = '<p><strong>Why direct credit card fields are risky:</strong></p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li><strong>PCI DSS Scope:</strong> Your server handles raw card data = full PCI DSS compliance required</li>';
        technicalDetails += '<li><strong>Data Breach Risk:</strong> If hacked, attackers steal actual credit card numbers</li>';
        technicalDetails += '<li><strong>Liability:</strong> You are responsible for securing and storing card data</li>';
        technicalDetails += '<li><strong>Better Alternative:</strong> Use tokenized payment gateways (Stripe, PayPal, Square)</li>';
        technicalDetails += '</ul>';
        
        verification = '<ol>';
        verification += '<li><strong>View page source</strong></li>';
        verification += '<li><strong>Search for input fields with card-related names:</strong></li>';
        verification += '<ul>';
        verification += '<li><code>card_number</code>, <code>cardnumber</code>, <code>cc_number</code></li>';
        verification += '<li><code>cvv</code>, <code>cvc</code>, <code>security_code</code></li>';
        verification += '<li><code>expiry</code>, <code>exp_date</code></li>';
        verification += '</ul>';
        verification += '<li><strong>If these fields POST directly to your server, you handle raw card data!</strong></li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>PCI DSS Level:</strong> Direct card handling = Level 1 compliance (most expensive)</li>';
        whyMatters += '<li><strong>Annual Audits:</strong> Required security audits cost $50,000+</li>';
        whyMatters += '<li><strong>Data Breach Fines:</strong> $5,000 - $100,000 per month for non-compliance</li>';
        whyMatters += '<li><strong>Card Brand Penalties:</strong> Visa/Mastercard can revoke your ability to process cards</li>';
        whyMatters += '<li><strong>Reputation Damage:</strong> Breaches destroy customer trust</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Inspect form fields:</strong></p><pre>';
        commands += `# Check for credit card input fields:\n`;
        commands += `curl -s "${targetUrl}" | grep -i 'card\\|cvv\\|cvc\\|expir' | grep -i 'input\\|name='\n\n`;
        commands += `# Check form action (where does it submit?):\n`;
        commands += `curl -s "${targetUrl}" | grep -i '<form' | grep -i 'action='\n`;
        commands += '</pre>';
        commands += '<p><strong>Recommendation:</strong> Use Stripe.js, PayPal SDK, or Square for tokenized payments!</p>';
    }
    
    // Payment: Mixed Content
    else if (findingId.includes('mixed-content')) {
        whatFound = `<p><strong>Mixed content detected - HTTP resources on HTTPS page!</strong></p>`;
        whatFound += `<p>${detail}</p>`;
        
        technicalDetails = '<p><strong>Mixed content compromises HTTPS security:</strong></p>';
        technicalDetails += '<ul>';
        technicalDetails += '<li><strong>Active Mixed Content:</strong> Scripts, stylesheets, iframes loaded over HTTP</li>';
        technicalDetails += '<li><strong>Passive Mixed Content:</strong> Images, videos loaded over HTTP</li>';
        technicalDetails += '<li><strong>Security Risk:</strong> HTTP resources can be modified by attackers (MITM)</li>';
        technicalDetails += '<li><strong>Browser Warnings:</strong> Browsers show "Not Secure" or block mixed content</li>';
        technicalDetails += '</ul>';
        technicalDetails += `<p>${detail}</p>`;
        
        verification = '<ol>';
        verification += '<li><strong>Open browser DevTools</strong> (F12)</li>';
        verification += '<li><strong>Check Console tab</strong> for mixed content warnings</li>';
        verification += '<li><strong>Look for messages like:</strong></li>';
        verification += '<ul>';
        verification += '<li>"Mixed Content: The page was loaded over HTTPS, but requested an insecure resource"</li>';
        verification += '<li>"This request has been blocked; the content must be served over HTTPS"</li>';
        verification += '</ul>';
        verification += '<li><strong>View page source</strong> and search for <code>http://</code> (not <code>https://</code>)</li>';
        verification += '</ol>';
        
        whyMatters = '<ul>';
        whyMatters += '<li><strong>Man-in-the-Middle Attacks:</strong> HTTP resources can inject malicious code</li>';
        whyMatters += '<li><strong>Payment Data Theft:</strong> Modified scripts can steal credit card information</li>';
        whyMatters += '<li><strong>False Security:</strong> Users see HTTPS lock, but page is actually vulnerable</li>';
        whyMatters += '<li><strong>PCI DSS 4.1:</strong> All resources must use strong encryption</li>';
        whyMatters += '<li><strong>Browser Blocking:</strong> Modern browsers block active mixed content by default</li>';
        whyMatters += '</ul>';
        
        commands = '<p><strong>Find mixed content:</strong></p><pre>';
        commands += `# Download page and search for HTTP resources:\n`;
        commands += `curl -s "${targetUrl}" | grep -i 'http://' | grep -v 'https://'\n\n`;
        commands += `# Check for insecure scripts specifically:\n`;
        commands += `curl -s "${targetUrl}" | grep -i '<script' | grep -i 'http://'\n\n`;
        commands += `# Check for insecure stylesheets:\n`;
        commands += `curl -s "${targetUrl}" | grep -i '<link' | grep -i 'http://'\n`;
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

