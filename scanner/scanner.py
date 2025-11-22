import requests
from requests.exceptions import RequestException
from datetime import datetime
import uuid
import tldextract
from bs4 import BeautifulSoup
import ssl
import socket

# A safe set of "checks" that do observation and light simulation only.

def get_recommendations(finding_id):
    """Get step-by-step recommendations for each finding"""
    from scanner.payment_scanner import get_recommendations as get_payment_recs
    return get_payment_recs(finding_id)

def filter_real_findings(findings):
    """
    Filter out informational positive confirmations, keep only real security issues
    Removes findings that are just status confirmations (✓, "No X Found", etc.)
    """
    real_findings = []
    for f in findings:
        title = f.get('title', '')
        title_lower = title.lower()
        
        # Always skip anything with ✓ symbol (positive confirmation)
        if '✓' in title:
            continue
        
        # Skip info-level positive confirmations
        if f['severity'] == 'info':
            # Skip positive confirmations ("No X", "All X", "enabled", "present", etc.)
            if any(keyword in title_lower for keyword in ['no ', 'all ', 'enabled', 'present', 'complete', 'properly', 'no additional', 'no open']):
                continue
            # Keep info findings that are actual discoveries (detected, found, discovered, exposed, missing)
            elif any(keyword in title_lower for keyword in ['detected', 'found', 'discovered', 'exposed', 'missing']):
                real_findings.append(f)
            else:
                # Keep other info findings that might be important
                real_findings.append(f)
        else:
            # Keep all non-info findings (critical, high, medium, low)
            real_findings.append(f)
    return real_findings

def score_from_findings(findings):
    # Start at 100, subtract weighted issues
    score = 100
    for f in findings:
        if f['severity'] == 'critical':
            score -= 30
        elif f['severity'] == 'high':
            score -= 15
        elif f['severity'] == 'medium':
            score -= 7
        elif f['severity'] == 'low':
            score -= 3
    return max(0, score)


def detect_cms_and_frameworks(soup, resp, body):
    """Detect CMS, frameworks, and platforms"""
    detected = []
    headers = {key.lower(): value for key, value in resp.headers.items()}
    
    # ===== CMS Detection =====
    
    # WordPress
    if 'wp-content' in body or 'wp-includes' in body or '/wp-json/' in body or 'wordpress' in body:
        detected.append('WordPress')
    
    # Joomla
    if 'joomla' in body or '/components/com_' in body or 'joomla.jspath' in body:
        detected.append('Joomla')
    
    # Drupal
    if 'drupal' in body or 'sites/default/files' in body or 'x-drupal-cache' in headers:
        detected.append('Drupal')
    
    # Ghost
    if 'ghost' in body or 'x-ghost-' in ' '.join(headers.keys()):
        detected.append('Ghost')
    
    # Wix
    if 'wix.com' in body or 'x-wix-' in ' '.join(headers.keys()):
        detected.append('Wix')
    
    # Squarespace
    if 'squarespace' in body or 'sqsp' in body:
        detected.append('Squarespace')
    
    # Webflow
    if 'webflow' in body or 'x-webflow' in headers:
        detected.append('Webflow')
    
    # Shopify (e-commerce)
    if 'shopify' in body or 'cdn.shopify.com' in body or 'x-shopify-stage' in headers:
        detected.append('Shopify')
    
    # WooCommerce (WordPress plugin)
    if 'woocommerce' in body or 'wc-' in body:
        detected.append('WooCommerce')
    
    # Magento
    if 'magento' in body or 'mage/cookies.js' in body:
        detected.append('Magento')
    
    # PrestaShop
    if 'prestashop' in body or '/modules/ps_' in body:
        detected.append('PrestaShop')
    
    # BigCommerce
    if 'bigcommerce' in body:
        detected.append('BigCommerce')
    
    # ===== Frameworks Detection =====
    
    # React
    if 'react' in body or '__react' in body or 'data-reactroot' in body:
        detected.append('React')
    
    # Vue.js
    if 'vue' in body or 'data-v-' in body or '__vue' in body:
        detected.append('Vue.js')
    
    # Angular
    if 'angular' in body or 'ng-' in body or 'data-ng-' in body:
        detected.append('Angular')
    
    # Next.js
    if 'next.js' in body or '_next/' in body or '__next' in body:
        detected.append('Next.js')
    
    # Nuxt.js
    if 'nuxt' in body or '__nuxt' in body:
        detected.append('Nuxt.js')
    
    # Laravel
    if 'laravel' in body or 'laravel_session' in body:
        detected.append('Laravel')
    
    # Django
    if 'django' in body or 'csrfmiddlewaretoken' in body:
        detected.append('Django')
    
    # Flask
    if 'werkzeug' in headers.get('server', '').lower():
        detected.append('Flask')
    
    # Express.js
    if 'x-powered-by' in headers and 'express' in headers['x-powered-by'].lower():
        detected.append('Express.js')
    
    # ASP.NET
    if 'asp.net' in body or 'x-aspnet-version' in headers or '__viewstate' in body:
        detected.append('ASP.NET')
    
    # Ruby on Rails
    if 'rails' in body or 'x-runtime' in headers:
        detected.append('Ruby on Rails')
    
    # ===== Static Site Generators =====
    
    # Jekyll
    if 'jekyll' in body or 'powered by jekyll' in body:
        detected.append('Jekyll')
    
    # Hugo
    if 'hugo' in body or 'generator" content="hugo' in body:
        detected.append('Hugo')
    
    # Gatsby
    if 'gatsby' in body or 'gatsby-' in body:
        detected.append('Gatsby')
    
    # 11ty
    if 'eleventy' in body or '11ty' in body:
        detected.append('Eleventy (11ty)')
    
    # ===== Web Servers =====
    
    server = headers.get('server', '')
    if server:
        if 'nginx' in server.lower():
            detected.append(f'Nginx {server.split("/")[1] if "/" in server else ""}')
        elif 'apache' in server.lower():
            detected.append(f'Apache {server.split("/")[1] if "/" in server else ""}')
        elif 'cloudflare' in server.lower():
            detected.append('Cloudflare')
        elif 'microsoft-iis' in server.lower():
            detected.append('IIS')
    
    return detected


def run_scan(target_url, options=None):
    options = options or {}
    findings = []
    details = {}
    scan_logs = []  # Track what's being scanned
    
    def log_scan(message):
        """Add a timestamped log entry"""
        scan_logs.append({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': message
        })

    uid = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + 'Z'
    
    log_scan('Starting general security scan...')

    # 1) Basic HTTP(S) GET
    try:
        log_scan('Fetching target URL...')
        # Add browser-like headers to avoid 406 errors
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        resp = requests.get(target_url, timeout=15, allow_redirects=True, headers=headers)
        details['status_code'] = resp.status_code
        details['headers'] = dict(resp.headers)
        details['final_url'] = resp.url
        details['response_time_ms'] = int(resp.elapsed.total_seconds() * 1000)
        log_scan(f'✓ Connected successfully (HTTP {resp.status_code})')

        # Check security-related headers
        log_scan('Checking security headers (CSP, X-Frame-Options, HSTS)...')
        sec_headers = ['Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security', 'Referrer-Policy']
        missing = [h for h in sec_headers if h not in resp.headers]
        if missing:
            findings.append({
                'id': 'missing-security-headers', 
                'title': 'Missing security headers', 
                'severity': 'medium', 
                'detail': f'Missing headers: {missing}',
                'recommendations': get_recommendations('missing-security-headers')
            })
            log_scan(f'⚠ Missing {len(missing)} security headers')
        else:
            log_scan('✓ All security headers present')

        # Cookies flags
        log_scan('Checking cookie security flags...')
        if resp.cookies:
            cookie_issues = []
            for c in resp.cookies:
                cstr = str(c)
                # This is a heuristic: we can't see HttpOnly via requests.cookies easily for remote cookies set by server,
                # but we flag cookie names without session-id hints as low-risk. (This is a lightweight check.)
                if 'session' in c.name.lower() and not (c._rest.get('httponly') or c._rest.get('HttpOnly')):
                    cookie_issues.append(c.name)
            if cookie_issues:
                findings.append({'id': 'cookie-flags', 'title': 'Session cookies missing secure flags', 'severity': 'high', 'detail': f'Cookies without HttpOnly/Secure: {cookie_issues}'})
                log_scan(f'⚠ Found {len(cookie_issues)} insecure cookies')
            else:
                log_scan('✓ Cookie security flags OK')
        else:
            log_scan('✓ No cookies detected')

        # Simple reflection test (NON-MALICIOUS): send a benign token as a query param and look for it in the body
        log_scan('Testing for reflected input (XSS vulnerability)...')
        token = 'SAFETEST12345'
        try:
            r2 = requests.get(target_url, params={'q': token}, timeout=10)
            if token in r2.text:
                findings.append({'id': 'reflected-input', 'title': 'Reflected input in response body', 'severity': 'high', 'detail': 'A benign token sent as a query parameter was reflected in the response body. This can indicate XSS risk; manual review recommended.'})
                log_scan('⚠ Reflected input detected')
            else:
                log_scan('✓ No reflected input detected')
        except RequestException:
            log_scan('⚠ Reflection test skipped (timeout)')

        # Directory/file presence checks (non-invasive): check for common files
        log_scan('Checking for exposed sensitive files...')
        common_paths = ['/robots.txt', '/.git/config', '/sitemap.xml', '/admin/', '/phpinfo.php', '/.htaccess', '/.env', '/backup.sql', '/config.php.bak']
        found = []
        sensitive_found = []
        for p in common_paths:
            url = resp.url.rstrip('/') + p
            try:
                # Use same headers as main request to avoid 406 errors
                r = requests.head(url, timeout=6, allow_redirects=True, headers=headers)
                if r.status_code == 200:
                    found.append({'path': p, 'status': r.status_code})
                    # Flag particularly sensitive files
                    if p in ['/.htaccess', '/.env', '/.git/config', '/backup.sql', '/config.php.bak', '/phpinfo.php']:
                        sensitive_found.append(p)
            except RequestException:
                continue
        
        if sensitive_found:
            findings.append({
                'id': 'critical-files-exposed', 
                'title': 'Critical configuration files exposed', 
                'severity': 'critical', 
                'detail': f'Exposed files: {sensitive_found}. These files should NEVER be publicly accessible!',
                'recommendations': get_recommendations('critical-files-exposed')
            })
            log_scan(f'❌ CRITICAL: {len(sensitive_found)} sensitive files exposed!')
        elif found:
            findings.append({'id': 'sensitive-files', 'title': 'Common files/endpoints exposed', 'severity': 'medium', 'detail': f'Found: {found}'})
            log_scan(f'⚠ Found {len(found)} common files/endpoints')
        else:
            log_scan('✓ No sensitive files exposed')

        # Comprehensive CMS/Framework/Platform detection
        log_scan('Detecting CMS, frameworks, and platforms...')
        soup = BeautifulSoup(resp.text, 'html.parser')
        body = resp.text.lower()
        
        cms_detected = detect_cms_and_frameworks(soup, resp, body)
        if cms_detected:
            platform_list = ', '.join(cms_detected)
            findings.append({
                'id': 'cms-detected', 
                'title': f'✓ Platform/CMS Detected: {platform_list}', 
                'severity': 'info', 
                'detail': f'Detected: {platform_list}. Ensure all components are up-to-date and properly secured.'
            })
            details['detected_platforms'] = cms_detected
            log_scan(f'✓ Detected: {platform_list}')
        else:
            log_scan('✓ Platform detection complete (none identified)')

    except RequestException as e:
        findings.append({'id': 'network-error', 'title': 'Network or request error', 'severity': 'high', 'detail': str(e)})
        details['error'] = str(e)

    # Get scan type to determine if advanced scans should run
    scan_type = options.get('scan_type', 'general')
    
    # ===== ADVANCED SCANS (ONLY run if scan_type is 'advanced' AND option is enabled) =====
    # Advanced Scan: SQL Injection Testing
    if scan_type == 'advanced' and options.get('advanced_sql_injection'):
        log_scan('🔴 Running ADVANCED SQL Injection tests...')
        try:
            from scanner.sql_injection import test_sql_injection
            sqli_results = test_sql_injection(target_url, timeout=10)
            
            if sqli_results['findings']:
                findings.extend(sqli_results['findings'])
                log_scan(f'⚠ SQL Injection: Found {sqli_results["vulnerable_params"]} vulnerable parameter(s)')
            else:
                log_scan('✓ SQL Injection: No vulnerabilities detected')
            
            details['sql_injection_tests'] = {
                'tested_payloads': sqli_results['tested_payloads'],
                'vulnerable_params': sqli_results['vulnerable_params']
            }
        except Exception as e:
            log_scan(f'⚠ SQL Injection test failed: {str(e)[:50]}')
    
    # Advanced Scan: XSS Detection
    if scan_type == 'advanced' and options.get('advanced_xss_detection'):
        log_scan('🔴 Running ADVANCED XSS Detection tests...')
        try:
            from scanner.xss_detection import test_xss_vulnerability
            xss_results = test_xss_vulnerability(target_url, timeout=10)
            
            if xss_results['findings']:
                findings.extend(xss_results['findings'])
                log_scan(f'⚠ XSS Detection: Found {xss_results["vulnerable_params"]} vulnerable parameter(s)')
            else:
                log_scan('✓ XSS Detection: No vulnerabilities detected')
            
            details['xss_tests'] = {
                'tested_payloads': xss_results['tested_payloads'],
                'vulnerable_params': xss_results['vulnerable_params']
            }
        except Exception as e:
            log_scan(f'⚠ XSS Detection test failed: {str(e)[:50]}')
    
    # Advanced Scan: Plugin Vulnerability Check
    if scan_type == 'advanced' and options.get('advanced_plugin_vuln'):
        log_scan('🔴 Running ADVANCED Plugin Vulnerability Check...')
        try:
            from scanner.plugin_vuln_checker import check_plugin_vulnerabilities
            plugin_results = check_plugin_vulnerabilities(
                target_url, 
                detected_platforms=details.get('detected_platforms'),
                timeout=10
            )
            
            if plugin_results['findings']:
                findings.extend(plugin_results['findings'])
                if plugin_results['vulnerable_plugins']:
                    log_scan(f'⚠ Plugin Vuln: Found {len(plugin_results["vulnerable_plugins"])} vulnerable component(s)')
                else:
                    log_scan('✓ Plugin Vuln: No known vulnerabilities detected')
            else:
                log_scan('✓ Plugin Vuln: No CMS or plugins detected')
            
            details['plugin_vuln_check'] = {
                'vulnerable_plugins': plugin_results['vulnerable_plugins'],
                'scanned_platforms': plugin_results['scanned_platforms']
            }
        except Exception as e:
            log_scan(f'⚠ Plugin Vuln check failed: {str(e)[:50]}')
    
    # Advanced Scan: Subdomain Enumeration
    if scan_type == 'advanced' and options.get('advanced_subdomain_enum'):
        log_scan('🔴 Running ADVANCED Subdomain Enumeration...')
        try:
            from scanner.subdomain_enum import enumerate_subdomains
            subdomain_results = enumerate_subdomains(target_url, timeout=10)
            
            if subdomain_results['findings']:
                findings.extend(subdomain_results['findings'])
                if subdomain_results['total_found'] > 0:
                    log_scan(f'✓ Subdomain Enum: Found {subdomain_results["total_found"]} subdomain(s)')
                else:
                    log_scan('✓ Subdomain Enum: No additional subdomains found')
            
            details['subdomain_enum'] = {
                'discovered_subdomains': subdomain_results['discovered_subdomains'],
                'total_found': subdomain_results['total_found']
            }
        except Exception as e:
            log_scan(f'⚠ Subdomain Enum failed: {str(e)[:50]}')
    
    # Advanced Scan: Port Scanning
    if scan_type == 'advanced' and options.get('advanced_port_scan'):
        log_scan('🔴 Running ADVANCED Port Scanning (INVASIVE!)...')
        try:
            from scanner.port_scanner import scan_ports
            port_results = scan_ports(target_url, timeout=30)
            
            if port_results['findings']:
                findings.extend(port_results['findings'])
                if port_results['total_open'] > 0:
                    log_scan(f'⚠ Port Scan: Found {port_results["total_open"]} open port(s)')
                else:
                    log_scan('✓ Port Scan: No additional open ports found')
            
            details['port_scan'] = {
                'open_ports': port_results['open_ports'],
                'total_open': port_results['total_open']
            }
        except Exception as e:
            log_scan(f'⚠ Port Scan failed: {str(e)[:50]}')
    
    # Advanced Scan: Directory Bruteforcing
    if scan_type == 'advanced' and options.get('advanced_directory_bruteforce'):
        log_scan('🔴 Running ADVANCED Directory Bruteforcing...')
        try:
            from scanner.directory_bruteforce import bruteforce_directories
            dir_results = bruteforce_directories(target_url, timeout=30)
            
            if dir_results['findings']:
                findings.extend(dir_results['findings'])
                if dir_results['total_found'] > 0:
                    log_scan(f'⚠ Directory Bruteforce: Found {dir_results["total_found"]} path(s)')
                else:
                    log_scan('✓ Directory Bruteforce: No sensitive paths found')
            
            details['directory_bruteforce'] = {
                'discovered_paths': dir_results['discovered_paths'],
                'total_found': dir_results['total_found']
            }
        except Exception as e:
            log_scan(f'⚠ Directory Bruteforce failed: {str(e)[:50]}')
    
    # Advanced Scan: API Endpoint Discovery
    if scan_type == 'advanced' and options.get('advanced_api_discovery'):
        log_scan('🔍 Running ADVANCED API Endpoint Discovery...')
        try:
            from scanner.api_discovery import discover_api_endpoints
            api_results = discover_api_endpoints(target_url, timeout=20)
            
            if api_results['findings']:
                findings.extend(api_results['findings'])
                if api_results['total_found'] > 0:
                    log_scan(f'✓ API Discovery: Found {api_results["total_found"]} endpoint(s)')
                else:
                    log_scan('✓ API Discovery: No API endpoints found')
            
            details['api_discovery'] = {
                'discovered_endpoints': api_results['discovered_endpoints'],
                'total_found': api_results['total_found']
            }
        except Exception as e:
            log_scan(f'⚠ API Discovery failed: {str(e)[:50]}')
    
    # Advanced Scan: S3 Bucket Exposure Check
    if scan_type == 'advanced' and options.get('advanced_s3_bucket_check'):
        log_scan('☁️ Running ADVANCED S3 Bucket Exposure Check...')
        try:
            from scanner.s3_bucket_checker import check_s3_exposure
            s3_results = check_s3_exposure(target_url, timeout=15)
            
            if s3_results['findings']:
                findings.extend(s3_results['findings'])
                if s3_results['total_found'] > 0:
                    log_scan(f'⚠ S3 Check: Found {s3_results["total_found"]} bucket(s)')
                else:
                    log_scan('✓ S3 Check: No S3 buckets found')
            
            details['s3_buckets'] = {
                'discovered_buckets': s3_results['discovered_buckets'],
                'total_found': s3_results['total_found']
            }
        except Exception as e:
            log_scan(f'⚠ S3 Bucket Check failed: {str(e)[:50]}')

    # 2) TLS certificate inspection (if HTTPS)
    try:
        if target_url.startswith('https://'):
            log_scan('Inspecting TLS/SSL certificate...')
            hostname = tldextract.extract(target_url).fqdn
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()  # Get TLS version (e.g., 'TLSv1.2', 'TLSv1.3')
                    cipher = ssock.cipher()  # Get cipher info
                    
                    # check expiry
                    notAfter = cert.get('notAfter')
                    if notAfter:
                        expires = datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expires - datetime.utcnow()).days
                        details['tls_expires_days'] = days_left
                        if days_left < 14:
                            findings.append({
                                'id': 'tls-expiring', 
                                'title': 'TLS certificate expiring soon', 
                                'severity': 'high', 
                                'detail': f'Certificate expires in {days_left} days',
                                'recommendations': get_recommendations('tls-expiring')
                            })
                            log_scan(f'⚠ TLS certificate expires in {days_left} days')
                        else:
                            log_scan(f'✓ TLS certificate valid ({days_left} days remaining)')
                        
                        # Build TLS info with version
                        details['tls_info'] = {
                            'version': tls_version or 'Unknown',
                            'cipher': cipher[0] if cipher else None,
                            'cipher_bits': cipher[2] if cipher and len(cipher) > 2 else None,
                            'expires': notAfter,
                            'days_remaining': days_left,
                            'expires_days': days_left,  # Add this for consistency with payment scanner
                            'issuer': cert.get('issuer'),
                            'subject': cert.get('subject')
                        }
                        log_scan(f'✓ TLS {tls_version} with {cipher[0] if cipher else "unknown"} cipher')
        else:
            log_scan('⚠ Not using HTTPS - skipping TLS check')
    except Exception as e:
        # don't fail scan for TLS check errors; just record
        details['tls_error'] = str(e)
        log_scan(f'⚠ TLS check failed: {str(e)[:50]}')

    # 3) Lightweight dependency/version hints via headers
    log_scan('Checking server version exposure...')
    server_header = details.get('headers', {}).get('Server')
    if server_header:
        if any(s in server_header.lower() for s in ['apache/2.', 'nginx/1.']):
            findings.append({'id': 'server-version-exposed', 'title': 'Server version exposed', 'severity': 'low', 'detail': f'Server header: {server_header}'})
            log_scan(f'⚠ Server version exposed: {server_header}')
        else:
            log_scan(f'✓ Server header present: {server_header}')
    else:
        log_scan('✓ Server header hidden')

    # 4) Filter out informational positive confirmations, keep only real security issues
    log_scan('Filtering findings to show only real security issues...')
    real_findings = filter_real_findings(findings)
    info_count = len(findings) - len(real_findings)
    if info_count > 0:
        log_scan(f'Filtered out {info_count} informational status messages')
    
    # 5) Build summary and score
    log_scan('Generating scan report...')
    score = score_from_findings(real_findings)
    summary = f'{len(real_findings)} findings, score: {score}'
    log_scan(f'✓ Scan complete! Score: {score}/100')

    result = {
        'id': uid,
        'target': target_url,
        'created_at': created_at,
        'summary': summary,
        'score': score,
        'scan_type': 'general',
        'scan_logs': scan_logs,  # Include scan progress logs
        'details': {
            'findings': real_findings,  # Use filtered findings
            'meta': details
        }
    }
    return result

