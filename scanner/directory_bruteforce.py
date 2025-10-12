"""
Directory Bruteforcing Module
Discovers hidden directories and files using common wordlists
WARNING: Only use with explicit authorization - this is an active reconnaissance technique
"""

import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin, urlparse
import time


def bruteforce_directories(target_url, timeout=30):
    """
    Bruteforce common directories and files
    
    Args:
        target_url: The target URL to scan
        timeout: Total timeout for the scan (default 30s)
        
    Returns:
        dict: Bruteforce findings
    """
    findings = []
    discovered_paths = []
    
    # Parse URL to get base
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    if not base_url or not parsed_url.scheme:
        findings.append({
            'id': 'dirbrute-invalid-url',
            'title': 'Invalid URL for Directory Bruteforcing',
            'severity': 'info',
            'detail': f'Could not extract a valid base URL from: {target_url}',
            'type': 'Directory Bruteforcing'
        })
        return {
            'findings': findings,
            'discovered_paths': [],
            'total_found': 0
        }
    
    # Common directory and file wordlist (top security-relevant paths)
    wordlist = _get_common_wordlist()
    
    # Start bruteforcing
    start_time = time.time()
    tested_count = 0
    waf_filtered_count = 0
    
    for path in wordlist:
        # Check timeout
        if time.time() - start_time > timeout:
            findings.append({
                'id': 'dirbrute-timeout',
                'title': 'Directory Bruteforce Timeout',
                'severity': 'info',
                'detail': f'Scan timed out after {timeout}s. Tested {tested_count}/{len(wordlist)} paths.',
                'type': 'Directory Bruteforcing'
            })
            break
        
        full_url = urljoin(base_url, path)
        tested_count += 1
        
        try:
            # Use HEAD request first (faster)
            response = requests.head(full_url, timeout=2, allow_redirects=False)
            status_code = response.status_code
            
            # If HEAD not allowed, try GET
            if status_code == 405:
                response = requests.get(full_url, timeout=2, allow_redirects=False)
                status_code = response.status_code
            
            # Check if path exists (200, 201, 204, 301, 302, 401, 403)
            if status_code in [200, 201, 204, 301, 302, 401, 403]:
                # Verify if this is a real finding or WAF false positive
                is_waf_block = _is_waf_false_positive(response, status_code)
                
                if is_waf_block:
                    waf_filtered_count += 1
                else:
                    discovered_paths.append({
                        'path': path,
                        'full_url': full_url,
                        'status_code': status_code,
                        'content_length': response.headers.get('Content-Length', 'Unknown'),
                        'server': response.headers.get('Server', 'Unknown')
                    })
        
        except RequestException:
            # Path doesn't exist or timed out, continue
            continue
        
        # Small delay to avoid overwhelming the server
        time.sleep(0.05)  # 50ms delay
    
    # Analyze findings
    if discovered_paths:
        # Categorize by sensitivity
        critical_paths = []
        high_risk_paths = []
        medium_risk_paths = []
        info_paths = []
        
        sensitive_patterns = {
            # Critical - Direct access to sensitive files
            '.env': 'critical',
            '.git': 'critical',
            'config.php': 'critical',
            'wp-config.php': 'critical',
            'database.yml': 'critical',
            '.htaccess': 'critical',
            'phpinfo.php': 'critical',
            'backup': 'critical',
            '.sql': 'critical',
            '.bak': 'critical',
            
            # High - Admin/sensitive areas
            'admin': 'high',
            'phpmyadmin': 'high',
            'administrator': 'high',
            'wp-admin': 'high',
            'cpanel': 'high',
            'manager': 'high',
            'login': 'high',
            
            # Medium - Information disclosure
            'robots.txt': 'medium',
            'sitemap.xml': 'medium',
            'readme': 'medium',
            'changelog': 'medium',
            'test': 'medium',
            'temp': 'medium',
            
            # Info - Standard paths
            'images': 'info',
            'css': 'info',
            'js': 'info',
            'fonts': 'info',
        }
        
        for path_info in discovered_paths:
            path = path_info['path'].lower()
            status_code = path_info['status_code']
            severity = 'info'
            
            # Determine base severity from path pattern
            for pattern, level in sensitive_patterns.items():
                if pattern in path:
                    severity = level
                    break
            
            # Check status code and adjust severity
            # Only flag as critical/high/medium if ACTUALLY ACCESSIBLE (200-series)
            if status_code == 403:
                path_info['note'] = '✅ Properly blocked (403 Forbidden)'
                severity = 'info'  # Downgrade to info - this is GOOD security
            elif status_code == 401:
                path_info['note'] = '✅ Requires authentication (401 Unauthorized)'
                severity = 'info'  # Downgrade to info - this is GOOD security
            elif status_code in [301, 302]:
                path_info['note'] = 'Redirects - verify destination'
                # Keep original severity for redirects (might still be accessible)
            elif status_code in [200, 201, 204]:
                path_info['note'] = '🔴 EXPOSED AND ACCESSIBLE!'
                # Keep original severity - this is the real issue
            else:
                path_info['note'] = f'Returned HTTP {status_code}'
            
            # Categorize based on final severity
            if severity == 'critical' and status_code in [200, 201, 204]:
                critical_paths.append(path_info)
            elif severity == 'high' and status_code in [200, 201, 204, 301, 302]:
                high_risk_paths.append(path_info)
            elif severity == 'medium' and status_code in [200, 201, 204, 301, 302]:
                medium_risk_paths.append(path_info)
            else:
                info_paths.append(path_info)
        
        # Generate findings
        if critical_paths:
            # Build detailed findings list
            path_details = []
            for p in critical_paths:
                size_info = f" ({p.get('size', 0)} bytes)" if p.get('size') else ""
                path_details.append(
                    f"\n  • {p['full_url']} (HTTP {p['status_code']}){size_info} - {p.get('note', 'CRITICAL EXPOSURE!')}"
                )
            
            findings.append({
                'id': 'dirbrute-critical-paths',
                'title': f'🔴 CRITICAL: Sensitive Files/Directories Exposed - {len(critical_paths)} Found',
                'severity': 'critical',
                'detail': f'Found {len(critical_paths)} critical paths that expose sensitive information or configuration:{"".join(path_details)}',
                'type': 'Directory Bruteforcing',
                'paths': critical_paths,
                'recommendations': [
                    'IMMEDIATELY remove or restrict access to exposed files',
                    'Block access to .git directory via .htaccess or web server config',
                    'Move .env and config files outside web root',
                    'Delete backup files and test files from production',
                    'Disable directory listing in web server configuration',
                    'Use .htaccess to deny access: Order deny,allow / Deny from all',
                    'Remove phpinfo.php and other diagnostic files',
                    'Implement proper file permissions (chmod 600 for configs)',
                    'Use robots.txt to disallow sensitive directories',
                    'Regularly audit web root for sensitive files'
                ]
            })
        
        if high_risk_paths:
            # Build detailed findings list
            path_details = []
            for p in high_risk_paths[:10]:  # Show up to 10
                size_info = f" ({p.get('size', 0)} bytes)" if p.get('size') else ""
                path_details.append(
                    f"\n  • {p['full_url']} (HTTP {p['status_code']}){size_info} - {p.get('note', 'Admin/sensitive path')}"
                )
            if len(high_risk_paths) > 10:
                path_details.append(f"\n  ... and {len(high_risk_paths) - 10} more")
            
            findings.append({
                'id': 'dirbrute-high-risk-paths',
                'title': f'⚠️ HIGH RISK: Admin/Sensitive Paths Discovered - {len(high_risk_paths)} Found',
                'severity': 'high',
                'detail': f'Found {len(high_risk_paths)} admin or sensitive paths:{"".join(path_details)}',
                'type': 'Directory Bruteforcing',
                'paths': high_risk_paths,
                'recommendations': [
                    'Implement IP whitelisting for admin areas',
                    'Add HTTP Basic Authentication at minimum',
                    'Use non-standard paths for admin panels',
                    'Implement rate limiting on login pages',
                    'Enable MFA (Multi-Factor Authentication)',
                    'Monitor access logs for unauthorized attempts',
                    'Use fail2ban or similar brute-force protection',
                    'Consider using a VPN for admin access',
                    'Implement CAPTCHA on login forms',
                    'Set up alerts for admin area access'
                ]
            })
        
        if medium_risk_paths:
            # Build detailed findings list
            path_details = []
            for p in medium_risk_paths[:10]:  # Show up to 10
                size_info = f" ({p.get('size', 0)} bytes)" if p.get('size') else ""
                path_details.append(
                    f"\n  • {p['full_url']} (HTTP {p['status_code']}){size_info} - {p.get('note', 'May leak information')}"
                )
            if len(medium_risk_paths) > 10:
                path_details.append(f"\n  ... and {len(medium_risk_paths) - 10} more")
            
            findings.append({
                'id': 'dirbrute-medium-risk-paths',
                'title': f'⚠️ Information Disclosure Paths - {len(medium_risk_paths)} Found',
                'severity': 'medium',
                'detail': f'Found {len(medium_risk_paths)} paths that may leak information:{"".join(path_details)}',
                'type': 'Directory Bruteforcing',
                'paths': medium_risk_paths,
                'recommendations': [
                    'Review robots.txt for sensitive path disclosure',
                    'Remove or secure readme and changelog files',
                    'Delete test and temp directories from production',
                    'Sanitize sitemap.xml to exclude admin paths',
                    'Implement proper error handling (don\'t reveal paths)',
                    'Use security headers to prevent information leakage'
                ]
            })
        
        # Summary finding
        waf_note = f' (Filtered {waf_filtered_count} WAF false positives)' if waf_filtered_count > 0 else ''
        findings.append({
            'id': 'dirbrute-results',
            'title': f'✓ Directory Bruteforce Complete: {len(discovered_paths)} Real Paths Found',
            'severity': 'info',
            'detail': f'Tested {tested_count} common paths on {base_url}. Found {len(discovered_paths)} accessible paths{waf_note}. Critical: {len(critical_paths)}, High: {len(high_risk_paths)}, Medium: {len(medium_risk_paths)}, Info: {len(info_paths)}',
            'type': 'Directory Bruteforcing',
            'all_paths': discovered_paths,
            'waf_filtered': waf_filtered_count
        })
    else:
        waf_note = f' (Filtered {waf_filtered_count} WAF false positives - Good!)' if waf_filtered_count > 0 else ''
        findings.append({
            'id': 'dirbrute-no-paths',
            'title': '✅ No Exposed Paths Found - Well Secured!',
            'severity': 'info',
            'detail': f'Directory bruteforce completed on {base_url}. No common sensitive paths were discovered{waf_note}. Tested {tested_count} paths. Your WAF/server configuration is effectively blocking malicious requests.',
            'type': 'Directory Bruteforcing',
            'waf_filtered': waf_filtered_count
        })
    
    return {
        'findings': findings,
        'discovered_paths': discovered_paths,
        'total_found': len(discovered_paths)
    }


def _is_waf_false_positive(response, status_code):
    """
    Detect if a 403/401 response is a WAF false positive
    
    Args:
        response: The HTTP response object
        status_code: The HTTP status code
        
    Returns:
        bool: True if this is likely a WAF false positive, False if it's a real finding
    """
    # Only check for false positives on 403/401 responses
    if status_code not in [403, 401]:
        return False
    
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    # Cloudflare WAF indicators
    if 'cf-ray' in headers or 'cloudflare' in headers.get('server', '').lower():
        content_length = headers.get('content-length', '0')
        
        # Cloudflare often returns small HTML error pages (< 2KB) for blocked requests
        # Real file blocks usually have different sizes
        try:
            cl_int = int(content_length)
            if cl_int == 0:
                # 0 bytes = file doesn't exist, WAF is just blocking pattern
                return True
            elif cl_int > 0 and cl_int < 2048:
                # Small response (< 2KB) = likely WAF block page
                return True
            elif cl_int > 5000:
                # Large response (>5KB) = likely real file or real error page from app
                return False
            else:
                # 2KB-5KB range = check content-type as tiebreaker
                if 'text/html' in headers.get('content-type', ''):
                    # HTML in medium size range = likely WAF error page
                    return True
        except (ValueError, TypeError):
            # If we can't parse content-length, assume WAF block
            return True
    
    # AWS WAF indicators
    if 'x-amzn-requestid' in headers or 'x-amzn-errortype' in headers:
        return True
    
    # Generic WAF patterns
    waf_servers = ['cloudflare', 'akamai', 'cloudfront', 'incapsula', 'sucuri']
    server_header = headers.get('server', '').lower()
    
    for waf in waf_servers:
        if waf in server_header:
            # If it's a WAF server and returns 403, it might be a pattern block
            # Only trust it if there's a substantial content-length (real file)
            content_length = headers.get('content-length', '0')
            try:
                if int(content_length) == 0 or int(content_length) > 5000:
                    # 0 bytes = likely doesn't exist
                    # >5KB = likely real error page from app, not WAF
                    return False
                else:
                    # Small response from WAF = likely false positive
                    return True
            except (ValueError, TypeError):
                return True
    
    # If we get here, assume it's a real finding
    return False


def _get_common_wordlist():
    """Get common directory/file wordlist"""
    # Top security-relevant paths (kept small for performance)
    wordlist = [
        # Critical files
        '.env',
        '.env.local',
        '.env.production',
        '.git/',
        '.git/config',
        '.gitignore',
        '.htaccess',
        '.htpasswd',
        'config.php',
        'wp-config.php',
        'wp-config.php.bak',
        'configuration.php',
        'database.yml',
        'settings.py',
        'phpinfo.php',
        'info.php',
        'test.php',
        
        # Backup files
        'backup/',
        'backups/',
        'backup.zip',
        'backup.sql',
        'backup.tar.gz',
        'db.sql',
        'database.sql',
        'dump.sql',
        'site.zip',
        'www.zip',
        
        # Admin areas
        'admin/',
        'administrator/',
        'wp-admin/',
        'cpanel/',
        'webmail/',
        'phpmyadmin/',
        'pma/',
        'mysql/',
        'manager/',
        'admin.php',
        'login.php',
        'login/',
        
        # Common directories
        'api/',
        'backup/',
        'db/',
        'temp/',
        'tmp/',
        'test/',
        'dev/',
        'old/',
        'logs/',
        'log/',
        'cache/',
        'upload/',
        'uploads/',
        'files/',
        'includes/',
        'inc/',
        
        # Information disclosure
        'robots.txt',
        'sitemap.xml',
        'readme.txt',
        'readme.html',
        'README.md',
        'changelog.txt',
        'CHANGELOG.md',
        'LICENSE',
        'package.json',
        'composer.json',
        '.DS_Store',
        
        # WordPress specific
        'wp-content/',
        'wp-includes/',
        'wp-json/',
        'xmlrpc.php',
        
        # Common files
        'index.php',
        'admin.php',
        'setup.php',
        'install.php',
        'config.php',
        'dashboard.php',
        'api.php',
    ]
    
    return wordlist


def get_dirbrute_recommendations(finding_id):
    """Get detailed recommendations for directory bruteforce findings"""
    recommendations = {
        'dirbrute-critical-paths': [
            '1. Remove .git directory: rm -rf .git/ (or block via .htaccess)',
            '2. Move .env files outside web root or deny access',
            '3. Delete all backup files: find . -name "*.bak" -delete',
            '4. Remove phpinfo.php and test files immediately',
            '5. Block .htaccess access in Apache config',
            '6. Set proper file permissions: chmod 600 for config files',
            '7. Add to .htaccess: <FilesMatch "\\.(env|git|bak|sql)$"> Order deny,allow / Deny from all',
            '8. Disable directory listing: Options -Indexes',
            '9. Regularly scan for sensitive files in web root',
            '10. Use .gitignore to prevent committing sensitive files'
        ],
        'dirbrute-high-risk-paths': [
            '1. Rename admin paths to non-standard names',
            '2. Implement IP whitelisting for admin areas',
            '3. Add HTTP Basic Auth: htpasswd -c /path/.htpasswd admin',
            '4. In .htaccess: AuthType Basic / AuthName "Restricted" / AuthUserFile /path/.htpasswd',
            '5. Enable fail2ban for brute-force protection',
            '6. Implement rate limiting on login endpoints',
            '7. Use VPN for admin access when possible',
            '8. Enable MFA (Multi-Factor Authentication)',
            '9. Monitor /var/log/apache2/access.log for admin access',
            '10. Set up alerts for repeated login failures'
        ],
        'dirbrute-medium-risk-paths': [
            '1. Review robots.txt - remove sensitive path listings',
            '2. Delete readme and changelog files from production',
            '3. Remove test, temp, and dev directories',
            '4. Sanitize sitemap.xml to exclude sensitive areas',
            '5. Configure error pages to not reveal directory structure',
            '6. Use security headers: X-Content-Type-Options: nosniff',
            '7. Implement proper access controls on all directories',
            '8. Regular security audits of web root',
            '9. Remove unnecessary files from production',
            '10. Use deployment scripts to exclude test files'
        ]
    }
    
    return recommendations.get(finding_id, [])

