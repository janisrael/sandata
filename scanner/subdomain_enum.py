"""
Subdomain Enumeration Module
Safe subdomain discovery using certificate transparency and DNS lookups
"""

import requests
from requests.exceptions import RequestException
import socket
import re
from urllib.parse import urlparse


def enumerate_subdomains(target_url, timeout=10):
    """
    Enumerate subdomains using safe, non-invasive methods
    
    Args:
        target_url: The target URL/domain to enumerate
        timeout: Request timeout in seconds
        
    Returns:
        dict: Enumeration findings and discovered subdomains
    """
    findings = []
    discovered_subdomains = []
    
    # Extract domain from URL
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Remove www if present to get root domain
    root_domain = domain.replace('www.', '')
    
    if not root_domain or '.' not in root_domain:
        findings.append({
            'id': 'subdomain-enum-invalid-domain',
            'title': 'Invalid Domain for Subdomain Enumeration',
            'severity': 'info',
            'detail': f'Could not extract a valid domain from: {target_url}',
            'type': 'Subdomain Enumeration'
        })
        return {
            'findings': findings,
            'discovered_subdomains': [],
            'total_found': 0
        }
    
    # Method 1: Certificate Transparency (crt.sh)
    ct_subdomains = _check_certificate_transparency(root_domain, timeout)
    discovered_subdomains.extend(ct_subdomains)
    
    # Method 2: Common subdomain bruteforce
    common_subdomains = _check_common_subdomains(root_domain, timeout)
    discovered_subdomains.extend(common_subdomains)
    
    # Remove duplicates and sort
    discovered_subdomains = sorted(list(set(discovered_subdomains)))
    
    # Verify subdomains (check if they resolve) and get IPs
    verified_subdomains = []
    subdomain_details = {}  # Store subdomain -> IP mapping
    for subdomain in discovered_subdomains[:50]:  # Limit to first 50 to avoid too many DNS queries
        ip = _verify_subdomain(subdomain)
        if ip:
            verified_subdomains.append(subdomain)
            subdomain_details[subdomain] = ip
    
    # Generate findings
    if verified_subdomains:
        # Check for potentially sensitive subdomains
        sensitive_patterns = {
            'dev': 'Development environment',
            'test': 'Testing environment',
            'staging': 'Staging environment',
            'admin': 'Admin panel',
            'api': 'API endpoint',
            'backup': 'Backup system',
            'db': 'Database',
            'mail': 'Mail server',
            'ftp': 'FTP server',
            'vpn': 'VPN access',
            'internal': 'Internal system',
            'private': 'Private system'
        }
        
        sensitive_found = []
        for subdomain in verified_subdomains:
            subdomain_name = subdomain.split('.')[0].lower()
            for pattern, description in sensitive_patterns.items():
                if pattern in subdomain_name:
                    ip = subdomain_details.get(subdomain, 'Unknown')
                    sensitive_found.append((subdomain, description, ip))
                    break
        
        if sensitive_found:
            # Build detailed findings list
            subdomain_list = []
            for subdomain, description, ip in sensitive_found[:10]:
                subdomain_list.append(f"\n  • {subdomain} → {ip} ({description})")
            if len(sensitive_found) > 10:
                subdomain_list.append(f"\n  ... and {len(sensitive_found) - 10} more")
            
            findings.append({
                'id': 'subdomain-sensitive-exposed',
                'title': f'⚠️ Potentially Sensitive Subdomains Found: {len(sensitive_found)}',
                'severity': 'medium',
                'detail': f'Found {len(sensitive_found)} subdomains that may expose sensitive systems:{"".join(subdomain_list)}',
                'type': 'Subdomain Enumeration',
                'subdomains': [f"{s[0]} ({s[1]})" for s in sensitive_found],  # For backwards compatibility
                'recommendations': [
                    'Review access controls on all discovered subdomains',
                    'Ensure dev/test/staging environments are not publicly accessible',
                    'Implement IP whitelisting for internal systems',
                    'Use VPN or firewall rules to restrict access',
                    'Remove or secure unused subdomains',
                    'Monitor access logs for suspicious activity',
                    'Consider using wildcard DNS with proper routing'
                ]
            })
        
        # Report all discovered subdomains
        subdomain_list = []
        for subdomain in verified_subdomains[:15]:
            ip = subdomain_details.get(subdomain, 'Unknown')
            subdomain_list.append(f"\n  • {subdomain} → {ip}")
        if len(verified_subdomains) > 15:
            subdomain_list.append(f"\n  ... and {len(verified_subdomains) - 15} more")
        
        findings.append({
            'id': 'subdomain-enum-results',
            'title': f'✓ Subdomains Discovered: {len(verified_subdomains)}',
            'severity': 'info',
            'detail': f'Found {len(verified_subdomains)} active subdomains for {root_domain}:{"".join(subdomain_list)}',
            'type': 'Subdomain Enumeration',
            'subdomains': verified_subdomains,
            'recommendations': [
                'Document all subdomains and their purposes',
                'Regularly audit subdomain inventory',
                'Remove unused or abandoned subdomains',
                'Ensure all subdomains use HTTPS',
                'Apply security headers to all subdomains',
                'Monitor certificate transparency logs for unauthorized subdomains'
            ]
        })
    else:
        findings.append({
            'id': 'subdomain-enum-none',
            'title': 'No Additional Subdomains Found',
            'severity': 'info',
            'detail': f'Subdomain enumeration completed for {root_domain}. No additional subdomains were discovered beyond the target domain.',
            'type': 'Subdomain Enumeration'
        })
    
    return {
        'findings': findings,
        'discovered_subdomains': verified_subdomains,
        'total_found': len(verified_subdomains)
    }


def _check_certificate_transparency(domain, timeout):
    """Check Certificate Transparency logs via crt.sh"""
    subdomains = []
    
    try:
        # Query crt.sh API
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        response = requests.get(url, timeout=timeout)
        
        if response.status_code == 200:
            try:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split by newlines (crt.sh returns multiple names per entry sometimes)
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip().lower()
                        # Remove wildcards
                        name = name.replace('*.', '')
                        # Only keep subdomains of our target
                        if name.endswith(domain) and name != domain:
                            subdomains.append(name)
            except ValueError:
                pass  # Invalid JSON
    except RequestException:
        pass  # CT lookup failed, continue with other methods
    
    return subdomains


def _check_common_subdomains(domain, timeout):
    """Check common subdomain names"""
    subdomains = []
    
    # Common subdomain wordlist
    common_subs = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'store',
        'api', 'dev', 'test', 'staging', 'prod', 'production',
        'app', 'mobile', 'portal', 'secure', 'vpn', 'remote',
        'cdn', 'static', 'images', 'assets', 'media', 'files',
        'docs', 'support', 'help', 'status', 'monitor', 'dashboard'
    ]
    
    for sub in common_subs:
        subdomain = f'{sub}.{domain}'
        subdomains.append(subdomain)
    
    return subdomains


def _verify_subdomain(subdomain):
    """Verify if a subdomain resolves via DNS and return its IP"""
    try:
        # Try to resolve the subdomain
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None
    except Exception:
        return None


def get_subdomain_recommendations(finding_id):
    """Get detailed recommendations for subdomain findings"""
    recommendations = {
        'subdomain-sensitive-exposed': [
            'Immediately review access to dev/test/staging subdomains',
            'Implement IP whitelisting: Only allow company IPs',
            'Add HTTP Basic Authentication at minimum',
            'Use VPN access for internal systems',
            'Set up firewall rules to block public access',
            'Monitor access logs for unauthorized attempts',
            'Remove robots.txt entries pointing to sensitive areas',
            'Use .htaccess or Nginx config to restrict access',
            'Consider using internal DNS instead of public DNS',
            'Regularly scan for new subdomains using CT logs'
        ],
        'subdomain-enum-results': [
            'Create an inventory of all subdomains and their owners',
            'Assign security responsibilities for each subdomain',
            'Decommission unused or abandoned subdomains',
            'Ensure all subdomains have valid SSL/TLS certificates',
            'Apply consistent security headers across all subdomains',
            'Set up monitoring/alerting for new subdomain creation',
            'Use wildcard certificates or automated cert management',
            'Review DNS records for typosquatting attempts',
            'Implement DMARC/SPF/DKIM for mail subdomains',
            'Document the purpose and security requirements of each subdomain'
        ]
    }
    
    return recommendations.get(finding_id, [])

