"""
S3 Bucket Exposure Checker
Detects publicly accessible AWS S3 buckets and potential data leakage
"""

import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup


def check_s3_exposure(target_url, timeout=15):
    """
    Check for S3 bucket exposure and misconfigurations
    
    Args:
        target_url: The target URL to scan
        timeout: Total timeout for the scan
        
    Returns:
        dict: S3 bucket exposure findings
    """
    findings = []
    discovered_buckets = []
    
    # Parse URL
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    
    # Extract potential bucket names from domain
    bucket_candidates = _generate_bucket_names(domain, target_url)
    
    # Also scan page content for S3 URLs
    try:
        response = requests.get(target_url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find S3 URLs in HTML
        s3_urls = _extract_s3_urls_from_html(response.text, soup)
        
        for url in s3_urls:
            bucket_name = _extract_bucket_name_from_url(url)
            if bucket_name and bucket_name not in bucket_candidates:
                bucket_candidates.append(bucket_name)
    
    except RequestException:
        pass
    
    # Test each bucket candidate
    for bucket_name in bucket_candidates[:10]:  # Limit to first 10
        bucket_info = _test_s3_bucket(bucket_name, timeout)
        if bucket_info:
            discovered_buckets.append(bucket_info)
    
    # Analyze findings
    if discovered_buckets:
        # Categorize by risk
        critical_buckets = []
        high_risk_buckets = []
        medium_risk_buckets = []
        
        for bucket in discovered_buckets:
            if bucket.get('public_write'):
                critical_buckets.append(bucket)
            elif bucket.get('public_read'):
                critical_buckets.append(bucket)
            elif bucket.get('exists') and bucket.get('list_enabled'):
                high_risk_buckets.append(bucket)
            elif bucket.get('exists'):
                medium_risk_buckets.append(bucket)
        
        # Generate findings
        if critical_buckets:
            # Build detailed findings list
            bucket_details = []
            for b in critical_buckets:
                status_text = "HTTP 200" if b.get('public_read') else "HTTP 403"
                access_level = "PUBLIC READ" if b.get('public_read') else "Exists but forbidden"
                listing_text = " + Directory Listing" if b.get('list_enabled') else ""
                bucket_details.append(
                    f"\n\n{b['bucket_name']}\nURL: {b.get('url', 'N/A')}\nStatus: {status_text}\nAccess: {access_level}{listing_text}\nRisk: {b.get('note', 'Public access enabled')}"
                )
            
            findings.append({
                'id': 's3-critical-exposure',
                'title': f'🔴 CRITICAL: Publicly Accessible S3 Buckets - {len(critical_buckets)} Found',
                'severity': 'critical',
                'detail': f'Found {len(critical_buckets)} S3 bucket(s) with public access.\n\n⚠️ CRITICAL: These buckets may expose sensitive data or allow unauthorized modifications!{"".join(bucket_details)}',
                'type': 'S3 Bucket Exposure',
                'buckets': critical_buckets,
                'recommendations': [
                    'IMMEDIATELY disable public access on all S3 buckets',
                    'Review bucket policies and remove public permissions',
                    'Enable "Block Public Access" settings on all buckets',
                    'Use AWS IAM policies for access control',
                    'Implement bucket encryption (AES-256 or KMS)',
                    'Enable S3 bucket logging for audit trails',
                    'Set up CloudTrail for S3 API monitoring',
                    'Use VPC endpoints for internal S3 access',
                    'Regularly audit S3 bucket permissions',
                    'Use AWS Access Analyzer to identify public buckets'
                ]
            })
        
        if high_risk_buckets:
            # Build detailed findings list
            bucket_details = []
            for b in high_risk_buckets:
                bucket_details.append(
                    f"\n\n{b['bucket_name']}\nURL: {b.get('url', 'N/A')}\nStatus: HTTP 200\nAccess: PUBLIC READ + Directory Listing\nRisk: {b.get('note', 'Directory listing enabled')}"
                )
            
            findings.append({
                'id': 's3-list-enabled',
                'title': f'⚠️ HIGH RISK: S3 Buckets with Directory Listing - {len(high_risk_buckets)} Found',
                'severity': 'high',
                'detail': f'Found {len(high_risk_buckets)} S3 bucket(s) with directory listing enabled.\n\n⚠️ WARNING: Attackers can enumerate all files in these buckets!{"".join(bucket_details)}',
                'type': 'S3 Bucket Exposure',
                'buckets': high_risk_buckets,
                'recommendations': [
                    'Disable directory listing on S3 buckets',
                    'Review and tighten bucket ACLs',
                    'Use bucket policies to restrict access',
                    'Enable "Block Public Access" at account level',
                    'Implement least privilege access principles',
                    'Use pre-signed URLs for temporary access',
                    'Monitor bucket access patterns for anomalies',
                    'Set up alerts for bucket policy changes'
                ]
            })
        
        if medium_risk_buckets:
            # Build detailed findings list with full info
            bucket_details = []
            for b in medium_risk_buckets:
                bucket_details.append(
                    f"\n  • {b['bucket_name']}\n    URL: {b.get('url', 'N/A')}\n    Status: HTTP 403\n    Access: {b.get('note', 'Exists but access forbidden')}"
                )
            
            findings.append({
                'id': 's3-buckets-found',
                'title': f'ℹ️ S3 Buckets Identified - {len(medium_risk_buckets)} Found',
                'severity': 'medium',
                'detail': f'Found {len(medium_risk_buckets)} S3 bucket(s) associated with this domain.\n\nℹ️ These buckets exist but are currently secured (HTTP 403 - Access Forbidden). Verify that access controls are properly configured and that no sensitive data could be exposed through misconfigurations.\n\nDISCOVERED BUCKETS:{"".join(bucket_details)}',
                'type': 'S3 Bucket Exposure',
                'buckets': medium_risk_buckets,
                'recommendations': [
                    'Audit all S3 bucket permissions regularly',
                    'Use descriptive bucket names (avoid guessable names)',
                    'Implement tagging for bucket organization',
                    'Enable versioning for critical buckets',
                    'Set up lifecycle policies for data retention',
                    'Use MFA Delete for critical buckets',
                    'Regularly review CloudWatch metrics',
                    'Document bucket purposes and owners'
                ]
            })
        
        # Summary
        findings.append({
            'id': 's3-check-results',
            'title': f'✓ S3 Bucket Check Complete: {len(discovered_buckets)} Buckets Found',
            'severity': 'info',
            'detail': f'Tested {len(bucket_candidates)} potential S3 bucket names. Found {len(discovered_buckets)} existing buckets. Critical: {len(critical_buckets)}, High-risk: {len(high_risk_buckets)}, Medium: {len(medium_risk_buckets)}',
            'type': 'S3 Bucket Exposure',
            'all_buckets': discovered_buckets
        })
    else:
        findings.append({
            'id': 's3-no-buckets',
            'title': 'No S3 Buckets Found',
            'severity': 'info',
            'detail': f'S3 bucket check completed. Tested {len(bucket_candidates)} potential bucket names. No S3 buckets were discovered.',
            'type': 'S3 Bucket Exposure'
        })
    
    return {
        'findings': findings,
        'discovered_buckets': discovered_buckets,
        'total_found': len(discovered_buckets)
    }


def _generate_bucket_names(domain, url):
    """Generate potential S3 bucket names based on domain"""
    bucket_names = []
    
    # Clean domain
    domain = domain.replace('www.', '').replace('http://', '').replace('https://', '')
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Base name from domain
    base_name = domain.replace('.', '-').replace('_', '-')
    company_name = domain.split('.')[0]
    
    # Common patterns
    patterns = [
        domain,
        base_name,
        company_name,
        f'{company_name}-assets',
        f'{company_name}-static',
        f'{company_name}-media',
        f'{company_name}-images',
        f'{company_name}-files',
        f'{company_name}-uploads',
        f'{company_name}-backup',
        f'{company_name}-prod',
        f'{company_name}-production',
        f'{company_name}-dev',
        f'{company_name}-staging',
        f'www-{company_name}',
        f'{company_name}-www',
        f'{company_name}-public',
        f'{company_name}-private',
    ]
    
    # Only add valid bucket names (lowercase, no special chars except hyphen)
    for pattern in patterns:
        clean_name = re.sub(r'[^a-z0-9\-]', '', pattern.lower())
        if clean_name and len(clean_name) >= 3:
            bucket_names.append(clean_name)
    
    return list(set(bucket_names))  # Remove duplicates


def _extract_s3_urls_from_html(html_text, soup):
    """Extract S3 URLs from HTML content"""
    s3_urls = []
    
    # Regex patterns for S3 URLs (non-capturing groups for regions, capturing full URL)
    patterns = [
        r'(https?://[a-z0-9\-]+\.s3\.amazonaws\.com[^\s\"\'<>]*)',
        r'(https?://s3\.amazonaws\.com/[a-z0-9\-]+[^\s\"\'<>]*)',
        r'(https?://[a-z0-9\-]+\.s3-[a-z0-9\-]+\.amazonaws\.com[^\s\"\'<>]*)',
        r'(https?://s3-[a-z0-9\-]+\.amazonaws\.com/[a-z0-9\-]+[^\s\"\'<>]*)',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html_text, re.IGNORECASE)
        for match in matches:
            if match and isinstance(match, str):
                s3_urls.append(match)
    
    # Also check src and href attributes
    for tag in soup.find_all(['img', 'script', 'link', 'a']):
        src = tag.get('src', '') or tag.get('href', '')
        if src and 's3.amazonaws.com' in src.lower():
            s3_urls.append(src)
    
    return list(set(s3_urls))  # Remove duplicates


def _extract_bucket_name_from_url(url):
    """Extract bucket name from S3 URL"""
    # Pattern: https://bucket-name.s3.amazonaws.com/
    match = re.search(r'https?://([a-z0-9\-]+)\.s3', url, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Pattern: https://s3.amazonaws.com/bucket-name/
    match = re.search(r's3\.amazonaws\.com/([a-z0-9\-]+)', url, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None


def _test_s3_bucket(bucket_name, timeout):
    """Test if S3 bucket exists and check permissions"""
    bucket_info = {
        'bucket_name': bucket_name,
        'exists': False,
        'public_read': False,
        'public_write': False,
        'list_enabled': False
    }
    
    # Try different S3 URL formats
    s3_urls = [
        f'https://{bucket_name}.s3.amazonaws.com/',
        f'https://s3.amazonaws.com/{bucket_name}/',
    ]
    
    for url in s3_urls:
        try:
            # Test for existence and public read
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                bucket_info['exists'] = True
                bucket_info['public_read'] = True
                bucket_info['url'] = url
                
                # Check if listing is enabled
                if '<ListBucketResult' in response.text or '<Contents>' in response.text:
                    bucket_info['list_enabled'] = True
                    bucket_info['note'] = 'Public read + directory listing enabled'
                else:
                    bucket_info['note'] = 'Public read access'
                
                return bucket_info
            
            elif response.status_code == 403:
                bucket_info['exists'] = True
                bucket_info['url'] = url
                bucket_info['note'] = 'Exists but access forbidden'
                return bucket_info
            
        except RequestException:
            continue
    
    return None if not bucket_info['exists'] else bucket_info

