"""
Cross-Site Scripting (XSS) Detection Module
Safe, ethical XSS detection using non-malicious payloads
"""

import requests
from requests.exceptions import RequestException
import re
from urllib.parse import urlencode, urlparse, parse_qs
import html


def test_xss_vulnerability(target_url, timeout=10):
    """
    Test for XSS vulnerabilities using safe payloads
    
    Args:
        target_url: The URL to test
        timeout: Request timeout in seconds
        
    Returns:
        dict: Findings from XSS tests
    """
    findings = []
    tested_payloads = []
    
    # Reduce timeout for individual requests to prevent overall timeout
    request_timeout = min(timeout, 5)  # Max 5 seconds per request
    
    # Safe XSS test payloads (non-malicious markers)
    # These don't actually execute harmful code
    xss_payloads = [
        # Basic XSS markers
        '<xss>',
        '<XSS>',
        '<xss/>',
        
        # Script tag variations (safe markers)
        '<script>xss</script>',
        '<SCRIPT>xss</SCRIPT>',
        '<script src=x>',
        
        # Event handler markers
        '<img src=x>',
        '<img src=x onerror=xss>',
        '<body onload=xss>',
        '<input onfocus=xss>',
        '<svg onload=xss>',
        
        # HTML encoding bypass tests
        '&lt;script&gt;xss&lt;/script&gt;',
        
        # JavaScript protocol
        'javascript:xss',
        'javascript:alert(1)',
        
        # Data URI
        'data:text/html,<script>xss</script>',
        
        # Attribute breaking
        '" onmouseover="xss',
        "' onmouseover='xss",
        '><script>xss</script>',
        
        # Comment breaking
        '--><script>xss</script><!--',
        
        # CSS injection
        '<style>@import"xss";</style>',
        
        # Template injection markers
        '{{7*7}}',  # Angular/Jinja2
        '${7*7}',   # JSP/EL
        '<%= 7*7 %>', # ERB
    ]
    
    # Test reflected XSS in URL parameters
    findings.extend(_test_reflected_xss(target_url, xss_payloads, tested_payloads, request_timeout))
    
    # Test DOM-based XSS indicators
    findings.extend(_test_dom_xss(target_url, request_timeout))
    
    return {
        'findings': findings,
        'tested_payloads': len(tested_payloads),
        'vulnerable_params': len([f for f in findings if f['severity'] in ['critical', 'high']])
    }


def _test_reflected_xss(target_url, payloads, tested_payloads, timeout):
    """Test for reflected XSS vulnerabilities"""
    findings = []
    
    # Parse URL and extract parameters
    if '?' not in target_url:
        # Try adding a test parameter (limit to 3 payloads to avoid too many requests)
        test_params = {'test': 'xss_probe'}
        findings.extend(_test_params(target_url, test_params, payloads[:3], tested_payloads, timeout))
        return findings
    
    base_url, query_string = target_url.split('?', 1)
    
    # Safer parameter parsing
    try:
        params = {}
        for p in query_string.split('&'):
            if '=' in p:
                key, value = p.split('=', 1)
                params[key] = value
    except Exception:
        return findings
    
    if not params:
        return findings
    
    # Test each parameter (limit to first 2 params to avoid timeouts)
    param_count = 0
    for param_name in params.keys():
        if param_count >= 2:  # Only test first 2 parameters
            break
        param_count += 1
        
        vulnerable = False
        found_payload = None
        
        for payload in payloads[:5]:  # Test first 5 payloads per parameter
            test_params = params.copy()
            test_params[param_name] = payload
            tested_payloads.append(f"{param_name}={payload}")
            
            try:
                response = requests.get(base_url, params=test_params, timeout=timeout)
                
                # Check if payload is reflected in response
                if _is_payload_reflected(payload, response.text):
                    vulnerable = True
                    found_payload = payload
                    
                    # Check if it's actually executable (not encoded)
                    if _is_payload_executable(payload, response.text):
                        break
                    
            except RequestException:
                continue
        
        if vulnerable:
            severity = 'critical' if _is_payload_executable(found_payload, response.text) else 'high'
            
            findings.append({
                'id': 'xss-reflected',
                'title': f'Reflected XSS vulnerability detected in parameter: {param_name}',
                'severity': severity,
                'detail': f'The parameter "{param_name}" reflects user input without proper encoding. Payload "{found_payload}" was found in the response. This allows attackers to inject malicious scripts that execute in victims\' browsers.',
                'param': param_name,
                'payload': found_payload,
                'type': 'Reflected XSS',
                'recommendations': [
                    'Use output encoding/escaping for all user input displayed in HTML',
                    'Implement Content Security Policy (CSP) headers',
                    'Use HTML templating engines with auto-escaping (e.g., Jinja2 with autoescape)',
                    'Validate and sanitize all user input on the server side',
                    'Use HTTPOnly and Secure flags on cookies to prevent session hijacking',
                    'Consider using a Web Application Firewall (WAF) with XSS protection',
                    'For WordPress: Use esc_html(), esc_attr(), esc_js() functions',
                    'Never use innerHTML, use textContent instead in JavaScript'
                ]
            })
    
    return findings


def _test_params(base_url, test_params, payloads, tested_payloads, timeout):
    """Test parameters for XSS"""
    findings = []
    
    for param_name, _ in test_params.items():
        for payload in payloads:
            test_params_copy = test_params.copy()
            test_params_copy[param_name] = payload
            tested_payloads.append(f"{param_name}={payload}")
            
            try:
                response = requests.get(base_url, params=test_params_copy, timeout=timeout)
                
                if _is_payload_reflected(payload, response.text):
                    findings.append({
                        'id': 'xss-reflected-probe',
                        'title': f'Possible XSS vulnerability detected',
                        'severity': 'medium',
                        'detail': f'User input is reflected in the response without testing parameters. This could indicate an XSS vulnerability. Payload: {payload}',
                        'type': 'Reflected XSS (Probe)',
                        'recommendations': [
                            'Implement proper output encoding',
                            'Use Content Security Policy (CSP)',
                            'Validate and sanitize all user input'
                        ]
                    })
                    return findings  # Return after first finding
                    
            except RequestException:
                continue
    
    return findings


def _test_dom_xss(target_url, timeout):
    """Test for DOM-based XSS indicators"""
    findings = []
    
    try:
        response = requests.get(target_url, timeout=timeout)
        
        # Dangerous JavaScript patterns that could lead to DOM XSS
        dangerous_patterns = [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(\s*["\']',
            r'setInterval\s*\(\s*["\']',
            r'location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'window\.open\s*\(',
        ]
        
        found_patterns = []
        for pattern in dangerous_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                found_patterns.append(pattern.replace('\\s*\\(', '(').replace('\\s*=', '='))
        
        if found_patterns:
            findings.append({
                'id': 'xss-dom-indicators',
                'title': 'Potential DOM-based XSS vulnerabilities detected',
                'severity': 'medium',
                'detail': f'The page contains {len(found_patterns)} dangerous JavaScript patterns that could lead to DOM-based XSS if user input is not properly sanitized. Found patterns: {", ".join(found_patterns[:5])}',
                'type': 'DOM-based XSS (Indicators)',
                'patterns': found_patterns,
                'recommendations': [
                    'Avoid using dangerous JavaScript functions with user input',
                    'Use textContent instead of innerHTML',
                    'Use setAttribute() instead of direct property assignment',
                    'Implement strict Content Security Policy (CSP)',
                    'Sanitize all user input before DOM manipulation',
                    'Use modern frameworks with built-in XSS protection (React, Vue, Angular)',
                    'Never use eval() or setTimeout/setInterval with strings',
                    'Validate URLs before using them in location or window.open'
                ]
            })
    
    except RequestException:
        pass
    
    return findings


def _is_payload_reflected(payload, response_text):
    """Check if payload appears in response"""
    # Check for exact match
    if payload in response_text:
        return True
    
    # Check for HTML-encoded version
    encoded_payload = html.escape(payload)
    if encoded_payload in response_text:
        return True
    
    # Check for URL-encoded version
    url_encoded = payload.replace('<', '%3C').replace('>', '%3E').replace('"', '%22').replace("'", '%27')
    if url_encoded in response_text:
        return True
    
    return False


def _is_payload_executable(payload, response_text):
    """Check if payload appears in executable context (not encoded)"""
    # If payload contains < or > and they appear unencoded, it's executable
    if '<' in payload or '>' in payload:
        # Check if it appears without HTML encoding
        if payload in response_text:
            # Make sure it's not inside a comment or textarea
            if not re.search(r'<!--.*?' + re.escape(payload) + r'.*?-->', response_text, re.DOTALL):
                if not re.search(r'<textarea[^>]*>.*?' + re.escape(payload) + r'.*?</textarea>', response_text, re.DOTALL | re.IGNORECASE):
                    return True
    
    # Check for javascript: protocol in href or src
    if 'javascript:' in payload.lower():
        if re.search(r'(href|src)\s*=\s*["\']?' + re.escape(payload), response_text, re.IGNORECASE):
            return True
    
    return False


def get_xss_recommendations(finding_id):
    """Get detailed recommendations for XSS findings"""
    recommendations = {
        'xss-reflected': [
            'Implement context-aware output encoding for ALL user input',
            'HTML Context: Use HTML entity encoding (&lt; &gt; &amp; &quot; &#x27;)',
            'JavaScript Context: Use JavaScript escaping (\\x3C \\x3E)',
            'URL Context: Use URL encoding (%3C %3E)',
            'CSS Context: Use CSS escaping (\\3C \\3E)',
            'Set Content-Security-Policy header: "default-src \'self\'; script-src \'self\'"',
            'Use HTTPOnly flag on session cookies: Set-Cookie: session=...; HttpOnly',
            'For PHP: Use htmlspecialchars($input, ENT_QUOTES, \'UTF-8\')',
            'For JavaScript: Use textContent instead of innerHTML',
            'For WordPress: Use esc_html(), esc_attr(), esc_url(), esc_js()',
            'Implement input validation with whitelists (not blacklists)',
            'Consider using a template engine with auto-escaping (Twig, Jinja2)'
        ],
        'xss-dom-indicators': [
            'Avoid using document.write() - use createElement() and appendChild() instead',
            'Replace innerHTML with textContent or innerText for untrusted data',
            'Use setAttribute() instead of direct property assignment',
            'Validate and sanitize all user input before DOM manipulation',
            'Use DOMPurify library for sanitizing HTML: DOMPurify.sanitize(input)',
            'Implement strict Content Security Policy (CSP) with nonce',
            'Never use eval() with user input',
            'Replace setTimeout(string) with setTimeout(function)',
            'Validate URLs before using in location.href or window.open()',
            'Use modern frameworks with built-in XSS protection'
        ]
    }
    
    return recommendations.get(finding_id, [])

