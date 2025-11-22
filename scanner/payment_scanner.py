import requests
from requests.exceptions import RequestException
from datetime import datetime
import uuid
import tldextract
from bs4 import BeautifulSoup
import ssl
import socket
import re
from urllib.parse import urlparse

# Specialized payment page security scanner
# IMPORTANT: These are OBSERVATIONAL checks only - no form submissions or real transactions

def filter_real_findings(findings):
    """
    Filter out informational positive confirmations, keep only real security issues
    Removes findings that are just status confirmations (✓, "No X Found", etc.)
    """
    real_findings = []
    for f in findings:
        # Skip info-level positive confirmations
        if f['severity'] == 'info':
            title_lower = f.get('title', '').lower()
            # Keep info findings that are actual issues, not confirmations
            if any(keyword in title_lower for keyword in ['detected', 'found', 'discovered', 'exposed', 'missing']):
                # These are actual findings, keep them
                real_findings.append(f)
            # Skip positive confirmations (✓, "No X", "All X", etc.)
            elif any(keyword in title_lower for keyword in ['✓', 'no ', 'all ', 'enabled', 'present', 'complete', 'properly']):
                continue  # Skip positive confirmations
            else:
                # Keep other info findings that might be important
                real_findings.append(f)
        else:
            # Keep all non-info findings (critical, high, medium, low)
            real_findings.append(f)
    return real_findings

def score_from_findings(findings):
    """Calculate security score from findings"""
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


def get_recommendations(finding_id):
    """Get step-by-step recommendations for each finding"""
    recommendations = {
        'no-https': [
            'Obtain an SSL/TLS certificate from a trusted Certificate Authority (Let\'s Encrypt is free)',
            'Install the certificate on your web server',
            'Configure your web server to listen on port 443 (HTTPS)',
            'Set up automatic HTTP to HTTPS redirects',
            'Update all internal links to use HTTPS',
            'Test the implementation using SSL Labs (ssllabs.com/ssltest)'
        ],
        'no-hsts': [
            'Add the Strict-Transport-Security header to your web server configuration',
            'For Apache: Add "Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"" to your .htaccess or VirtualHost',
            'For Nginx: Add "add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;" to your server block',
            'Start with a shorter max-age (e.g., 300 seconds) for testing',
            'After verifying it works, increase max-age to 31536000 (1 year)',
            'Consider submitting your domain to the HSTS preload list'
        ],
        'mixed-content': [
            'Identify all HTTP resources on your HTTPS page',
            'Update all resource URLs to use HTTPS instead of HTTP',
            'Use protocol-relative URLs (//example.com/resource.js) or relative paths',
            'Check third-party scripts and ensure they support HTTPS',
            'Add Content-Security-Policy header to block mixed content',
            'Use browser developer tools to identify remaining mixed content'
        ],
        'insecure-form-action': [
            'Change form action attribute to use HTTPS',
            'Ensure the receiving endpoint is SSL-enabled',
            'Test form submission to verify HTTPS works',
            'Add SSL certificate to the destination server if needed'
        ],
        'no-csrf-token': [
            'Implement CSRF protection in your web framework',
            'Generate a unique token for each user session',
            'Include the token as a hidden field in all forms',
            'Verify the token on the server before processing form data',
            'For payment forms, also consider double-submit cookie pattern',
            'Rotate tokens after sensitive operations'
        ],
        'no-captcha-protection': [
            'Sign up for Google reCAPTCHA at google.com/recaptcha',
            'Get your site key and secret key',
            'Add reCAPTCHA script to your HTML: <script src="https://www.google.com/recaptcha/api.js"></script>',
            'Add the reCAPTCHA widget to your form: <div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>',
            'Verify the reCAPTCHA response on your server using the secret key',
            'Consider using reCAPTCHA v3 for invisible protection'
        ],
        'htaccess-exposed': [
            'Immediately block access to .htaccess in your web server configuration',
            'For Apache: Add "RedirectMatch 403 /\\..*$" to your configuration',
            'For Nginx: Add "location ~ /\\. { deny all; }" to your server block',
            'Verify the file is no longer accessible',
            'Review your .htaccess file for any exposed sensitive information',
            'Change any passwords or secrets that may have been exposed'
        ],
        'critical-files-exposed': [
            'Immediately block access to sensitive files (.env, .git, backup files)',
            'Move sensitive files outside the web root directory',
            'Add deny rules in your web server configuration',
            'For Apache: Use "RedirectMatch 403" or "Deny from all"',
            'For Nginx: Use "location" blocks with "deny all"',
            'Review what information was exposed and rotate credentials',
            'Use .gitignore to prevent committing sensitive files'
        ],
        'missing-security-headers': [
            'Add Content-Security-Policy header to prevent XSS attacks',
            'Add X-Content-Type-Options: nosniff to prevent MIME sniffing',
            'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking',
            'Add Referrer-Policy to control referrer information',
            'For Apache: Use "Header set" directives in .htaccess or config',
            'For Nginx: Use "add_header" directives in server block',
            'Test headers using securityheaders.com'
        ],
        'weak-form-validation': [
            'Add HTML5 validation attributes (required, pattern, maxlength)',
            'Use appropriate input types (email, tel, url, number)',
            'Implement client-side JavaScript validation for better UX',
            'ALWAYS validate on the server side (client-side can be bypassed)',
            'Provide clear error messages for validation failures',
            'Consider using a validation library like validator.js'
        ],
        'autocomplete-payment': [
            'Set autocomplete="off" for sensitive payment fields',
            'Use specific autocomplete values: autocomplete="cc-number", "cc-csc", "cc-exp"',
            'This prevents browsers from saving credit card data',
            'Test in multiple browsers to ensure it works',
            'Consider using payment tokenization to avoid handling card data'
        ],
        'tls-expiring': [
            'Renew your SSL/TLS certificate immediately',
            'Set up automatic renewal if using Let\'s Encrypt (certbot)',
            'Configure monitoring/alerts for certificate expiration (30 days before)',
            'Keep certificate renewal process documented',
            'Test the new certificate after installation',
            'Consider using a certificate management service'
        ],
        'old-tls-version': [
            'Disable TLS 1.0 and TLS 1.1 in your web server configuration',
            'Enable only TLS 1.2 and TLS 1.3',
            'For Apache: Use "SSLProtocol -all +TLSv1.2 +TLSv1.3"',
            'For Nginx: Use "ssl_protocols TLSv1.2 TLSv1.3;"',
            'Test your changes using SSL Labs',
            'Notify users if you need to support legacy browsers'
        ],
        'weak-cipher': [
            'Configure your server to use strong cipher suites',
            'Prioritize forward secrecy (ECDHE) cipher suites',
            'Disable weak ciphers (RC4, 3DES, DES)',
            'Use Mozilla\'s SSL Configuration Generator for best practices',
            'Test cipher configuration using SSL Labs',
            'Keep your OpenSSL library updated'
        ],
        'insecure-cookies': [
            'Add Secure flag to all cookies on HTTPS sites',
            'Add HttpOnly flag to session/auth cookies',
            'Add SameSite=Strict or SameSite=Lax attribute',
            'In PHP: session_set_cookie_params with proper flags',
            'In Express.js: Use cookie-session with secure options',
            'Test cookie settings in browser developer tools'
        ],
        'direct-card-input': [
            'Use a payment gateway that handles card data (Stripe, PayPal, Square)',
            'Implement tokenization - never store raw card numbers',
            'Use the payment provider\'s hosted payment page or embedded form',
            'This eliminates PCI DSS compliance requirements',
            'Stripe Elements and PayPal Smart Buttons are good options',
            'Remove any direct card input fields from your forms'
        ]
    }
    
    # Default recommendations for unknown finding types
    default_recommendations = [
        'Review the security issue details carefully',
        'Research best practices for this specific vulnerability',
        'Consult your framework\'s security documentation',
        'Test the fix in a development environment first',
        'Deploy the fix and verify it works correctly',
        'Monitor for any related issues after deployment'
    ]
    
    return recommendations.get(finding_id, default_recommendations)


def check_https_enforcement(target_url, resp):
    """Check if HTTPS is enforced"""
    findings = []
    
    if not target_url.startswith('https://'):
        findings.append({
            'id': 'no-https',
            'title': 'Payment page not using HTTPS',
            'severity': 'critical',
            'detail': 'Payment pages MUST use HTTPS. This is a critical PCI DSS requirement.',
            'recommendations': get_recommendations('no-https')
        })
    else:
        # Positive finding
        findings.append({
            'id': 'https-enabled',
            'title': '✓ HTTPS Enabled',
            'severity': 'info',
            'detail': 'Page is using HTTPS encryption for secure communication'
        })
    
    # Check for HSTS header
    if 'Strict-Transport-Security' not in resp.headers:
        findings.append({
            'id': 'no-hsts',
            'title': 'Missing HSTS header',
            'severity': 'high',
            'detail': 'Strict-Transport-Security header is missing. Payment pages should enforce HTTPS with HSTS.',
            'recommendations': get_recommendations('no-hsts')
        })
    else:
        hsts_value = resp.headers.get('Strict-Transport-Security', '')
        findings.append({
            'id': 'hsts-enabled',
            'title': '✓ HSTS Header Present',
            'severity': 'info',
            'detail': f'HSTS properly configured: {hsts_value}'
        })
    
    return findings


def check_mixed_content(soup, final_url):
    """Check for mixed content (HTTP resources on HTTPS page)"""
    findings = []
    mixed_resources = []
    
    # Check scripts
    for script in soup.find_all('script', src=True):
        src = script['src']
        if src.startswith('http://'):
            mixed_resources.append(f'Script: {src}')
    
    # Check stylesheets
    for link in soup.find_all('link', href=True):
        href = link['href']
        if href.startswith('http://'):
            mixed_resources.append(f'Stylesheet: {href}')
    
    # Check images
    for img in soup.find_all('img', src=True):
        src = img['src']
        if src.startswith('http://'):
            mixed_resources.append(f'Image: {src}')
    
    # Check forms
    for form in soup.find_all('form', action=True):
        action = form['action']
        if action.startswith('http://'):
            mixed_resources.append(f'Form action: {action}')
    
    if mixed_resources:
        findings.append({
            'id': 'mixed-content',
            'title': 'Mixed content detected',
            'severity': 'critical',
            'detail': f'Found {len(mixed_resources)} insecure resources on HTTPS page: {mixed_resources[:5]}',
            'recommendations': get_recommendations('mixed-content')
        })
    else:
        # Show positive finding when no mixed content
        findings.append({
            'id': 'no-mixed-content',
            'title': 'No Mixed Content',
            'severity': 'info',
            'detail': 'All resources (scripts, stylesheets, images, forms) are loaded securely via HTTPS'
        })
    
    return findings


def check_recaptcha(soup, body_text):
    """Check for reCAPTCHA/CAPTCHA implementation"""
    findings = []
    captcha_info = {}
    
    # Check for Google reCAPTCHA
    recaptcha_patterns = [
        'google.com/recaptcha',
        'www.google.com/recaptcha',
        'g-recaptcha',
        'grecaptcha',
        'data-sitekey'
    ]
    
    has_recaptcha = any(pattern in body_text for pattern in recaptcha_patterns)
    
    if has_recaptcha:
        captcha_info['type'] = 'Google reCAPTCHA'
        captcha_info['detected'] = True
    else:
        # Check for other CAPTCHA solutions
        other_captcha = ['hcaptcha', 'turnstile', 'captcha']
        for captcha in other_captcha:
            if captcha in body_text:
                captcha_info['type'] = captcha
                captcha_info['detected'] = True
                break
    
    # Check if forms exist without CAPTCHA (potential bot vulnerability)
    forms = soup.find_all('form')
    if forms and not captcha_info.get('detected'):
        findings.append({
            'id': 'no-captcha-protection',
            'title': 'No CAPTCHA protection detected',
            'severity': 'medium',
            'detail': f'Found {len(forms)} form(s) without CAPTCHA/reCAPTCHA protection. Consider adding bot prevention for payment forms.',
            'recommendations': get_recommendations('no-captcha-protection')
        })
    elif captcha_info.get('detected'):
        # Positive finding
        findings.append({
            'id': 'captcha-enabled',
            'title': f'✓ {captcha_info.get("type", "CAPTCHA")} Protection Enabled',
            'severity': 'info',
            'detail': 'Bot protection is active on forms'
        })
    
    return findings, captcha_info


def check_form_validation(soup):
    """Check HTML5 form validation attributes"""
    findings = []
    validation_info = []
    
    forms = soup.find_all('form')
    
    for idx, form in enumerate(forms):
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        validation_stats = {
            'form_index': idx,
            'has_required': False,
            'has_pattern': False,
            'has_maxlength': False,
            'has_type_validation': False
        }
        
        for inp in inputs:
            # Check for required attribute
            if inp.get('required') or inp.get('required') == '':
                validation_stats['has_required'] = True
            
            # Check for pattern validation
            if inp.get('pattern'):
                validation_stats['has_pattern'] = True
            
            # Check for maxlength
            if inp.get('maxlength'):
                validation_stats['has_maxlength'] = True
            
            # Check for input type validation
            input_type = inp.get('type', 'text')
            if input_type in ['email', 'tel', 'number', 'url']:
                validation_stats['has_type_validation'] = True
        
        validation_info.append(validation_stats)
        
        # Flag forms with minimal validation
        if inputs and not any([validation_stats['has_required'], validation_stats['has_pattern'], validation_stats['has_maxlength']]):
            findings.append({
                'id': f'weak-form-validation-{idx}',
                'title': 'Weak client-side form validation',
                'severity': 'low',
                'detail': f'Form {idx} lacks HTML5 validation attributes (required, pattern, maxlength). While server-side validation is critical, client-side validation improves UX.'
            })
    
    return findings, validation_info


def check_htaccess_security(target_url):
    """Check for .htaccess exposure and security"""
    findings = []
    htaccess_info = {}
    
    try:
        # Try to access .htaccess file
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        htaccess_url = f"{base_url}/.htaccess"
        
        resp = requests.get(htaccess_url, timeout=5, allow_redirects=False)
        
        if resp.status_code == 200:
            findings.append({
                'id': 'htaccess-exposed',
                'title': '.htaccess file is publicly accessible',
                'severity': 'critical',
                'detail': '.htaccess file should NEVER be publicly accessible. This file contains sensitive server configuration and can reveal security measures.',
                'recommendations': get_recommendations('htaccess-exposed')
            })
            htaccess_info['exposed'] = True
            htaccess_info['size'] = len(resp.content)
        elif resp.status_code == 403:
            # Good - file exists but is protected
            htaccess_info['exposed'] = False
            htaccess_info['protected'] = True
        else:
            htaccess_info['exposed'] = False
            htaccess_info['not_found'] = True
            
    except RequestException:
        htaccess_info['check_failed'] = True
    
    return findings, htaccess_info


def check_payment_forms(soup):
    """Analyze payment form security"""
    findings = []
    form_details = []
    
    forms = soup.find_all('form')
    
    for idx, form in enumerate(forms):
        form_info = {'index': idx}
        
        # Check form action
        action = form.get('action', '')
        form_info['action'] = action
        
        # Check for HTTPS in form action
        if action and not action.startswith('https://') and not action.startswith('/'):
            findings.append({
                'id': f'insecure-form-action-{idx}',
                'title': 'Form submits to insecure endpoint',
                'severity': 'critical',
                'detail': f'Form {idx} submits to: {action}'
            })
        
        # Check form method
        method = form.get('method', 'get').lower()
        form_info['method'] = method
        
        # Look for payment-related fields
        inputs = form.find_all(['input', 'select', 'textarea'])
        payment_fields = []
        
        for inp in inputs:
            name = inp.get('name', '').lower()
            input_type = inp.get('type', 'text').lower()
            autocomplete = inp.get('autocomplete', '').lower()
            
            # Detect payment fields
            if any(keyword in name for keyword in ['card', 'credit', 'cvv', 'cvc', 'expiry', 'exp_', 'billing', 'payment']):
                payment_fields.append({
                    'name': name,
                    'type': input_type,
                    'autocomplete': autocomplete
                })
                
                # Check if credit card fields have autocomplete off
                if 'card' in name or 'cvv' in name or 'cvc' in name:
                    if autocomplete not in ['off', 'cc-number', 'cc-csc', 'cc-exp']:
                        findings.append({
                            'id': f'autocomplete-payment-{idx}',
                            'title': 'Payment field autocomplete not properly configured',
                            'severity': 'medium',
                            'detail': f'Field "{name}" should have autocomplete="off" or proper cc-* values for security'
                        })
                
                # Check if sensitive fields are using proper input types
                if 'cvv' in name or 'cvc' in name:
                    if input_type != 'password' and input_type != 'tel':
                        findings.append({
                            'id': f'cvv-input-type-{idx}',
                            'title': 'CVV field not using secure input type',
                            'severity': 'medium',
                            'detail': f'CVV field "{name}" should use type="password" or type="tel"'
                        })
        
        form_info['payment_fields'] = payment_fields
        
        # Check for CSRF token
        csrf_found = False
        csrf_tokens = []
        for inp in inputs:
            name = inp.get('name', '').lower()
            if any(token in name for token in ['csrf', 'token', '_token', 'authenticity', 'xsrf']):
                csrf_found = True
                csrf_tokens.append(name)
        
        form_info['csrf_token'] = csrf_found
        form_info['csrf_token_names'] = csrf_tokens
        
        if payment_fields and not csrf_found:
            findings.append({
                'id': f'no-csrf-token-{idx}',
                'title': 'Payment form missing CSRF token',
                'severity': 'critical',
                'detail': f'Form {idx} appears to be a payment form but no CSRF token detected. This is a critical security vulnerability that can lead to Cross-Site Request Forgery attacks.',
                'recommendations': get_recommendations('no-csrf-token')
            })
        elif not csrf_found and len(inputs) > 2:
            findings.append({
                'id': f'no-csrf-token-general-{idx}',
                'title': 'Form missing CSRF protection',
                'severity': 'high',
                'detail': f'Form {idx} has no CSRF token. All forms that modify data should have CSRF protection.',
                'recommendations': get_recommendations('no-csrf-token')
            })
        
        form_details.append(form_info)
    
    return findings, form_details


def check_pci_indicators(resp, soup):
    """Check for PCI DSS compliance indicators"""
    findings = []
    indicators = []
    
    body = resp.text.lower()
    
    # Check security headers critical for PCI DSS
    critical_headers = {
        'Content-Security-Policy': 'CSP helps prevent XSS attacks',
        'X-Content-Type-Options': 'Prevents MIME type sniffing',
        'X-Frame-Options': 'Prevents clickjacking attacks'
    }
    
    missing_headers = []
    for header, description in critical_headers.items():
        if header not in resp.headers:
            missing_headers.append(f'{header} ({description})')
    
    if missing_headers:
        findings.append({
            'id': 'pci-security-headers',
            'title': 'Missing PCI-critical security headers',
            'severity': 'high',
            'detail': f'Missing: {", ".join(missing_headers)}'
        })
    
    # Look for payment gateway integrations (enhanced detection)
    gateways = {
        # Direct API integrations
        'js.stripe.com': 'Stripe',
        'stripe.com': 'Stripe',
        'paypal.com/sdk': 'PayPal',
        'paypalobjects.com': 'PayPal',
        'paypal-script': 'PayPal',
        'squareup.com': 'Square',
        'squareupsandbox.com': 'Square',
        'braintreegateway.com': 'Braintree',
        'braintree-api.com': 'Braintree',
        'authorize.net': 'Authorize.Net',
        'authorizenet.com': 'Authorize.Net',
        'worldpay.com': 'Worldpay',
        'live.adyen.com': 'Adyen',
        'checkout.com': 'Checkout.com',
        'mollie.com': 'Mollie',
        'razorpay.com': 'Razorpay',
        # E-commerce platforms
        'shopify': 'Shopify Payments',
        'woocommerce': 'WooCommerce',
        'bigcommerce': 'BigCommerce',
        'magento': 'Magento',
        # Embedded/iframe solutions
        'securepaynet': 'SecurePay',
        'moneris': 'Moneris',
        'bambora': 'Bambora',
        'paysafe': 'Paysafe'
    }
    
    detected_gateways = []
    detected_gateway_names = set()  # To avoid duplicates
    
    # Check in multiple places
    scripts = soup.find_all('script', src=True)
    forms = soup.find_all('form', action=True)
    inline_scripts = soup.find_all('script')
    
    # Combine all sources
    script_sources = ' '.join([s.get('src', '') for s in scripts]).lower()
    form_actions = ' '.join([f.get('action', '') for f in forms]).lower()
    inline_content = ' '.join([s.string for s in inline_scripts if s.string]).lower()
    combined_check = script_sources + ' ' + form_actions + ' ' + inline_content + ' ' + body
    
    for key, name in gateways.items():
        # Check if gateway reference is present
        if key.lower() in combined_check:
            if name not in detected_gateway_names:
                detected_gateways.append(name)
                detected_gateway_names.add(name)
                indicators.append(f'{name} detected')
    
    # Additional check: Look for common payment form indicators
    payment_indicators = ['payment-method', 'credit-card', 'card-number', 'cvv', 'expiry', 'billing-address']
    has_payment_fields = any(indicator in body for indicator in payment_indicators)
    
    if has_payment_fields and not detected_gateways:
        # Likely has payment form but gateway loads dynamically
        indicators.append('Payment form detected (gateway may load dynamically)')
    
    # Check for PCI compliance badges/seals (specific indicators only)
    pci_badges = {
        'pci-dss': 'PCI DSS',
        'pci compliant': 'PCI Compliant',
        'pci certified': 'PCI Certified', 
        'verified by visa': 'Verified by Visa',
        'mastercard securecode': 'MasterCard SecureCode',
        'american express safekey': 'American Express SafeKey'
    }
    for badge, label in pci_badges.items():
        if badge in body:
            indicators.append(f'{label} badge detected')
    
    # Show summary finding
    if detected_gateways:
        findings.append({
            'id': 'payment-gateways-detected',
            'title': f'✓ Payment Gateway(s) Detected: {", ".join(detected_gateways)}',
            'severity': 'info',
            'detail': f'Integrated payment providers found: {", ".join(detected_gateways)}'
        })
    elif has_payment_fields:
        findings.append({
            'id': 'payment-fields-no-gateway',
            'title': 'Payment Form Found - Gateway Loads Dynamically',
            'severity': 'info',
            'detail': 'Payment form fields detected, but the payment gateway may load via JavaScript after page load (common with modern checkouts). This scan only checks the initial HTML.'
        })
    else:
        findings.append({
            'id': 'no-payment-gateways',
            'title': 'No Payment Gateway Integration Detected',
            'severity': 'info',
            'detail': 'No payment gateway or payment form fields found. Note: Gateways loaded via iframes or dynamically after page load may not be detected.'
        })
    
    # Detect E-commerce Platform/CMS
    platforms = detect_ecommerce_platform(soup, resp, body)
    if platforms:
        platform_names = ', '.join(platforms)
        findings.append({
            'id': 'platform-detected',
            'title': f'✓ E-commerce Platform Detected: {platform_names}',
            'severity': 'info',
            'detail': f'Platform: {platform_names}. This helps identify platform-specific security considerations.'
        })
        indicators.append(f'Platform: {platform_names}')
    
    return findings, indicators, detected_gateways


def detect_ecommerce_platform(soup, resp, body):
    """Detect e-commerce platform or CMS"""
    detected = []
    
    # Check response headers for platform signatures
    headers = {key.lower(): value for key, value in resp.headers.items()}
    
    # Shopify detection
    if 'x-shopify-stage' in headers or 'shopify' in body or 'cdn.shopify.com' in body:
        detected.append('Shopify')
    
    # WooCommerce detection
    if 'woocommerce' in body or 'wc-' in body or 'wp-content/plugins/woocommerce' in body:
        detected.append('WooCommerce')
        if 'wordpress' not in detected:
            detected.append('WordPress')
    
    # WordPress detection (standalone)
    if 'wp-content' in body or 'wp-includes' in body or '/wp-json/' in body:
        if 'WordPress' not in detected:
            detected.append('WordPress')
    
    # Magento detection
    if 'magento' in body.lower() or 'mage/cookies.js' in body or 'Mage.Cookies' in body:
        detected.append('Magento')
    
    # BigCommerce detection
    if 'bigcommerce' in body or 'bc-sf-filter' in body:
        detected.append('BigCommerce')
    
    # PrestaShop detection
    if 'prestashop' in body.lower() or '/modules/ps_' in body:
        detected.append('PrestaShop')
    
    # OpenCart detection  
    if 'opencart' in body.lower() or 'catalog/view/theme' in body:
        detected.append('OpenCart')
    
    # Wix detection
    if 'wix.com' in body or 'x-wix-' in ' '.join(headers.keys()):
        detected.append('Wix')
    
    # Squarespace detection
    if 'squarespace' in body or 'sqsp' in body:
        detected.append('Squarespace')
    
    # Ecwid detection
    if 'ecwid' in body:
        detected.append('Ecwid')
    
    # 3dcart detection
    if '3dcart' in body or '3dcartstores' in body:
        detected.append('3dcart')
    
    # Volusion detection
    if 'volusion' in body:
        detected.append('Volusion')
    
    # Salesforce Commerce Cloud detection
    if 'demandware' in body or 'salesforce commerce' in body.lower():
        detected.append('Salesforce Commerce Cloud')
    
    return detected


def check_javascript_security(soup):
    """Check JavaScript security for payment pages"""
    findings = []
    
    scripts = soup.find_all('script')
    inline_scripts = [s for s in scripts if not s.get('src')]
    
    if inline_scripts:
        findings.append({
            'id': 'inline-scripts',
            'title': 'Inline JavaScript detected',
            'severity': 'low',
            'detail': f'Found {len(inline_scripts)} inline scripts. Consider using CSP with nonce/hash for better security.'
        })
    
    # Check for external scripts from unknown domains
    external_scripts = [s.get('src') for s in scripts if s.get('src')]
    suspicious_scripts = []
    
    trusted_domains = ['stripe.com', 'paypal.com', 'braintreegateway.com', 'square.com', 'adyen.com', 'googleapis.com', 'cloudflare.com']
    
    for src in external_scripts:
        if src.startswith('http'):
            domain = urlparse(src).netloc
            if not any(trusted in domain for trusted in trusted_domains):
                suspicious_scripts.append(src)
    
    if suspicious_scripts:
        findings.append({
            'id': 'unknown-external-scripts',
            'title': 'Third-party scripts from unknown sources',
            'severity': 'medium',
            'detail': f'Review these scripts: {suspicious_scripts[:3]}'
        })
    
    return findings


def check_cookie_security(resp):
    """Check payment page cookie security"""
    findings = []
    
    cookies = resp.cookies
    if not cookies:
        return findings
    
    insecure_cookies = []
    for cookie in cookies:
        cookie_issues = []
        
        # Check Secure flag
        if not cookie.secure:
            cookie_issues.append('missing Secure flag')
        
        # Check HttpOnly flag for session cookies
        if 'session' in cookie.name.lower() or 'auth' in cookie.name.lower():
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_issues.append('missing HttpOnly flag')
        
        # Check SameSite attribute
        if not cookie.has_nonstandard_attr('SameSite'):
            cookie_issues.append('missing SameSite attribute')
        
        if cookie_issues:
            insecure_cookies.append(f"{cookie.name}: {', '.join(cookie_issues)}")
    
    if insecure_cookies:
        findings.append({
            'id': 'insecure-cookies',
            'title': 'Insecure cookie configuration',
            'severity': 'high',
            'detail': f'Cookies with issues: {insecure_cookies}'
        })
    
    return findings


def check_tls_configuration(target_url):
    """Check TLS/SSL configuration for payment pages"""
    findings = []
    tls_info = {}
    
    if not target_url.startswith('https://'):
        return findings, tls_info
    
    try:
        hostname = tldextract.extract(target_url).fqdn
        ctx = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Check certificate expiry
                notAfter = cert.get('notAfter')
                if notAfter:
                    expires = datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expires - datetime.utcnow()).days
                    tls_info['expires_days'] = days_left
                    tls_info['expires_date'] = notAfter
                    
                    if days_left < 30:
                        findings.append({
                            'id': 'cert-expiring',
                            'title': 'TLS certificate expiring soon',
                            'severity': 'critical' if days_left < 7 else 'high',
                            'detail': f'Certificate expires in {days_left} days. Renew immediately for payment pages.'
                        })
                
                # Check TLS version (PCI DSS requires TLS 1.2+)
                tls_info['version'] = version
                if version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                    findings.append({
                        'id': 'old-tls-version',
                        'title': 'Outdated TLS version',
                        'severity': 'critical',
                        'detail': f'Using {version}. PCI DSS requires TLS 1.2 or higher for payment pages.'
                    })
                
                # Check cipher strength
                if cipher:
                    tls_info['cipher'] = cipher[0]
                    tls_info['cipher_bits'] = cipher[2]
                    
                    if cipher[2] < 128:
                        findings.append({
                            'id': 'weak-cipher',
                            'title': 'Weak cipher strength',
                            'severity': 'high',
                            'detail': f'Using {cipher[2]}-bit cipher. Payment pages should use 128-bit or stronger.'
                        })
                
                # Certificate details
                tls_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                tls_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                
    except Exception as e:
        findings.append({
            'id': 'tls-check-error',
            'title': 'TLS configuration check failed',
            'severity': 'medium',
            'detail': f'Could not verify TLS configuration: {str(e)}'
        })
    
    return findings, tls_info


def run_payment_scan(target_url, options=None):
    """Run comprehensive payment page security scan"""
    options = options or {}
    findings = []
    details = {}
    scan_logs = []  # Track scan progress
    
    def log_scan(message):
        """Add a timestamped log entry"""
        scan_logs.append({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': message
        })
    
    uid = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + 'Z'
    
    log_scan('Starting payment page security scan...')
    
    # 1) Fetch the page
    try:
        log_scan('Fetching target payment page...')
        # Add browser-like headers to avoid 406 errors
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        resp = requests.get(target_url, timeout=15, allow_redirects=True, verify=True, headers=headers)
        details['status_code'] = resp.status_code
        details['headers'] = dict(resp.headers)
        details['final_url'] = resp.url
        details['response_time_ms'] = int(resp.elapsed.total_seconds() * 1000)
        log_scan(f'✓ Connected successfully (HTTP {resp.status_code})')
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # 2) HTTPS enforcement check
        log_scan('Checking HTTPS enforcement...')
        https_findings = check_https_enforcement(target_url, resp)
        findings.extend(https_findings)
        log_scan('✓ HTTPS enforcement check complete')
        
        # 3) Mixed content check
        log_scan('Scanning for mixed content (HTTP resources on HTTPS page)...')
        mixed_findings = check_mixed_content(soup, resp.url)
        findings.extend(mixed_findings)
        log_scan('✓ Mixed content check complete')
        
        # 4) Payment form analysis
        log_scan('Analyzing payment forms and CSRF protection...')
        form_findings, form_details = check_payment_forms(soup)
        findings.extend(form_findings)
        details['forms'] = form_details
        log_scan(f'✓ Found {len(form_details)} form(s)')
        
        # 5) PCI DSS indicators
        log_scan('Detecting payment gateways and PCI DSS indicators...')
        pci_findings, pci_indicators, gateways = check_pci_indicators(resp, soup)
        findings.extend(pci_findings)
        details['pci_indicators'] = pci_indicators
        details['payment_gateways'] = gateways
        if gateways:
            log_scan(f'✓ Detected payment gateway(s): {", ".join(gateways)}')
        else:
            log_scan('✓ No payment gateway detected')
        
        # 6) JavaScript security
        log_scan('Checking JavaScript security...')
        js_findings = check_javascript_security(soup)
        findings.extend(js_findings)
        log_scan('✓ JavaScript security check complete')
        
        # 7) Cookie security
        log_scan('Checking cookie security (HttpOnly, Secure, SameSite)...')
        cookie_findings = check_cookie_security(resp)
        findings.extend(cookie_findings)
        log_scan('✓ Cookie security check complete')
        
        # 8) TLS configuration
        log_scan('Inspecting TLS/SSL certificate and cipher suite...')
        tls_findings, tls_info = check_tls_configuration(target_url)
        findings.extend(tls_findings)
        details['tls_info'] = tls_info
        log_scan('✓ TLS configuration check complete')
        
        # 9) reCAPTCHA/CAPTCHA detection
        log_scan('Checking for CAPTCHA/bot protection...')
        captcha_findings, captcha_info = check_recaptcha(soup, resp.text)
        findings.extend(captcha_findings)
        details['captcha_info'] = captcha_info
        log_scan('✓ CAPTCHA detection complete')
        
        # 10) Form validation checks
        log_scan('Analyzing HTML5 form validation attributes...')
        validation_findings, validation_info = check_form_validation(soup)
        findings.extend(validation_findings)
        details['form_validation'] = validation_info
        log_scan('✓ Form validation check complete')
        
        # 11) .htaccess security check
        log_scan('Checking for exposed .htaccess file...')
        htaccess_findings, htaccess_info = check_htaccess_security(target_url)
        findings.extend(htaccess_findings)
        details['htaccess_info'] = htaccess_info
        log_scan('✓ .htaccess security check complete')
        
        # Additional checks for payment pages
        body = resp.text.lower()
        
        # Check for visible credit card forms (potential security issue)
        if re.search(r'<input[^>]*name=["\']?.*card.*number', body, re.IGNORECASE):
            findings.append({
                'id': 'direct-card-input',
                'title': 'Direct credit card input detected',
                'severity': 'high',
                'detail': 'Page has direct credit card input fields. Consider using tokenized payment gateway (Stripe, PayPal) for better security and PCI DSS compliance.'
            })
        
        # Check for password fields on payment page (unusual)
        password_fields = soup.find_all('input', type='password')
        if password_fields and any('card' in str(f).lower() or 'cvv' in str(f).lower() for f in password_fields):
            details['password_fields_count'] = len(password_fields)
        
    except RequestException as e:
        findings.append({
            'id': 'network-error',
            'title': 'Network or request error',
            'severity': 'high',
            'detail': str(e)
        })
        details['error'] = str(e)
        log_scan(f'❌ Network error: {str(e)[:50]}')
    
    # Filter out informational positive confirmations, keep only real security issues
    log_scan('Filtering findings to show only real security issues...')
    real_findings = filter_real_findings(findings)
    info_count = len(findings) - len(real_findings)
    if info_count > 0:
        log_scan(f'Filtered out {info_count} informational status messages')
    
    # Calculate score
    log_scan('Calculating security score...')
    score = score_from_findings(real_findings)
    
    # Build summary
    critical_count = len([f for f in real_findings if f['severity'] == 'critical'])
    high_count = len([f for f in real_findings if f['severity'] == 'high'])
    
    if critical_count > 0:
        summary = f'❌ CRITICAL: {critical_count} critical issues found. Score: {score}'
        log_scan(f'❌ CRITICAL: {critical_count} critical issues found!')
    elif high_count > 0:
        summary = f'⚠️ WARNING: {high_count} high-severity issues. Score: {score}'
        log_scan(f'⚠ {high_count} high-severity issues found')
    else:
        summary = f'✓ {len(real_findings)} findings, score: {score}'
    
    log_scan(f'✓ Payment scan complete! Score: {score}/100')
    
    result = {
        'id': uid,
        'target': target_url,
        'created_at': created_at,
        'summary': summary,
        'score': score,
        'scan_type': 'payment',
        'scan_logs': scan_logs,  # Include scan progress logs
        'details': {
            'findings': real_findings,  # Use filtered findings
            'meta': details
        }
    }
    
    return result

