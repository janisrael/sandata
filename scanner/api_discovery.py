"""
API Endpoint Discovery Module
Discovers API endpoints, documentation, and potential information leakage
"""

import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin, urlparse
import re
import json


def discover_api_endpoints(target_url, timeout=20):
    """
    Discover API endpoints and documentation
    
    Args:
        target_url: The target URL to scan
        timeout: Total timeout for the scan
        
    Returns:
        dict: API discovery findings
    """
    findings = []
    discovered_endpoints = []
    
    # Parse URL to get base
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    if not base_url or not parsed_url.scheme:
        findings.append({
            'id': 'api-discovery-invalid-url',
            'title': 'Invalid URL for API Discovery',
            'severity': 'info',
            'detail': f'Could not extract a valid base URL from: {target_url}',
            'type': 'API Endpoint Discovery'
        })
        return {
            'findings': findings,
            'discovered_endpoints': [],
            'total_found': 0
        }
    
    # Common API endpoints wordlist
    api_paths = _get_api_wordlist()
    
    # Scan for endpoints
    for path in api_paths:
        full_url = urljoin(base_url, path)
        
        try:
            response = requests.get(full_url, timeout=3, allow_redirects=False)
            status_code = response.status_code
            
            # Check if endpoint exists
            if status_code in [200, 201, 401, 403]:
                endpoint_info = {
                    'path': path,
                    'full_url': full_url,
                    'status_code': status_code,
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'size': len(response.content)
                }
                
                # Check for API characteristics
                if status_code == 200:
                    endpoint_info['accessible'] = True
                    
                    # Try to parse as JSON
                    try:
                        data = response.json()
                        endpoint_info['format'] = 'JSON'
                        
                        # Check for sensitive information
                        json_str = json.dumps(data).lower()
                        if 'password' in json_str or 'secret' in json_str or 'key' in json_str:
                            endpoint_info['sensitive'] = True
                            endpoint_info['note'] = 'May contain sensitive information'
                    except:
                        endpoint_info['format'] = 'Non-JSON'
                    
                    # Check for API documentation patterns
                    body_lower = response.text.lower()
                    if 'swagger' in body_lower or 'openapi' in body_lower:
                        endpoint_info['doc_type'] = 'Swagger/OpenAPI'
                    elif 'graphql' in body_lower:
                        endpoint_info['doc_type'] = 'GraphQL'
                    elif 'rest' in body_lower or 'api' in body_lower:
                        endpoint_info['doc_type'] = 'REST API'
                
                elif status_code == 401:
                    endpoint_info['accessible'] = False
                    endpoint_info['note'] = 'Requires authentication'
                elif status_code == 403:
                    endpoint_info['accessible'] = False
                    endpoint_info['note'] = 'Forbidden'
                
                discovered_endpoints.append(endpoint_info)
        
        except RequestException:
            continue
    
    # Analyze findings
    if discovered_endpoints:
        # Categorize by risk
        critical_endpoints = []
        high_risk_endpoints = []
        medium_risk_endpoints = []
        info_endpoints = []
        
        for endpoint in discovered_endpoints:
            if endpoint.get('sensitive'):
                critical_endpoints.append(endpoint)
            elif endpoint.get('doc_type') and endpoint.get('accessible'):
                high_risk_endpoints.append(endpoint)
            elif endpoint.get('accessible') and endpoint['status_code'] == 200:
                if any(x in endpoint['path'] for x in ['admin', 'internal', 'debug', 'test']):
                    high_risk_endpoints.append(endpoint)
                else:
                    medium_risk_endpoints.append(endpoint)
            else:
                info_endpoints.append(endpoint)
        
        # Generate findings
        if critical_endpoints:
            findings.append({
                'id': 'api-discovery-sensitive',
                'title': f'🔴 CRITICAL: API Endpoints with Sensitive Data - {len(critical_endpoints)} Found',
                'severity': 'critical',
                'detail': f'Found {len(critical_endpoints)} API endpoints that may expose sensitive information: {", ".join([e["path"] for e in critical_endpoints])}',
                'type': 'API Endpoint Discovery',
                'endpoints': critical_endpoints,
                'recommendations': [
                    'IMMEDIATELY secure or remove endpoints exposing sensitive data',
                    'Implement proper API authentication (OAuth 2.0, JWT)',
                    'Never expose passwords, keys, or secrets in API responses',
                    'Use environment variables for sensitive configuration',
                    'Implement API key rotation policies',
                    'Add rate limiting to prevent data extraction',
                    'Log all API access for security monitoring',
                    'Use API gateways for centralized security',
                    'Implement CORS policies to restrict access',
                    'Encrypt sensitive data in responses'
                ]
            })
        
        if high_risk_endpoints:
            findings.append({
                'id': 'api-discovery-documentation',
                'title': f'⚠️ HIGH RISK: Exposed API Documentation - {len(high_risk_endpoints)} Found',
                'severity': 'high',
                'detail': f'Found {len(high_risk_endpoints)} exposed API documentation/admin endpoints: {", ".join([e["path"] for e in high_risk_endpoints[:5]])}',
                'type': 'API Endpoint Discovery',
                'endpoints': high_risk_endpoints,
                'recommendations': [
                    'Restrict API documentation to internal networks only',
                    'Add authentication to Swagger/OpenAPI endpoints',
                    'Use IP whitelisting for documentation access',
                    'Disable documentation in production environments',
                    'Remove debug and test endpoints from production',
                    'Implement API versioning and deprecation policies',
                    'Use API keys for all endpoint access',
                    'Set up monitoring for unusual API usage patterns',
                    'Implement request/response validation',
                    'Use API management platforms (Kong, Apigee)'
                ]
            })
        
        if medium_risk_endpoints:
            findings.append({
                'id': 'api-discovery-endpoints',
                'title': f'ℹ️ Accessible API Endpoints Found - {len(medium_risk_endpoints)}',
                'severity': 'medium',
                'detail': f'Found {len(medium_risk_endpoints)} accessible API endpoints: {", ".join([e["path"] for e in medium_risk_endpoints[:5]])}',
                'type': 'API Endpoint Discovery',
                'endpoints': medium_risk_endpoints,
                'recommendations': [
                    'Review all API endpoints for necessary public access',
                    'Implement authentication where appropriate',
                    'Add rate limiting to prevent abuse',
                    'Validate all input parameters',
                    'Use HTTPS for all API communications',
                    'Implement proper error handling (don\'t reveal stack traces)',
                    'Document expected API behavior',
                    'Monitor for unauthorized access attempts'
                ]
            })
        
        # Summary
        findings.append({
            'id': 'api-discovery-results',
            'title': f'✓ API Discovery Complete: {len(discovered_endpoints)} Endpoints Found',
            'severity': 'info',
            'detail': f'Scanned for API endpoints on {base_url}. Found: {len(critical_endpoints)} critical, {len(high_risk_endpoints)} high-risk, {len(medium_risk_endpoints)} medium-risk, {len(info_endpoints)} info-level.',
            'type': 'API Endpoint Discovery',
            'all_endpoints': discovered_endpoints
        })
    else:
        findings.append({
            'id': 'api-discovery-no-endpoints',
            'title': 'No API Endpoints Found',
            'severity': 'info',
            'detail': f'API endpoint discovery completed on {base_url}. No common API endpoints were discovered.',
            'type': 'API Endpoint Discovery'
        })
    
    return {
        'findings': findings,
        'discovered_endpoints': discovered_endpoints,
        'total_found': len(discovered_endpoints)
    }


def _get_api_wordlist():
    """Get common API endpoint wordlist"""
    return [
        # API Documentation
        'api/',
        'api/v1/',
        'api/v2/',
        'api/v3/',
        '/v1/',
        '/v2/',
        'swagger/',
        'swagger-ui/',
        'swagger.json',
        'swagger.yaml',
        'openapi.json',
        'openapi.yaml',
        'api-docs/',
        'api/docs/',
        'docs/',
        'documentation/',
        'redoc/',
        
        # GraphQL
        'graphql/',
        'graphql/v1/',
        'api/graphql/',
        'graphiql/',
        
        # REST Endpoints
        'api/users/',
        'api/user/',
        'api/auth/',
        'api/login/',
        'api/config/',
        'api/settings/',
        'api/admin/',
        'api/status/',
        'api/health/',
        'api/info/',
        'api/version/',
        'api/ping/',
        
        # Debug/Test Endpoints
        'api/debug/',
        'api/test/',
        'debug/',
        'test/api/',
        '_debug/',
        
        # Common API Patterns
        'rest/',
        'restapi/',
        'webapi/',
        'services/',
        'service/',
        'ws/',
        'api.php',
        'api.json',
    ]

