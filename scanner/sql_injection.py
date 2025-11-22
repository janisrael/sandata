"""
SQL Injection Testing Module
Safe, ethical SQLi detection using non-destructive payloads
"""

import requests
from requests.exceptions import RequestException
import re
import time


def test_sql_injection(target_url, params=None, timeout=10):
    """
    Test for SQL injection vulnerabilities using safe payloads
    
    Args:
        target_url: The URL to test
        params: Dictionary of parameters to test (optional)
        timeout: Request timeout in seconds
        
    Returns:
        dict: Findings from SQL injection tests
    """
    findings = []
    tested_payloads = []
    
    # Common SQL error signatures across different databases
    sql_errors = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        
        # Microsoft SQL Server
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc",
        
        # Oracle
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
        
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"sqlite3.OperationalError",
        
        # Generic
        r"syntax error.*SQL",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQLSTATE\[",
        r"Warning.*SQL",
    ]
    
    # Safe SQL injection test payloads
    # These are designed to trigger errors without causing damage
    payloads = [
        "'",  # Single quote - most basic test
        "''",  # Double single quote
        "`",  # Backtick
        "\\",  # Backslash
        "';",  # Single quote with semicolon
        "\"",  # Double quote
        "\"\"",  # Double quotes
        "1' AND '1'='1",  # Boolean-based (always true)
        "1' AND '1'='2",  # Boolean-based (always false)
        "1' OR '1'='1",  # Boolean-based OR
        "' OR '1'='1",  # Classic SQLi
        "' OR '1'='1'--",  # With comment
        "' OR '1'='1'/*",  # MySQL comment
        "admin'--",  # Admin bypass attempt
        "1' ORDER BY 1--",  # Column enumeration
        "1' ORDER BY 100--",  # Out of range column
        "' UNION SELECT NULL--",  # Union-based
    ]
    
    # Test direct URL injection (GET parameters)
    if '?' in target_url or params:
        findings.extend(_test_get_injection(target_url, payloads, sql_errors, tested_payloads, timeout))
    
    # Test for time-based blind SQL injection
    findings.extend(_test_time_based_injection(target_url, tested_payloads, timeout))
    
    return {
        'findings': findings,
        'tested_payloads': len(tested_payloads),
        'vulnerable_params': len([f for f in findings if f['severity'] in ['critical', 'high']])
    }


def _test_get_injection(target_url, payloads, sql_errors, tested_payloads, timeout):
    """Test GET parameters for SQL injection"""
    findings = []
    
    # Parse URL and extract parameters
    if '?' not in target_url:
        return findings
    
    base_url, query_string = target_url.split('?', 1)
    params = dict(p.split('=') for p in query_string.split('&') if '=' in p)
    
    for param_name in params.keys():
        vulnerable = False
        error_found = False
        
        for payload in payloads[:10]:  # Test first 10 payloads per parameter
            test_params = params.copy()
            test_params[param_name] = payload
            tested_payloads.append(f"{param_name}={payload}")
            
            try:
                response = requests.get(base_url, params=test_params, timeout=timeout)
                
                # Check for SQL error signatures
                for error_pattern in sql_errors:
                    if re.search(error_pattern, response.text, re.IGNORECASE):
                        vulnerable = True
                        error_found = True
                        break
                
                if vulnerable:
                    break
                    
            except RequestException:
                continue
        
        if vulnerable:
            findings.append({
                'id': 'sql-injection-error-based',
                'title': f'SQL Injection vulnerability detected in parameter: {param_name}',
                'severity': 'critical',
                'detail': f'The parameter "{param_name}" appears to be vulnerable to SQL injection. SQL error messages were detected in the response when testing with malicious payloads.',
                'param': param_name,
                'type': 'Error-based SQL Injection',
                'recommendations': [
                    'Use parameterized queries (prepared statements) instead of string concatenation',
                    'Implement input validation and sanitization',
                    'Use an ORM (Object-Relational Mapping) framework',
                    'Apply principle of least privilege for database accounts',
                    'Never display raw database errors to users',
                    'Consider using a Web Application Firewall (WAF)'
                ]
            })
    
    return findings


def _test_time_based_injection(target_url, tested_payloads, timeout):
    """Test for time-based blind SQL injection"""
    findings = []
    
    # Time-based payloads (very conservative delay)
    time_payloads = [
        "' AND SLEEP(3)--",  # MySQL
        "'; WAITFOR DELAY '00:00:03'--",  # MSSQL
        "' AND pg_sleep(3)--",  # PostgreSQL
    ]
    
    try:
        # Get baseline response time
        start = time.time()
        requests.get(target_url, timeout=timeout)
        baseline_time = time.time() - start
        
        for payload in time_payloads[:2]:  # Test only 2 to avoid long delays
            tested_payloads.append(f"time_test={payload}")
            
            try:
                # Test with time-based payload
                test_url = f"{target_url}{'&' if '?' in target_url else '?'}test={payload}"
                start = time.time()
                requests.get(test_url, timeout=timeout + 5)  # nosec B113
                response_time = time.time() - start
                
                # If response time is significantly longer (>2.5 seconds more)
                if response_time - baseline_time > 2.5:
                    findings.append({
                        'id': 'sql-injection-time-based',
                        'title': 'Possible Time-Based Blind SQL Injection',
                        'severity': 'high',
                        'detail': f'The application response time increased significantly when a time-delay SQL payload was injected. Baseline: {baseline_time:.2f}s, With payload: {response_time:.2f}s',
                        'type': 'Time-based Blind SQL Injection',
                        'recommendations': [
                            'Use parameterized queries (prepared statements)',
                            'Implement strict input validation',
                            'Monitor and log unusual response times',
                            'Use a Web Application Firewall (WAF) with SQLi protection',
                            'Conduct a thorough code review of database queries'
                        ]
                    })
                    break
                    
            except RequestException:
                continue
                
    except RequestException:
        pass
    
    return findings


def get_sql_injection_recommendations(finding_id):
    """Get detailed recommendations for SQL injection findings"""
    recommendations = {
        'sql-injection-error-based': [
            'Immediately patch the vulnerable parameter using parameterized queries',
            'Review all database queries in the application for similar vulnerabilities',
            'Implement prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");',
            'Never concatenate user input directly into SQL queries',
            'Use ORM frameworks like SQLAlchemy (Python), Hibernate (Java), or Entity Framework (.NET)',
            'Implement input validation with whitelists, not blacklists',
            'Configure database errors to log securely without exposing details to users',
            'Apply principle of least privilege: use read-only database accounts where possible'
        ],
        'sql-injection-time-based': [
            'Investigate and patch the time-based blind SQL injection vulnerability',
            'Review all user input handling in the application',
            'Implement parameterized queries across the entire codebase',
            'Add rate limiting to prevent automated exploitation',
            'Monitor database query execution times for anomalies',
            'Use prepared statements for ALL database interactions',
            'Consider implementing a Web Application Firewall (WAF)'
        ]
    }
    
    return recommendations.get(finding_id, [])

