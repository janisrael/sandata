"""
Port Scanner Module
Network port scanning using nmap for security assessment
WARNING: This is an invasive test - only use with explicit authorization
"""

import subprocess
import socket
from urllib.parse import urlparse


def scan_ports(target_url, timeout=30):
    """
    Scan common ports on target domain
    
    Args:
        target_url: The target URL/domain to scan
        timeout: Scan timeout in seconds
        
    Returns:
        dict: Port scan findings
    """
    findings = []
    open_ports = []
    
    # Extract domain from URL
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Remove www if present
    domain = domain.replace('www.', '')
    
    if not domain or '.' not in domain:
        findings.append({
            'id': 'port-scan-invalid-domain',
            'title': 'Invalid Domain for Port Scanning',
            'severity': 'info',
            'detail': f'Could not extract a valid domain from: {target_url}',
            'type': 'Port Scanning'
        })
        return {
            'findings': findings,
            'open_ports': [],
            'total_open': 0
        }
    
    # Resolve domain to IP
    try:
        target_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        findings.append({
            'id': 'port-scan-dns-failed',
            'title': 'DNS Resolution Failed',
            'severity': 'info',
            'detail': f'Could not resolve domain {domain} to an IP address',
            'type': 'Port Scanning'
        })
        return {
            'findings': findings,
            'open_ports': [],
            'total_open': 0
        }
    
    # Check if nmap is available
    nmap_available = _check_nmap_available()
    
    if nmap_available:
        # Use nmap for comprehensive scanning
        open_ports = _scan_with_nmap(target_ip, domain)
    else:
        # Fallback to basic Python socket scanning
        findings.append({
            'id': 'port-scan-nmap-unavailable',
            'title': 'Nmap Not Available - Using Basic Scan',
            'severity': 'info',
            'detail': 'Nmap is not installed. Using basic Python socket scanning (slower and less accurate). Install nmap for better results: sudo apt install nmap or sudo yum install nmap',
            'type': 'Port Scanning'
        })
        open_ports = _scan_with_socket(target_ip, domain)
    
    # Analyze findings
    if open_ports:
        # Categorize ports by risk
        critical_ports = []
        high_risk_ports = []
        medium_risk_ports = []
        info_ports = []
        
        port_risks = {
            # Critical - Direct database/admin access
            3306: ('critical', 'MySQL Database', 'Direct database access should never be publicly exposed'),
            5432: ('critical', 'PostgreSQL Database', 'Direct database access should never be publicly exposed'),
            1433: ('critical', 'MSSQL Database', 'Direct database access should never be publicly exposed'),
            27017: ('critical', 'MongoDB', 'Direct database access should never be publicly exposed'),
            6379: ('critical', 'Redis', 'Direct Redis access allows data manipulation'),
            9200: ('critical', 'Elasticsearch', 'Exposed Elasticsearch can leak sensitive data'),
            
            # High - Remote access/admin
            22: ('high', 'SSH', 'Ensure SSH is properly secured with key-based auth'),
            23: ('high', 'Telnet', 'Telnet is unencrypted - should be disabled'),
            3389: ('high', 'RDP (Remote Desktop)', 'RDP should not be publicly exposed'),
            5900: ('high', 'VNC', 'VNC should not be publicly exposed'),
            
            # Medium - Web services/APIs
            21: ('medium', 'FTP', 'FTP is unencrypted - use SFTP instead'),
            25: ('medium', 'SMTP', 'Mail server - ensure proper authentication'),
            110: ('medium', 'POP3', 'Mail retrieval - should use encryption'),
            143: ('medium', 'IMAP', 'Mail retrieval - should use encryption'),
            8080: ('medium', 'HTTP Alternate', 'Often used for admin panels or proxies'),
            8443: ('medium', 'HTTPS Alternate', 'Secondary HTTPS port'),
            
            # Info - Expected web services
            80: ('info', 'HTTP', 'Standard web server port'),
            443: ('info', 'HTTPS', 'Secure web server port'),
            53: ('info', 'DNS', 'Domain Name System'),
        }
        
        for port_info in open_ports:
            port = port_info['port']
            risk_level, service, description = port_risks.get(port, ('info', port_info['service'], 'Unknown service'))
            
            port_detail = {
                'port': port,
                'service': service,
                'description': description,
                'state': port_info.get('state', 'open')
            }
            
            if risk_level == 'critical':
                critical_ports.append(port_detail)
            elif risk_level == 'high':
                high_risk_ports.append(port_detail)
            elif risk_level == 'medium':
                medium_risk_ports.append(port_detail)
            else:
                info_ports.append(port_detail)
        
        # Generate findings for each risk level
        if critical_ports:
            findings.append({
                'id': 'port-scan-critical-ports',
                'title': f'🔴 CRITICAL: Dangerous Ports Exposed - {len(critical_ports)} Found',
                'severity': 'critical',
                'detail': f'Found {len(critical_ports)} critical ports that should NEVER be publicly accessible: {", ".join([f"{p["port"]} ({p["service"]})" for p in critical_ports])}. These ports provide direct access to databases or sensitive services.',
                'type': 'Port Scanning',
                'ports': critical_ports,
                'recommendations': [
                    'IMMEDIATELY close these ports to public access',
                    'Use firewall rules to block external access',
                    'Only allow access from trusted IP addresses',
                    'Use VPN for administrative access',
                    'If these services are needed, use SSH tunneling',
                    'Implement strong authentication and encryption',
                    'Monitor access logs for unauthorized attempts',
                    'Consider using cloud provider security groups'
                ]
            })
        
        if high_risk_ports:
            findings.append({
                'id': 'port-scan-high-risk-ports',
                'title': f'⚠️ HIGH RISK: Remote Access Ports Open - {len(high_risk_ports)} Found',
                'severity': 'high',
                'detail': f'Found {len(high_risk_ports)} high-risk ports open: {", ".join([f"{p["port"]} ({p["service"]})" for p in high_risk_ports])}. These ports allow remote access and are frequent attack targets.',
                'type': 'Port Scanning',
                'ports': high_risk_ports,
                'recommendations': [
                    'Restrict access using firewall rules',
                    'For SSH (22): Use key-based authentication only, disable password auth',
                    'For RDP (3389): Use Network Level Authentication (NLA)',
                    'Change default ports to reduce automated attacks',
                    'Implement fail2ban or similar brute-force protection',
                    'Use VPN for remote access instead of direct exposure',
                    'Enable MFA (Multi-Factor Authentication)',
                    'Regularly review authentication logs'
                ]
            })
        
        if medium_risk_ports:
            findings.append({
                'id': 'port-scan-medium-risk-ports',
                'title': f'⚠️ Medium Risk Ports Open - {len(medium_risk_ports)} Found',
                'severity': 'medium',
                'detail': f'Found {len(medium_risk_ports)} medium-risk ports: {", ".join([f"{p["port"]} ({p["service"]})" for p in medium_risk_ports])}.',
                'type': 'Port Scanning',
                'ports': medium_risk_ports,
                'recommendations': [
                    'Review if these services need to be publicly accessible',
                    'Use encrypted alternatives (FTPS instead of FTP)',
                    'Implement rate limiting and access controls',
                    'Enable logging and monitoring',
                    'Keep services updated to latest versions'
                ]
            })
        
        # Info finding for all open ports
        findings.append({
            'id': 'port-scan-results',
            'title': f'✓ Port Scan Complete: {len(open_ports)} Open Ports',
            'severity': 'info',
            'detail': f'Scanned target {domain} ({target_ip}). Found {len(open_ports)} open ports total. Open ports: {", ".join([str(p["port"]) for p in open_ports])}',
            'type': 'Port Scanning',
            'all_ports': open_ports
        })
    else:
        findings.append({
            'id': 'port-scan-no-ports',
            'title': 'No Open Ports Found',
            'severity': 'info',
            'detail': f'Port scan completed for {domain} ({target_ip}). No additional open ports were detected beyond standard web services.',
            'type': 'Port Scanning'
        })
    
    return {
        'findings': findings,
        'open_ports': open_ports,
        'total_open': len(open_ports)
    }


def _check_nmap_available():
    """Check if nmap is installed"""
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _scan_with_nmap(target_ip, domain):
    """Scan ports using nmap"""
    open_ports = []
    
    try:
        # Scan common ports: top 100 most common ports
        # Use -F for fast scan (top 100 ports)
        # -T4 for faster timing
        # --open to only show open ports
        result = subprocess.run(
            ['nmap', '-F', '-T4', '--open', target_ip],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            # Parse nmap output
            lines = result.stdout.split('\n')
            for line in lines:
                # Look for lines like: "22/tcp   open  ssh"
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]
                        port = int(port_proto.split('/')[0])
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        open_ports.append({
                            'port': port,
                            'state': state,
                            'service': service
                        })
    except subprocess.TimeoutExpired:
        # Scan timed out, return what we have
        pass
    except Exception:
        # Nmap failed, will fall back to socket scan
        pass
    
    return open_ports


def _scan_with_socket(target_ip, domain):
    """Basic port scanning using Python sockets"""
    open_ports = []
    
    # Common ports to scan
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        9200: 'Elasticsearch',
        27017: 'MongoDB'
    }
    
    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                open_ports.append({
                    'port': port,
                    'state': 'open',
                    'service': service
                })
        except socket.error:
            continue
    
    return open_ports

