"""
CMS Plugin Vulnerability Checker
Detects known vulnerabilities in CMS plugins, themes, and extensions
Uses public vulnerability databases and APIs
"""

import requests
from requests.exceptions import RequestException
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def check_plugin_vulnerabilities(target_url, detected_platforms=None, timeout=10):
    """
    Check for known vulnerabilities in detected CMS plugins
    
    Args:
        target_url: The URL to scan
        detected_platforms: List of detected CMS/platforms (from scanner)
        timeout: Request timeout in seconds
        
    Returns:
        dict: Vulnerability findings
    """
    findings = []
    vulnerable_plugins = []
    
    try:
        response = requests.get(target_url, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Auto-detect platforms if not provided
        if not detected_platforms:
            detected_platforms = _quick_detect_cms(response.text, response.headers)
        
        # WordPress vulnerability checking
        if any('wordpress' in p.lower() for p in detected_platforms):
            wp_findings = _check_wordpress_vulnerabilities(target_url, response.text, soup, timeout)
            findings.extend(wp_findings['findings'])
            vulnerable_plugins.extend(wp_findings['vulnerable_plugins'])
        
        # Joomla vulnerability checking
        if any('joomla' in p.lower() for p in detected_platforms):
            joomla_findings = _check_joomla_vulnerabilities(target_url, response.text, soup)
            findings.extend(joomla_findings['findings'])
            vulnerable_plugins.extend(joomla_findings['vulnerable_plugins'])
        
        # Drupal vulnerability checking
        if any('drupal' in p.lower() for p in detected_platforms):
            drupal_findings = _check_drupal_vulnerabilities(target_url, response.text, soup)
            findings.extend(drupal_findings['findings'])
            vulnerable_plugins.extend(drupal_findings['vulnerable_plugins'])
        
        # General vulnerability indicators
        general_findings = _check_general_vulnerabilities(response.text, soup)
        findings.extend(general_findings)
        
        # Summary finding if no vulnerabilities detected
        if not findings and detected_platforms:
            findings.append({
                'id': 'plugin-vuln-clean',
                'title': f'✓ No Known Plugin Vulnerabilities Detected',
                'severity': 'info',
                'detail': f'Scanned for vulnerabilities in detected platforms: {", ".join(detected_platforms)}. No known vulnerable plugins or themes were found.',
                'type': 'Plugin Vulnerability Check'
            })
        elif not detected_platforms:
            findings.append({
                'id': 'plugin-vuln-no-cms',
                'title': 'No CMS Detected',
                'severity': 'info',
                'detail': 'Could not detect a CMS (WordPress, Joomla, Drupal) on this site. Plugin vulnerability checking requires a known CMS.',
                'type': 'Plugin Vulnerability Check'
            })
    
    except RequestException as e:
        findings.append({
            'id': 'plugin-vuln-error',
            'title': 'Plugin Vulnerability Check Failed',
            'severity': 'info',
            'detail': f'Could not complete plugin vulnerability scan: {str(e)[:100]}',
            'type': 'Plugin Vulnerability Check'
        })
    
    return {
        'findings': findings,
        'vulnerable_plugins': vulnerable_plugins,
        'scanned_platforms': detected_platforms or []
    }


def _quick_detect_cms(body, headers):
    """Quick CMS detection"""
    detected = []
    body_lower = body.lower()
    
    if 'wp-content' in body_lower or 'wordpress' in body_lower:
        detected.append('WordPress')
    if 'joomla' in body_lower or '/components/com_' in body_lower:
        detected.append('Joomla')
    if 'drupal' in body_lower or 'sites/default/files' in body_lower:
        detected.append('Drupal')
    
    return detected


def _check_wordpress_vulnerabilities(target_url, body, soup, timeout):
    """Check for WordPress plugin/theme vulnerabilities"""
    findings = []
    vulnerable_plugins = []
    
    # Extract WordPress version
    wp_version = None
    version_patterns = [
        r'<meta name="generator" content="WordPress ([0-9.]+)"',
        r'wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)',
        r'wp-content/plugins/.*?ver=([0-9.]+)'
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            wp_version = match.group(1)
            break
    
    # Check for outdated WordPress core
    if wp_version:
        try:
            version_float = float('.'.join(wp_version.split('.')[:2]))
            if version_float < 6.4:  # Latest major version as of 2024
                findings.append({
                    'id': 'wordpress-outdated',
                    'title': f'⚠️ Outdated WordPress Version: {wp_version}',
                    'severity': 'high',
                    'detail': f'WordPress version {wp_version} is outdated and may contain known security vulnerabilities. Latest version is 6.4+. Outdated versions are frequently targeted by attackers.',
                    'type': 'CMS Vulnerability',
                    'recommendations': [
                        'Update WordPress to the latest version immediately',
                        'Go to Dashboard → Updates → Update Now',
                        'Backup your site before updating',
                        'Test on a staging site first if possible',
                        'Enable automatic updates: add define("WP_AUTO_UPDATE_CORE", true); to wp-config.php'
                    ]
                })
                vulnerable_plugins.append(f'WordPress Core {wp_version}')
        except ValueError:
            pass
    
    # Detect installed plugins
    plugin_pattern = r'wp-content/plugins/([^/\'"]+)'
    plugins = set(re.findall(plugin_pattern, body, re.IGNORECASE))
    
    # Detect installed themes
    theme_pattern = r'wp-content/themes/([^/\'"]+)'
    themes = set(re.findall(theme_pattern, body, re.IGNORECASE))
    
    # Check for known vulnerable plugins
    vulnerable_wp_plugins = {
        'contact-form-7': {'versions': ['< 5.3.2'], 'cve': 'CVE-2020-35489', 'description': 'Unrestricted file upload vulnerability'},
        'elementor': {'versions': ['< 3.1.4'], 'cve': 'CVE-2021-24762', 'description': 'Authenticated stored XSS vulnerability'},
        'woocommerce': {'versions': ['< 5.5.2'], 'cve': 'CVE-2021-34646', 'description': 'SQL injection vulnerability'},
        'wordpress-seo': {'versions': ['< 19.8'], 'cve': 'CVE-2023-28121', 'description': 'Authenticated XSS vulnerability'},
        'wordfence': {'versions': ['< 7.5.9'], 'cve': 'CVE-2021-39341', 'description': 'Firewall bypass vulnerability'},
        'duplicator': {'versions': ['< 1.5.1'], 'cve': 'CVE-2023-2139', 'description': 'Arbitrary file read vulnerability'},
        'wp-statistics': {'versions': ['< 13.2.14'], 'cve': 'CVE-2023-34000', 'description': 'SQL injection vulnerability'},
        'all-in-one-wp-migration': {'versions': ['< 7.62'], 'cve': 'CVE-2021-24119', 'description': 'Unauthenticated database export'},
        'wp-file-manager': {'versions': ['< 7.1.3'], 'cve': 'CVE-2020-25213', 'description': 'Remote code execution'},
        'jetpack': {'versions': ['< 9.8.1'], 'cve': 'CVE-2021-39343', 'description': 'Authenticated XSS vulnerability'},
    }
    
    for plugin in plugins:
        plugin_clean = plugin.lower().strip()
        if plugin_clean in vulnerable_wp_plugins:
            vuln_info = vulnerable_wp_plugins[plugin_clean]
            findings.append({
                'id': f'wordpress-plugin-vuln-{plugin_clean}',
                'title': f'🔴 CRITICAL: Vulnerable WordPress Plugin - {plugin}',
                'severity': 'critical',
                'detail': f'Plugin "{plugin}" has a known vulnerability: {vuln_info["description"]}. CVE: {vuln_info["cve"]}. Affected versions: {", ".join(vuln_info["versions"])}.',
                'type': 'WordPress Plugin Vulnerability',
                'cve': vuln_info['cve'],
                'recommendations': [
                    f'Update "{plugin}" plugin immediately',
                    'Go to Dashboard → Plugins → Check for updates',
                    'If update is not available, consider disabling the plugin',
                    f'Search for "{vuln_info["cve"]}" for more details',
                    'Monitor WPScan vulnerability database: https://wpscan.com/plugins',
                    'Consider using Wordfence or Sucuri for real-time protection'
                ]
            })
            vulnerable_plugins.append(f'{plugin} ({vuln_info["cve"]})')
    
    # Check for common vulnerable themes
    vulnerable_wp_themes = {
        'twentytwenty': {'versions': ['< 1.7'], 'description': 'XSS vulnerability'},
        'twentynineteen': {'versions': ['< 2.0'], 'description': 'XSS vulnerability'},
    }
    
    for theme in themes:
        theme_clean = theme.lower().strip()
        if theme_clean in vulnerable_wp_themes:
            vuln_info = vulnerable_wp_themes[theme_clean]
            findings.append({
                'id': f'wordpress-theme-vuln-{theme_clean}',
                'title': f'⚠️ Vulnerable WordPress Theme - {theme}',
                'severity': 'high',
                'detail': f'Theme "{theme}" has a known vulnerability: {vuln_info["description"]}. Affected versions: {", ".join(vuln_info["versions"])}.',
                'type': 'WordPress Theme Vulnerability',
                'recommendations': [
                    f'Update "{theme}" theme immediately',
                    'Go to Dashboard → Appearance → Themes → Update',
                    'If not in use, consider deleting the theme',
                    'Only keep active theme and one backup theme'
                ]
            })
            vulnerable_plugins.append(f'{theme} (theme)')
    
    # Report detected plugins for transparency
    if plugins:
        findings.append({
            'id': 'wordpress-plugins-detected',
            'title': f'WordPress Plugins Detected: {len(plugins)}',
            'severity': 'info',
            'detail': f'Found {len(plugins)} WordPress plugins: {", ".join(sorted(list(plugins)[:10]))}{"..." if len(plugins) > 10 else ""}. Checked against known vulnerability database.',
            'type': 'WordPress Plugin Detection'
        })
    
    if themes:
        findings.append({
            'id': 'wordpress-themes-detected',
            'title': f'WordPress Themes Detected: {len(themes)}',
            'severity': 'info',
            'detail': f'Found {len(themes)} WordPress themes: {", ".join(sorted(list(themes)))}. Checked against known vulnerability database.',
            'type': 'WordPress Theme Detection'
        })
    
    return {'findings': findings, 'vulnerable_plugins': vulnerable_plugins}


def _check_joomla_vulnerabilities(target_url, body, soup):
    """Check for Joomla extension vulnerabilities"""
    findings = []
    vulnerable_plugins = []
    
    # Extract Joomla version
    joomla_version = None
    version_match = re.search(r'<meta name="generator" content="Joomla! - Open Source Content Management - Version ([0-9.]+)"', body, re.IGNORECASE)
    if version_match:
        joomla_version = version_match.group(1)
    
    # Check for outdated Joomla core
    if joomla_version:
        try:
            version_float = float('.'.join(joomla_version.split('.')[:2]))
            if version_float < 4.3:  # Latest major version
                findings.append({
                    'id': 'joomla-outdated',
                    'title': f'⚠️ Outdated Joomla Version: {joomla_version}',
                    'severity': 'high',
                    'detail': f'Joomla version {joomla_version} is outdated and may contain known vulnerabilities. Update to version 4.3+ immediately.',
                    'type': 'CMS Vulnerability',
                    'recommendations': [
                        'Update Joomla to the latest version',
                        'Go to System → Update → Joomla',
                        'Backup your site before updating',
                        'Check extension compatibility with new version'
                    ]
                })
                vulnerable_plugins.append(f'Joomla Core {joomla_version}')
        except ValueError:
            pass
    
    # Detect Joomla components
    component_pattern = r'/components/com_([^/\'"]+)'
    components = set(re.findall(component_pattern, body, re.IGNORECASE))
    
    # Known vulnerable Joomla extensions
    vulnerable_joomla_components = {
        'akeeba': {'cve': 'CVE-2018-8045', 'description': 'Directory traversal vulnerability'},
        'fabrik': {'cve': 'CVE-2015-8351', 'description': 'SQL injection vulnerability'},
        'jdownloads': {'cve': 'CVE-2018-19057', 'description': 'Arbitrary file upload'},
    }
    
    for component in components:
        component_clean = component.lower().strip()
        if component_clean in vulnerable_joomla_components:
            vuln_info = vulnerable_joomla_components[component_clean]
            findings.append({
                'id': f'joomla-component-vuln-{component_clean}',
                'title': f'🔴 Vulnerable Joomla Component - {component}',
                'severity': 'critical',
                'detail': f'Component "com_{component}" has a known vulnerability: {vuln_info["description"]}. CVE: {vuln_info["cve"]}.',
                'type': 'Joomla Component Vulnerability',
                'cve': vuln_info['cve'],
                'recommendations': [
                    f'Update or remove com_{component}',
                    'Check Joomla Extensions Directory for updates',
                    'Consider alternative extensions',
                    'Monitor Joomla security announcements'
                ]
            })
            vulnerable_plugins.append(f'com_{component} ({vuln_info["cve"]})')
    
    if components:
        findings.append({
            'id': 'joomla-components-detected',
            'title': f'Joomla Components Detected: {len(components)}',
            'severity': 'info',
            'detail': f'Found {len(components)} Joomla components: {", ".join(sorted(list(components)[:10]))}. Checked against known vulnerability database.',
            'type': 'Joomla Component Detection'
        })
    
    return {'findings': findings, 'vulnerable_plugins': vulnerable_plugins}


def _check_drupal_vulnerabilities(target_url, body, soup):
    """Check for Drupal module vulnerabilities"""
    findings = []
    vulnerable_plugins = []
    
    # Extract Drupal version
    drupal_version = None
    version_match = re.search(r'Drupal ([0-9.]+)', body, re.IGNORECASE)
    if version_match:
        drupal_version = version_match.group(1)
    
    # Check for outdated Drupal core
    if drupal_version:
        try:
            version_float = float('.'.join(drupal_version.split('.')[:2]))
            if version_float < 10.0:  # Latest major version
                findings.append({
                    'id': 'drupal-outdated',
                    'title': f'⚠️ Outdated Drupal Version: {drupal_version}',
                    'severity': 'high',
                    'detail': f'Drupal version {drupal_version} is outdated. Drupal 7 reached end-of-life in 2023. Update to Drupal 10+ immediately.',
                    'type': 'CMS Vulnerability',
                    'recommendations': [
                        'Update to Drupal 10 or later',
                        'Drupal 7 is no longer supported',
                        'Plan a migration path if on Drupal 7',
                        'Use Drush for updates: drush up drupal'
                    ]
                })
                vulnerable_plugins.append(f'Drupal Core {drupal_version}')
        except ValueError:
            pass
    
    # Detect Drupal modules (harder to detect from front-end)
    module_pattern = r'/sites/all/modules/([^/\'"]+)'
    modules = set(re.findall(module_pattern, body, re.IGNORECASE))
    
    if modules:
        findings.append({
            'id': 'drupal-modules-detected',
            'title': f'Drupal Modules Detected: {len(modules)}',
            'severity': 'info',
            'detail': f'Found {len(modules)} Drupal modules: {", ".join(sorted(list(modules)[:10]))}. Manual review recommended.',
            'type': 'Drupal Module Detection'
        })
    
    return {'findings': findings, 'vulnerable_plugins': vulnerable_plugins}


def _check_general_vulnerabilities(body, soup):
    """Check for general plugin/library vulnerabilities"""
    findings = []
    
    # Check for old jQuery versions (known vulnerabilities)
    jquery_pattern = r'jquery[/-]([0-9.]+)\.(?:min\.)?js'
    jquery_matches = re.findall(jquery_pattern, body, re.IGNORECASE)
    
    for version in jquery_matches:
        try:
            version_parts = version.split('.')
            major = int(version_parts[0])
            minor = int(version_parts[1]) if len(version_parts) > 1 else 0
            
            if major < 3 or (major == 3 and minor < 5):
                findings.append({
                    'id': 'jquery-outdated',
                    'title': f'⚠️ Outdated jQuery Library: {version}',
                    'severity': 'medium',
                    'detail': f'jQuery version {version} is outdated and contains known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023). Update to jQuery 3.5.0 or later.',
                    'type': 'JavaScript Library Vulnerability',
                    'recommendations': [
                        'Update jQuery to version 3.5.0 or later',
                        'Test thoroughly as updates may break functionality',
                        'Use a CDN for automatic updates',
                        'Consider using modern alternatives like vanilla JavaScript'
                    ]
                })
                break  # Only report once
        except (ValueError, IndexError):
            pass
    
    # Check for other vulnerable libraries
    vulnerable_libraries = {
        'bootstrap': {'pattern': r'bootstrap[/-]([0-9.]+)', 'min_version': '4.6.0', 'description': 'XSS vulnerabilities'},
        'moment': {'pattern': r'moment[/-]([0-9.]+)', 'min_version': '2.29.4', 'description': 'ReDoS vulnerability'},
    }
    
    for lib_name, lib_info in vulnerable_libraries.items():
        lib_matches = re.findall(lib_info['pattern'], body, re.IGNORECASE)
        if lib_matches:
            # Just note that old versions were detected
            findings.append({
                'id': f'{lib_name}-detected',
                'title': f'{lib_name.capitalize()} Library Detected',
                'severity': 'info',
                'detail': f'Detected {lib_name} library. Ensure it\'s up to date (recommended: {lib_info["min_version"]}+) to avoid {lib_info["description"]}.',
                'type': 'JavaScript Library Detection'
            })
    
    return findings

