# ------------------------------------------------------------------
# UTILS.PY
# "The Worker Code"
# This file contains the actual logic for:
# 1. Scanning Headers (requests)
# 2. Scanning Ports (sockets)
# ------------------------------------------------------------------
import requests
import socket
import re
from urllib.parse import urlparse

SECURITY_HEADERS_INFO = {
    'Content-Security-Policy': 'A powerful mechanism to prevent Cross-Site Scripting (XSS) and data injection attacks by defining which dynamic resources are allowed to load.',
    'Strict-Transport-Security': 'Enforces the use of HTTPS (HTTP over SSL/TLS) to ensure all communications are encrypted and secure, preventing Man-in-the-Middle (MitM) attacks.',
    'X-Frame-Options': 'Protects the website against Clickjacking attacks by controlling whether the site can be embedded within an iframe on another domain.',
    'X-Content-Type-Options': 'Prevents the browser from "MIME-sniffing" a response away from the declared Content-Type, reducing exposure to drive-by download attacks.',
    'Referrer-Policy': 'Controls how much of the referrer header (current URL) is included when navigating to other sites, protecting user privacy and preventing information leakage.',
    'X-XSS-Protection': 'A legacy HTTP header that enables the Cross-Site Scripting (XSS) filter built into older web browsers as a first line of defense.',
}


# Dictionary defining all ports we check, along with their:
# - Service Name (e.g., FTP, SSH)
# - Risk Level (Low to Critical)
# - Description (What it does)
# - Attacks (What bad things can happen)
# - Recommendation (How to fix it)
PORT_DETAILS = {
    21: {
        'service': 'FTP',
        'risk_level': 'High',
        'description': 'Unencrypted file transfer protocol. Credentials sent in cleartext.',
        'attacks': ['Credential Theft', 'Brute Force', 'Anonymous Access'],
        'recommendation': 'Replace with SFTP or FTPS.'
    },
    22: {
        'service': 'SSH',
        'risk_level': 'Medium',
        'description': 'Secure Secure Shell for remote administration.',
        'attacks': ['Brute Force', 'Key Theft'],
        'recommendation': 'Disable root login. Use keys instead of passwords. Use Fail2Ban.'
    },
    23: {
        'service': 'Telnet',
        'risk_level': 'Critical',
        'description': 'Obsolete, unencrypted remote terminal protocol.',
        'attacks': ['Credential Sniffing', 'Man-in-the-Middle', 'Session Hijacking'],
        'recommendation': 'Disable immediately. Use SSH.'
    },
    25: {
        'service': 'SMTP',
        'risk_level': 'Medium',
        'description': 'Email delivery protocol. Can be abused for spam if unsecured.',
        'attacks': ['Open Relay (Spam)', 'User Enumeration', 'Phishing'],
        'recommendation': 'Restrict access. Configure Authentication. Disable Open Relay.'
    },
    53: {
        'service': 'DNS',
        'risk_level': 'Medium',
        'description': 'Domain Name System. Resolvers can be abused for attacks.',
        'attacks': ['Amplification DDoS', 'Cache Poisoning', 'Zone Transfer'],
        'recommendation': 'Disable recursion for external clients. Restrict Zone Transfers.'
    },
    80: {
        'service': 'HTTP',
        'risk_level': 'Medium',
        'description': 'Unencrypted web traffic.',
        'attacks': ['Sniffing', 'Man-in-the-Middle', 'Information Disclosure'],
        'recommendation': 'Redirect to HTTPS (Port 443).'
    },
    110: {
        'service': 'POP3',
        'risk_level': 'High',
        'description': 'Unencrypted email retrieval protocol.',
        'attacks': ['Credential Sniffing', 'Man-in-the-Middle'],
        'recommendation': 'Use POP3S (SSL/TLS).'
    },
    143: {
        'service': 'IMAP',
        'risk_level': 'High',
        'description': 'Unencrypted email access protocol.',
        'attacks': ['Credential Sniffing', 'Man-in-the-Middle'],
        'recommendation': 'Use IMAPS (SSL/TLS).'
    },
    443: {
        'service': 'HTTPS',
        'risk_level': 'Low',
        'description': 'Encrypted web traffic using SSL/TLS.',
        'attacks': ['SSL Vulnerabilities (e.g. Heartbleed)', 'Weak Ciphers'],
        'recommendation': 'Use strong ciphers. Disable legacy SSL/TLS versions.'
    },
    445: {
        'service': 'SMB',
        'risk_level': 'Critical',
        'description': 'Network file sharing. High target for ransomware.',
        'attacks': ['EternalBlue', 'WannaCry', 'Unauthorized Access'],
        'recommendation': 'Block internet access. Require VPN.'
    },
    3306: {
        'service': 'MySQL',
        'risk_level': 'High',
        'description': 'Relational Access Database. Vulnerable to brute force if exposed.',
        'attacks': ['Brute Force', 'SQL Injection', 'DoS'],
        'recommendation': 'Bind to localhost. Use VPN/SSH Tunnel for remote access.'
    },
    5432: {
        'service': 'PostgreSQL',
        'risk_level': 'High',
        'description': 'Advanced open source database.',
        'attacks': ['Brute Force', 'RCE via exploits'],
        'recommendation': 'Bind to localhost. Restrict access via pg_hba.conf.'
    },
    8080: {
        'service': 'HTTP-Alt',
        'risk_level': 'Medium',
        'description': 'Alternative web port (e.g. Tomcat/Proxy).',
        'attacks': ['Unpatched Exploits', 'Console Exposure'],
        'recommendation': 'Ensure service is behind a secure reverse proxy.'
    },
    8443: {
        'service': 'HTTPS-Alt',
        'risk_level': 'Low',
        'description': 'Alternative secure web port.',
        'attacks': ['Weak Auth', 'Exposed Admin Panels'],
        'recommendation': 'Enforce strong authentication.'
    },
    3389: {
        'service': 'RDP',
        'risk_level': 'Critical',
        'description': 'Windows Remote Desktop Protocol.',
        'attacks': ['BlueKeep', 'Brute Force', 'Ransomware'],
        'recommendation': 'Disable if unused. Require VPN and NLA.'
    },
    5900: {
        'service': 'VNC',
        'risk_level': 'High',
        'description': 'Remote desktop sharing system.',
        'attacks': ['Brute Force', 'Auth Bypass'],
        'recommendation': 'Tunnel via SSH or VPN. Do not expose directly.'
    },
    6379: {
        'service': 'Redis',
        'risk_level': 'High',
        'description': 'In-memory data store. No built-in security by default.',
        'attacks': ['Unathenticated Access', 'RCE'],
        'recommendation': 'Bind to localhost. Enable protected-mode and auth.'
    },
    27017: {
        'service': 'MongoDB',
        'risk_level': 'High',
        'description': 'NoSQL Database.',
        'attacks': ['Data Leakage', 'Ransomware', 'Data Exfiltration'],
        'recommendation': 'Bind to localhost. Enable Authentication.'
    },
}



import ipaddress


def validate_url(url):
    """Validate if URL is properly formatted (Private IPs are ALLOWED)"""
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        return False
        
    # Extra Security: Explicitly forbid dangerous characters that might be used for XSS/Injection
    # even if they slip past the regex (though strict regex usually catches them).
    if any(char in url for char in ['<', '>', '"', "'", ';', '(', ')']):
        return False
        
    # SSRF Check: Removed to allow internal scanning as requested
    # We now allow localhost, 127.0.0.1, and private IPs.
    
    return True

def validate_ip_or_domain(target):
    """Validate if target is valid IP or domain (Private IPs are ALLOWED)"""
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    domain_pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    
    if not (ip_pattern.match(target) or domain_pattern.match(target)):
        return False
        
    # SSRF Check: Removed to allow internal scanning as requested.
    # We now explicitly permit private IPs and localhost.
    return True
        
    return True

def scan_security_headers(url):
    """Scan HTTP security headers of target URL"""
    results = {
        'headers_found': {},
        'headers_missing': [],
        'recommendations': []
    }
    
    try:
        # ---------------------------------------------------------
        # SETUP HTTP SESSION
        # ---------------------------------------------------------
        # We use a 'Session' object which persists settings across requests.
        session = requests.Session()
        
        # Configure a "Retry Strategy"
        # If the server is busy (Errror 500, 502, etc.), we will try again 3 times.
        # backoff_factor=1 means we wait 0s, then 2s, then 4s between retries.
        retry = requests.adapters.Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        # Mount this strategy to both HTTP and HTTPS prefixes
        adapter = requests.adapters.HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # ---------------------------------------------------------
        # PERFORM REQUEST
        # ---------------------------------------------------------
        # User-Agent: We pretend to be a real Chrome browser so we don't get blocked.
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # session.get(): actually sends the request to the URL.
        # timeout=30: If server doesn't reply in 30 seconds, give up.
        response = session.get(url, timeout=30, allow_redirects=True, headers=headers)
        
        # ---------------------------------------------------------
        # ANALYZE HEADERS
        # ---------------------------------------------------------
        # Check if our important security headers exist in the response
        for header, description in SECURITY_HEADERS_INFO.items():
            if header in response.headers:
                # Found it! Save the value and the description.
                results['headers_found'][header] = {
                    'value': response.headers[header],
                    'description': description
                }
            else:
                # Missing! Add to missing list with description.
                results['headers_missing'].append({
                    'header': header,
                    'description': description
                })
        
        # ---------------------------------------------------------
        # GENERATE RECOMMENDATIONS
        # ---------------------------------------------------------
        # Based on what's missing, tell the user how to fix it.
        
        if 'Content-Security-Policy' not in response.headers:
            results['recommendations'].append({
                'action': 'Configure Content-Security-Policy (CSP)',
                'description': 'Implement a strict CSP to control which resources (scripts, styles, images) can be loaded. This is the most effective defense against Cross-Site Scripting (XSS) attacks.'
            })
        
        if 'Strict-Transport-Security' not in response.headers:
            results['recommendations'].append({
                'action': 'Enable HTTP Strict Transport Security (HSTS)',
                'description': 'Add the "Strict-Transport-Security" header with a long max-age (e.g., 31536000) to forcedly upgrade all connections to HTTPS, preventing protocol downgrade attacks.'
            })
        
        if 'X-Frame-Options' not in response.headers:
            results['recommendations'].append({
                'action': 'Set X-Frame-Options Header',
                'description': 'Configure this header to "DENY" or "SAMEORIGIN" to prevent your site from being framed by deeper pages. This mitigates Clickjacking attacks.'
            })
        
        if 'X-Content-Type-Options' not in response.headers:
            results['recommendations'].append({
                'action': 'Add X-Content-Type-Options: nosniff',
                'description': 'This header prevents the browser from interpreting files as a different MIME type than what is specified, reducing the risk of drive-by downloads.'
            })
        
        if 'Referrer-Policy' not in response.headers:
            results['recommendations'].append({
                'action': 'Set Referrer-Policy',
                'description': 'Configure to "strict-origin-when-cross-origin" or "no-referrer" to protect user privacy by limiting how much of the URL is sent to other sites.'
            })

        if 'X-XSS-Protection' not in response.headers:
            results['recommendations'].append({
                'action': 'Enable X-XSS-Protection',
                'description': 'Set to "1; mode=block" to enable the browser\'s built-in XSS filter. Note: CSP is modern and preferred, but this adds defense-in-depth for older browsers.'
            })
        
        results['status'] = 'success'
        results['message'] = f'Found {len(results["headers_found"])} security headers'
        
    except requests.exceptions.RequestException as e:
        # This catches DNS errors, connection timeouts, etc.
        results['status'] = 'error'
        results['message'] = f'Failed to scan target: {str(e)}'
    
    return results


# ------------------------------------------------------------------
# scan_ports FUNCTION
# This is the detailed logic for checking open ports (doors)
# ------------------------------------------------------------------
def scan_ports(target):
    """Scan open ports on target IP or domain"""
    # 1. Setup an empty result box
    results = {
        'open_ports': [],
        'closed_ports': [],
        'status': 'success'
    }
    
    try:
        # 2. Convert Domain (e.g., google.com) to IP Address (e.g., 142.250.x.x)
        # Think of this like looking up a name in a phone book to get the number.
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                # If we can't find the number, stop here.
                results['status'] = 'error'
                results['message'] = 'Failed to resolve domain'
                return results
        else:
            target_ip = target
        
        # 3. Validation: Port Scanning Loop
        # We process each port one by one, like knocking on a list of doors.
        for port, details in PORT_DETAILS.items():
            # Create a "Socket" - this is our virtual network cable.
            # AF_INET = IPv4 (Standard Internet)
            # SOCK_STREAM = TCP (Reliable Connection)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Timeout: Don't wait forever. If no answer in 2 seconds, assume closed.
            sock.settimeout(2.0) 
            
            try:
                # 4. Attempt Connection
                # connect_ex tries to plug our cable into the target's port.
                # If target is 0.0.0.0 (all interfaces), we scan localhost (127.0.0.1) effectively.
                scan_target_ip = target_ip
                if target_ip == '0.0.0.0':
                    scan_target_ip = '127.0.0.1'

                result = sock.connect_ex((scan_target_ip, port))
                
                if result == 0:
                    # Port is OPEN! 
                    # BANNER GRABBING: Try to receive data to identify the service
                    banner = "Unknown"
                    try:
                        # Send a dummy byte to provoke a response (some protocols wait for client first)
                        # But for many simple banners, just recv is enough.
                        # We'll try receiving first.
                        sock.settimeout(1.0) # Short timeout for banner recv
                        try:
                            # Try to read 1024 bytes
                            banner_bytes = sock.recv(1024)
                            banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                        except socket.timeout:
                            # If they didn't say anything, maybe they are waiting for us?
                            # This is common in HTTP, but SSH usually speaks first.
                            pass
                        
                        if not banner or banner == "":
                             banner = "Open (No banner received)"
                    except Exception:
                         banner = "Open (Banner grab failed)"

                    # Port is OPEN! Add all the risk details to the result list
                    results['open_ports'].append({
                        'port': port, 
                        'service': f"{details['service']} ({banner})", # Include banner in service name
                        'status': 'open',
                        'risk_level': details['risk_level'],
                        'description': details['description'],
                        'attacks': details['attacks'],
                        'recommendation': details['recommendation']
                    })
                else:
                    # Port is CLOSED or FILTERED (Firewall)
                    results['closed_ports'].append({'port': port, 'service': details['service'], 'status': 'closed'})
            except socket.error:
                # If any socket error occurs (network down, etc.), mark as closed
                results['closed_ports'].append({'port': port, 'service': details['service'], 'status': 'closed'})
            finally:
                # ALWAYS close the socket to free up system resources
                sock.close()
        
        results['message'] = f'Found {len(results["open_ports"])} open ports'
        
    except Exception as e:
        results['status'] = 'error'
        results['message'] = f'Scan failed: {str(e)}'
    
    return results