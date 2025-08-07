#!/usr/bin/env python3
"""
Network Vulnerability Scanner Module
Provides comprehensive network scanning capabilities for vulnerability assessment
"""

import socket
import threading
import time
import subprocess
import platform
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NetworkScanner:
    def __init__(self):
        self.scan_results = []
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = []
        self.scan_progress = 0
        
    def port_scan(self, target, ports=None, timeout=1):
        """
        Perform port scanning on target host
        
        Args:
            target (str): Target IP address or hostname
            ports (list): List of ports to scan (default: common ports)
            timeout (int): Connection timeout in seconds
            
        Returns:
            dict: Scan results with open ports and services
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        logging.info(f"Starting port scan on {target}")
        self.scan_progress = 0
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self.get_service_name(port)
                    return {
                        'port': port,
                        'service': service,
                        'status': 'open',
                        'banner': self.grab_banner(target, port)
                    }
                return None
            except Exception as e:
                logging.debug(f"Error scanning port {port}: {str(e)}")
                return None
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                self.scan_progress += 1
        
        self.open_ports = open_ports
        logging.info(f"Port scan completed. Found {len(open_ports)} open ports")
        
        return {
            'status': 'success',
            'target': target,
            'open_ports': open_ports,
            'total_ports_scanned': len(ports),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy'
        }
        return common_services.get(port, 'Unknown')
    
    def grab_banner(self, target, port, timeout=3):
        """Grab service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send a simple probe
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-OpenSSH_8.0\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception as e:
            logging.debug(f"Error grabbing banner from {target}:{port}: {str(e)}")
            return None
    
    def service_enumeration(self, target, ports):
        """
        Enumerate services on open ports
        
        Args:
            target (str): Target IP address
            ports (list): List of open ports
            
        Returns:
            dict: Service enumeration results
        """
        logging.info(f"Starting service enumeration on {target}")
        services = {}
        
        for port in ports:
            service_info = self.get_detailed_service_info(target, port)
            if service_info:
                services[port] = service_info
        
        self.services = services
        return {
            'status': 'success',
            'target': target,
            'services': services,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_detailed_service_info(self, target, port):
        """Get detailed information about a service"""
        try:
            if port == 80 or port == 443:
                return self.enumerate_web_service(target, port)
            elif port == 22:
                return self.enumerate_ssh_service(target, port)
            elif port == 21:
                return self.enumerate_ftp_service(target, port)
            elif port == 3306:
                return self.enumerate_mysql_service(target, port)
            else:
                return {
                    'service': self.get_service_name(port),
                    'banner': self.grab_banner(target, port),
                    'version': 'Unknown'
                }
        except Exception as e:
            logging.debug(f"Error enumerating service on port {port}: {str(e)}")
            return None
    
    def enumerate_web_service(self, target, port):
        """Enumerate web service details"""
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}"
            
            response = requests.get(url, timeout=5, verify=False)
            
            return {
                'service': 'HTTP/HTTPS',
                'version': response.headers.get('Server', 'Unknown'),
                'title': self.extract_title(response.text),
                'headers': dict(response.headers),
                'status_code': response.status_code
            }
        except Exception as e:
            logging.debug(f"Error enumerating web service: {str(e)}")
            return {'service': 'HTTP/HTTPS', 'version': 'Unknown'}
    
    def extract_title(self, html_content):
        """Extract page title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
            return 'No title'
        except:
            return 'No title'
    
    def enumerate_ssh_service(self, target, port):
        """Enumerate SSH service details"""
        try:
            banner = self.grab_banner(target, port)
            if banner:
                return {
                    'service': 'SSH',
                    'banner': banner,
                    'version': banner.split()[1] if len(banner.split()) > 1 else 'Unknown'
                }
            return {'service': 'SSH', 'version': 'Unknown'}
        except Exception as e:
            logging.debug(f"Error enumerating SSH service: {str(e)}")
            return {'service': 'SSH', 'version': 'Unknown'}
    
    def enumerate_ftp_service(self, target, port):
        """Enumerate FTP service details"""
        try:
            banner = self.grab_banner(target, port)
            return {
                'service': 'FTP',
                'banner': banner,
                'version': 'Unknown'
            }
        except Exception as e:
            logging.debug(f"Error enumerating FTP service: {str(e)}")
            return {'service': 'FTP', 'version': 'Unknown'}
    
    def enumerate_mysql_service(self, target, port):
        """Enumerate MySQL service details"""
        try:
            banner = self.grab_banner(target, port)
            return {
                'service': 'MySQL',
                'banner': banner,
                'version': 'Unknown'
            }
        except Exception as e:
            logging.debug(f"Error enumerating MySQL service: {str(e)}")
            return {'service': 'MySQL', 'version': 'Unknown'}
    
    def network_topology(self, network):
        """
        Map network topology
        
        Args:
            network (str): Network range (e.g., 192.168.1.0/24)
            
        Returns:
            dict: Network topology information
        """
        logging.info(f"Starting network topology mapping for {network}")
        
        # This is a simplified implementation
        # In a real scenario, you'd use tools like nmap or custom implementations
        try:
            # Extract network information
            if '/' in network:
                base_ip, mask = network.split('/')
                mask = int(mask)
            else:
                base_ip = network
                mask = 24
            
            # Generate IP range
            ip_range = self.generate_ip_range(base_ip, mask)
            
            # Scan for live hosts
            live_hosts = []
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in ip_range}
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            live_hosts.append(ip)
                    except Exception as e:
                        logging.debug(f"Error pinging {ip}: {str(e)}")
            
            return {
                'status': 'success',
                'network': network,
                'live_hosts': live_hosts,
                'total_hosts': len(ip_range),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error mapping network topology: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def generate_ip_range(self, base_ip, mask):
        """Generate IP range from base IP and mask"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{base_ip}/{mask}", strict=False)
            return [str(ip) for ip in network.hosts()]
        except Exception as e:
            logging.error(f"Error generating IP range: {str(e)}")
            return []
    
    def ping_host(self, ip):
        """Ping a host to check if it's alive"""
        try:
            if platform.system().lower() == "windows":
                command = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                command = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception as e:
            logging.debug(f"Error pinging {ip}: {str(e)}")
            return False
    
    def vulnerability_scan(self, target, ports):
        """
        Perform vulnerability scanning on target
        
        Args:
            target (str): Target IP address
            ports (list): List of open ports
            
        Returns:
            dict: Vulnerability scan results
        """
        logging.info(f"Starting vulnerability scan on {target}")
        vulnerabilities = []
        
        for port in ports:
            port_vulns = self.check_port_vulnerabilities(target, port)
            if port_vulns:
                vulnerabilities.extend(port_vulns)
        
        self.vulnerabilities = vulnerabilities
        
        return {
            'status': 'success',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'timestamp': datetime.now().isoformat()
        }
    
    def check_port_vulnerabilities(self, target, port):
        """Check for vulnerabilities on specific port"""
        vulnerabilities = []
        
        try:
            if port == 21:  # FTP
                vulns = self.check_ftp_vulnerabilities(target, port)
                vulnerabilities.extend(vulns)
            elif port == 22:  # SSH
                vulns = self.check_ssh_vulnerabilities(target, port)
                vulnerabilities.extend(vulns)
            elif port == 80 or port == 443:  # HTTP/HTTPS
                vulns = self.check_web_vulnerabilities(target, port)
                vulnerabilities.extend(vulns)
            elif port == 3306:  # MySQL
                vulns = self.check_mysql_vulnerabilities(target, port)
                vulnerabilities.extend(vulns)
            elif port == 3389:  # RDP
                vulns = self.check_rdp_vulnerabilities(target, port)
                vulnerabilities.extend(vulns)
        except Exception as e:
            logging.debug(f"Error checking vulnerabilities on port {port}: {str(e)}")
        
        return vulnerabilities
    
    def check_ftp_vulnerabilities(self, target, port):
        """Check FTP vulnerabilities"""
        vulnerabilities = []
        
        # Check for anonymous access
        try:
            banner = self.grab_banner(target, port)
            if banner and 'anonymous' in banner.lower():
                vulnerabilities.append({
                    'type': 'FTP_ANONYMOUS_ACCESS',
                    'severity': 'Medium',
                    'description': 'FTP anonymous access enabled',
                    'port': port,
                    'details': banner
                })
        except Exception as e:
            logging.debug(f"Error checking FTP vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_ssh_vulnerabilities(self, target, port):
        """Check SSH vulnerabilities"""
        vulnerabilities = []
        
        try:
            banner = self.grab_banner(target, port)
            if banner:
                # Check for weak SSH versions
                if 'SSH-1.99' in banner or 'SSH-1.5' in banner:
                    vulnerabilities.append({
                        'type': 'SSH_WEAK_VERSION',
                        'severity': 'High',
                        'description': 'Weak SSH version detected',
                        'port': port,
                        'details': banner
                    })
        except Exception as e:
            logging.debug(f"Error checking SSH vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_web_vulnerabilities(self, target, port):
        """Check web vulnerabilities"""
        vulnerabilities = []
        
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}"
            
            # Check for common web vulnerabilities
            response = requests.get(url, timeout=5, verify=False)
            
            # Check for missing security headers
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
            missing_headers = [header for header in security_headers if header not in response.headers]
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'MISSING_SECURITY_HEADERS',
                    'severity': 'Medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'port': port,
                    'details': f'Missing headers: {missing_headers}'
                })
            
            # Check for server information disclosure
            server_header = response.headers.get('Server', '')
            if server_header and server_header != 'Unknown':
                vulnerabilities.append({
                    'type': 'SERVER_INFO_DISCLOSURE',
                    'severity': 'Low',
                    'description': 'Server information disclosed',
                    'port': port,
                    'details': f'Server: {server_header}'
                })
                
        except Exception as e:
            logging.debug(f"Error checking web vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_mysql_vulnerabilities(self, target, port):
        """Check MySQL vulnerabilities"""
        vulnerabilities = []
        
        try:
            banner = self.grab_banner(target, port)
            if banner:
                vulnerabilities.append({
                    'type': 'MYSQL_EXPOSED',
                    'severity': 'High',
                    'description': 'MySQL service exposed',
                    'port': port,
                    'details': banner
                })
        except Exception as e:
            logging.debug(f"Error checking MySQL vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_rdp_vulnerabilities(self, target, port):
        """Check RDP vulnerabilities"""
        vulnerabilities = []
        
        try:
            banner = self.grab_banner(target, port)
            if banner:
                vulnerabilities.append({
                    'type': 'RDP_EXPOSED',
                    'severity': 'High',
                    'description': 'RDP service exposed',
                    'port': port,
                    'details': banner
                })
        except Exception as e:
            logging.debug(f"Error checking RDP vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def comprehensive_scan(self, target, ports=None):
        """
        Perform comprehensive network scan
        
        Args:
            target (str): Target IP address
            ports (list): List of ports to scan
            
        Returns:
            dict: Comprehensive scan results
        """
        logging.info(f"Starting comprehensive network scan on {target}")
        
        # Step 1: Port scanning
        port_results = self.port_scan(target, ports)
        
        # Step 2: Service enumeration
        if port_results['open_ports']:
            service_results = self.service_enumeration(target, [p['port'] for p in port_results['open_ports']])
        else:
            service_results = {'services': {}}
        
        # Step 3: Vulnerability scanning
        if port_results['open_ports']:
            vuln_results = self.vulnerability_scan(target, [p['port'] for p in port_results['open_ports']])
        else:
            vuln_results = {'vulnerabilities': []}
        
        # Compile results
        comprehensive_results = {
            'status': 'success',
            'target': target,
            'scan_type': 'comprehensive',
            'timestamp': datetime.now().isoformat(),
            'port_scan': port_results,
            'service_enumeration': service_results,
            'vulnerability_scan': vuln_results,
            'summary': {
                'open_ports': len(port_results['open_ports']),
                'services_found': len(service_results['services']),
                'vulnerabilities_found': len(vuln_results['vulnerabilities']),
                'risk_score': self.calculate_risk_score(vuln_results['vulnerabilities'])
            }
        }
        
        self.scan_results.append(comprehensive_results)
        return comprehensive_results
    
    def calculate_risk_score(self, vulnerabilities):
        """Calculate risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0
        
        severity_scores = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1,
            'Info': 0
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            total_score += severity_scores.get(severity, 1)
        
        # Normalize to 0-100 scale
        max_possible_score = len(vulnerabilities) * 10
        if max_possible_score > 0:
            risk_score = (total_score / max_possible_score) * 100
        else:
            risk_score = 0
        
        return round(risk_score, 2)

# Convenience functions for backward compatibility
def scan_network(target, ports=None):
    """Convenience function for network scanning"""
    scanner = NetworkScanner()
    return scanner.comprehensive_scan(target, ports)

def port_scan(target, ports=None):
    """Convenience function for port scanning"""
    scanner = NetworkScanner()
    return scanner.port_scan(target, ports)

def vulnerability_scan(target, ports=None):
    """Convenience function for vulnerability scanning"""
    scanner = NetworkScanner()
    return scanner.vulnerability_scan(target, ports or [80, 443, 22, 21, 3306, 3389])
