#!/usr/bin/env python3
"""
Enhanced Network Service Vulnerability Scanner
Advanced network service discovery and vulnerability detection
"""

import socket
import threading
import subprocess
import json
import logging
import time
import ssl
import re
from datetime import datetime
import platform
import concurrent.futures
from urllib.parse import urlparse
import requests

class EnhancedNetworkScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.open_ports = []
        self.services = {}
        self.timeout = 3
        self.max_threads = 100
        
    def port_scan(self, target, ports):
        """Enhanced port scanning with service detection"""
        logging.info(f"Starting enhanced port scan on {target}")
        
        if isinstance(ports, str):
            ports = self.parse_port_range(ports)
        elif ports is None:
            ports = self.get_common_ports()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, target, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.open_ports.append({
                            'port': port,
                            'service': result.get('service', 'unknown'),
                            'banner': result.get('banner', ''),
                            'version': result.get('version', ''),
                            'protocol': result.get('protocol', 'tcp')
                        })
                except Exception as e:
                    logging.debug(f"Error scanning port {port}: {e}")
        
        return self.open_ports
    
    def scan_port(self, target, port):
        """Scan individual port with service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open, try to identify service
                service_info = self.identify_service(sock, target, port)
                sock.close()
                return service_info
            else:
                sock.close()
                return None
                
        except Exception as e:
            logging.debug(f"Error scanning {target}:{port} - {e}")
            return None
    
    def identify_service(self, sock, target, port):
        """Identify service running on open port"""
        service_info = {
            'service': 'unknown',
            'banner': '',
            'version': '',
            'protocol': 'tcp'
        }
        
        try:
            # Try to grab banner
            if port in [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3389]:
                banner = self.grab_banner(sock, port)
                service_info['banner'] = banner
                
                # Identify service based on port and banner
                service_info['service'] = self.identify_service_by_port(port, banner)
                service_info['version'] = self.extract_version(banner)
                
        except Exception as e:
            logging.debug(f"Error identifying service on {target}:{port} - {e}")
        
        return service_info
    
    def grab_banner(self, sock, port):
        """Grab service banner"""
        try:
            if port == 80:
                # HTTP banner grab
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 443:
                # HTTPS banner grab
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname='localhost')
                ssl_sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                response = ssl_sock.recv(1024).decode('utf-8', errors='ignore')
                ssl_sock.close()
                return response
            elif port in [21, 22, 25, 110, 143]:
                # Services that send banner immediately
                pass
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner.strip()
            
        except Exception as e:
            logging.debug(f"Error grabbing banner on port {port}: {e}")
            return ""
    
    def identify_service_by_port(self, port, banner):
        """Identify service based on port number and banner"""
        port_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            135: 'rpc',
            139: 'netbios',
            143: 'imap',
            443: 'https',
            445: 'smb',
            993: 'imaps',
            995: 'pop3s',
            1433: 'mssql',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis'
        }
        
        service = port_services.get(port, 'unknown')
        
        # Refine based on banner
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service = 'ssh'
            elif 'ftp' in banner_lower:
                service = 'ftp'
            elif 'http' in banner_lower or 'server:' in banner_lower:
                service = 'http' if port != 443 else 'https'
            elif 'smtp' in banner_lower or 'mail' in banner_lower:
                service = 'smtp'
            elif 'mysql' in banner_lower:
                service = 'mysql'
            elif 'postgresql' in banner_lower:
                service = 'postgresql'
        
        return service
    
    def extract_version(self, banner):
        """Extract version information from banner"""
        if not banner:
            return ""
        
        # Common version patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'version\s+(\d+\.\d+\.\d+)',
            r'version\s+(\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def scan_service_vulnerabilities(self, target):
        """Scan detected services for vulnerabilities"""
        logging.info("Scanning services for vulnerabilities...")
        
        for port_info in self.open_ports:
            port = port_info['port']
            service = port_info['service']
            version = port_info['version']
            banner = port_info['banner']
            
            # Check service-specific vulnerabilities
            if service == 'ssh':
                self.scan_ssh_vulnerabilities(target, port, banner, version)
            elif service == 'ftp':
                self.scan_ftp_vulnerabilities(target, port, banner, version)
            elif service in ['http', 'https']:
                self.scan_web_vulnerabilities(target, port, service)
            elif service == 'smb':
                self.scan_smb_vulnerabilities(target, port)
            elif service == 'rdp':
                self.scan_rdp_vulnerabilities(target, port)
            elif service in ['mysql', 'postgresql', 'mssql']:
                self.scan_database_vulnerabilities(target, port, service)
            elif service == 'redis':
                self.scan_redis_vulnerabilities(target, port)
            elif service == 'vnc':
                self.scan_vnc_vulnerabilities(target, port)
    
    def scan_ssh_vulnerabilities(self, target, port, banner, version):
        """Scan SSH for vulnerabilities"""
        try:
            # Check for weak SSH configurations
            if 'openssh' in banner.lower():
                # Extract OpenSSH version
                ssh_version_match = re.search(r'openssh[_\s](\d+\.\d+)', banner, re.IGNORECASE)
                if ssh_version_match:
                    ssh_version = ssh_version_match.group(1)
                    
                    # Check for known vulnerable versions
                    vulnerable_versions = [
                        ('7.4', 'CVE-2018-15473', 'User enumeration vulnerability'),
                        ('6.6', 'CVE-2016-0777', 'Information disclosure vulnerability'),
                        ('5.3', 'CVE-2010-4478', 'Certificate validation bypass')
                    ]
                    
                    for vuln_version, cve, description in vulnerable_versions:
                        if self.version_compare(ssh_version, vuln_version) <= 0:
                            self.vulnerabilities.append({
                                'type': 'SSH Vulnerability',
                                'severity': 'High',
                                'target': target,
                                'port': port,
                                'service': 'ssh',
                                'cve': cve,
                                'description': description,
                                'version': ssh_version,
                                'recommendation': 'Update SSH server to latest version'
                            })
            
            # Check for weak authentication
            try:
                # Try common weak credentials
                weak_creds = [('root', ''), ('admin', 'admin'), ('user', 'user')]
                for username, password in weak_creds:
                    if self.test_ssh_auth(target, port, username, password):
                        self.vulnerabilities.append({
                            'type': 'Weak SSH Credentials',
                            'severity': 'Critical',
                            'target': target,
                            'port': port,
                            'service': 'ssh',
                            'username': username,
                            'password': password if password else '(empty)',
                            'description': f'SSH accessible with weak credentials: {username}:{password or "(empty)"}',
                            'recommendation': 'Change default credentials and enforce strong passwords'
                        })
                        break  # Stop after finding one
            except:
                pass
                
        except Exception as e:
            logging.debug(f"Error scanning SSH vulnerabilities: {e}")
    
    def scan_ftp_vulnerabilities(self, target, port, banner, version):
        """Scan FTP for vulnerabilities"""
        try:
            # Check for anonymous FTP access
            if self.test_ftp_anonymous(target, port):
                self.vulnerabilities.append({
                    'type': 'Anonymous FTP Access',
                    'severity': 'Medium',
                    'target': target,
                    'port': port,
                    'service': 'ftp',
                    'description': 'FTP server allows anonymous access',
                    'recommendation': 'Disable anonymous FTP access if not required'
                })
            
            # Check for weak FTP credentials
            weak_creds = [('ftp', 'ftp'), ('admin', 'admin'), ('user', 'password')]
            for username, password in weak_creds:
                if self.test_ftp_auth(target, port, username, password):
                    self.vulnerabilities.append({
                        'type': 'Weak FTP Credentials',
                        'severity': 'High',
                        'target': target,
                        'port': port,
                        'service': 'ftp',
                        'username': username,
                        'password': password,
                        'description': f'FTP accessible with weak credentials: {username}:{password}',
                        'recommendation': 'Change default credentials and enforce strong passwords'
                    })
                    break
                    
        except Exception as e:
            logging.debug(f"Error scanning FTP vulnerabilities: {e}")
    
    def scan_web_vulnerabilities(self, target, port, service):
        """Scan web services for basic vulnerabilities"""
        try:
            protocol = 'https' if service == 'https' else 'http'
            base_url = f"{protocol}://{target}:{port}"
            
            # Check for directory listing
            try:
                response = requests.get(base_url, timeout=5, verify=False)
                if 'Index of /' in response.text or 'Directory Listing' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'Medium',
                        'target': target,
                        'port': port,
                        'service': service,
                        'url': base_url,
                        'description': 'Web server allows directory listing',
                        'recommendation': 'Disable directory listing'
                    })
            except:
                pass
            
            # Check for common vulnerable paths
            vulnerable_paths = [
                '/admin/',
                '/phpmyadmin/',
                '/wp-admin/',
                '/cgi-bin/',
                '/server-info',
                '/server-status'
            ]
            
            for path in vulnerable_paths:
                try:
                    url = f"{base_url}{path}"
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Exposed Admin Interface',
                            'severity': 'Medium',
                            'target': target,
                            'port': port,
                            'service': service,
                            'url': url,
                            'description': f'Admin interface exposed at {path}',
                            'recommendation': 'Restrict access to admin interfaces'
                        })
                except:
                    continue
                    
        except Exception as e:
            logging.debug(f"Error scanning web vulnerabilities: {e}")
    
    def scan_smb_vulnerabilities(self, target, port):
        """Scan SMB for vulnerabilities"""
        try:
            # Check for SMB version and known vulnerabilities
            if platform.system() == 'Linux':
                try:
                    result = subprocess.run([
                        'smbclient', '-L', target, '-N'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        # SMB accessible without authentication
                        if 'Sharename' in result.stdout:
                            self.vulnerabilities.append({
                                'type': 'SMB Anonymous Access',
                                'severity': 'Medium',
                                'target': target,
                                'port': port,
                                'service': 'smb',
                                'description': 'SMB shares accessible without authentication',
                                'recommendation': 'Require authentication for SMB access'
                            })
                except FileNotFoundError:
                    # smbclient not available
                    pass
            
            # Check for EternalBlue vulnerability (MS17-010)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, 445))
                
                # Simple check for SMB1 support (vulnerable to EternalBlue)
                smb_negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
                
                sock.send(smb_negotiate)
                response = sock.recv(1024)
                sock.close()
                
                if b'SMB' in response:
                    self.vulnerabilities.append({
                        'type': 'SMB Protocol Vulnerability',
                        'severity': 'Critical',
                        'target': target,
                        'port': port,
                        'service': 'smb',
                        'cve': 'MS17-010',
                        'description': 'SMB service may be vulnerable to EternalBlue (MS17-010)',
                        'recommendation': 'Apply MS17-010 patch and disable SMBv1'
                    })
                    
            except:
                pass
                
        except Exception as e:
            logging.debug(f"Error scanning SMB vulnerabilities: {e}")
    
    def scan_rdp_vulnerabilities(self, target, port):
        """Scan RDP for vulnerabilities"""
        try:
            # Check for BlueKeep vulnerability
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                self.vulnerabilities.append({
                    'type': 'RDP Service Exposed',
                    'severity': 'High',
                    'target': target,
                    'port': port,
                    'service': 'rdp',
                    'description': 'RDP service is exposed to network',
                    'recommendation': 'Restrict RDP access and enable Network Level Authentication'
                })
                
                # Additional check for weak RDP credentials could be added here
                
            sock.close()
            
        except Exception as e:
            logging.debug(f"Error scanning RDP vulnerabilities: {e}")
    
    def scan_database_vulnerabilities(self, target, port, service):
        """Scan database services for vulnerabilities"""
        try:
            # Check for default credentials and open access
            default_creds = {
                'mysql': [('root', ''), ('root', 'root'), ('mysql', 'mysql')],
                'postgresql': [('postgres', ''), ('postgres', 'postgres')],
                'mssql': [('sa', ''), ('sa', 'sa'), ('admin', 'admin')]
            }
            
            creds_to_test = default_creds.get(service, [])
            
            for username, password in creds_to_test:
                if self.test_database_auth(target, port, service, username, password):
                    self.vulnerabilities.append({
                        'type': 'Weak Database Credentials',
                        'severity': 'Critical',
                        'target': target,
                        'port': port,
                        'service': service,
                        'username': username,
                        'password': password if password else '(empty)',
                        'description': f'{service.upper()} accessible with default credentials: {username}:{password or "(empty)"}',
                        'recommendation': 'Change default database credentials'
                    })
                    break
                    
        except Exception as e:
            logging.debug(f"Error scanning database vulnerabilities: {e}")
    
    def scan_redis_vulnerabilities(self, target, port):
        """Scan Redis for vulnerabilities"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Try Redis INFO command
            sock.send(b'INFO\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'redis_version' in response:
                self.vulnerabilities.append({
                    'type': 'Redis No Authentication',
                    'severity': 'High',
                    'target': target,
                    'port': port,
                    'service': 'redis',
                    'description': 'Redis server accessible without authentication',
                    'recommendation': 'Enable Redis authentication and bind to localhost only'
                })
                
        except Exception as e:
            logging.debug(f"Error scanning Redis vulnerabilities: {e}")
    
    def scan_vnc_vulnerabilities(self, target, port):
        """Scan VNC for vulnerabilities"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # VNC handshake
            response = sock.recv(1024)
            if b'RFB' in response:
                self.vulnerabilities.append({
                    'type': 'VNC Service Exposed',
                    'severity': 'High',
                    'target': target,
                    'port': port,
                    'service': 'vnc',
                    'description': 'VNC service is exposed without authentication',
                    'recommendation': 'Enable VNC authentication and use VPN for remote access'
                })
            
            sock.close()
            
        except Exception as e:
            logging.debug(f"Error scanning VNC vulnerabilities: {e}")
    
    # Helper methods for authentication testing
    def test_ssh_auth(self, target, port, username, password):
        """Test SSH authentication (placeholder)"""
        # In a real implementation, this would use paramiko or similar
        return False
    
    def test_ftp_anonymous(self, target, port):
        """Test FTP anonymous access"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            ftp.login('anonymous', 'anonymous@domain.com')
            ftp.quit()
            return True
        except:
            return False
    
    def test_ftp_auth(self, target, port, username, password):
        """Test FTP authentication"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            ftp.login(username, password)
            ftp.quit()
            return True
        except:
            return False
    
    def test_database_auth(self, target, port, service, username, password):
        """Test database authentication (placeholder)"""
        # In a real implementation, this would use appropriate database drivers
        return False
    
    def version_compare(self, version1, version2):
        """Compare version strings"""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)
            
            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            return 0
        except:
            return 0
    
    def parse_port_range(self, port_range):
        """Parse port range string into list of ports"""
        ports = []
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        else:
            ports = [int(port_range)]
        return ports
    
    def get_common_ports(self):
        """Get list of common ports to scan"""
        return [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 9443
        ]
    
    def comprehensive_network_scan(self, target, ports=None):
        """Run comprehensive network vulnerability scan"""
        logging.info(f"Starting comprehensive network scan on {target}")
        
        start_time = datetime.now()
        
        # Phase 1: Port scanning and service detection
        self.port_scan(target, ports)
        
        # Phase 2: Service vulnerability scanning
        self.scan_service_vulnerabilities(target)
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        return {
            'scan_type': 'comprehensive_network_scan',
            'target': target,
            'timestamp': end_time.isoformat(),
            'scan_duration': scan_duration,
            'open_ports': self.open_ports,
            'vulnerabilities': self.vulnerabilities,
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': self.get_severity_breakdown()
        }
    
    def get_severity_breakdown(self):
        """Get breakdown of vulnerabilities by severity"""
        breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Low')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown

def scan_network_vulnerabilities(target='127.0.0.1', ports=None):
    """Main function to scan network vulnerabilities"""
    try:
        scanner = EnhancedNetworkScanner()
        results = scanner.comprehensive_network_scan(target, ports)
        results['status'] = 'success'
        return results
    except Exception as e:
        logging.error(f"Network vulnerability scan failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Test the scanner
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    results = scan_network_vulnerabilities(target)
    print(json.dumps(results, indent=2))
