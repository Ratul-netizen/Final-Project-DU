#!/usr/bin/env python3
"""
Advanced Linux Vulnerability Scanner
Comprehensive OS-level vulnerability detection for Linux systems
"""

import os
import sys
import json
import logging
import subprocess
import platform
import socket
import pwd
import grp
import stat
import glob
from datetime import datetime
from pathlib import Path
import re

class LinuxVulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.system_info = self.get_system_info()
        self.kernel_exploits = self.load_kernel_exploits()
        
    def get_system_info(self):
        """Get detailed Linux system information"""
        try:
            info = {
                'os_name': platform.system(),
                'os_release': platform.release(),
                'os_version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'hostname': socket.gethostname(),
                'kernel_version': self.get_kernel_version(),
                'distribution': self.get_distribution(),
                'uptime': self.get_uptime()
            }
            return info
        except Exception as e:
            logging.error(f"Error getting system info: {e}")
            return {}
    
    def get_kernel_version(self):
        """Get detailed kernel version"""
        try:
            with open('/proc/version', 'r') as f:
                return f.read().strip()
        except:
            return platform.release()
    
    def get_distribution(self):
        """Get Linux distribution information"""
        try:
            # Try /etc/os-release first
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    os_release = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_release[key] = value.strip('"')
                    return os_release
            
            # Fallback to lsb_release
            result = subprocess.run(['lsb_release', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                return {'description': result.stdout}
                
        except Exception as e:
            logging.error(f"Error getting distribution: {e}")
        
        return {'description': 'Unknown'}
    
    def get_uptime(self):
        """Get system uptime"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                return uptime_seconds / 3600  # Convert to hours
        except:
            return 0
    
    def load_kernel_exploits(self):
        """Load known kernel exploits database"""
        return {
            "4.15.0": [
                {
                    "cve": "CVE-2018-18955",
                    "title": "Subpage permissions issue",
                    "severity": "High",
                    "description": "Privilege escalation vulnerability in kernel"
                }
            ],
            "5.4.0": [
                {
                    "cve": "CVE-2021-4034",
                    "title": "PwnKit",
                    "severity": "Critical", 
                    "description": "Local privilege escalation vulnerability in polkit"
                }
            ],
            "general": [
                {
                    "cve": "CVE-2016-5195",
                    "title": "Dirty COW",
                    "severity": "Critical",
                    "description": "Race condition in memory subsystem"
                },
                {
                    "cve": "CVE-2021-3156",
                    "title": "Baron Samedit",
                    "severity": "Critical",
                    "description": "Heap-based buffer overflow in sudo"
                }
            ]
        }
    
    def scan_kernel_vulnerabilities(self):
        """Scan for known kernel vulnerabilities"""
        logging.info("Scanning for kernel vulnerabilities...")
        try:
            kernel_version = platform.release()
            
            # Check against known kernel exploits
            exploits = self.kernel_exploits.get(kernel_version, []) + self.kernel_exploits.get("general", [])
            
            for exploit in exploits:
                # Additional checks could be added here
                self.vulnerabilities.append({
                    'type': 'Kernel Vulnerability',
                    'severity': exploit['severity'],
                    'cve': exploit['cve'],
                    'title': exploit['title'],
                    'description': exploit['description'],
                    'kernel_version': kernel_version,
                    'recommendation': f"Update kernel to patch {exploit['cve']}"
                })
                
        except Exception as e:
            logging.error(f"Error scanning kernel vulnerabilities: {e}")
    
    def scan_suid_binaries(self):
        """Scan for SUID binaries that might be exploitable"""
        logging.info("Scanning for SUID binaries...")
        try:
            # Common paths to search for SUID binaries
            search_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']
            
            for path in search_paths:
                if os.path.exists(path):
                    try:
                        result = subprocess.run([
                            'find', path, '-perm', '-4000', '-type', 'f', '2>/dev/null'
                        ], capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0:
                            suid_files = result.stdout.strip().split('\n')
                            for suid_file in suid_files:
                                if suid_file and os.path.exists(suid_file):
                                    # Check if this is a known exploitable SUID binary
                                    filename = os.path.basename(suid_file)
                                    if self.is_exploitable_suid(filename):
                                        self.vulnerabilities.append({
                                            'type': 'Exploitable SUID Binary',
                                            'severity': 'High',
                                            'file_path': suid_file,
                                            'filename': filename,
                                            'description': f"Potentially exploitable SUID binary: {filename}",
                                            'recommendation': 'Review if SUID bit is necessary, consider alternatives'
                                        })
                    except subprocess.TimeoutExpired:
                        logging.warning(f"Timeout scanning {path}")
                        
        except Exception as e:
            logging.error(f"Error scanning SUID binaries: {e}")
    
    def is_exploitable_suid(self, filename):
        """Check if SUID binary is known to be exploitable"""
        exploitable_binaries = [
            'vim', 'nano', 'emacs', 'less', 'more', 'man', 'awk', 'gawk',
            'find', 'bash', 'sh', 'csh', 'ksh', 'zsh', 'python', 'perl',
            'ruby', 'lua', 'php', 'node', 'python3', 'wget', 'curl',
            'tar', 'zip', 'unzip', 'git', 'ftp', 'nc', 'netcat', 'socat'
        ]
        return filename in exploitable_binaries
    
    def scan_world_writable_files(self):
        """Scan for world-writable files in sensitive locations"""
        logging.info("Scanning for world-writable files...")
        try:
            sensitive_paths = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/opt']
            
            for path in sensitive_paths:
                if os.path.exists(path):
                    try:
                        result = subprocess.run([
                            'find', path, '-type', 'f', '-perm', '-002', '2>/dev/null'
                        ], capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0:
                            writable_files = result.stdout.strip().split('\n')
                            for writable_file in writable_files:
                                if writable_file and os.path.exists(writable_file):
                                    self.vulnerabilities.append({
                                        'type': 'World Writable File',
                                        'severity': 'Medium',
                                        'file_path': writable_file,
                                        'description': f"World-writable file in sensitive location: {writable_file}",
                                        'recommendation': 'Remove world-write permissions'
                                    })
                    except subprocess.TimeoutExpired:
                        logging.warning(f"Timeout scanning {path}")
                        
        except Exception as e:
            logging.error(f"Error scanning world-writable files: {e}")
    
    def scan_ssh_configuration(self):
        """Scan SSH configuration for security issues"""
        logging.info("Scanning SSH configuration...")
        try:
            ssh_config_files = ['/etc/ssh/sshd_config', '/etc/ssh/ssh_config']
            
            for config_file in ssh_config_files:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config_content = f.read()
                    
                    # Check for insecure SSH configurations
                    insecure_configs = [
                        ('PermitRootLogin yes', 'Root login is enabled'),
                        ('PasswordAuthentication yes', 'Password authentication is enabled'),
                        ('PermitEmptyPasswords yes', 'Empty passwords are allowed'),
                        ('Protocol 1', 'Insecure SSH protocol version 1 is enabled'),
                        ('X11Forwarding yes', 'X11 forwarding is enabled')
                    ]
                    
                    for config_pattern, description in insecure_configs:
                        if re.search(config_pattern, config_content, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'type': 'Insecure SSH Configuration',
                                'severity': 'Medium',
                                'config_file': config_file,
                                'setting': config_pattern,
                                'description': description,
                                'recommendation': 'Review and harden SSH configuration'
                            })
                            
        except Exception as e:
            logging.error(f"Error scanning SSH configuration: {e}")
    
    def scan_cron_permissions(self):
        """Scan cron files for permission issues"""
        logging.info("Scanning cron permissions...")
        try:
            cron_locations = [
                '/etc/crontab',
                '/etc/cron.d/',
                '/etc/cron.daily/',
                '/etc/cron.hourly/',
                '/etc/cron.monthly/',
                '/etc/cron.weekly/',
                '/var/spool/cron/crontabs/'
            ]
            
            for location in cron_locations:
                if os.path.exists(location):
                    if os.path.isfile(location):
                        # Check file permissions
                        file_stat = os.stat(location)
                        if file_stat.st_mode & stat.S_IWOTH:  # World writable
                            self.vulnerabilities.append({
                                'type': 'Insecure Cron Permissions',
                                'severity': 'High',
                                'file_path': location,
                                'description': f"Cron file {location} is world-writable",
                                'recommendation': 'Remove world-write permissions from cron files'
                            })
                    elif os.path.isdir(location):
                        # Check directory and files within
                        for root, dirs, files in os.walk(location):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    file_stat = os.stat(file_path)
                                    if file_stat.st_mode & stat.S_IWOTH:
                                        self.vulnerabilities.append({
                                            'type': 'Insecure Cron Permissions',
                                            'severity': 'High',
                                            'file_path': file_path,
                                            'description': f"Cron file {file_path} is world-writable",
                                            'recommendation': 'Remove world-write permissions from cron files'
                                        })
                                except OSError:
                                    continue
                                    
        except Exception as e:
            logging.error(f"Error scanning cron permissions: {e}")
    
    def scan_sudoers_configuration(self):
        """Scan sudoers configuration for security issues"""
        logging.info("Scanning sudoers configuration...")
        try:
            sudoers_files = ['/etc/sudoers'] + glob.glob('/etc/sudoers.d/*')
            
            for sudoers_file in sudoers_files:
                if os.path.exists(sudoers_file):
                    try:
                        with open(sudoers_file, 'r') as f:
                            content = f.read()
                        
                        # Check for risky sudo configurations
                        risky_patterns = [
                            (r'ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL', 'User can run any command as any user without password'),
                            (r'%\w+\s+ALL\s*=\s*\(ALL\)\s*ALL', 'Group has full sudo access'),
                            (r'NOPASSWD:.*\*', 'Wildcards used with NOPASSWD'),
                            (r'!/usr/bin/passwd\s+root', 'Specifically allows changing root password')
                        ]
                        
                        for pattern, description in risky_patterns:
                            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                                self.vulnerabilities.append({
                                    'type': 'Risky Sudoers Configuration',
                                    'severity': 'High',
                                    'file_path': sudoers_file,
                                    'pattern': pattern,
                                    'description': description,
                                    'recommendation': 'Review and restrict sudo permissions'
                                })
                                
                    except PermissionError:
                        # Can't read sudoers file (expected for non-privileged users)
                        pass
                        
        except Exception as e:
            logging.error(f"Error scanning sudoers: {e}")
    
    def scan_package_vulnerabilities(self):
        """Scan for outdated packages with known vulnerabilities"""
        logging.info("Scanning package vulnerabilities...")
        try:
            # Check for package managers and get outdated packages
            package_managers = [
                ('apt', ['apt', 'list', '--upgradable']),
                ('yum', ['yum', 'check-update']),
                ('dnf', ['dnf', 'check-update']),
                ('pacman', ['pacman', '-Qu']),
                ('zypper', ['zypper', 'list-updates'])
            ]
            
            for pm_name, command in package_managers:
                if self.command_exists(command[0]):
                    try:
                        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                        
                        if result.stdout and 'upgradable' in result.stdout.lower():
                            # Parse output to count upgradable packages
                            lines = result.stdout.strip().split('\n')
                            upgradable_count = len([line for line in lines if '/' in line and 'upgradable' in line.lower()])
                            
                            if upgradable_count > 0:
                                self.vulnerabilities.append({
                                    'type': 'Outdated Packages',
                                    'severity': 'Medium',
                                    'package_manager': pm_name,
                                    'upgradable_packages': upgradable_count,
                                    'description': f"{upgradable_count} packages have available updates",
                                    'recommendation': f"Update packages using {pm_name}"
                                })
                        break  # Found a working package manager
                        
                    except subprocess.TimeoutExpired:
                        logging.warning(f"Timeout checking {pm_name} updates")
                    except Exception as e:
                        logging.warning(f"Error checking {pm_name}: {e}")
                        
        except Exception as e:
            logging.error(f"Error scanning packages: {e}")
    
    def command_exists(self, command):
        """Check if a command exists"""
        try:
            subprocess.run(['which', command], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def scan_network_services(self):
        """Scan for running network services"""
        logging.info("Scanning network services...")
        try:
            # Get listening ports
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            address = parts[3]
                            if '0.0.0.0:' in address:  # Listening on all interfaces
                                port = address.split(':')[-1]
                                
                                # Check for potentially risky services
                                risky_ports = {
                                    '21': 'FTP',
                                    '23': 'Telnet',
                                    '25': 'SMTP',
                                    '53': 'DNS',
                                    '80': 'HTTP',
                                    '110': 'POP3',
                                    '143': 'IMAP',
                                    '993': 'IMAPS',
                                    '995': 'POP3S'
                                }
                                
                                if port in risky_ports:
                                    self.vulnerabilities.append({
                                        'type': 'Network Service Exposure',
                                        'severity': 'Medium',
                                        'port': port,
                                        'service': risky_ports[port],
                                        'address': address,
                                        'description': f"{risky_ports[port]} service exposed on all interfaces",
                                        'recommendation': 'Restrict service to specific interfaces if not needed'
                                    })
                                    
        except Exception as e:
            logging.error(f"Error scanning network services: {e}")
    
    def scan_file_permissions(self):
        """Scan for sensitive files with weak permissions"""
        logging.info("Scanning file permissions...")
        try:
            sensitive_files = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/group',
                '/etc/gshadow',
                '/etc/hosts',
                '/etc/fstab',
                '/boot/grub/grub.cfg',
                '/root/.ssh/authorized_keys'
            ]
            
            for file_path in sensitive_files:
                if os.path.exists(file_path):
                    try:
                        file_stat = os.stat(file_path)
                        
                        # Check for world-readable shadow files
                        if 'shadow' in file_path and file_stat.st_mode & stat.S_IROTH:
                            self.vulnerabilities.append({
                                'type': 'Weak File Permissions',
                                'severity': 'Critical',
                                'file_path': file_path,
                                'description': f"Shadow file {file_path} is world-readable",
                                'recommendation': 'Remove world-read permissions from shadow files'
                            })
                        
                        # Check for world-writable sensitive files
                        if file_stat.st_mode & stat.S_IWOTH:
                            self.vulnerabilities.append({
                                'type': 'Weak File Permissions',
                                'severity': 'High',
                                'file_path': file_path,
                                'description': f"Sensitive file {file_path} is world-writable",
                                'recommendation': 'Remove world-write permissions'
                            })
                            
                    except OSError as e:
                        logging.warning(f"Cannot stat {file_path}: {e}")
                        
        except Exception as e:
            logging.error(f"Error scanning file permissions: {e}")
    
    def comprehensive_scan(self):
        """Run comprehensive Linux vulnerability scan"""
        logging.info("Starting comprehensive Linux vulnerability scan...")
        
        scan_functions = [
            self.scan_kernel_vulnerabilities,
            self.scan_suid_binaries,
            self.scan_world_writable_files,
            self.scan_ssh_configuration,
            self.scan_cron_permissions,
            self.scan_sudoers_configuration,
            self.scan_package_vulnerabilities,
            self.scan_network_services,
            self.scan_file_permissions
        ]
        
        for scan_func in scan_functions:
            try:
                scan_func()
            except Exception as e:
                logging.error(f"Error in {scan_func.__name__}: {e}")
        
        return {
            'scan_type': 'linux_vulnerability_scan',
            'timestamp': datetime.now().isoformat(),
            'system_info': self.system_info,
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

def scan_linux_vulnerabilities():
    """Main function to scan Linux vulnerabilities"""
    if platform.system() != 'Linux':
        return {
            'status': 'error',
            'error': 'This scanner is designed for Linux systems only'
        }
    
    try:
        scanner = LinuxVulnerabilityScanner()
        results = scanner.comprehensive_scan()
        results['status'] = 'success'
        return results
    except Exception as e:
        logging.error(f"Linux vulnerability scan failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Test the scanner
    results = scan_linux_vulnerabilities()
    print(json.dumps(results, indent=2))
