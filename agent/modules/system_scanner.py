#!/usr/bin/env python3
"""
System Vulnerability Scanner Module
Provides comprehensive system vulnerability assessment capabilities
"""

import os
import sys
import platform
import subprocess
import logging
import json
import re
import hashlib
from datetime import datetime
import psutil
import winreg
import ctypes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SystemScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.system_info = {}
        self.scan_results = {}
        self.risk_score = 0
        
    def check_os_vulnerabilities(self):
        """
        Check OS-specific vulnerabilities
        
        Returns:
            dict: OS vulnerability scan results
        """
        logging.info("Checking OS vulnerabilities")
        vulnerabilities = []
        
        try:
            os_type = platform.system()
            if os_type == "Windows":
                vulnerabilities.extend(self.check_windows_vulnerabilities())
            elif os_type == "Linux":
                vulnerabilities.extend(self.check_linux_vulnerabilities())
            else:
                vulnerabilities.append({
                    'type': 'UNSUPPORTED_OS',
                    'severity': 'Medium',
                    'description': f'Unsupported operating system: {os_type}',
                    'details': f'OS: {os_type}, Version: {platform.version()}'
                })
        except Exception as e:
            logging.error(f"Error checking OS vulnerabilities: {str(e)}")
            vulnerabilities.append({
                'type': 'OS_SCAN_ERROR',
                'severity': 'Info',
                'description': f'Error scanning OS vulnerabilities: {str(e)}',
                'details': str(e)
            })
        
        return {
            'status': 'success',
            'os_type': platform.system(),
            'vulnerabilities': vulnerabilities,
            'timestamp': datetime.now().isoformat()
        }
    
    def check_windows_vulnerabilities(self):
        """Check Windows-specific vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check Windows version
            win_version = platform.version()
            vulnerabilities.extend(self.check_windows_version_vulnerabilities(win_version))
            
            # Check for missing updates
            vulnerabilities.extend(self.check_windows_updates())
            
            # Check registry vulnerabilities
            vulnerabilities.extend(self.check_registry_vulnerabilities())
            
            # Check service vulnerabilities
            vulnerabilities.extend(self.check_service_vulnerabilities())
            
            # Check file system vulnerabilities
            vulnerabilities.extend(self.check_file_system_vulnerabilities())
            
            # Check user account vulnerabilities
            vulnerabilities.extend(self.check_user_account_vulnerabilities())
            
        except Exception as e:
            logging.error(f"Error checking Windows vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_linux_vulnerabilities(self):
        """Check Linux-specific vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check kernel version
            vulnerabilities.extend(self.check_kernel_vulnerabilities())
            
            # Check for missing updates
            vulnerabilities.extend(self.check_linux_updates())
            
            # Check file permissions
            vulnerabilities.extend(self.check_linux_file_permissions())
            
            # Check user account vulnerabilities
            vulnerabilities.extend(self.check_linux_user_vulnerabilities())
            
            # Check service vulnerabilities
            vulnerabilities.extend(self.check_linux_service_vulnerabilities())
            
        except Exception as e:
            logging.error(f"Error checking Linux vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_windows_version_vulnerabilities(self, version):
        """Check for known Windows version vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for end-of-life Windows versions
            eol_versions = [
                'Windows 7', 'Windows 8', 'Windows 8.1', 'Windows Server 2008',
                'Windows Server 2012', 'Windows Server 2012 R2'
            ]
            
            for eol_version in eol_versions:
                if eol_version.lower() in version.lower():
                    vulnerabilities.append({
                        'type': 'EOL_WINDOWS_VERSION',
                        'severity': 'Critical',
                        'description': f'Windows version {eol_version} is end-of-life',
                        'details': f'Version: {version}',
                        'recommendation': 'Upgrade to a supported Windows version'
                    })
                    break
            
            # Check for specific version vulnerabilities
            if 'Windows 10' in version and '1903' in version:
                vulnerabilities.append({
                    'type': 'WINDOWS_10_1903_VULNERABILITY',
                    'severity': 'High',
                    'description': 'Windows 10 version 1903 has known vulnerabilities',
                    'details': f'Version: {version}',
                    'recommendation': 'Apply latest security updates'
                })
                
        except Exception as e:
            logging.debug(f"Error checking Windows version vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_windows_updates(self):
        """Check for missing Windows updates"""
        vulnerabilities = []
        
        try:
            # Check Windows Update status
            try:
                result = subprocess.run(
                    ['wmic', 'qfe', 'list', 'brief', '/format:csv'],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    # Parse update information
                    lines = result.stdout.strip().split('\n')
                    if len(lines) < 2:
                        vulnerabilities.append({
                            'type': 'WINDOWS_UPDATES_UNKNOWN',
                            'severity': 'Medium',
                            'description': 'Unable to determine Windows update status',
                            'details': 'Windows Update status check failed',
                            'recommendation': 'Manually check for Windows updates'
                        })
                else:
                    vulnerabilities.append({
                        'type': 'WINDOWS_UPDATES_CHECK_FAILED',
                        'severity': 'Medium',
                        'description': 'Failed to check Windows updates',
                        'details': result.stderr,
                        'recommendation': 'Manually check for Windows updates'
                    })
                    
            except subprocess.TimeoutExpired:
                vulnerabilities.append({
                    'type': 'WINDOWS_UPDATES_TIMEOUT',
                    'severity': 'Medium',
                    'description': 'Windows update check timed out',
                    'details': 'Update check took too long to complete',
                    'recommendation': 'Manually check for Windows updates'
                })
                
        except Exception as e:
            logging.debug(f"Error checking Windows updates: {str(e)}")
        
        return vulnerabilities
    
    def check_registry_vulnerabilities(self):
        """Check for registry-based vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for AlwaysInstallElevated
            try:
                hkcu = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                    r"SOFTWARE\Policies\Microsoft\Windows\Installer")
                hklm = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Policies\Microsoft\Windows\Installer")
                
                if (winreg.QueryValueEx(hkcu, "AlwaysInstallElevated")[0] == 1 and 
                    winreg.QueryValueEx(hklm, "AlwaysInstallElevated")[0] == 1):
                    vulnerabilities.append({
                        'type': 'ALWAYS_INSTALL_ELEVATED',
                        'severity': 'High',
                        'description': 'AlwaysInstallElevated policy enabled',
                        'details': 'MSI files can be installed with elevated privileges',
                        'recommendation': 'Disable AlwaysInstallElevated policy'
                    })
                    
            except FileNotFoundError:
                # Registry keys don't exist, which is good
                pass
            except Exception as e:
                logging.debug(f"Error checking AlwaysInstallElevated: {str(e)}")
            
            # Check for weak password policies
            try:
                hklm = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters")
                min_pass_len = winreg.QueryValueEx(hklm, "MinimumPasswordLength")[0]
                
                if min_pass_len < 8:
                    vulnerabilities.append({
                        'type': 'WEAK_PASSWORD_POLICY',
                        'severity': 'Medium',
                        'description': f'Weak password policy: minimum length is {min_pass_len}',
                        'details': f'Minimum password length: {min_pass_len}',
                        'recommendation': 'Set minimum password length to at least 8 characters'
                    })
                    
            except FileNotFoundError:
                pass
            except Exception as e:
                logging.debug(f"Error checking password policy: {str(e)}")
                
        except Exception as e:
            logging.debug(f"Error checking registry vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_service_vulnerabilities(self):
        """Check for service-based vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for unquoted service paths
            try:
                import wmi
                c = wmi.WMI()
                for service in c.Win32_Service():
                    if (service.PathName and ' ' in service.PathName and 
                        not service.PathName.startswith('"')):
                        vulnerabilities.append({
                            'type': 'UNQUOTED_SERVICE_PATH',
                            'severity': 'Medium',
                            'description': f'Unquoted service path: {service.Name}',
                            'details': f'Path: {service.PathName}, Start Mode: {service.StartMode}',
                            'recommendation': 'Quote the service path or move executable to path without spaces'
                        })
            except ImportError:
                logging.debug("WMI module not available")
            except Exception as e:
                logging.debug(f"Error checking service vulnerabilities: {str(e)}")
                
        except Exception as e:
            logging.debug(f"Error checking service vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_file_system_vulnerabilities(self):
        """Check for file system vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for world-writable directories
            sensitive_dirs = [
                r'C:\Windows\System32',
                r'C:\Windows\SysWOW64',
                r'C:\Program Files',
                r'C:\Program Files (x86)'
            ]
            
            for directory in sensitive_dirs:
                if os.path.exists(directory):
                    try:
                        # Check if directory is writable by current user
                        test_file = os.path.join(directory, 'test_write.tmp')
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.remove(test_file)
                        
                        vulnerabilities.append({
                            'type': 'WORLD_WRITABLE_DIRECTORY',
                            'severity': 'High',
                            'description': f'World-writable directory: {directory}',
                            'details': f'Directory {directory} is writable by current user',
                            'recommendation': 'Restrict write permissions on sensitive directories'
                        })
                    except (PermissionError, OSError):
                        # Directory is not writable, which is good
                        pass
                        
        except Exception as e:
            logging.debug(f"Error checking file system vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_user_account_vulnerabilities(self):
        """Check for user account vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for accounts with no password expiration
            try:
                result = subprocess.run(
                    ['wmic', 'useraccount', 'get', 'name,passwordexpires'],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                username = parts[0]
                                password_expires = parts[1]
                                
                                if password_expires.lower() == 'false':
                                    vulnerabilities.append({
                                        'type': 'NO_PASSWORD_EXPIRATION',
                                        'severity': 'Medium',
                                        'description': f'User account {username} has no password expiration',
                                        'details': f'Username: {username}',
                                        'recommendation': 'Enable password expiration for user accounts'
                                    })
                                    
            except subprocess.TimeoutExpired:
                logging.debug("User account check timed out")
            except Exception as e:
                logging.debug(f"Error checking user accounts: {str(e)}")
                
        except Exception as e:
            logging.debug(f"Error checking user account vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_kernel_vulnerabilities(self):
        """Check for kernel vulnerabilities on Linux"""
        vulnerabilities = []
        
        try:
            # Get kernel version
            kernel_version = platform.release()
            
            # Check for known vulnerable kernel versions
            vulnerable_kernels = [
                '2.6.32', '3.10.0', '4.4.0', '4.9.0', '4.14.0', '4.19.0'
            ]
            
            for vuln_kernel in vulnerable_kernels:
                if kernel_version.startswith(vuln_kernel):
                    vulnerabilities.append({
                        'type': 'VULNERABLE_KERNEL_VERSION',
                        'severity': 'High',
                        'description': f'Potentially vulnerable kernel version: {kernel_version}',
                        'details': f'Kernel version: {kernel_version}',
                        'recommendation': 'Update kernel to latest stable version'
                    })
                    break
                    
        except Exception as e:
            logging.debug(f"Error checking kernel vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_linux_updates(self):
        """Check for missing Linux updates"""
        vulnerabilities = []
        
        try:
            # Check for available updates
            if os.path.exists('/etc/debian_version'):
                # Debian/Ubuntu
                try:
                    result = subprocess.run(
                        ['apt-get', 'update'],
                        capture_output=True, text=True, timeout=60
                    )
                    
                    if result.returncode == 0:
                        result = subprocess.run(
                            ['apt-get', 'upgrade', '--dry-run'],
                            capture_output=True, text=True, timeout=60
                        )
                        
                        if result.returncode == 0 and 'upgraded' in result.stdout:
                            vulnerabilities.append({
                                'type': 'LINUX_UPDATES_AVAILABLE',
                                'severity': 'Medium',
                                'description': 'Linux updates are available',
                                'details': 'System has pending security updates',
                                'recommendation': 'Run apt-get upgrade to install updates'
                            })
                            
                except subprocess.TimeoutExpired:
                    logging.debug("Linux update check timed out")
                    
            elif os.path.exists('/etc/redhat-release'):
                # RHEL/CentOS
                try:
                    result = subprocess.run(
                        ['yum', 'check-update'],
                        capture_output=True, text=True, timeout=60
                    )
                    
                    if result.returncode == 100:  # Updates available
                        vulnerabilities.append({
                            'type': 'LINUX_UPDATES_AVAILABLE',
                            'severity': 'Medium',
                            'description': 'Linux updates are available',
                            'details': 'System has pending security updates',
                            'recommendation': 'Run yum update to install updates'
                        })
                        
                except subprocess.TimeoutExpired:
                    logging.debug("Linux update check timed out")
                    
        except Exception as e:
            logging.debug(f"Error checking Linux updates: {str(e)}")
        
        return vulnerabilities
    
    def check_linux_file_permissions(self):
        """Check for file permission vulnerabilities on Linux"""
        vulnerabilities = []
        
        try:
            # Check for world-writable files
            sensitive_files = [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                '/etc/ssh/sshd_config', '/etc/hosts'
            ]
            
            for file_path in sensitive_files:
                if os.path.exists(file_path):
                    try:
                        stat_info = os.stat(file_path)
                        mode = stat_info.st_mode
                        
                        # Check if world writable
                        if mode & 0o002:
                            vulnerabilities.append({
                                'type': 'WORLD_WRITABLE_FILE',
                                'severity': 'Critical',
                                'description': f'World-writable sensitive file: {file_path}',
                                'details': f'File {file_path} is writable by all users',
                                'recommendation': f'Restrict write permissions on {file_path}'
                            })
                            
                    except Exception as e:
                        logging.debug(f"Error checking file {file_path}: {str(e)}")
                        
        except Exception as e:
            logging.debug(f"Error checking Linux file permissions: {str(e)}")
        
        return vulnerabilities
    
    def check_linux_user_vulnerabilities(self):
        """Check for user account vulnerabilities on Linux"""
        vulnerabilities = []
        
        try:
            # Check for users with UID 0 (root equivalent)
            try:
                result = subprocess.run(
                    ['awk', '-F:', '$3 == 0 {print $1}', '/etc/passwd'],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    root_users = result.stdout.strip().split('\n')
                    if len(root_users) > 1 or (len(root_users) == 1 and root_users[0] != 'root'):
                        vulnerabilities.append({
                            'type': 'MULTIPLE_ROOT_USERS',
                            'severity': 'High',
                            'description': 'Multiple users with UID 0 found',
                            'details': f'Users with UID 0: {", ".join(root_users)}',
                            'recommendation': 'Remove unnecessary root-equivalent users'
                        })
                        
            except subprocess.TimeoutExpired:
                logging.debug("User check timed out")
            except Exception as e:
                logging.debug(f"Error checking users: {str(e)}")
                
        except Exception as e:
            logging.debug(f"Error checking Linux user vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_linux_service_vulnerabilities(self):
        """Check for service vulnerabilities on Linux"""
        vulnerabilities = []
        
        try:
            # Check for running services with known vulnerabilities
            try:
                result = subprocess.run(
                    ['systemctl', 'list-units', '--type=service', '--state=running'],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    services = result.stdout.strip().split('\n')
                    for service in services:
                        if 'sshd' in service and 'running' in service:
                            # Check SSH configuration
                            vulnerabilities.extend(self.check_ssh_configuration())
                        elif 'apache2' in service or 'httpd' in service:
                            # Check web server configuration
                            vulnerabilities.extend(self.check_web_server_configuration())
                            
            except subprocess.TimeoutExpired:
                logging.debug("Service check timed out")
            except Exception as e:
                logging.debug(f"Error checking services: {str(e)}")
                
        except Exception as e:
            logging.debug(f"Error checking Linux service vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_ssh_configuration(self):
        """Check SSH configuration for vulnerabilities"""
        vulnerabilities = []
        
        try:
            ssh_config_file = '/etc/ssh/sshd_config'
            if os.path.exists(ssh_config_file):
                with open(ssh_config_file, 'r') as f:
                    config_content = f.read()
                
                # Check for weak configurations
                if 'PermitRootLogin yes' in config_content:
                    vulnerabilities.append({
                        'type': 'SSH_ROOT_LOGIN_ENABLED',
                        'severity': 'High',
                        'description': 'SSH root login is enabled',
                        'details': 'PermitRootLogin is set to yes in sshd_config',
                        'recommendation': 'Disable root login via SSH'
                    })
                
                if 'PasswordAuthentication yes' in config_content:
                    vulnerabilities.append({
                        'type': 'SSH_PASSWORD_AUTH_ENABLED',
                        'severity': 'Medium',
                        'description': 'SSH password authentication is enabled',
                        'details': 'PasswordAuthentication is set to yes in sshd_config',
                        'recommendation': 'Use key-based authentication instead of passwords'
                    })
                    
        except Exception as e:
            logging.debug(f"Error checking SSH configuration: {str(e)}")
        
        return vulnerabilities
    
    def check_web_server_configuration(self):
        """Check web server configuration for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check Apache configuration
            apache_configs = ['/etc/apache2/apache2.conf', '/etc/httpd/conf/httpd.conf']
            
            for config_file in apache_configs:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config_content = f.read()
                    
                    # Check for directory listing
                    if 'Options Indexes' in config_content:
                        vulnerabilities.append({
                            'type': 'APACHE_DIRECTORY_LISTING',
                            'severity': 'Medium',
                            'description': 'Apache directory listing is enabled',
                            'details': f'Options Indexes found in {config_file}',
                            'recommendation': 'Disable directory listing in Apache configuration'
                        })
                        
        except Exception as e:
            logging.debug(f"Error checking web server configuration: {str(e)}")
        
        return vulnerabilities
    
    def comprehensive_system_scan(self):
        """
        Perform comprehensive system vulnerability scan
        
        Returns:
            dict: Comprehensive system scan results
        """
        logging.info("Starting comprehensive system vulnerability scan")
        
        # Step 1: OS vulnerability scan
        os_results = self.check_os_vulnerabilities()
        
        # Step 2: System information gathering
        system_info = self.gather_system_info()
        
        # Step 3: Calculate risk score
        risk_score = self.calculate_risk_score(os_results['vulnerabilities'])
        
        # Compile results
        comprehensive_results = {
            'status': 'success',
            'scan_type': 'comprehensive_system',
            'timestamp': datetime.now().isoformat(),
            'system_info': system_info,
            'os_vulnerabilities': os_results,
            'summary': {
                'total_vulnerabilities': len(os_results['vulnerabilities']),
                'critical_vulnerabilities': len([v for v in os_results['vulnerabilities'] if v.get('severity') == 'Critical']),
                'high_vulnerabilities': len([v for v in os_results['vulnerabilities'] if v.get('severity') == 'High']),
                'medium_vulnerabilities': len([v for v in os_results['vulnerabilities'] if v.get('severity') == 'Medium']),
                'low_vulnerabilities': len([v for v in os_results['vulnerabilities'] if v.get('severity') == 'Low']),
                'risk_score': risk_score
            }
        }
        
        self.scan_results = comprehensive_results
        return comprehensive_results
    
    def gather_system_info(self):
        """Gather comprehensive system information"""
        try:
            system_info = {
                'os_type': platform.system(),
                'os_version': platform.version(),
                'os_release': platform.release(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'hostname': platform.node(),
                'python_version': sys.version,
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/').total if os.path.exists('/') else psutil.disk_usage('C:\\').total,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'current_user': os.getlogin() if hasattr(os, 'getlogin') else 'Unknown'
            }
            
            return system_info
        except Exception as e:
            logging.error(f"Error gathering system info: {str(e)}")
            return {'error': str(e)}
    
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
def scan_system():
    """Convenience function for system scanning"""
    scanner = SystemScanner()
    return scanner.comprehensive_system_scan()

def check_os_vulnerabilities():
    """Convenience function for OS vulnerability checking"""
    scanner = SystemScanner()
    return scanner.check_os_vulnerabilities()
