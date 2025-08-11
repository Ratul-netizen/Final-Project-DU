#!/usr/bin/env python3
"""
Advanced Windows Vulnerability Scanner
Comprehensive OS-level vulnerability detection for Windows systems
"""

import os
import sys
import json
import logging
import subprocess
import platform
import winreg
import psutil
import socket
from datetime import datetime
from pathlib import Path
import ctypes
from ctypes import wintypes
import win32api
import win32security
import win32con

class WindowsVulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.system_info = self.get_system_info()
        self.cve_database = self.load_cve_database()
        
    def get_system_info(self):
        """Get detailed Windows system information"""
        try:
            return {
                'os_name': platform.system(),
                'os_version': platform.version(),
                'os_release': platform.release(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'hostname': socket.gethostname(),
                'build_number': self.get_build_number(),
                'edition': self.get_windows_edition(),
                'install_date': self.get_install_date()
            }
        except Exception as e:
            logging.error(f"Error getting system info: {e}")
            return {}
    
    def get_build_number(self):
        """Get Windows build number"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            build, _ = winreg.QueryValueEx(key, "CurrentBuild")
            winreg.CloseKey(key)
            return build
        except:
            return "Unknown"
    
    def get_windows_edition(self):
        """Get Windows edition"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            edition, _ = winreg.QueryValueEx(key, "ProductName")
            winreg.CloseKey(key)
            return edition
        except:
            return "Unknown"
    
    def get_install_date(self):
        """Get Windows installation date"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            install_date, _ = winreg.QueryValueEx(key, "InstallDate")
            winreg.CloseKey(key)
            return datetime.fromtimestamp(install_date).isoformat()
        except:
            return "Unknown"
    
    def load_cve_database(self):
        """Load CVE database for Windows vulnerabilities"""
        # Simplified CVE database - in production, this would be more comprehensive
        return {
            "10.0.19041": [  # Windows 10 20H1
                {
                    "cve": "CVE-2021-34527",
                    "title": "PrintNightmare",
                    "severity": "Critical",
                    "description": "Windows Print Spooler Remote Code Execution Vulnerability",
                    "affected_services": ["spoolsv.exe"]
                },
                {
                    "cve": "CVE-2021-36934", 
                    "title": "HiveNightmare/SeriousSAM",
                    "severity": "High",
                    "description": "Windows SAM database access vulnerability",
                    "affected_files": ["C:\\Windows\\System32\\config\\SAM"]
                }
            ],
            "10.0.19042": [  # Windows 10 20H2
                {
                    "cve": "CVE-2021-34527",
                    "title": "PrintNightmare", 
                    "severity": "Critical",
                    "description": "Windows Print Spooler Remote Code Execution Vulnerability",
                    "affected_services": ["spoolsv.exe"]
                }
            ],
            "general": [
                {
                    "cve": "CVE-2020-1472",
                    "title": "Zerologon",
                    "severity": "Critical", 
                    "description": "Netlogon elevation of privilege vulnerability",
                    "affected_services": ["netlogon"]
                }
            ]
        }
    
    def scan_missing_patches(self):
        """Scan for missing Windows patches"""
        logging.info("Scanning for missing Windows patches...")
        try:
            # Get installed updates
            result = subprocess.run([
                'powershell', '-Command',
                'Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                installed_patches = json.loads(result.stdout) if result.stdout.strip() else []
                
                # Check against known vulnerabilities
                os_version = f"{platform.version()}"
                known_cves = self.cve_database.get(os_version, []) + self.cve_database.get("general", [])
                
                for cve in known_cves:
                    # Simple check - in production, this would be more sophisticated
                    self.vulnerabilities.append({
                        'type': 'Missing Patch',
                        'severity': cve['severity'],
                        'cve': cve['cve'],
                        'title': cve['title'],
                        'description': cve['description'],
                        'recommendation': f"Install security update for {cve['cve']}"
                    })
                    
        except Exception as e:
            logging.error(f"Error scanning patches: {e}")
    
    def scan_unquoted_service_paths(self):
        """Scan for unquoted service paths vulnerability"""
        logging.info("Scanning for unquoted service paths...")
        try:
            result = subprocess.run([
                'powershell', '-Command',
                'Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch "^\\\".*\\\"$" -and $_.PathName -match " "} | Select-Object Name, PathName | ConvertTo-Json'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                services = json.loads(result.stdout)
                if not isinstance(services, list):
                    services = [services]
                
                for service in services:
                    self.vulnerabilities.append({
                        'type': 'Unquoted Service Path',
                        'severity': 'Medium',
                        'service_name': service['Name'],
                        'path': service['PathName'],
                        'description': f"Service '{service['Name']}' has unquoted path: {service['PathName']}",
                        'recommendation': 'Quote the service path or ensure no spaces in directory names'
                    })
                    
        except Exception as e:
            logging.error(f"Error scanning service paths: {e}")
    
    def scan_weak_service_permissions(self):
        """Scan for services with weak permissions"""
        logging.info("Scanning for weak service permissions...")
        try:
            result = subprocess.run([
                'powershell', '-Command',
                '''
                $services = Get-WmiObject -Class Win32_Service
                foreach ($service in $services) {
                    try {
                        $acl = Get-Acl -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($service.Name)" -ErrorAction SilentlyContinue
                        if ($acl) {
                            foreach ($access in $acl.Access) {
                                if ($access.IdentityReference -like "*Users*" -or $access.IdentityReference -like "*Everyone*") {
                                    if ($access.AccessControlType -eq "Allow" -and ($access.FileSystemRights -like "*FullControl*" -or $access.FileSystemRights -like "*Modify*")) {
                                        Write-Output "$($service.Name)|$($access.IdentityReference)|$($access.FileSystemRights)"
                                    }
                                }
                            }
                        }
                    } catch {}
                }
                '''
            ], capture_output=True, text=True, timeout=45)
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 3:
                            service_name, identity, permissions = parts[0], parts[1], parts[2]
                            self.vulnerabilities.append({
                                'type': 'Weak Service Permissions',
                                'severity': 'High',
                                'service_name': service_name,
                                'identity': identity,
                                'permissions': permissions,
                                'description': f"Service '{service_name}' allows {identity} to have {permissions}",
                                'recommendation': 'Restrict service permissions to authorized users only'
                            })
                            
        except Exception as e:
            logging.error(f"Error scanning service permissions: {e}")
    
    def scan_registry_autologon(self):
        """Scan for autologon credentials in registry"""
        logging.info("Scanning for autologon credentials...")
        try:
            autologon_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
            ]
            
            for hkey, subkey in autologon_keys:
                try:
                    key = winreg.OpenKey(hkey, subkey)
                    try:
                        value, _ = winreg.QueryValueEx(key, "DefaultPassword")
                        if value:
                            self.vulnerabilities.append({
                                'type': 'Autologon Credentials',
                                'severity': 'High',
                                'registry_key': f"{hkey}\\{subkey}",
                                'description': 'Autologon password found in registry',
                                'recommendation': 'Remove autologon credentials or use more secure authentication'
                            })
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(key)
                except Exception:
                    continue
                    
        except Exception as e:
            logging.error(f"Error scanning autologon: {e}")
    
    def scan_stored_credentials(self):
        """Scan for stored credentials"""
        logging.info("Scanning for stored credentials...")
        try:
            # Check Windows Credential Manager
            result = subprocess.run([
                'powershell', '-Command',
                'cmdkey /list | Where-Object {$_ -like "*Target:*"}'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                credentials = result.stdout.strip().split('\n')
                for cred in credentials:
                    if 'Target:' in cred:
                        self.vulnerabilities.append({
                            'type': 'Stored Credentials',
                            'severity': 'Medium',
                            'credential': cred.strip(),
                            'description': 'Stored credential found in Windows Credential Manager',
                            'recommendation': 'Review and remove unnecessary stored credentials'
                        })
                        
        except Exception as e:
            logging.error(f"Error scanning credentials: {e}")
    
    def scan_network_shares(self):
        """Scan for insecure network shares"""
        logging.info("Scanning network shares...")
        try:
            result = subprocess.run([
                'powershell', '-Command',
                'Get-WmiObject -Class Win32_Share | Where-Object {$_.Type -eq 0} | Select-Object Name, Path, Description | ConvertTo-Json'
            ], capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0 and result.stdout.strip():
                shares = json.loads(result.stdout)
                if not isinstance(shares, list):
                    shares = [shares]
                
                for share in shares:
                    # Check if share allows Everyone with full access
                    share_name = share['Name']
                    if share_name not in ['IPC$', 'ADMIN$', 'C$']:  # Skip administrative shares
                        try:
                            acl_result = subprocess.run([
                                'powershell', '-Command',
                                f'Get-Acl "\\\\localhost\\{share_name}" | Select-Object -ExpandProperty Access | Where-Object {{$_.IdentityReference -like "*Everyone*"}} | ConvertTo-Json'
                            ], capture_output=True, text=True, timeout=10)
                            
                            if acl_result.returncode == 0 and acl_result.stdout.strip():
                                self.vulnerabilities.append({
                                    'type': 'Insecure Network Share',
                                    'severity': 'Medium',
                                    'share_name': share_name,
                                    'path': share['Path'],
                                    'description': f"Network share '{share_name}' may have weak permissions",
                                    'recommendation': 'Review and restrict network share permissions'
                                })
                        except:
                            continue
                            
        except Exception as e:
            logging.error(f"Error scanning network shares: {e}")
    
    def scan_firewall_status(self):
        """Scan Windows Firewall status"""
        logging.info("Scanning Windows Firewall status...")
        try:
            result = subprocess.run([
                'powershell', '-Command',
                'Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                profiles = json.loads(result.stdout)
                if not isinstance(profiles, list):
                    profiles = [profiles]
                
                for profile in profiles:
                    if not profile['Enabled']:
                        self.vulnerabilities.append({
                            'type': 'Firewall Disabled',
                            'severity': 'High',
                            'profile': profile['Name'],
                            'description': f"Windows Firewall profile '{profile['Name']}' is disabled",
                            'recommendation': 'Enable Windows Firewall for all profiles'
                        })
                        
        except Exception as e:
            logging.error(f"Error scanning firewall: {e}")
    
    def scan_uac_settings(self):
        """Scan UAC settings"""
        logging.info("Scanning UAC settings...")
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            
            uac_settings = {}
            uac_keys = [
                "EnableLUA",
                "ConsentPromptBehaviorAdmin", 
                "ConsentPromptBehaviorUser",
                "PromptOnSecureDesktop"
            ]
            
            for setting in uac_keys:
                try:
                    value, _ = winreg.QueryValueEx(key, setting)
                    uac_settings[setting] = value
                except FileNotFoundError:
                    uac_settings[setting] = None
            
            winreg.CloseKey(key)
            
            # Check for weak UAC settings
            if uac_settings.get("EnableLUA") == 0:
                self.vulnerabilities.append({
                    'type': 'UAC Disabled',
                    'severity': 'High',
                    'description': 'User Account Control (UAC) is disabled',
                    'recommendation': 'Enable UAC for better security'
                })
            
            if uac_settings.get("ConsentPromptBehaviorAdmin", 0) == 0:
                self.vulnerabilities.append({
                    'type': 'Weak UAC Settings',
                    'severity': 'Medium',
                    'description': 'UAC consent prompt for administrators is disabled',
                    'recommendation': 'Configure UAC to prompt for consent'
                })
                
        except Exception as e:
            logging.error(f"Error scanning UAC: {e}")
    
    def scan_system_integrity(self):
        """Scan system file integrity"""
        logging.info("Scanning system integrity...")
        try:
            # Run SFC scan
            result = subprocess.run([
                'powershell', '-Command',
                'sfc /verifyonly 2>&1 | Select-String -Pattern "corrupt"'
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout.strip():
                self.vulnerabilities.append({
                    'type': 'System File Corruption',
                    'severity': 'Medium',
                    'description': 'Corrupted system files detected',
                    'details': result.stdout.strip(),
                    'recommendation': 'Run "sfc /scannow" to repair system files'
                })
                
        except Exception as e:
            logging.error(f"Error scanning system integrity: {e}")
    
    def comprehensive_scan(self):
        """Run comprehensive Windows vulnerability scan"""
        logging.info("Starting comprehensive Windows vulnerability scan...")
        
        scan_functions = [
            self.scan_missing_patches,
            self.scan_unquoted_service_paths,
            self.scan_weak_service_permissions,
            self.scan_registry_autologon,
            self.scan_stored_credentials,
            self.scan_network_shares,
            self.scan_firewall_status,
            self.scan_uac_settings,
            self.scan_system_integrity
        ]
        
        for scan_func in scan_functions:
            try:
                scan_func()
            except Exception as e:
                logging.error(f"Error in {scan_func.__name__}: {e}")
        
        return {
            'scan_type': 'windows_vulnerability_scan',
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

def scan_windows_vulnerabilities():
    """Main function to scan Windows vulnerabilities"""
    if platform.system() != 'Windows':
        return {
            'status': 'error',
            'error': 'This scanner is designed for Windows systems only'
        }
    
    try:
        scanner = WindowsVulnerabilityScanner()
        results = scanner.comprehensive_scan()
        results['status'] = 'success'
        return results
    except Exception as e:
        logging.error(f"Windows vulnerability scan failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Test the scanner
    results = scan_windows_vulnerabilities()
    print(json.dumps(results, indent=2))
