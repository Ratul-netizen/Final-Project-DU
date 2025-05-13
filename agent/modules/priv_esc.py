import os
import sys
import logging
import platform
import subprocess
import win32security
import win32api
import win32con
import win32process
import win32service
import win32serviceutil
import win32net
import win32netcon
import ctypes
from datetime import datetime
import psutil
import re

class PrivilegeEscalation:
    def __init__(self):
        self.setup_logging()
        self.os_type = platform.system()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('priv_esc.log'),
                logging.StreamHandler()
            ]
        )
        
    def check_admin(self):
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
            
    def get_system_info(self):
        """Get system information"""
        try:
            info = {
                'os': platform.system(),
                'version': platform.version(),
                'architecture': platform.machine(),
                'hostname': platform.node(),
                'username': os.getenv('USERNAME'),
                'user_domain': os.getenv('USERDOMAIN'),
                'computer_name': os.getenv('COMPUTERNAME')
            }
            return info
        except Exception as e:
            logging.error(f"Error getting system info: {str(e)}")
            return None
            
    def check_windows_services(self):
        """Check for vulnerable Windows services"""
        try:
            vulnerable_services = []
            services = win32service.EnumServicesStatus(
                win32service.SC_MANAGER_ALL_ACCESS,
                win32service.SERVICE_WIN32
            )
            
            for service in services:
                try:
                    service_name, display_name, status, type = service
                    config = win32serviceutil.QueryServiceConfig(service_name)
                    
                    # Check for unquoted service paths
                    if ' ' in config[3] and not config[3].startswith('"'):
                        vulnerable_services.append({
                            'name': service_name,
                            'display_name': display_name,
                            'path': config[3],
                            'type': 'unquoted_path'
                        })
                        
                    # Check for weak permissions
                    try:
                        security = win32security.GetServiceSecurity(
                            service_name,
                            win32security.DACL_SECURITY_INFORMATION
                        )
                        if self.check_weak_permissions(security):
                            vulnerable_services.append({
                                'name': service_name,
                                'display_name': display_name,
                                'type': 'weak_permissions'
                            })
                    except:
                        pass
                        
                except Exception as e:
                    logging.error(f"Error checking service {service_name}: {str(e)}")
                    continue
                    
            return vulnerable_services
            
        except Exception as e:
            logging.error(f"Error checking Windows services: {str(e)}")
            return None
            
    def check_weak_permissions(self, security):
        """Check for weak permissions in security descriptor"""
        try:
            dacl = security.GetSecurityDescriptorDacl()
            if not dacl:
                return True
                
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                if ace[1] & win32con.GENERIC_ALL:
                    return True
                    
            return False
            
        except Exception as e:
            logging.error(f"Error checking permissions: {str(e)}")
            return False
            
    def check_scheduled_tasks(self):
        """Check for vulnerable scheduled tasks"""
        try:
            vulnerable_tasks = []
            tasks = subprocess.check_output(['schtasks', '/query', '/fo', 'csv']).decode()
            
            for task in tasks.split('\n'):
                try:
                    task_info = task.split(',')
                    if len(task_info) >= 2:
                        task_name = task_info[0].strip('"')
                        task_path = task_info[1].strip('"')
                        
                        # Check for unquoted paths
                        if ' ' in task_path and not task_path.startswith('"'):
                            vulnerable_tasks.append({
                                'name': task_name,
                                'path': task_path,
                                'type': 'unquoted_path'
                            })
                            
                except Exception as e:
                    logging.error(f"Error checking task {task_name}: {str(e)}")
                    continue
                    
            return vulnerable_tasks
            
        except Exception as e:
            logging.error(f"Error checking scheduled tasks: {str(e)}")
            return None
            
    def check_registry(self):
        """Check for vulnerable registry entries"""
        try:
            vulnerable_registry = []
            
            # Check autorun entries
            autorun_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
            ]
            
            for path in autorun_paths:
                try:
                    key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, path)
                    i = 0
                    while True:
                        try:
                            name, value, type = win32api.RegEnumValue(key, i)
                            if ' ' in value and not value.startswith('"'):
                                vulnerable_registry.append({
                                    'path': path,
                                    'name': name,
                                    'value': value,
                                    'type': 'unquoted_path'
                                })
                            i += 1
                        except:
                            break
                    win32api.RegCloseKey(key)
                except Exception as e:
                    logging.error(f"Error checking registry path {path}: {str(e)}")
                    continue
                    
            return vulnerable_registry
            
        except Exception as e:
            logging.error(f"Error checking registry: {str(e)}")
            return None
            
    def check_drivers(self):
        """Check for vulnerable drivers"""
        try:
            vulnerable_drivers = []
            drivers = subprocess.check_output(['driverquery', '/fo', 'csv']).decode()
            
            for driver in drivers.split('\n'):
                try:
                    driver_info = driver.split(',')
                    if len(driver_info) >= 2:
                        driver_name = driver_info[0].strip('"')
                        driver_path = driver_info[1].strip('"')
                        
                        # Check for unquoted paths
                        if ' ' in driver_path and not driver_path.startswith('"'):
                            vulnerable_drivers.append({
                                'name': driver_name,
                                'path': driver_path,
                                'type': 'unquoted_path'
                            })
                            
                except Exception as e:
                    logging.error(f"Error checking driver {driver_name}: {str(e)}")
                    continue
                    
            return vulnerable_drivers
            
        except Exception as e:
            logging.error(f"Error checking drivers: {str(e)}")
            return None
            
    def save_report(self, findings, output_file=None):
        """Save privilege escalation findings to file"""
        try:
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"priv_esc_report_{timestamp}.txt"
                
            with open(output_file, 'w') as f:
                f.write("=== Privilege Escalation Report ===\n\n")
                
                # System Information
                f.write("System Information:\n")
                system_info = self.get_system_info()
                if system_info:
                    for key, value in system_info.items():
                        f.write(f"{key}: {value}\n")
                f.write("\n")
                
                # Vulnerable Services
                f.write("Vulnerable Services:\n")
                if findings.get('services'):
                    for service in findings['services']:
                        f.write(f"Name: {service['name']}\n")
                        f.write(f"Display Name: {service['display_name']}\n")
                        f.write(f"Type: {service['type']}\n")
                        if 'path' in service:
                            f.write(f"Path: {service['path']}\n")
                        f.write("-" * 50 + "\n")
                else:
                    f.write("No vulnerable services found.\n")
                f.write("\n")
                
                # Vulnerable Scheduled Tasks
                f.write("Vulnerable Scheduled Tasks:\n")
                if findings.get('tasks'):
                    for task in findings['tasks']:
                        f.write(f"Name: {task['name']}\n")
                        f.write(f"Path: {task['path']}\n")
                        f.write(f"Type: {task['type']}\n")
                        f.write("-" * 50 + "\n")
                else:
                    f.write("No vulnerable scheduled tasks found.\n")
                f.write("\n")
                
                # Vulnerable Registry Entries
                f.write("Vulnerable Registry Entries:\n")
                if findings.get('registry'):
                    for reg in findings['registry']:
                        f.write(f"Path: {reg['path']}\n")
                        f.write(f"Name: {reg['name']}\n")
                        f.write(f"Value: {reg['value']}\n")
                        f.write(f"Type: {reg['type']}\n")
                        f.write("-" * 50 + "\n")
                else:
                    f.write("No vulnerable registry entries found.\n")
                f.write("\n")
                
                # Vulnerable Drivers
                f.write("Vulnerable Drivers:\n")
                if findings.get('drivers'):
                    for driver in findings['drivers']:
                        f.write(f"Name: {driver['name']}\n")
                        f.write(f"Path: {driver['path']}\n")
                        f.write(f"Type: {driver['type']}\n")
                        f.write("-" * 50 + "\n")
                else:
                    f.write("No vulnerable drivers found.\n")
                    
            logging.info(f"Report saved to {output_file}")
            return True
            
        except Exception as e:
            logging.error(f"Error saving report: {str(e)}")
            return False 