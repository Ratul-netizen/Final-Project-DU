import os
import sys
import platform
import subprocess
import ctypes
import psutil
import win32api
import win32con
import win32security
import win32process
import win32event
import win32service
import win32serviceutil
import win32timezone
import socket
import logging
from datetime import datetime

class Evasion:
    def __init__(self):
        self.os_type = platform.system()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('evasion.log'),
                logging.StreamHandler()
            ]
        )
        
    def check_vm(self):
        """Basic VM detection"""
        vm_indicators = [
            'VMware',
            'VBox',
            'Virtual',
            'QEMU'
        ]
        
        # Check system manufacturer
        try:
            manufacturer = subprocess.check_output('wmic computersystem get manufacturer', shell=True).decode()
            if any(indicator.lower() in manufacturer.lower() for indicator in vm_indicators):
                return True
        except:
            pass
            
        # Check running processes
        try:
            processes = [p.name().lower() for p in psutil.process_iter(['name'])]
            if any(indicator.lower() in ' '.join(processes) for indicator in vm_indicators):
                return True
        except:
            pass
            
        return False
        
    def check_debugger(self):
        """Check for debugger presence"""
        try:
            if self.os_type == 'Windows':
                return ctypes.windll.kernel32.IsDebuggerPresent() != 0
            return False
        except:
            return False
            
    def check_sandbox(self):
        """Basic sandbox detection"""
        try:
            # Check CPU cores
            if psutil.cpu_count() < 2:
                return True
                
            # Check RAM
            if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:  # 2GB
                return True
                
            # Check disk size
            if psutil.disk_usage('/').total < 20 * 1024 * 1024 * 1024:  # 20GB
                return True
                
            return False
        except:
            return False
            
    def check_av(self):
        """Basic antivirus detection"""
        av_processes = [
            'avast',
            'avg',
            'mcafee',
            'norton',
            'kaspersky',
            'defender'
        ]
        
        try:
            processes = [p.name().lower() for p in psutil.process_iter(['name'])]
            return any(av in ' '.join(processes) for av in av_processes)
        except:
            return False
            
    def check_network(self):
        """Check for network analysis tools"""
        suspicious_ports = [
            21,  # FTP
            22,  # SSH
            23,  # Telnet
            25,  # SMTP
            53,  # DNS
            80,  # HTTP
            443, # HTTPS
            3306, # MySQL
            3389  # RDP
        ]
        
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port in suspicious_ports:
                    return True
            return False
        except:
            return False
            
    def check_time(self):
        """Check for time manipulation"""
        try:
            start_time = datetime.now()
            time.sleep(1)
            end_time = datetime.now()
            
            if (end_time - start_time).total_seconds() > 2:
                return True
            return False
        except:
            return False
            
    def check_artifacts(self):
        """Check for common analysis artifacts"""
        suspicious_files = [
            'wireshark',
            'processhacker',
            'procmon',
            'fiddler',
            'burpsuite'
        ]
        
        try:
            for root, dirs, files in os.walk('C:\\Program Files'):
                for file in files:
                    if any(artifact in file.lower() for artifact in suspicious_files):
                        return True
            return False
        except:
            return False
            
    def check_all(self):
        """Run all evasion checks"""
        results = {
            'vm_detected': self.check_vm(),
            'debugger_detected': self.check_debugger(),
            'sandbox_detected': self.check_sandbox(),
            'av_detected': self.check_av(),
            'network_analysis_detected': self.check_network(),
            'time_manipulation_detected': self.check_time(),
            'analysis_artifacts_detected': self.check_artifacts()
        }
        
        return results 