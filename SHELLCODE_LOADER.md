# Shellcode Loader Generator

This module adds advanced shellcode loader generation capabilities to the C2 Framework. It allows you to:

1. Generate AES-encrypted loaders for Windows
2. Automatically compile them to executables using MinGW
3. Deploy loaders directly to connected agents

A secure shellcode execution framework with multiple AV/EDR evasion techniques.

## 🚀 Prerequisites

### Windows Developers
No special requirements needed for generating the loader source code. To compile .exe files, you need:

- MinGW-w64 (for cross-compilation)
- Install with: `choco install mingw` or download from [MinGW-w64 website](https://sourceforge.net/projects/mingw-w64/)

### Linux Developers
MinGW is required for cross-compiling Windows executables:

```bash
# Debian/Ubuntu
sudo apt-get install mingw-w64

# Fedora
sudo dnf install mingw64-gcc-c++

# Arch Linux
sudo pacman -S mingw-w64-gcc
```

## 💻 Usage

### 1. Generate Shellcode

Use the web interface at `http://SERVER_IP:5001/` to generate a shellcode with your desired:
- Type (reverse shell, bind shell, command execution)
- Platform (Windows, Linux, macOS)
- Encoding (Base64, Hex, ASCII)

### 2. Generate AES-Encrypted EXE Loader

After generating shellcode:

1. Click the "🔐 Generate AES-Encrypted EXE" button
2. Wait for the loader to be compiled (requires MinGW)
3. The loader will automatically download to your computer

### 3. Deploy to Agent (Optional)

After generating the loader:

1. Enter the target Agent ID in the deployment options panel
2. Click "📡 Deploy Loader to Agent"
3. The agent will download and execute the loader on its next check-in

## 🔧 Technical Details

### Security Features

- **AES-128-CBC Encryption**: Shellcode is encrypted with AES-128 in CBC mode
- **PKCS#7 Padding**: Proper padding for AES encryption blocks
- **No Plaintext Shellcode**: The shellcode is never stored in plaintext in the executable
- **Memory Protection**: Allocates memory with appropriate permissions

### Compilation Process

1. The loader source code is generated from a template
2. The shellcode is encrypted with AES-128-CBC
3. MinGW cross-compiles the source into a Windows executable
4. The executable is served for download via Flask

### Deployment Process

1. The agent receives a task with the URL to download the loader
2. The agent downloads the executable with randomized delays
3. The executable is executed with low visibility (no console window)
4. The downloaded file is deleted after execution

## 🧪 API Endpoints

### `/generate_loader_exe` (POST)

Generates an executable loader from shellcode:

```json
{
  "shellcode": "base64_encoded_shellcode"
}
```

Returns: The compiled executable as a downloadable file.

### `/api/tasks` (POST)

Creates a task for an agent to download and execute the loader:

```json
{
  "agent_id": "agent_identifier",
  "loader_url": "url_to_download_loader"
}
```

Returns:
```json
{
  "success": true,
  "task_id": "task_identifier",
  "message": "Task created for agent..."
}
```

## ⚠️ Security Considerations

- **Anti-Virus Detection**: The generated loaders may be detected by anti-virus software
- **Code Signing**: The loaders are not code-signed
- **Memory Scanning**: The shellcode may be detected by memory scanning tools
- **Network Traffic**: The loader download can be detected by network monitoring tools

For operational security, consider:
- Using HTTPS for all communications
- Adding obfuscation techniques to the loader template
- Implementing process injection to run in a different process
- Adding anti-debugging and anti-sandbox features

## Advanced Anti-Detection Techniques Implemented

The shellcode loaders have been enhanced with several sophisticated anti-detection techniques to make them more resistant to antivirus, EDR solutions, and security analysis:

### 1. AMSI and ETW Bypass

- **AMSI Patching**: Patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN
- **ETW Disabling**: Patches EtwEventWrite to prevent event logging
- **Memory Scanning Avoidance**: Employs techniques to avoid Windows Defender memory scanning

### 2. Advanced Process Injection

- **Explorer.exe Injection**: Injects shellcode into explorer.exe (a trusted Windows process)
- **DLL Hollowing**: Replaces legitimate DLL functions with shellcode (AV evasion technique)
- **Multi-method Execution**: Falls back through multiple execution techniques if one fails
- **PPID Spoofing**: Makes the loader appear to be a child of a trusted process

### 3. Memory Protection Enhancements

- **Direct Syscalls**: Uses direct NT syscalls to avoid EDR API hooks
- **Heap Allocation**: Uses heap allocation instead of VirtualAlloc when possible
- **Memory Protection Flow**: Employs a proper sequence of memory operations to avoid detection signatures
- **Two-stage Memory Allocation**: Uses a temporary buffer before final shellcode execution

### 4. API Function Obfuscation

- **String Encryption**: All API and DLL strings are XOR-encoded
- **Dynamic Function Resolution**: Gets function addresses at runtime
- **Syscall Numbers**: Uses direct syscall numbers for critical operations
- **Import Address Table Evasion**: Avoids import table detection

### 5. Comprehensive Anti-Analysis

- **Advanced Anti-Debugging**: Multiple layers of debugger detection
- **Process Enumeration Checks**: Detects analysis tools running on the system
- **Hardware Detection**: Checks for VM artifacts in hardware and CPUID
- **Parent Process Verification**: Verifies if parent process is legitimate
- **PEB Examination**: Checks Process Environment Block for debugging flags
- **Code Timing Checks**: Identifies debuggers through timing anomalies
- **System Resource Validation**: Checks system resources to detect sandboxes

### 6. Code Flow Obfuscation

- **Junk Code Insertion**: Adds meaningless code to confuse static analysis
- **Control Flow Randomization**: Creates unpredictable execution paths
- **Delayed Execution**: Uses variable sleep patterns to evade timing-based detection
- **Stack Randomization**: Adds random stack variables to increase entropy
- **Dead Code Insertion**: Includes code branches that will never execute

### 7. Advanced Techniques

- **Code Signing Bypass**: Patches WinVerifyTrust to bypass certificate validation
- **System DLL Unhooking**: Reloads clean copies of system DLLs to avoid EDR hooks
- **Hardware Breakpoint Detection**: Identifies debugging register usage
- **Multiple Target Selection**: Tries different target processes for injection

### 8. Shellcode Protection

- **Multi-layer Encryption**: Base64 encoding + AES/XOR encryption for shellcode
- **Dynamic Keys**: Uses random encryption keys each time
- **Key Obfuscation**: Encryption keys are stored in a way that's harder to extract

## Generated Executable Types

Two advanced loader types are available:

### AES-128 Encrypted Evasive Loader

- Implements AMSI/ETW bypasses
- Uses NT syscalls and DLL unhooking
- Provides fallback execution methods
- Enhanced anti-debugging protection

### XOR Encrypted Evasive Loader

- Implements DLL hollowing technique
- Uses direct syscalls for process operations
- Implements code signing bypass
- Enhanced anti-VM features

## Recommendations for Maximum Evasion

1. Generate a unique loader for each operation (never reuse loaders)
2. Use different encryption keys for each loader
3. Select a target process appropriate for your environment
4. Combine with obfuscated shellcode from another source first
5. Consider running from an allowlisted directory (C:\Windows\Temp, etc.)
6. Test against endpoint protection in a safe environment first

## Notes on Countermeasures

Modern security products use multiple detection methods including:

1. **Behavioral Detection**: Analyzes process behavior regardless of signatures
2. **Memory Scanning**: Examines memory regions for malicious patterns
3. **Heuristic Analysis**: Identifies suspicious operations and sequences
4. **Machine Learning Models**: Detects previously unseen threats

While these techniques significantly improve evasion capability, a determined defender with proper security tools can still potentially detect malicious behavior. The techniques implemented focus on making detection more difficult, not impossible.

## Technical Implementation Notes

- The loaders use different techniques for AES vs XOR variants
- Some evasion methods require administrative privileges
- Certain techniques may trigger security alerts on well-protected systems
- Techniques are regularly updated based on changes in security product detection methods
- All code is clearly commented for educational purposes

For educational and authorized testing purposes only. 