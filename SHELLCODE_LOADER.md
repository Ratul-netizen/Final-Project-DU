# Shellcode Loader Generator

This module adds advanced shellcode loader generation capabilities to the C2 Framework. It allows you to:

1. Generate AES-encrypted loaders for Windows
2. Automatically compile them to executables using MinGW
3. Deploy loaders directly to connected agents

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