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
     - ASCII
   - Automatic file saving
   - Cross-platform support (Windows/Linux)

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

- Flask 2.0.1
- Cryptography 3.4.7
- PyCryptodome 3.10.1
- Requests 2.26.0
- Python-dotenv 0.19.0
- Pynput 1.7.3
- OpenCV 4.5.3.56
- NumPy 1.21.2
- Pillow 8.3.2
- Psutil 5.8.0
- PyWin32 303 (Windows)
- PyAutoGUI 0.9.53
- Keyboard 0.13.5
- PyCryptodomeX 3.10.1
- dnspython 2.1.0
- pywin32-ctypes 0.2.2
- pywin32-security 0.1.0
- pywin32-netcon 0.1.0
- pywin32-service 0.1.0
- pywin32-serviceutil 0.1.0

## Project Structure

```
c2-framework/
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
├── server/
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
