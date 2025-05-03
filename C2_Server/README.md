# C2 Server

A modular Command and Control (C2) server with advanced features for remote system administration and security testing.

## Features

- Modular architecture with pluggable components
- Web-based control panel with dark mode support
- Real-time agent management
- Advanced task scheduling and automation
- Secure communication with encryption
- Multiple communication channels (HTTP, DNS)
- Shellcode generation and injection capabilities
- System information gathering
- Process management
- File operations
- Surveillance capabilities
- Privilege escalation tools
- Credential access
- Persistence mechanisms

## Installation

1. Clone the repository:
```bash
git clone <repository_url>
cd C2_Server
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Module Structure

```
C2_Server/
├── modules/
│   ├── system/         # System information gathering
│   ├── process/        # Process management
│   ├── surveillance/   # Screenshot, webcam, keylogger
│   ├── files/          # File operations
│   ├── shellcode/      # Shellcode generation and injection
│   ├── privesc/        # Privilege escalation
│   ├── credentials/    # Credential access
│   ├── dns_tunnel/     # DNS tunneling
│   ├── persistence/    # Persistence mechanisms
│   └── shell/          # Command execution
```

## Usage

1. Start the server:
```bash
python server.py
```

2. Access the web interface:
```
http://localhost:5000
```

3. Default credentials:
```
Username: admin
Password: changeme
```

## Security Notice

This tool is for educational and authorized testing purposes only. Ensure you have proper authorization before using any features in a production environment.

## License

[Insert License Information] 