# Modular Command-and-Control (C2) Framework

A powerful, modular Command-and-Control (C2) framework for red team operations, adversary simulation, and security research. Features a modern web dashboard, robust agent-server communication, advanced post-exploitation modules, evasion techniques, and real-time result visualization.

---

## Features

### Core Components

- **C2 Server**
  - Modern, responsive dashboard (Flask web app)
  - Real-time agent management and monitoring
  - Task creation, dispatch, and result collection
  - Secure, base64-encoded communication
  - Download and preview of all result types (files, images, JSON, etc.)

- **Agent**
  - Modular, cross-platform (Windows/Linux) agent
  - Automatic privilege escalation attempts
  - Adds itself to Windows Defender exclusions (PowerShell)
  - Periodic keylogger reporting (full text and key events)
  - Credential dumping (Windows: SAM hashes, Linux: root hash)
  - Handles and executes tasks from the C2 server

- **Post-Exploitation Modules**
  - System information
  - Process listing and management
  - Screenshot capture (with image preview/download)
  - Webcam capture (with image preview/download)
  - Keylogger (periodic reporting)
  - File browser and file download
  - Shellcode injection
  - Privilege escalation checks
  - Credential dumping (hash extraction)
  - DNS tunneling for covert C2
  - Persistence installation
  - Custom command execution

- **Evasion & Security**
  - Anti-VM, anti-debug, and sandbox detection (optional)
  - Process monitoring and hiding
  - Network traffic obfuscation
  - Encrypted payloads (XOR/AES)
  - Secure session management

---

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd <project-root>
```

### 2. Install dependencies

#### C2 Server

```bash
cd C2_Server
pip install -r requirements.txt
```

#### Agent

```bash
cd ../agent
pip install -r requirements.txt
```

### 3. Start the C2 Server

```bash
cd ../C2_Server
python c2_server.py
```

### 4. Deploy the Agent

- Build or run `agent.py` on the target system.

---

## Usage

### C2 Server Dashboard

- Access at: `http://localhost:5001`
- View and manage agents
- Assign tasks (modules) to agents
- View results in real-time
- Download files/images or preview them in the browser

### Task Modules

- **System Info**: Collects detailed system information
- **Process Management**: List/kill processes
- **Screenshot/Webcam**: Captures and previews images
- **Keylogger**: Start/stop and receive periodic logs
- **File Browser**: Browse/download files from the agent
- **Shellcode Injection**: Inject custom shellcode
- **Privilege Escalation**: Checks for privilege escalation opportunities
- **Credential Dumping**: Extracts password hashes (SAM/root)
- **DNS Tunneling**: Establishes covert C2 channel
- **Persistence**: Installs persistence mechanisms
- **Custom Command**: Run arbitrary shell commands

### Result Handling

- All results are shown in the dashboard
- Image results have previews and can be downloaded in native format
- Files can be downloaded directly
- Large JSON/text results are expandable/collapsible for easy viewing

---

## Project Structure

```
project-root/
├── agent/
│   ├── agent.py
│   └── modules/
├── C2_Server/
│   ├── c2_server.py
│   ├── modules/
│   ├── templates/
│   └── requirements.txt
├── README.md
└── ...
```

---

## Security & Evasion Features

- **Privilege escalation**: Automatic attempt on agent startup
- **Defender evasion**: Adds agent folder to Defender exclusions
- **Credential dumping**: Extracts hashes for offline cracking
- **Keylogger**: Periodic reporting, both full text and key events
- **Image/file handling**: Native format download and preview
- **Network**: DNS tunneling for stealthy C2

---

## Dependencies

- Flask
- Flask-Login
- Cryptography
- PyCryptodome
- Requests
- Pynput
- OpenCV
- NumPy
- Pillow
- Psutil
- PyAutoGUI
- Keyboard
- dnspython
- (and others, see `requirements.txt` in each component)

---

## Documentation

- See `docs/` for MITRE ATT&CK mapping and technical documentation.

---

## Disclaimer

**For educational and research purposes only.**  
Do not use this tool on systems you do not own or have explicit permission to test.
