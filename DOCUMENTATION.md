# Command and Control (C2) Framework Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Modules](#modules)
4. [Web Interface](#web-interface)
5. [Security Features](#security-features)
6. [Usage Guide](#usage-guide)
7. [API Reference](#api-reference)

## Overview
This Command and Control (C2) Framework consists of two main components:
1. C2 Server: Central management server with web interface
2. Agent: Remote client that executes commands on target systems

Server URL: http://192.168.200.80:5001

## Architecture

### Server Components
```
C2_Server/
├── cpp_templates/          # Shellcode templates
├── modules/               # Core functionality modules
├── templates/            # Web interface templates
├── server.py            # Main server application
└── requirements.txt     # Dependencies
```

### Agent Components
```
agent/
├── modules/             # Agent operation modules
├── agent.py            # Main agent application
└── requirements.txt    # Dependencies
```

## Modules

### 1. DNS Tunneling Module
**Purpose**: Provides alternative communication channel when HTTP/HTTPS is blocked

Features:
- DNS-based command and control
- Data exfiltration through DNS queries
- Covert channel communication
- Custom DNS record types support

Functions:
```python
start_dns_tunnel(domain)    # Start DNS tunneling
stop_dns_tunnel()          # Stop DNS tunneling
send_dns_data(data)        # Send data through DNS
receive_dns_data()         # Receive DNS tunnel data
```

### 2. File Operations Module
**Purpose**: Manage file system operations on target systems

Features:
- Remote file browsing
- File transfer operations
- Permission management
- Directory manipulation

Functions:
```python
list_directory(path)       # List directory contents
upload_file(source, dest)  # Upload file to target
download_file(path)        # Download file from target
delete_file(path)         # Delete file on target
```

### 3. Process Management Module
**Purpose**: Monitor and control system processes

Features:
- Process listing
- Process manipulation
- Resource monitoring
- Process injection

Functions:
```python
list_processes()          # List running processes
kill_process(pid)         # Terminate process
inject_process(pid, data) # Inject into process
monitor_process(pid)      # Monitor process activity
```

### 4. Shell Module
**Purpose**: Provide remote command execution

Features:
- Command execution
- Shell session management
- Output handling
- Error management

Functions:
```python
execute_command(cmd)      # Execute shell command
start_shell_session()     # Start interactive shell
end_shell_session()       # End shell session
get_command_output()      # Get command results
```

### 5. Shellcode Module
**Purpose**: Generate and execute custom shellcode

Features:
- Custom shellcode generation
- Multiple encryption options
- Process injection
- Template-based generation

Functions:
```python
generate_shellcode(type)  # Generate shellcode
encrypt_shellcode(data)   # Encrypt shellcode
inject_shellcode(proc)    # Inject shellcode
load_template(name)       # Load shellcode template
```

### 6. Surveillance Module
**Purpose**: Monitor target system activities

Components:

a) Keylogger:
```python
start_keylogger()        # Start logging keystrokes
stop_keylogger()         # Stop keylogger
get_keylog_data()        # Retrieve logged keys
```

b) Screenshot:
```python
take_screenshot()        # Capture screen
capture_window(title)    # Capture specific window
save_screenshot(path)    # Save screenshot
```

c) Webcam:
```python
capture_webcam()         # Take webcam photo
start_webcam_record()    # Start webcam recording
stop_webcam_record()     # Stop recording
```

### 7. System Module
**Purpose**: System information and configuration

Features:
- System information gathering
- Configuration management
- System state monitoring
- Resource tracking

Functions:
```python
get_system_info()        # Get system details
modify_config(params)    # Change configuration
monitor_resources()      # Monitor system resources
```

## Web Interface

### Pages
1. **Dashboard** (index.html)
   - Agent status overview
   - Recent activities
   - System statistics

2. **Control Panel** (control.html)
   - Agent management
   - Task deployment
   - Real-time monitoring
   - Result visualization

3. **Shellcode Generator** (shellcode.html)
   - Custom shellcode creation
   - Template selection
   - Encryption options

4. **Login** (login.html)
   - Authentication
   - Session management

## Security Features

### Authentication
- Username/password authentication
- Session management
- Access control levels
- Token-based API access

### Communication Security
- Encrypted data transmission
- Certificate validation
- Session encryption
- Data integrity checks

### Operational Security
- Audit logging
- Activity monitoring
- Error handling
- Resource protection

## Usage Guide

### Server Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start C2 server:
   ```bash
   python server.py
   ```

3. Access web interface:
   ```
   http://192.168.200.80:5001
   ```

### Agent Deployment
1. Configure agent:
   ```python
   C2_URL = "http://192.168.200.80:5001"
   ```

2. Run agent:
   ```bash
   python agent.py
   ```

### Basic Operations
1. Agent Management
   - Register new agents
   - Monitor agent status
   - Deploy tasks
   - Collect results

2. Task Execution
   - Select agent
   - Choose operation
   - Set parameters
   - Execute task
   - Monitor results

## API Reference

### Server API Endpoints
```
POST /api/agents/register    # Register new agent
POST /api/agents/beacon     # Agent heartbeat
GET  /api/tasks/{agent_id}  # Get agent tasks
POST /api/results           # Submit task results
```

### Agent API Usage
```python
# Registration
register_agent(agent_id, system_info)

# Task Handling
fetch_tasks()
execute_task(task)
send_result(task_id, result)

# Communication
send_beacon()
establish_connection()
```

## Notes
- This framework is for authorized testing only
- Ensure proper authorization before deployment
- Monitor resource usage
- Follow security best practices
- Maintain operational security 