# C2 Server Documentation

## Overview
This document provides a comprehensive explanation of all modules, their dependencies, and functionalities in the C2 Server project.

## Table of Contents
1. [Dependencies](#dependencies)
2. [Module Structure](#module-structure)
3. [Module Details](#module-details)
   - [System Module](#system-module)
   - [Process Module](#process-module)
   - [Surveillance Module](#surveillance-module)
   - [Files Module](#files-module)
   - [Shellcode Module](#shellcode-module)
   - [DNS Tunnel Module](#dns-tunnel-module)
   - [Shell Module](#shell-module)

## Dependencies

### Core Dependencies
- `psutil`: System and process utilities
- `pynput`: Keyboard monitoring
- `pillow` (PIL): Image handling for screenshots
- `pyscreenshot`: Alternative screenshot capability for Linux
- `cryptography`: Encryption and security features
- `dnspython`: DNS protocol handling
- `platform`: System platform information
- `socket`: Network socket operations
- `base64`: Data encoding/decoding
- `json`: JSON data handling
- `threading`: Multi-threading support
- `subprocess`: Process management
- `logging`: Logging functionality
- `shlex`: Shell command parsing
- `struct`: Binary data structure handling

## Module Structure
Each module follows a specific structure:
```
C2_Server/modules/
├── module_name/
│   ├── __init__.py       # Module initialization and exports
│   ├── core.py          # Core functionality
│   └── utils.py         # Utility functions
```

## Module Details

### System Module
**Purpose**: Gather detailed system information

**Key Functions**:
- `get_info()`: Returns comprehensive system information including:
  - Hostname
  - Operating System details
  - Architecture
  - Processor information
  - Memory usage
  - Disk usage
  - Network interfaces

**Dependencies**:
- `platform`
- `psutil`
- `socket`
- `json`

### Process Module
**Purpose**: Process management and monitoring

**Key Functions**:
- `list_processes()`: Lists all running processes with details:
  - Process ID (PID)
  - Process name
  - Username
  - Memory usage
  - CPU usage

**Dependencies**:
- `psutil`
- `json`

### Surveillance Module
**Purpose**: System surveillance capabilities

**Components**:
1. **Screenshot Component**
   - `take_screenshot()`: Captures screen content
   - Uses PIL/Pillow or pyscreenshot
   - Returns base64 encoded image data

2. **Keylogger Component**
   - `start_keylogger()`: Initiates keyboard monitoring
   - `stop_keylogger()`: Stops monitoring and returns logs
   - Records both character and special keys
   - Timestamps all keystrokes

**Dependencies**:
- `pynput`
- `PIL` or `pyscreenshot`
- `threading`
- `datetime`
- `base64`

### Shellcode Module
**Purpose**: Shellcode generation and manipulation

**Key Features**:
- Supports multiple platforms (Windows, Linux)
- Various shellcode types:
  - Reverse shell
  - Bind shell
  - Command execution
- Encoding options:
  - Base64
  - Hex
  - Raw
- Encryption methods:
  - XOR
  - AES
  - None (plain)

**Dependencies**:
- `cryptography`
- `os`
- `base64`

### DNS Tunnel Module
**Purpose**: Covert communications using DNS protocol

**Key Features**:
- DNS-based data tunneling
- Encryption support
- Chunked data transfer
- Retry mechanism
- Queue-based message handling

**Key Classes**:
- `DNSTunnel`:
  - `start()`: Starts the tunnel server
  - `stop()`: Stops the tunnel
  - `send_data()`: Sends data through tunnel
  - `receive_data()`: Receives tunneled data

**Dependencies**:
- `dns.resolver`
- `socket`
- `base64`
- `cryptography`
- `threading`
- `queue`

### Shell Module
**Purpose**: Secure command execution

**Key Functions**:
- `execute(command)`: Safely executes shell commands
  - Platform-aware execution
  - Timeout handling
  - Error capture
  - Output streaming

**Features**:
- Cross-platform support
- Command sanitization
- Timeout management
- Error handling

**Dependencies**:
- `subprocess`
- `shlex`
- `platform`
- `logging`

## Security Considerations
1. All modules implement error handling
2. Encryption used where necessary
3. Platform-specific adaptations
4. Timeout mechanisms
5. Resource cleanup
6. Secure command execution
7. Data sanitization

## Usage Guidelines
1. Initialize modules before use
2. Handle exceptions appropriately
3. Clean up resources after use
4. Monitor system resource usage
5. Implement appropriate security measures
6. Follow platform-specific considerations
7. Maintain proper logging

## Best Practices
1. Always check return status
2. Implement proper error handling
3. Clean up resources
4. Use encryption where appropriate
5. Monitor system impact
6. Follow security guidelines
7. Maintain logs 