# Troubleshooting Guide for C2 Framework

This guide will help you troubleshoot common issues when running the C2 Framework.

## Quick Start

If you're experiencing issues, try running the framework with the simplified server:

```bash
python run_c2_framework.py --simple
```

This uses a lightweight server implementation that doesn't depend on problematic modules like OpenCV or NumPy.

## Setup on Linux

If you're on a Linux system, you can use the provided setup script:

```bash
chmod +x linux_setup.sh
./linux_setup.sh
```

### Installing UPX on Linux

UPX is required for PyInstaller to create smaller executables. It should be installed as a system package, not via pip:

```bash
# Debian/Ubuntu
sudo apt-get install upx

# Fedora
sudo dnf install upx

# Arch Linux
sudo pacman -S upx
```

## Common Issues and Solutions

### Issue 1: Missing server.py or file path problems

**Error message:**
```
can't open file '/path/to/c2_server/server.py': [Errno 2] No such file or directory
```

**Solution:**
The framework has been updated to automatically search for the correct path. If it still fails, use:

```bash
python run_c2_framework.py --simple
```

### Issue 2: NumPy/OpenCV compatibility problems

**Error message:**
```
A module that was compiled using NumPy 1.x cannot be run in NumPy 2.2.3...
```
or
```
ImportError: No module named 'numpy._utils'
```

**Solution:**
These are dependency compatibility issues. Use the simplified server:

```bash
python run_c2_framework.py --simple
```

### Issue 3: Missing Python packages

**Error message:**
```
ModuleNotFoundError: No module named 'requests'
```
or similar.

**Solution:**
Install all required dependencies:

```bash
pip install -r requirements.txt
pip install flask-login flask-socketio
```

## Command Line Options

The `run_c2_framework.py` script supports several options:

- `--simple`: Use the simplified server (most reliable option)
- `--no-web`: Run without the web interface
- `--no-agent`: Do not deploy a test agent
- `--port NUM`: Set the server port (default: 5001)
- `--agent-delay NUM`: Delay before starting agent (default: 3s)
- `--agent-only`: Only deploy an agent to connect to an existing server
- `--server-url URL`: URL of the C2 server for the agent (default: auto-detect)

## Using Only the Server or Agent

To run just the C2 server:

```bash
python run_c2_framework.py --simple --no-agent
```

To run just the agent:

```bash
python run_c2_framework.py --agent-only --server-url "http://SERVER_IP:5001"
```

## Manually Running Components

If you need more control, you can run components directly:

```bash
# Run the simplified server
python simple_c2_server.py

# Run the agent separately
python agent/agent.py http://SERVER_IP:5001
``` 