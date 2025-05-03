# C2 Server Modules

This directory contains all the modules used by the C2 server. Each module is organized in its own directory with a specific structure.

## Module Structure

Each module should follow this structure:
```C2_Server/modules/
├── module_name/
│   ├── __init__.py       # Module initialization and exports
│   ├── core.py          # Core functionality
│   └── utils.py         # Utility functions
```

## Available Modules

1. **dns_tunnel** - DNS tunneling for covert communications
   - Uses main dns_tunnel.py implementation

2. **shellcode** - Shellcode generation and injection
   - Uses main shellcode_generator.py implementation

3. **surveillance** - System surveillance capabilities
   - keylogger.py - Keylogging functionality
   - webcam.py - Webcam capture
   - screenshot.py - Screenshot capture

4. **files** - File system operations
   - operations.py - Core file operations
   - browser.py - Browser-related file operations

5. **system** - System information and operations
   - Implemented in __init__.py

6. **process** - Process management
   - Implemented in __init__.py

7. **shell** - Command execution
   - Implemented in __init__.py

## Import Guidelines

1. For modules with implementation in the main modules directory:
```python
from .. import module_file
from ..module_file import ClassName
```

2. For modules with implementation in their own directory:
```python
from .submodule import ClassName
``` 