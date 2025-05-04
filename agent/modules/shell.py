import subprocess
import logging
from datetime import datetime

def execute_command(command):
    """Execute a shell command and return its output"""
    try:
        # Execute command with timeout
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=30)
        
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'stdout': stdout,
            'stderr': stderr,
            'return_code': process.returncode,
            'command': command
        }
        
    except subprocess.TimeoutExpired:
        process.kill()
        return {
            'status': 'error',
            'error': 'Command execution timed out',
            'command': command,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logging.error(f"Error executing command: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'command': command,
            'timestamp': datetime.now().isoformat()
        } 