import subprocess
import logging
import shlex
from datetime import datetime

def execute_command(command, timeout=30, shell=True):
    """Execute a shell command and return its output
    
    Args:
        command (str): Command to execute
        timeout (int): Command timeout in seconds
        shell (bool): Whether to run command through shell
    """
    try:
        # Validate command
        if not command or not isinstance(command, str):
            return {
                'status': 'error',
                'error': 'Invalid command format',
                'timestamp': datetime.now().isoformat()
            }
            
        logging.info(f"Executing command: {command}")
        
        # Execute command with timeout
        if shell:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
        else:
            # Split command safely for non-shell execution
            cmd_parts = shlex.split(command)
            process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
        
        stdout, stderr = process.communicate(timeout=timeout)
        
        # Log based on return code
        if process.returncode == 0:
            logging.info(f"Command executed successfully: {command}")
        else:
            logging.warning(f"Command returned non-zero exit code: {process.returncode}")
            
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
        error_msg = f"Command execution timed out after {timeout} seconds"
        logging.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
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