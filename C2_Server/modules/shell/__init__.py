"""Shell command execution module"""
import subprocess
import shlex
import platform
import logging

def execute(command):
    """
    Execute a shell command safely
    Args:
        command (str): Command to execute
    Returns:
        dict: Command execution results
    """
    try:
        # Use shell=True on Windows, shell=False on Unix-like systems
        use_shell = platform.system().lower() == 'windows'
        
        # Split command if not using shell
        if not use_shell:
            command = shlex.split(command)
            
        # Execute command with timeout
        process = subprocess.Popen(
            command,
            shell=use_shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Get output with timeout
        stdout, stderr = process.communicate(timeout=30)
        
        return {
            'status': 'success',
            'exit_code': process.returncode,
            'stdout': stdout,
            'stderr': stderr
        }
    except subprocess.TimeoutExpired:
        if process:
            process.kill()
        return {
            'status': 'error',
            'message': 'Command execution timed out'
        }
    except Exception as e:
        logging.error(f"Error executing command: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

__all__ = ['execute'] 