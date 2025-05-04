import psutil
import logging
from datetime import datetime

def list_processes():
    """List all running processes with their details"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status']):
            try:
                pinfo = proc.as_dict()
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'username': pinfo['username'],
                    'memory_percent': round(pinfo['memory_percent'], 2),
                    'cpu_percent': round(pinfo['cpu_percent'], 2),
                    'status': pinfo['status']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'processes': processes
        }
    except Exception as e:
        logging.error(f"Error listing processes: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def kill_process(pid):
    """Kill a process by its PID"""
    try:
        process = psutil.Process(pid)
        process.terminate()
        return {
            'status': 'success',
            'message': f'Process {pid} terminated',
            'timestamp': datetime.now().isoformat()
        }
    except psutil.NoSuchProcess:
        return {
            'status': 'error',
            'error': f'Process {pid} not found',
            'timestamp': datetime.now().isoformat()
        }
    except psutil.AccessDenied:
        return {
            'status': 'error',
            'error': f'Access denied to terminate process {pid}',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logging.error(f"Error killing process: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        } 