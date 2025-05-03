"""Process management module"""
import psutil
import json

def list_processes():
    """List all running processes"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
        try:
            pinfo = proc.info
            processes.append({
                'pid': pinfo['pid'],
                'name': pinfo['name'],
                'username': pinfo['username'],
                'memory_percent': round(pinfo['memory_percent'], 2),
                'cpu_percent': round(pinfo['cpu_percent'], 2)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def kill_process(pid):
    """Kill a process by PID"""
    try:
        proc = psutil.Process(pid)
        proc.kill()
        return {'status': 'success', 'message': f'Process {pid} killed'}
    except psutil.NoSuchProcess:
        return {'status': 'error', 'message': f'Process {pid} not found'}
    except psutil.AccessDenied:
        return {'status': 'error', 'message': f'Access denied to kill process {pid}'}

__all__ = ['list_processes', 'kill_process'] 