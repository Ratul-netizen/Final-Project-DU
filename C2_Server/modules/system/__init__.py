"""System information gathering module"""
import platform
import psutil
import socket
import json

def get_info():
    """Get detailed system information"""
    info = {
        'hostname': socket.gethostname(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'memory': {
            'total': psutil.virtual_memory().total,
            'available': psutil.virtual_memory().available,
            'percent': psutil.virtual_memory().percent
        },
        'disk': {
            'total': psutil.disk_usage('/').total,
            'used': psutil.disk_usage('/').used,
            'free': psutil.disk_usage('/').free,
            'percent': psutil.disk_usage('/').percent
        },
        'network': {
            'interfaces': list(psutil.net_if_addrs().keys()),
            'connections': len(psutil.net_connections())
        }
    }
    return info

__all__ = ['get_info'] 