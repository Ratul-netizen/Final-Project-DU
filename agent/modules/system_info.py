import platform
import socket
import uuid
import psutil
import os
import getpass
import datetime

def get_system_info():
    try:
        info = {
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "username": getpass.getuser(),
            "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1]),
            "cpu_count": psutil.cpu_count(logical=True),
            "memory_total": f"{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB",
            "disk_total": f"{round(psutil.disk_usage('/').total / (1024 ** 3), 2)} GB",
            "boot_time": str(datetime.datetime.fromtimestamp(psutil.boot_time())),
            "timestamp": datetime.datetime.now().isoformat()
        }
        return info
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }