#!/usr/bin/env python3
import psutil
from datetime import datetime

class ProcessList:
    def __init__(self):
        self.name = "process_list"
        self.description = "List running processes"
        self.author = "Your C2 Framework"

    def get_process_list(self):
        """
        Get list of running processes with details
        """
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status']):
                try:
                    pinfo = proc.info
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
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "data": processes
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def run(self, **kwargs):
        """
        Main execution method
        """
        return self.get_process_list()

def setup():
    """
    Module initialization
    """
    return ProcessList() 