import requests
import json

# Send a comprehensive vulnerability scan task to the agent
task_data = {
    "agent_id": "agent_cdaaab09-c728-4b7f-a64b-a65f9295570f",
    "module": "vulnerability.comprehensive_scan",
    "params": {}
}

try:
    response = requests.post("http://localhost:5000/api/tasks", json=task_data)
    print(f"Response status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
