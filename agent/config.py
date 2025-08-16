#!/usr/bin/env python3
"""
Agent configuration file
"""
import os
import socket

# C2 Server Configuration
C2_HOST = os.environ.get('C2_HOST', '192.168.0.103')
C2_PORT = int(os.environ.get('C2_PORT', '5000'))
C2_PROTOCOL = os.environ.get('C2_PROTOCOL', 'http')

# Agent Configuration
BEACON_INTERVAL = int(os.environ.get('BEACON_INTERVAL', '10'))
AGENT_ID_PREFIX = os.environ.get('AGENT_ID_PREFIX', 'monitor_')

# Network Configuration
NETWORK_TIMEOUT = int(os.environ.get('NETWORK_TIMEOUT', '10'))
MAX_RETRIES = int(os.environ.get('MAX_RETRIES', '3'))

# Dynamic IP Discovery
def get_local_ip():
    """Get local IP address dynamically"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def get_c2_url():
    """Get C2 URL with fallback to local IP"""
    # Try configured host first
    configured_url = f"{C2_PROTOCOL}://{C2_HOST}:{C2_PORT}"
    
    # Fallback to local IP if configured host fails
    try:
        import requests
        response = requests.get(f"{configured_url}/api/agents/register", timeout=5)
        if response.status_code == 405:  # Method not allowed is expected for GET
            return configured_url
    except:
        pass
    
    # Use local IP as fallback
    local_ip = get_local_ip()
    return f"{C2_PROTOCOL}://{local_ip}:{C2_PORT}"

# Build C2 URL
C2_URL = get_c2_url()

# Logging Configuration
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Module Configuration
ENABLE_SURVEILLANCE = os.environ.get('ENABLE_SURVEILLANCE', 'true').lower() == 'true'
ENABLE_VULNERABILITY_SCANNING = os.environ.get('ENABLE_VULNERABILITY_SCANNING', 'true').lower() == 'true'
ENABLE_AUTO_SCANNING = os.environ.get('ENABLE_AUTO_SCANNING', 'true').lower() == 'true'

# Security Configuration
ENCRYPTION_ENABLED = os.environ.get('ENCRYPTION_ENABLED', 'true').lower() == 'true'
KEY_B64 = os.environ.get('ENCRYPTION_KEY', 'dGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIGVuY3J5cHRpb24=')

# Print configuration for debugging
if __name__ == "__main__":
    print("Agent Configuration:")
    print(f"C2 URL: {C2_URL}")
    print(f"Beacon Interval: {BEACON_INTERVAL}s")
    print(f"Network Timeout: {NETWORK_TIMEOUT}s")
    print(f"Local IP: {get_local_ip()}")
    print(f"Surveillance Enabled: {ENABLE_SURVEILLANCE}")
    print(f"Vulnerability Scanning: {ENABLE_VULNERABILITY_SCANNING}")
