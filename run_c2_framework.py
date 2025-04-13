#!/usr/bin/env python
import os
import sys
import time
import subprocess
import argparse
import threading
import socket
import random
import platform

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
        s.close()
        return IP
    except Exception:
        return '127.0.0.1'

def start_c2_server(port=5001, no_web=False):
    """Start the C2 server component"""
    print(f"[*] Starting C2 server on port {port}...")
    
    # Set environment variables
    env = os.environ.copy()
    env['PORT'] = str(port)
    
    if no_web:
        # Start without web interface
        server_script = os.path.join('c2_server', 'c2_server.py')
    else:
        # Start with web interface
        server_script = os.path.join('c2_server', 'server.py')
    
    # Start the server process
    try:
        process = subprocess.Popen(
            [sys.executable, server_script], 
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Print server output
        for line in process.stdout:
            print(f"[SERVER] {line.strip()}")
            
    except Exception as e:
        print(f"[!] Error starting C2 server: {str(e)}")
        return None
        
    return process

def deploy_agent(server_url, delay=0):
    """Deploy a test agent that connects to the specified C2 server"""
    if delay > 0:
        print(f"[*] Waiting {delay} seconds before deploying agent...")
        time.sleep(delay)
        
    print(f"[*] Deploying test agent to connect to {server_url}...")
    
    # Start the agent process
    try:
        agent_script = os.path.join('agent', 'agent.py')
        
        process = subprocess.Popen(
            [sys.executable, agent_script, server_url], 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Print agent output
        for line in process.stdout:
            print(f"[AGENT] {line.strip()}")
            
    except Exception as e:
        print(f"[!] Error deploying agent: {str(e)}")
        return None
        
    return process

def main():
    parser = argparse.ArgumentParser(description='C2 Framework Runner')
    parser.add_argument('--port', type=int, default=5001, help='Port for C2 server (default: 5001)')
    parser.add_argument('--no-web', action='store_true', help='Run without web interface')
    parser.add_argument('--no-agent', action='store_true', help='Do not deploy a test agent')
    parser.add_argument('--agent-delay', type=int, default=3, help='Delay before starting agent (default: 3s)')
    parser.add_argument('--agent-only', action='store_true', help='Only deploy agent to existing C2 server')
    parser.add_argument('--server-url', help='URL of C2 server for agent (default: auto-detect)')
    
    args = parser.parse_args()
    
    # Determine server URL
    if args.server_url:
        server_url = args.server_url
    else:
        local_ip = get_local_ip()
        server_url = f"http://{local_ip}:{args.port}"
    
    # Start components based on arguments
    server_process = None
    agent_process = None
    
    try:
        # Start server if not agent-only mode
        if not args.agent_only:
            server_process = start_c2_server(args.port, args.no_web)
            if not server_process:
                return 1
        
        # Deploy agent if requested
        if not args.no_agent:
            agent_process = deploy_agent(server_url, args.agent_delay)
            if not agent_process:
                return 1
        
        # Keep running until Ctrl+C
        if server_process or agent_process:
            print("\n[*] Press Ctrl+C to stop all components...")
            try:
                if server_process:
                    server_process.wait()
                elif agent_process:
                    agent_process.wait()
            except KeyboardInterrupt:
                print("\n[*] Shutting down...")
        
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        # Clean up processes
        if server_process:
            print("[*] Stopping C2 server...")
            server_process.terminate()
            server_process.wait()
            
        if agent_process:
            print("[*] Stopping agent...")
            agent_process.terminate()
            agent_process.wait()
    
    print("[*] All components stopped")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 