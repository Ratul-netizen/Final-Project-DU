#!/usr/bin/env python3
"""
Test script to check agent data storage and API endpoints
"""
import json
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_agent_storage():
    """Test the current state of agent data stores"""
    print("=== Testing Agent Data Storage ===")
    
    # Import the C2 server components
    from c2_server import agents, tasks, results
    
    print(f"Agents dictionary: {len(agents)} agents")
    for agent_id, agent_data in agents.items():
        print(f"  Agent ID: {agent_id}")
        print(f"    Status: {agent_data.get('status', 'unknown')}")
        print(f"    Last seen: {agent_data.get('last_seen', 'unknown')}")
        print(f"    System info: {agent_data.get('system_info', {})}")
        print(f"    Metrics: {agent_data.get('metrics', {})}")
        print(f"    Results count: {len(agent_data.get('results', {}))}")
        print()
    
    print(f"Tasks dictionary: {len(tasks)} agent task queues")
    for agent_id, task_list in tasks.items():
        print(f"  Agent {agent_id}: {len(task_list)} tasks")
    
    print(f"Results dictionary: {len(results)} agent result sets")
    for agent_id, result_list in results.items():
        print(f"  Agent {agent_id}: {len(result_list)} results")

def test_api_endpoints():
    """Test the API endpoints that the dashboard calls"""
    print("\n=== Testing API Endpoints ===")
    
    from c2_server import app
    from c2_server import get_vulnerabilities, get_agents_api, get_scan_history, get_all_results
    
    with app.test_request_context():
        print("Testing /api/vulnerabilities...")
        try:
            vuln_response = get_vulnerabilities()
            print(f"  Status: {vuln_response.status_code}")
            if hasattr(vuln_response, 'get_json'):
                vuln_data = vuln_response.get_json()
                print(f"  Data: {json.dumps(vuln_data, indent=2)}")
        except Exception as e:
            print(f"  Error: {e}")
        
        print("\nTesting /api/agents...")
        try:
            agent_response = get_agents_api()
            print(f"  Status: {agent_response.status_code}")
            if hasattr(agent_response, 'get_json'):
                agent_data = agent_response.get_json()
                print(f"  Data: {json.dumps(agent_data, indent=2)}")
        except Exception as e:
            print(f"  Error: {e}")
        
        print("\nTesting /api/scan-history...")
        try:
            history_response = get_scan_history()
            print(f"  Status: {history_response.status_code}")
            if hasattr(history_response, 'get_json'):
                history_data = history_response.get_json()
                print(f"  Data: {json.dumps(history_data, indent=2)}")
        except Exception as e:
            print(f"  Error: {e}")
        
        print("\nTesting /api/results...")
        try:
            results_response = get_all_results()
            print(f"  Status: {results_response.status_code}")
            if hasattr(results_response, 'get_json'):
                results_data = results_response.get_json()
                print(f"  Data: {json.dumps(results_data, indent=2)}")
        except Exception as e:
            print(f"  Error: {e}")

def test_vulnerability_dashboard():
    """Test the vulnerability dashboard module"""
    print("\n=== Testing Vulnerability Dashboard ===")
    
    try:
        from vulnerability_dashboard import dashboard
        dashboard_data = dashboard.update_dashboard_data()
        print(f"Dashboard data: {json.dumps(dashboard_data, indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_agent_storage()
    test_api_endpoints()
    test_vulnerability_dashboard()
