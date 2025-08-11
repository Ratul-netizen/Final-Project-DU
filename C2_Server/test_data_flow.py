#!/usr/bin/env python3
"""
Test script to check data flow and identify issues with dashboard data display
"""

import json
import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_data_stores():
    """Test the current state of data stores in the C2 server"""
    
    print("=== Testing C2 Server Data Stores ===\n")
    
    try:
        # Import the C2 server components
        from c2_server import agents, tasks, results
        
        print(f"Agents store: {len(agents)} agents")
        if agents:
            print("Agent IDs:", list(agents.keys()))
            for agent_id, agent_data in agents.items():
                print(f"  Agent {agent_id}:")
                print(f"    Keys: {list(agent_data.keys()) if isinstance(agent_data, dict) else 'Not a dict'}")
                if isinstance(agent_data, dict):
                    print(f"    Last seen: {agent_data.get('last_seen', 'N/A')}")
                    print(f"    Status: {agent_data.get('status', 'N/A')}")
                    print(f"    System info: {agent_data.get('system_info', 'N/A')}")
                    print(f"    Metrics: {agent_data.get('metrics', 'N/A')}")
        else:
            print("  No agents found")
        
        print(f"\nTasks store: {len(tasks)} tasks")
        if tasks:
            print("Task IDs:", list(tasks.keys()))
        
        print(f"\nResults store: {len(results)} agent results")
        if results:
            for agent_id, agent_results in results.items():
                print(f"  Agent {agent_id}: {len(agent_results)} results")
                if agent_results:
                    for task_id, result in list(agent_results.items())[:3]:  # Show first 3
                        print(f"    Task {task_id}: {type(result)}")
                        if isinstance(result, dict):
                            print(f"      Keys: {list(result.keys())}")
                            print(f"      Result type: {result.get('type', 'N/A')}")
                            print(f"      Timestamp: {result.get('timestamp', 'N/A')}")
        else:
            print("  No results found")
            
    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure you're running this from the C2_Server directory")
    except Exception as e:
        print(f"Error: {e}")

def test_api_endpoints():
    """Test the API endpoints that the dashboard calls"""
    
    print("\n=== Testing API Endpoints ===\n")
    
    try:
        from c2_server import app
        from c2_server import get_vulnerabilities, get_agents_api, get_scan_history, get_all_results
        
        # Create a test context
        with app.test_request_context():
            print("Testing /api/vulnerabilities...")
            try:
                vuln_response = get_vulnerabilities()
                print(f"  Status: {vuln_response.status_code}")
                if vuln_response.status_code == 200:
                    vuln_data = json.loads(vuln_response.data)
                    print(f"  Data: {json.dumps(vuln_data, indent=2)}")
                else:
                    print(f"  Error: {vuln_response.data}")
            except Exception as e:
                print(f"  Error: {e}")
            
            print("\nTesting /api/agents...")
            try:
                agent_response = get_agents_api()
                print(f"  Status: {agent_response.status_code}")
                if agent_response.status_code == 200:
                    agent_data = json.loads(agent_response.data)
                    print(f"  Data: {json.dumps(agent_data, indent=2)}")
                else:
                    print(f"  Error: {agent_response.data}")
            except Exception as e:
                print(f"  Error: {e}")
            
            print("\nTesting /api/scan-history...")
            try:
                history_response = get_scan_history()
                print(f"  Status: {history_response.status_code}")
                if history_response.status_code == 200:
                    history_data = json.loads(history_response.data)
                    print(f"  Data: {json.dumps(history_data, indent=2)}")
                else:
                    print(f"  Error: {history_response.data}")
            except Exception as e:
                print(f"  Error: {e}")
            
            print("\nTesting /api/results...")
            try:
                results_response = get_all_results()
                print(f"  Status: {results_response.status_code}")
                if results_response.status_code == 200:
                    results_data = json.loads(results_response.data)
                    print(f"  Data: {json.dumps(results_data, indent=2)}")
                else:
                    print(f"  Error: {results_response.data}")
            except Exception as e:
                print(f"  Error: {e}")
                
    except ImportError as e:
        print(f"Import error: {e}")
    except Exception as e:
        print(f"Error: {e}")

def test_vulnerability_dashboard():
    """Test the vulnerability dashboard module"""
    
    print("\n=== Testing Vulnerability Dashboard ===\n")
    
    try:
        from vulnerability_dashboard import dashboard
        
        print("Dashboard object:", dashboard)
        print("Dashboard methods:", [method for method in dir(dashboard) if not method.startswith('_')])
        
        # Test update_dashboard_data
        if hasattr(dashboard, 'update_dashboard_data'):
            try:
                dashboard_data = dashboard.update_dashboard_data()
                print(f"Dashboard data: {json.dumps(dashboard_data, indent=2)}")
            except Exception as e:
                print(f"Error updating dashboard data: {e}")
        else:
            print("update_dashboard_data method not found")
            
    except ImportError as e:
        print(f"Import error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("C2 Server Data Flow Test")
    print("=" * 50)
    
    test_data_stores()
    test_api_endpoints()
    test_vulnerability_dashboard()
    
    print("\n=== Test Complete ===")
