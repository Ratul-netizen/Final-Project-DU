#!/usr/bin/env python3
"""
Test script to verify agent connectivity to C2 server
"""
import requests
import json
import base64
import time

def test_c2_connectivity():
    """Test basic connectivity to C2 server"""
    
    # Test URLs
    test_urls = [
        "http://localhost:5000",
        "http://192.168.0.103:5000",
        "http://127.0.0.1:5000"
    ]
    
    print("Testing C2 server connectivity...")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        
        # Test basic connectivity
        try:
            response = requests.get(f"{url}/api/agents/register", timeout=5)
            if response.status_code == 405:  # Method not allowed is expected for GET
                print(f"✓ Server accessible at {url}")
                
                # Test POST request
                test_data = {
                    "agent_id": "test_agent_123",
                    "status": "test",
                    "system_info": {"hostname": "test", "os": "test"}
                }
                
                encoded_data = base64.b64encode(json.dumps(test_data).encode()).decode()
                post_data = {"data": encoded_data}
                
                try:
                    post_response = requests.post(f"{url}/api/agents/register", 
                                               json=post_data, timeout=10)
                    if post_response.status_code == 200:
                        print(f"✓ POST request successful: {post_response.json()}")
                        return url  # Return working URL
                    else:
                        print(f"✗ POST request failed: {post_response.status_code} - {post_response.text}")
                except Exception as e:
                    print(f"✗ POST request error: {e}")
                    
            else:
                print(f"✗ Unexpected response: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"✗ Connection failed")
        except requests.exceptions.Timeout:
            print(f"✗ Request timed out")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    return None

def test_agent_registration():
    """Test full agent registration process"""
    working_url = test_c2_connectivity()
    
    if not working_url:
        print("\n❌ No working C2 server found!")
        return False
    
    print(f"\n✅ Testing agent registration with: {working_url}")
    
    # Simulate agent registration
    agent_data = {
        "agent_id": "test_agent_" + str(int(time.time())),
        "system_info": {
            "hostname": "test_host",
            "os": "Windows",
            "os_release": "10",
            "architecture": "x64"
        },
        "module_status": {
            "system_info": True,
            "process": True
        },
        "status": "active"
    }
    
    try:
        encoded_data = base64.b64encode(json.dumps(agent_data).encode()).decode()
        post_data = {"data": encoded_data}
        
        response = requests.post(f"{working_url}/api/agents/register", 
                               json=post_data, timeout=10)
        
        if response.status_code == 200:
            print("✅ Agent registration successful!")
            print(f"Response: {response.json()}")
            return True
        else:
            print(f"❌ Agent registration failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Agent registration error: {e}")
        return False

if __name__ == "__main__":
    print("Agent Connectivity Test")
    print("=" * 50)
    
    success = test_agent_registration()
    
    if success:
        print("\n🎉 All tests passed! Agent should be able to connect.")
    else:
        print("\n💥 Tests failed! Check server configuration and network.")
