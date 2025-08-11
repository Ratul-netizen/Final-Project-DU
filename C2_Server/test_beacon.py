#!/usr/bin/env python3
"""
Test script to simulate an agent beacon and check data storage
"""
import json
import base64
import requests
import time

def test_agent_beacon():
    """Test sending a beacon to the C2 server"""
    
    # Simulate agent data
    agent_data = {
        "agent_id": "test_agent_001",
        "status": "online",
        "system_info": {
            "hostname": "TEST-PC",
            "platform": "Windows-10-10.0.19045-SP0",
            "architecture": "64bit",
            "processor": "Intel64 Family 6"
        },
        "metrics": {
            "cpu_usage": 25.5,
            "memory_usage": 67.2,
            "disk_usage": 45.1,
            "process_count": 156
        },
        "timestamp": "2024-01-01T12:00:00"
    }
    
    # Encode the data
    encoded_data = base64.b64encode(json.dumps(agent_data).encode()).decode()
    
    # Send beacon
    beacon_payload = {"data": encoded_data}
    
    try:
        print("Sending beacon to C2 server...")
        print(f"Agent data: {json.dumps(agent_data, indent=2)}")
        print(f"Encoded data: {encoded_data[:100]}...")
        
        response = requests.post(
            "http://localhost:5000/api/agents/beacon",
            json=beacon_payload,
            timeout=10
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text}")
        
        if response.status_code == 200:
            print("✅ Beacon sent successfully!")
        else:
            print("❌ Beacon failed!")
            
    except Exception as e:
        print(f"❌ Error sending beacon: {e}")

def test_dashboard_apis():
    """Test the dashboard API endpoints"""
    
    print("\n=== Testing Dashboard APIs ===")
    
    # Test agents endpoint
    try:
        response = requests.get("http://localhost:5000/api/agents", timeout=10)
        print(f"Agents API - Status: {response.status_code}")
        print(f"Agents API - Raw response: {repr(response.text)}")
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"Agents data: {json.dumps(data, indent=2)}")
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                print(f"Response content: {response.text}")
        else:
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"Agents API error: {e}")
    
    # Test vulnerabilities endpoint
    try:
        response = requests.get("http://localhost:5000/api/vulnerabilities", timeout=10)
        print(f"Vulnerabilities API - Status: {response.status_code}")
        print(f"Vulnerabilities API - Raw response: {repr(response.text)}")
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"Vulnerabilities data: {json.dumps(data, indent=2)}")
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                print(f"Response content: {response.text}")
        else:
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"Vulnerabilities API error: {e}")

if __name__ == "__main__":
    print("=== Agent Beacon Test ===")
    test_agent_beacon()
    
    # Wait a moment for processing
    print("\nWaiting 2 seconds for data processing...")
    time.sleep(2)
    
    test_dashboard_apis()
