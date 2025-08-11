#!/usr/bin/env python3
"""
Test script to verify authentication flow and dashboard access
"""
import requests
import json

def test_auth_flow():
    """Test the complete authentication flow"""
    
    base_url = "http://localhost:5000"
    session = requests.Session()
    
    print("=== Testing Authentication Flow ===")
    
    # Step 1: Try to access dashboard without login (should redirect to login)
    print("\n1. Testing dashboard access without authentication...")
    try:
        response = session.get(f"{base_url}/", allow_redirects=False)
        print(f"   Dashboard response status: {response.status_code}")
        if response.status_code == 302:
            print("   ✅ Correctly redirected to login (as expected)")
        else:
            print(f"   ❌ Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error accessing dashboard: {e}")
    
    # Step 2: Access login page
    print("\n2. Accessing login page...")
    try:
        response = session.get(f"{base_url}/login")
        print(f"   Login page status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Login page accessible")
        else:
            print(f"   ❌ Login page error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error accessing login page: {e}")
    
    # Step 3: Attempt login with correct credentials
    print("\n3. Attempting login with admin credentials...")
    try:
        login_data = {
            "username": "admin",
            "password": "admin123"
        }
        response = session.post(f"{base_url}/login", data=login_data, allow_redirects=False)
        print(f"   Login response status: {response.status_code}")
        
        if response.status_code == 302:
            print("   ✅ Login successful, redirected to dashboard")
            # Follow the redirect
            dashboard_response = session.get(f"{base_url}/", allow_redirects=False)
            print(f"   Dashboard after login status: {dashboard_response.status_code}")
            if dashboard_response.status_code == 200:
                print("   ✅ Dashboard accessible after login")
            else:
                print(f"   ❌ Dashboard still not accessible: {dashboard_response.status_code}")
        else:
            print(f"   ❌ Login failed: {response.status_code}")
            print(f"   Response content: {response.text[:200]}...")
    except Exception as e:
        print(f"   ❌ Error during login: {e}")
    
    # Step 4: Test API endpoints after authentication
    print("\n4. Testing API endpoints after authentication...")
    try:
        # Test agents endpoint
        response = session.get(f"{base_url}/api/agents")
        print(f"   Agents API status: {response.status_code}")
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"   ✅ Agents API working, data: {json.dumps(data, indent=2)}")
            except json.JSONDecodeError:
                print(f"   ⚠️  Agents API returned non-JSON: {response.text[:200]}...")
        else:
            print(f"   ❌ Agents API failed: {response.status_code}")
        
        # Test vulnerabilities endpoint
        response = session.get(f"{base_url}/api/vulnerabilities")
        print(f"   Vulnerabilities API status: {response.status_code}")
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"   ✅ Vulnerabilities API working, data: {json.dumps(data, indent=2)}")
            except json.JSONDecodeError:
                print(f"   ⚠️  Vulnerabilities API returned non-JSON: {response.text[:200]}...")
        else:
            print(f"   ❌ Vulnerabilities API failed: {response.status_code}")
            
    except Exception as e:
        print(f"   ❌ Error testing API endpoints: {e}")
    
    print("\n=== Authentication Flow Test Complete ===")

if __name__ == "__main__":
    test_auth_flow()
