#!/usr/bin/env python3
"""
Test script to verify API endpoints are working correctly
"""

import requests
import json

def test_api_endpoints():
    base_url = "http://localhost:5000"
    
    # Test the results endpoint
    try:
        response = requests.get(f"{base_url}/api/results")
        print(f"Results endpoint status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Results data: {json.dumps(data, indent=2)}")
        else:
            print(f"Error response: {response.text}")
    except Exception as e:
        print(f"Error testing results endpoint: {e}")
    
    # Test the vulnerabilities endpoint
    try:
        response = requests.get(f"{base_url}/api/vulnerabilities")
        print(f"\nVulnerabilities endpoint status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Vulnerabilities data: {json.dumps(data, indent=2)}")
        else:
            print(f"Error response: {response.text}")
    except Exception as e:
        print(f"Error testing vulnerabilities endpoint: {e}")

if __name__ == "__main__":
    test_api_endpoints()
