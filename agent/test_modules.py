#!/usr/bin/env python3
"""
Comprehensive Module Tester for C2 Framework
Tests all agent modules for functionality
"""

import sys
import traceback
from datetime import datetime

def test_module(module_name, test_func, description=""):
    """Test a single module and return result"""
    try:
        print(f"\n🔍 Testing {module_name}...")
        if description:
            print(f"   Description: {description}")
        
        result = test_func()
        
        if isinstance(result, dict) and result.get('status') == 'error':
            print(f"❌ {module_name}: FAILED - {result.get('error', 'Unknown error')}")
            return False
        else:
            print(f"✅ {module_name}: SUCCESS")
            if isinstance(result, dict):
                # Print useful info from result
                if 'message' in result:
                    print(f"   Message: {result['message']}")
                if 'platform' in result:
                    print(f"   Platform: {result['platform']}")
                if 'hostname' in result:
                    print(f"   Hostname: {result['hostname']}")
                if 'processes' in result:
                    print(f"   Processes found: {len(result['processes'])}")
                if 'files' in result:
                    print(f"   Files found: {len(result['files'])}")
                if 'credentials' in result:
                    print(f"   Credentials found: {len(result['credentials'])}")
            return True
            
    except Exception as e:
        print(f"❌ {module_name}: FAILED - {str(e)}")
        print(f"   Error details: {traceback.format_exc()}")
        return False

def main():
    print("🚀 C2 Framework Module Testing Suite")
    print("=" * 50)
    print(f"Started at: {datetime.now()}")
    
    passed = 0
    failed = 0
    
    # Test 1: System Information
    if test_module("system_info", lambda: __import__('modules.system_info', fromlist=['get_system_info']).get_system_info(), "Get basic system information"):
        passed += 1
    else:
        failed += 1
    
    # Test 2: Process Management
    if test_module("process", lambda: __import__('modules.process', fromlist=['list_processes']).list_processes(), "List running processes"):
        passed += 1
    else:
        failed += 1
    
    # Test 3: File Operations
    if test_module("files.list_directory", lambda: __import__('modules.files', fromlist=['list_directory']).list_directory('.'), "List directory contents"):
        passed += 1
    else:
        failed += 1
    
    # Test 4: Shell Commands
    if test_module("shell.execute", lambda: __import__('modules.shell', fromlist=['execute_command']).execute_command('echo test'), "Execute shell command"):
        passed += 1
    else:
        failed += 1
    
    # Test 5: Screenshot (Basic test)
    try:
        from modules.surveillance import take_screenshot
        if test_module("surveillance.screenshot", lambda: take_screenshot(), "Take screenshot"):
            passed += 1
        else:
            failed += 1
    except Exception as e:
        print(f"❌ surveillance.screenshot: FAILED - {str(e)}")
        failed += 1
    
    # Test 6: Credential Dump
    try:
        from modules.credential_dump import dump_credentials
        if test_module("credential_dump", lambda: dump_credentials(), "Dump stored credentials"):
            passed += 1
        else:
            failed += 1
    except Exception as e:
        print(f"❌ credential_dump: FAILED - {str(e)}")
        failed += 1
    
    # Test 7: Network Scanner (if available)
    try:
        from modules.network_scanner import scan_network
        if test_module("network_scanner", lambda: scan_network('127.0.0.1', [80, 443]), "Network port scan"):
            passed += 1
        else:
            failed += 1
    except ImportError:
        print("⏭️  network_scanner: SKIPPED (not available)")
    except Exception as e:
        print(f"❌ network_scanner: FAILED - {str(e)}")
        failed += 1
    
    # Test 8: System Scanner (if available)
    try:
        from modules.system_scanner import scan_system
        if test_module("system_scanner", lambda: scan_system(), "System vulnerability scan"):
            passed += 1
        else:
            failed += 1
    except ImportError:
        print("⏭️  system_scanner: SKIPPED (not available)")
    except Exception as e:
        print(f"❌ system_scanner: FAILED - {str(e)}")
        failed += 1
    
    # Test 9: DNS Tunnel
    try:
        from modules.dns_tunnel import start_dns_tunnel
        if test_module("dns_tunnel", lambda: start_dns_tunnel('test.com'), "DNS tunnel start"):
            passed += 1
        else:
            failed += 1
    except Exception as e:
        print(f"❌ dns_tunnel: FAILED - {str(e)}")
        failed += 1
    
    # Test 10: Privilege Escalation
    try:
        from modules.privesc import attempt_privilege_escalation
        if test_module("privesc", lambda: attempt_privilege_escalation(), "Privilege escalation attempt"):
            passed += 1
        else:
            failed += 1
    except Exception as e:
        print(f"❌ privesc: FAILED - {str(e)}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 MODULE TEST SUMMARY")
    print("=" * 50)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success Rate: {(passed/(passed+failed)*100):.1f}%" if (passed+failed) > 0 else "N/A")
    
    if failed == 0:
        print("\n🎉 ALL MODULES WORKING CORRECTLY!")
    else:
        print(f"\n⚠️  {failed} modules need attention")
    
    print(f"\nCompleted at: {datetime.now()}")

if __name__ == "__main__":
    main()
