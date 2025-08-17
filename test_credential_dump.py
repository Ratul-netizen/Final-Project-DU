#!/usr/bin/env python3
"""
Test script to debug credential dump functionality
"""

import sys
import os
from pathlib import Path

# Add the modules directory to Python path
current_dir = Path(__file__).parent
modules_dir = current_dir / "agent" / "modules"
if str(modules_dir) not in sys.path:
    sys.path.insert(0, str(modules_dir))

def test_credential_dump():
    """Test the credential dump functionality"""
    print("🔐 Testing Credential Dump Functionality")
    print("=" * 50)
    
    try:
        # Test 1: Import credential dump function
        print("📥 Testing imports...")
        from credential_dump import dump_credentials
        print("✅ Credential dump function imported successfully")
        
        # Test 2: Test credential dump without task_id
        print("\n🧪 Testing credential dump...")
        result = dump_credentials()
        print(f"   Result status: {result.get('status')}")
        print(f"   Result type: {type(result)}")
        
        if result.get('status') == 'success':
            print("✅ Credential dump successful!")
            
            # Check what data we got
            if 'data' in result:
                data = result['data']
                print(f"   Windows credentials: {len(data.get('windows_credentials', {}).get('credentials', []))}")
                print(f"   LSASS dump: {data.get('lsass_dump', {}).get('status')}")
                print(f"   SAM hashes: {data.get('sam_hashes', {}).get('status')}")
                
                # Show some sample credentials
                if data.get('windows_credentials', {}).get('credentials'):
                    creds = data['windows_credentials']['credentials']
                    print(f"   Sample credential: {creds[0].get('target')} - {creds[0].get('username')}")
            else:
                print("   No data field in result")
                
        else:
            print(f"❌ Credential dump failed: {result.get('error', 'Unknown error')}")
        
        # Test 3: Test with decryptor
        print("\n🔓 Testing with decryptor...")
        try:
            from credential_decryptor import decrypt_credentials_auto
            print("✅ Decryptor imported successfully")
            
            if result.get('status') == 'success':
                decrypted = decrypt_credentials_auto(result)
                print(f"   Decryption status: {decrypted.get('status')}")
                print(f"   Decrypted credentials: {len(decrypted.get('decrypted_credentials', []))}")
            else:
                print("   Skipping decryption test - no credentials to decrypt")
                
        except ImportError as e:
            print(f"❌ Decryptor import failed: {e}")
        
        print("\n✅ Credential dump test completed!")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you're running this from the correct directory")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_credential_dump()
