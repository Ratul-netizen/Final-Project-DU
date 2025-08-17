#!/usr/bin/env python3
"""
Command-line credential decryptor tool
Usage: python decrypt_credentials.py [input_file] [output_file]
"""

import sys
import json
import argparse
from pathlib import Path

# Add the modules directory to Python path
current_dir = Path(__file__).parent
modules_dir = current_dir / "modules"
if str(modules_dir) not in sys.path:
    sys.path.insert(0, str(modules_dir))

def main():
    parser = argparse.ArgumentParser(description='Decrypt credential dump results')
    parser.add_argument('input', nargs='?', help='Input JSON file (or use stdin)')
    parser.add_argument('output', nargs='?', help='Output JSON file (or use stdout)')
    parser.add_argument('--pretty', action='store_true', help='Pretty print output')
    parser.add_argument('--summary-only', action='store_true', help='Show only summary')
    
    args = parser.parse_args()
    
    try:
        # Read input
        if args.input:
            with open(args.input, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            # Read from stdin
            data = json.load(sys.stdin)
        
        # Decrypt credentials
        from modules.credential_decryptor import decrypt_credentials_auto
        decrypted = decrypt_credentials_auto(data)
        
        # Prepare output
        if args.summary_only:
            output_data = {
                'summary': decrypted.get('summary', {}),
                'security_insights': decrypted.get('security_insights', {}),
                'timestamp': decrypted.get('timestamp')
            }
        else:
            output_data = decrypted
        
        # Write output
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                if args.pretty:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(output_data, f, ensure_ascii=False)
            print(f"✅ Decrypted credentials saved to: {args.output}")
        else:
            # Print to stdout
            if args.pretty:
                json.dump(output_data, sys.stdout, indent=2, ensure_ascii=False)
            else:
                json.dump(output_data, sys.stdout, ensure_ascii=False)
        
        # Show summary
        if not args.summary_only:
            summary = decrypted.get('summary', {})
            print(f"\n📊 Summary: {summary.get('successfully_decrypted', 0)}/{summary.get('total_credentials', 0)} credentials decrypted", file=sys.stderr)
    
    except FileNotFoundError:
        print(f"❌ Error: File '{args.input}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in input: {e}", file=sys.stderr)
        sys.exit(1)
    except ImportError as e:
        print(f"❌ Error: Could not import decryptor module: {e}", file=sys.stderr)
        print("Make sure the credential_decryptor module is in the modules directory", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
