#!/usr/bin/env python
import os
import sys
import subprocess
import platform
import importlib.util

def check_python_package(package_name):
    """Check if a Python package is installed"""
    spec = importlib.util.find_spec(package_name)
    if spec is None:
        print(f"❌ Python package {package_name} is not installed")
        return False
    else:
        print(f"✅ Python package {package_name} is installed")
        return True

def check_command(command):
    """Check if a command is available in PATH"""
    try:
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            shell=True
        )
        if result.returncode == 0:
            print(f"✅ Command '{command}' is available")
            return True
        else:
            print(f"❌ Command '{command}' failed: {result.stderr.decode()}")
            return False
    except Exception as e:
        print(f"❌ Error checking command '{command}': {str(e)}")
        return False

def check_directory(path):
    """Check if a directory exists"""
    if os.path.isdir(path):
        print(f"✅ Directory {path} exists")
        return True
    else:
        print(f"❌ Directory {path} does not exist")
        return False

def check_file(path):
    """Check if a file exists"""
    if os.path.isfile(path):
        print(f"✅ File {path} exists")
        return True
    else:
        print(f"❌ File {path} does not exist")
        return False

def main():
    """Run all checks"""
    print("🔍 Checking dependencies for shellcode loader generator...")
    
    # Check Python packages
    missing_packages = []
    for package in ["flask", "Cryptodome", "requests"]:
        if not check_python_package(package):
            missing_packages.append(package)
    
    # Check MinGW
    has_mingw = check_command("x86_64-w64-mingw32-g++ --version")
    
    # Check directories and files
    has_dirs = check_directory("C2_Server/cpp_templates") and check_directory("C2_Server/compiled")
    has_template = check_file("C2_Server/cpp_templates/shellcode_loader_template.cpp")
    has_encryption = check_file("C2_Server/encrypt_aes.py")
    has_generator = check_file("C2_Server/generate_loader.py")
    
    # Print summary
    print("\n📊 Summary:")
    if missing_packages:
        print(f"❌ Missing Python packages: {', '.join(missing_packages)}")
        print("   Install with: pip install " + " ".join(missing_packages))
    else:
        print("✅ All required Python packages are installed")
        
    if not has_mingw:
        if platform.system() == "Linux":
            print("❌ MinGW not found, needed for cross-compiling Windows executables")
            print("   Install with: sudo apt-get install mingw-w64  # Debian/Ubuntu")
            print("   Or:           sudo dnf install mingw64-gcc-c++  # Fedora")
            print("   Or:           sudo pacman -S mingw-w64-gcc  # Arch Linux")
        elif platform.system() == "Windows":
            print("❌ MinGW not found, needed for compiling Windows executables")
            print("   Install with: choco install mingw  # using Chocolatey")
            print("   Or download from: https://sourceforge.net/projects/mingw-w64/")
        else:
            print("❌ MinGW not found, needed for cross-compiling Windows executables")
    else:
        print("✅ MinGW is installed")
        
    if not has_dirs or not has_template or not has_encryption or not has_generator:
        print("❌ Some required files or directories are missing")
        print("   Make sure you have run the setup script")
    else:
        print("✅ All required files and directories are present")
        
    # Final verdict
    if missing_packages or not has_mingw or not has_dirs or not has_template or not has_encryption or not has_generator:
        print("\n❌ Some dependencies are missing. Please install them before generating loaders.")
        return 1
    else:
        print("\n✅ All dependencies are installed. You're ready to generate loaders!")
        return 0
    
if __name__ == "__main__":
    sys.exit(main()) 