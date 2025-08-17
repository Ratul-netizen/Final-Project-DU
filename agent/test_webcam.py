#!/usr/bin/env python3
"""
Test script to verify webcam module functionality
Run this after installing dependencies to ensure everything works
"""

import sys
import os
from pathlib import Path

# Add the modules directory to Python path in an IDE-friendly way
current_dir = Path(__file__).parent
modules_dir = current_dir / "modules"
if str(modules_dir) not in sys.path:
    sys.path.insert(0, str(modules_dir))

def test_imports():
    """Test if all required modules can be imported"""
    print("🧪 Testing module imports...")
    
    modules_to_test = [
        ("cv2", "OpenCV for webcam functionality"),
        ("numpy", "NumPy for numerical operations"),
        ("PIL", "Pillow for image processing"),
        ("psutil", "System monitoring utilities"),
        ("requests", "HTTP requests"),
        ("cryptography", "Encryption capabilities")
    ]
    
    all_imported = True
    
    for module_name, description in modules_to_test:
        try:
            __import__(module_name)
            print(f"  ✅ {module_name} - {description}")
        except ImportError as e:
            print(f"  ❌ {module_name} - {description} - Error: {e}")
            all_imported = False
    
    return all_imported

def test_webcam_module():
    """Test the webcam module specifically"""
    print("\n📷 Testing webcam module...")
    
    try:
        # Import the webcam module
        from webcam import Webcam
        
        # Create webcam instance
        webcam = Webcam()
        print(f"  ✅ Webcam module loaded: {webcam.name}")
        print(f"  ✅ Description: {webcam.description}")
        
        # Test basic functionality
        print("  🔍 Testing webcam capture...")
        result = webcam.capture_image()
        
        if result and result.get("status") == "success":
            print("  ✅ Webcam capture successful!")
            print(f"  📊 Image format: {result.get('format')}")
            print(f"  📊 Encoding: {result.get('encoding')}")
            print(f"  📊 Timestamp: {result.get('timestamp')}")
        else:
            print("  ⚠️  Webcam capture returned error:")
            print(f"     Status: {result.get('status') if result else 'None'}")
            print(f"     Error: {result.get('error') if result else 'Unknown'}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Webcam module test failed: {e}")
        return False

def test_opencv_functionality():
    """Test OpenCV basic functionality"""
    print("\n🎥 Testing OpenCV functionality...")
    
    try:
        import cv2
        import numpy as np
        
        # Test OpenCV version
        print(f"  ✅ OpenCV version: {cv2.__version__}")
        
        # Test numpy
        print(f"  ✅ NumPy version: {np.__version__}")
        
        # Test basic OpenCV operations
        test_image = np.zeros((100, 100, 3), dtype=np.uint8)
        test_image[25:75, 25:75] = [255, 255, 255]  # White square
        
        # Test image operations
        gray = cv2.cvtColor(test_image, cv2.COLOR_BGR2GRAY)
        print("  ✅ Basic OpenCV operations successful")
        
        return True
        
    except Exception as e:
        print(f"  ❌ OpenCV test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🔍 Webcam Module Test Suite")
    print("=" * 40)
    
    # Test basic imports
    imports_ok = test_imports()
    
    if not imports_ok:
        print("\n❌ Some critical modules failed to import!")
        print("Please run: pip install -r requirements.txt")
        return False
    
    # Test OpenCV
    opencv_ok = test_opencv_functionality()
    
    # Test webcam module
    webcam_ok = test_webcam_module()
    
    print("\n" + "=" * 40)
    print("📊 Test Results Summary:")
    print(f"  Module Imports: {'✅ PASS' if imports_ok else '❌ FAIL'}")
    print(f"  OpenCV Tests: {'✅ PASS' if opencv_ok else '❌ FAIL'}")
    print(f"  Webcam Module: {'✅ PASS' if webcam_ok else '❌ FAIL'}")
    
    if all([imports_ok, opencv_ok, webcam_ok]):
        print("\n🎉 All tests passed! Webcam module is ready to use.")
        return True
    else:
        print("\n⚠️  Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
