import os
import sys
import base64
import random
import argparse
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_random_delay():
    """Add random delay to throw off timing analysis"""
    time.sleep(random.uniform(0.1, 0.5))

class ShellcodeEncryptor:
    def __init__(self):
        self.key = None
        self.iv = None
    
    def generate_key(self):
        """Generate random AES key"""
        self.key = get_random_bytes(16)  # 128-bit key
        self.iv = get_random_bytes(16)   # 128-bit IV
        return self.key, self.iv
    
    def load_key(self, key_file):
        """Load key and IV from file"""
        with open(key_file, 'rb') as f:
            data = f.read()
            self.key = data[:16]
            self.iv = data[16:32]
        return self.key, self.iv
    
    def save_key(self, key_file):
        """Save key and IV to file"""
        if not self.key or not self.iv:
            self.generate_key()
        
        with open(key_file, 'wb') as f:
            f.write(self.key + self.iv)
    
    def encrypt_xor(self, data, key=0x55):
        """Simple XOR encryption"""
        return bytes([b ^ key for b in data])
    
    def decrypt_xor(self, data, key=0x55):
        """Simple XOR decryption (same as encryption)"""
        return self.encrypt_xor(data, key)
    
    def encrypt_aes(self, data):
        """Encrypt data using AES-128 in CBC mode"""
        generate_random_delay()  # Anti-analysis
        
        if not self.key or not self.iv:
            self.generate_key()
            
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        return encrypted_data
    
    def decrypt_aes(self, encrypted_data):
        """Decrypt data using AES-128 in CBC mode"""
        if not self.key or not self.iv:
            raise ValueError("No key/IV available. Call load_key() first.")
            
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        
        return unpadded_data
    
    def generate_decryption_code(self, output_file, encryption_type="aes"):
        """Generate Python code for decryption"""
        generate_random_delay()  # Anti-analysis
        
        if encryption_type == "aes":
            if not self.key or not self.iv:
                raise ValueError("No key/IV available")
                
            key_b64 = base64.b64encode(self.key).decode()
            iv_b64 = base64.b64encode(self.iv).decode()
            
            code = f'''
# Shellcode decryption function
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_shellcode(encrypted_data):
    key = base64.b64decode("{key_b64}")
    iv = base64.b64decode("{iv_b64}")
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    
    return unpadded_data
'''
        elif encryption_type == "xor":
            code = '''
# Shellcode decryption function
def decrypt_shellcode(encrypted_data, key=0x55):
    return bytes([b ^ key for b in encrypted_data])
'''
        else:
            raise ValueError("Unsupported encryption type")
            
        with open(output_file, 'w') as f:
            f.write(code)
            
        print(f"[+] Decryption code written to {output_file}")
        
def main():
    parser = argparse.ArgumentParser(description='Shellcode Encryption Utility')
    parser.add_argument('--input', required=True, help='Input raw shellcode file')
    parser.add_argument('--output', required=True, help='Output encrypted shellcode file')
    parser.add_argument('--type', choices=['xor', 'aes'], default='aes', help='Encryption type')
    parser.add_argument('--key-file', help='Key file (for AES)')
    parser.add_argument('--gen-code', help='Generate decryption code to this file')
    parser.add_argument('--save-key', help='Save generated key to this file')
    args = parser.parse_args()
    
    encryptor = ShellcodeEncryptor()
    
    # Read input shellcode
    with open(args.input, 'rb') as f:
        shellcode = f.read()
    
    print(f"[*] Read {len(shellcode)} bytes from {args.input}")
    
    # Encrypt shellcode
    if args.type == 'xor':
        encrypted = encryptor.encrypt_xor(shellcode)
        print(f"[+] XOR encrypted shellcode ({len(encrypted)} bytes)")
    else:  # AES
        if args.key_file and os.path.exists(args.key_file):
            encryptor.load_key(args.key_file)
            print(f"[+] Loaded AES key from {args.key_file}")
        else:
            encryptor.generate_key()
            print(f"[+] Generated new AES key")
            
            if args.save_key:
                encryptor.save_key(args.save_key)
                print(f"[+] Saved AES key to {args.save_key}")
        
        encrypted = encryptor.encrypt_aes(shellcode)
        print(f"[+] AES encrypted shellcode ({len(encrypted)} bytes)")
    
    # Write output
    with open(args.output, 'wb') as f:
        f.write(encrypted)
    
    print(f"[+] Wrote encrypted shellcode to {args.output}")
    
    # Generate decryption code if requested
    if args.gen_code:
        encryptor.generate_decryption_code(args.gen_code, args.type)
    
if __name__ == "__main__":
    generate_random_delay()  # Add initial delay
    main() 