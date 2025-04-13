#!/usr/bin/env python
from Cryptodome.Cipher import AES
import base64
import os
import string
import random

# Default AES key and IV (as fallback)
DEFAULT_KEY = b"ThisIsASecretKey"  # 16 bytes
DEFAULT_IV = b"ThisIsInitVector"   # 16 bytes

def generate_random_key(length=16):
    """Generate a random key of specified length"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length)).encode()

def pad(data):
    """PKCS#7 padding for AES"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove PKCS#7 padding"""
    return data[:-data[-1]]

def encrypt_shellcode(shellcode_bytes, key=None, iv=None):
    """
    Encrypt shellcode using AES-128-CBC
    Args:
        shellcode_bytes: Raw shellcode bytes
        key: Optional AES key (16 bytes)
        iv: Optional AES IV (16 bytes)
    Returns:
        Dictionary with base64 encoded encrypted shellcode, key and IV
    """
    # Use provided key/IV or generate random ones
    key = key or DEFAULT_KEY
    iv = iv or DEFAULT_IV
    
    # Ensure key and IV are bytes and correct length
    if isinstance(key, str):
        key = key.encode()
    if isinstance(iv, str):
        iv = iv.encode()
        
    # Ensure correct lengths
    key = key[:16].ljust(16, b'0')
    iv = iv[:16].ljust(16, b'0')
    
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad and encrypt
    padded_data = pad(shellcode_bytes)
    encrypted_data = cipher.encrypt(padded_data)
    
    # Return base64 encoded result and the key/IV used
    return {
        'encrypted': base64.b64encode(encrypted_data).decode(),
        'key': key,
        'iv': iv,
        'key_str': key.decode('latin1'),  # For embedding in C++ code
        'iv_str': iv.decode('latin1')    # For embedding in C++ code
    }

def decrypt_shellcode(encrypted_b64, key=None, iv=None):
    """
    Decrypt base64 encoded, AES encrypted shellcode
    Args:
        encrypted_b64: Base64 encoded, AES encrypted shellcode
        key: Optional AES key (16 bytes)
        iv: Optional AES IV (16 bytes)
    Returns:
        Raw shellcode bytes
    """
    # Use provided key/IV or default ones
    key = key or DEFAULT_KEY
    iv = iv or DEFAULT_IV
    
    # Ensure key and IV are bytes and correct length
    if isinstance(key, str):
        key = key.encode()
    if isinstance(iv, str):
        iv = iv.encode()
        
    # Ensure correct lengths
    key = key[:16].ljust(16, b'0')
    iv = iv[:16].ljust(16, b'0')
    
    # Decode base64
    encrypted_data = base64.b64decode(encrypted_b64)
    
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)

if __name__ == "__main__":
    # Test encryption/decryption with random key
    test_data = b"\x90\x90\x90\x90\xcc\xc3"  # Simple shellcode (NOP sled + INT3 + RET)
    
    # Generate random key and IV
    random_key = generate_random_key(16)
    random_iv = generate_random_key(16)
    print(f"Random Key: {random_key}")
    print(f"Random IV: {random_iv}")
    
    # Encrypt with random key/IV
    result = encrypt_shellcode(test_data, random_key, random_iv)
    encrypted = result['encrypted']
    print(f"Encrypted: {encrypted}")
    
    # Decrypt with same key/IV
    decrypted = decrypt_shellcode(encrypted, random_key, random_iv)
    print(f"Decrypted: {decrypted.hex()}")
    
    assert decrypted == test_data, "Encryption/decryption test failed!"
    print("Encryption/decryption test with random key passed!") 