#!/usr/bin/env python
from Cryptodome.Cipher import AES
import base64
import os

# AES key and IV (must match client-side values in C++ template)
KEY = b"ThisIsASecretKey"  # 16 bytes
IV = b"ThisIsInitVector"   # 16 bytes

def pad(data):
    """PKCS#7 padding for AES"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove PKCS#7 padding"""
    return data[:-data[-1]]

def encrypt_shellcode(shellcode_bytes):
    """
    Encrypt shellcode using AES-128-CBC
    Args:
        shellcode_bytes: Raw shellcode bytes
    Returns:
        Base64 encoded encrypted shellcode
    """
    # Create AES cipher
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    # Pad and encrypt
    padded_data = pad(shellcode_bytes)
    encrypted_data = cipher.encrypt(padded_data)
    
    # Return base64 encoded result
    return base64.b64encode(encrypted_data).decode()

def decrypt_shellcode(encrypted_b64):
    """
    Decrypt base64 encoded, AES encrypted shellcode
    Args:
        encrypted_b64: Base64 encoded, AES encrypted shellcode
    Returns:
        Raw shellcode bytes
    """
    # Decode base64
    encrypted_data = base64.b64decode(encrypted_b64)
    
    # Create AES cipher
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    # Decrypt and unpad
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)

if __name__ == "__main__":
    # Test encryption/decryption
    test_data = b"\x90\x90\x90\x90\xcc\xc3"  # Simple shellcode (NOP sled + INT3 + RET)
    encrypted = encrypt_shellcode(test_data)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt_shellcode(encrypted)
    print(f"Decrypted: {decrypted.hex()}")
    
    assert decrypted == test_data, "Encryption/decryption test failed!"
    print("Encryption/decryption test passed!") 