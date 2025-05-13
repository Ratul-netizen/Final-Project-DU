#!/usr/bin/env python3
import os
import sys
import time
import base64
import socket
import struct
import random
import logging
import threading
import queue
import dns.resolver
import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
from typing import Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class DNSTunnel:
    def __init__(self, domain: str, encryption_key: Optional[str] = None):
        self.domain = domain
        self.chunk_size = 30  # Max size for DNS label
        self.max_retries = 3
        self.timeout = 5
        self.encryption_key = self._setup_encryption(encryption_key)
        self.message_queue = queue.Queue()
        self.running = False
        self.logger = logging.getLogger('DNSTunnel')
        
    def _setup_encryption(self, key=None):
        """Setup encryption key using PBKDF2"""
        if not key:
            key = base64.b64encode(os.urandom(32)).decode()
            
        salt = b'dns_tunnel_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_bytes = key.encode() if isinstance(key, str) else key
        derived_key = base64.b64encode(kdf.derive(key_bytes))
        return Fernet(derived_key)

    def start(self, port=53):
        """Start DNS tunnel server"""
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, args=(port,))
        self.server_thread.daemon = True
        self.server_thread.start()
        self.logger.info(f"DNS tunnel server started on port {port}")

    def stop(self):
        """Stop DNS tunnel server"""
        self.running = False
        if hasattr(self, 'server_thread'):
            self.server_thread.join()
        self.logger.info("DNS tunnel server stopped")

    def _run_server(self, port):
        """Run DNS server"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.bind(('0.0.0.0', port))
            server_socket.settimeout(1)
            
            while self.running:
                try:
                    data, addr = server_socket.recvfrom(4096)
                    response = self._handle_dns_query(data)
                    if response:
                        server_socket.sendto(response, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error handling DNS query: {e}")
                    
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            server_socket.close()

    def _handle_dns_query(self, data):
        """Handle incoming DNS query"""
        try:
            query = dns.message.from_wire(data)
            response = dns.message.make_response(query)
            
            if len(query.question) > 0:
                qname = str(query.question[0].name)
                if self.domain in qname:
                    # Extract data from subdomain
                    data = self._extract_data_from_query(qname)
                    if data:
                        self.message_queue.put((data, time.time()))
                        
                    # Create response
                    response.answer.append(self._create_response_record(query.question[0].name))
                    
            return response.to_wire()
        except Exception as e:
            self.logger.error(f"Error processing DNS query: {e}")
            return None

    def _extract_data_from_query(self, qname):
        """Extract and decrypt data from DNS query"""
        try:
            # Remove domain suffix
            data = qname.replace(f".{self.domain}.", "")
            
            # Decode base32 data from subdomains
            parts = data.split('.')
            assembled_data = ''
            for part in parts:
                try:
                    decoded = base64.b32decode(part.upper())
                    assembled_data += decoded.decode()
                except:
                    continue
                    
            # Decrypt if encryption is used
            if assembled_data and self.encryption_key:
                try:
                    decrypted = self.encryption_key.decrypt(assembled_data.encode())
                    return decrypted.decode()
                except:
                    return assembled_data
                    
            return assembled_data
        except Exception as e:
            self.logger.error(f"Error extracting data: {e}")
            return None

    def _create_response_record(self, qname):
        """Create DNS response record"""
        return dns.rrset.from_text(
            qname, 300, dns.rdataclass.IN, dns.rdatatype.TXT, '"ok"'
        )

    def send_data(self, data):
        """Send data through DNS tunnel"""
        if not isinstance(data, str):
            data = str(data)
            
        # Encrypt if key available
        if self.encryption_key:
            data = self.encryption_key.encrypt(data.encode()).decode()
            
        # Split into chunks that fit DNS labels
        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i + self.chunk_size]
            # Encode chunk to base32 and make DNS-safe
            encoded = base64.b32encode(chunk.encode()).decode().lower().rstrip('=')
            chunks.append(encoded)
            
        # Create DNS query
        subdomain = '.'.join(chunks)
        domain = f"{subdomain}.{self.domain}"
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            for _ in range(self.max_retries):
                try:
                    resolver.resolve(domain, 'TXT')
                    return True
                except dns.exception.Timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error sending data: {e}")
                    break
                    
            return False
        except Exception as e:
            self.logger.error(f"Error initializing resolver: {e}")
            return False

    def receive_data(self, timeout=1):
        """Receive data from the tunnel"""
        try:
            data, timestamp = self.message_queue.get(timeout=timeout)
            return data
        except queue.Empty:
            return None

    def flush_queue(self):
        """Clear message queue"""
        while not self.message_queue.empty():
            self.message_queue.get_nowait()

def create_server(domain: str, encryption_key: Optional[str] = None) -> DNSTunnel:
    """Create and return a configured DNS tunnel server"""
    return DNSTunnel(domain, encryption_key)

def create_client(domain: str, encryption_key: Optional[str] = None) -> DNSTunnel:
    """Create and return a configured DNS tunnel client"""
    return DNSTunnel(domain, encryption_key)

if __name__ == "__main__":
    # Example usage
    domain = "example.com"  # Replace with your domain
    encryption_key = "your-secret-key"  # Replace with your key
    
    # Server example
    server = create_server(domain, encryption_key)
    server.start()
    
    # Client example
    client = create_client(domain, encryption_key)
    client.send_data("Hello from DNS tunnel!") 