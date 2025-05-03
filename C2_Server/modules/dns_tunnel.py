import os
import sys
import time
import base64
import socket
import struct
import random
import logging
import threading
from typing import Optional, Tuple, List
import queue
import dns.resolver
import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class DNSTunnelConfig:
    def __init__(self, domain: str, encryption_key: Optional[str] = None):
        self.domain = domain
        self.chunk_size = 30  # Max size for DNS label
        self.max_retries = 3
        self.timeout = 5
        self.encryption_key = self._setup_encryption(encryption_key)
        
    def _setup_encryption(self, key: Optional[str]) -> bytes:
        if key:
            # Generate encryption key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'dnstunnel_salt',  # In production, use random salt
                iterations=100000,
            )
            return base64.urlsafe_b64encode(kdf.derive(key.encode()))
        return Fernet.generate_key()

class DNSTunnelServer:
    def __init__(self, config: DNSTunnelConfig):
        self.config = config
        self.fernet = Fernet(self.config.encryption_key)
        self.message_queue = queue.Queue()
        self.response_cache = {}
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('dns_tunnel.log'),
                logging.StreamHandler()
            ]
        )
        
    def start(self, port: int = 53):
        """Start DNS tunnel server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', port))
            logging.info(f"DNS tunnel server started on port {port}")
            
            # Start processing thread
            self.processing = True
            self.process_thread = threading.Thread(target=self._process_queue)
            self.process_thread.daemon = True
            self.process_thread.start()
            
            while True:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    threading.Thread(target=self._handle_query, args=(data, addr)).start()
                except Exception as e:
                    logging.error(f"Error handling DNS query: {str(e)}")
                    
        except Exception as e:
            logging.error(f"Server error: {str(e)}")
        finally:
            self.cleanup()
            
    def cleanup(self):
        """Cleanup resources"""
        self.processing = False
        if hasattr(self, 'sock'):
            self.sock.close()
            
    def _handle_query(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming DNS query"""
        try:
            query = dns.message.from_wire(data)
            
            # Process only if it's our domain
            qname = str(query.question[0].name)
            if not qname.endswith(self.config.domain + '.'):
                return
                
            # Extract encoded data from subdomain
            encoded_data = qname[0:-(len(self.config.domain) + 2)]
            chunks = encoded_data.split('.')
            
            # Reconstruct and decrypt data
            data = self._reconstruct_data(chunks)
            if data:
                # Add to processing queue
                self.message_queue.put((data, addr))
                
            # Send acknowledgment
            response = self._create_response(query)
            self.sock.sendto(response.to_wire(), addr)
            
        except Exception as e:
            logging.error(f"Error processing DNS query: {str(e)}")
            
    def _reconstruct_data(self, chunks: List[str]) -> Optional[bytes]:
        """Reconstruct and decrypt data from DNS chunks"""
        try:
            # Join chunks and decode
            data = ''.join(chunks)
            decoded = base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))
            
            # Decrypt
            return self.fernet.decrypt(decoded)
        except Exception as e:
            logging.error(f"Error reconstructing data: {str(e)}")
            return None
            
    def _create_response(self, query: dns.message.Message) -> dns.message.Message:
        """Create DNS response"""
        response = dns.message.make_response(query)
        response.flags |= dns.flags.QR
        return response
        
    def _process_queue(self):
        """Process received messages"""
        while self.processing:
            try:
                data, addr = self.message_queue.get(timeout=1)
                self._handle_message(data, addr)
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error processing message: {str(e)}")
                
    def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle reconstructed message"""
        try:
            message = data.decode()
            logging.info(f"Received message from {addr}: {message}")
            # Handle command/data as needed
            # Add your command processing logic here
        except Exception as e:
            logging.error(f"Error handling message: {str(e)}")

class DNSTunnelClient:
    def __init__(self, config: DNSTunnelConfig):
        self.config = config
        self.fernet = Fernet(self.config.encryption_key)
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message_s)s',
            handlers=[
                logging.FileHandler('dns_tunnel_client.log'),
                logging.StreamHandler()
            ]
        )
        
    def send(self, data: str) -> bool:
        """Send data through DNS tunnel"""
        try:
            # Encrypt data
            encrypted = self.fernet.encrypt(data.encode())
            encoded = base64.urlsafe_b64encode(encrypted).decode()
            
            # Split into chunks
            chunks = self._chunk_data(encoded)
            
            # Send chunks as DNS queries
            for chunk in chunks:
                if not self._send_chunk(chunk):
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Error sending data: {str(e)}")
            return False
            
    def _chunk_data(self, data: str) -> List[str]:
        """Split data into DNS-compatible chunks"""
        return [data[i:i+self.config.chunk_size] 
                for i in range(0, len(data), self.config.chunk_size)]
                
    def _send_chunk(self, chunk: str) -> bool:
        """Send single chunk as DNS query"""
        for attempt in range(self.config.max_retries):
            try:
                # Create DNS query
                query = f"{chunk}.{self.config.domain}"
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.config.timeout
                resolver.lifetime = self.config.timeout
                
                # Send query
                resolver.resolve(query, 'A')
                return True
                
            except Exception as e:
                logging.error(f"Error sending chunk (attempt {attempt+1}): {str(e)}")
                time.sleep(random.uniform(0.1, 0.5))
                
        return False

def create_server(domain: str, encryption_key: Optional[str] = None) -> DNSTunnelServer:
    """Create and return a configured DNS tunnel server"""
    config = DNSTunnelConfig(domain, encryption_key)
    return DNSTunnelServer(config)

def create_client(domain: str, encryption_key: Optional[str] = None) -> DNSTunnelClient:
    """Create and return a configured DNS tunnel client"""
    config = DNSTunnelConfig(domain, encryption_key)
    return DNSTunnelClient(config)

if __name__ == "__main__":
    # Example usage
    domain = "example.com"  # Replace with your domain
    encryption_key = "your-secret-key"  # Replace with your key
    
    # Server example
    server = create_server(domain, encryption_key)
    server.start()
    
    # Client example
    client = create_client(domain, encryption_key)
    client.send("Hello from DNS tunnel!") 