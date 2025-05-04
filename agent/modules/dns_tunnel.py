import socket
import base64
import logging
import threading
import time
from datetime import datetime

class DNSTunnel:
    def __init__(self, domain):
        self.domain = domain
        self.running = False
        self.tunnel_thread = None
        self.buffer = []
        
    def encode_data(self, data):
        """Encode data for DNS transmission"""
        return base64.b32encode(data.encode()).decode().strip('=').lower()
        
    def decode_data(self, data):
        """Decode DNS transmitted data"""
        padding = '=' * (8 - (len(data) % 8))
        return base64.b32decode(data.upper() + padding).decode()
        
    def create_dns_query(self, data):
        """Create a DNS query with encoded data"""
        encoded = self.encode_data(data)
        return f"{encoded}.{self.domain}"
        
    def extract_data(self, response):
        """Extract data from DNS response"""
        try:
            if response.startswith(self.domain):
                encoded = response.replace(self.domain, '').strip('.')
                return self.decode_data(encoded)
        except:
            return None
        return None
        
    def send_data(self, data):
        """Send data through DNS tunnel"""
        try:
            query = self.create_dns_query(data)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(query.encode(), ('8.8.8.8', 53))
            return True
        except Exception as e:
            logging.error(f"Error sending data: {str(e)}")
            return False
            
    def receive_data(self):
        """Receive data from DNS tunnel"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', 53))
            while self.running:
                data, addr = sock.recvfrom(1024)
                response = data.decode()
                extracted = self.extract_data(response)
                if extracted:
                    self.buffer.append(extracted)
        except Exception as e:
            logging.error(f"Error receiving data: {str(e)}")
            
    def start(self):
        """Start the DNS tunnel"""
        if not self.running:
            self.running = True
            self.tunnel_thread = threading.Thread(target=self.receive_data)
            self.tunnel_thread.daemon = True
            self.tunnel_thread.start()
            return {
                'status': 'success',
                'message': f'DNS tunnel started with domain {self.domain}',
                'timestamp': datetime.now().isoformat()
            }
        return {
            'status': 'error',
            'error': 'DNS tunnel already running',
            'timestamp': datetime.now().isoformat()
        }
        
    def stop(self):
        """Stop the DNS tunnel"""
        if self.running:
            self.running = False
            if self.tunnel_thread:
                self.tunnel_thread.join(timeout=5)
            return {
                'status': 'success',
                'message': 'DNS tunnel stopped',
                'timestamp': datetime.now().isoformat()
            }
        return {
            'status': 'error',
            'error': 'DNS tunnel not running',
            'timestamp': datetime.now().isoformat()
        }

def start_dns_tunnel(domain):
    """Start a new DNS tunnel"""
    try:
        tunnel = DNSTunnel(domain)
        result = tunnel.start()
        if result['status'] == 'success':
            return {
                'status': 'success',
                'message': f'DNS tunnel established with {domain}',
                'timestamp': datetime.now().isoformat()
            }
        return result
    except Exception as e:
        logging.error(f"Error starting DNS tunnel: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        } 