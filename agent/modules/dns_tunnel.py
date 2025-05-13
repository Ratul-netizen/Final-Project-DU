import socket
import base64
import logging
import threading
import time
from datetime import datetime
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def validate_domain(domain):
    """Validate domain name format"""
    try:
        if not domain:
            return False, "Domain name is required"
        # Basic domain validation regex
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            return False, "Invalid domain name format"
        return True, domain
    except Exception as e:
        return False, f"Domain validation error: {str(e)}"

class DNSTunnel:
    def __init__(self, domain):
        self.domain = domain
        self.running = False
        self.tunnel_thread = None
        self.buffer = []
        self.max_buffer_size = 1000  # Limit buffer size
        
    def encode_data(self, data):
        """Encode data for DNS transmission"""
        try:
            return base64.b32encode(data.encode()).decode().strip('=').lower()
        except Exception as e:
            logging.error(f"Data encoding error: {str(e)}")
            return None
        
    def decode_data(self, data):
        """Decode DNS transmitted data"""
        try:
            padding = '=' * (8 - (len(data) % 8))
            return base64.b32decode(data.upper() + padding).decode()
        except Exception as e:
            logging.error(f"Data decoding error: {str(e)}")
            return None
        
    def create_dns_query(self, data):
        """Create a DNS query with encoded data"""
        try:
            encoded = self.encode_data(data)
            if encoded:
                return f"{encoded}.{self.domain}"
            return None
        except Exception as e:
            logging.error(f"DNS query creation error: {str(e)}")
            return None
        
    def extract_data(self, response):
        """Extract data from DNS response"""
        try:
            if response.startswith(self.domain):
                encoded = response.replace(self.domain, '').strip('.')
                return self.decode_data(encoded)
        except Exception as e:
            logging.error(f"Data extraction error: {str(e)}")
        return None
        
    def send_data(self, data):
        """Send data through DNS tunnel"""
        try:
            query = self.create_dns_query(data)
            if not query:
                return False
                
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)  # Set timeout
            sock.sendto(query.encode(), ('8.8.8.8', 53))
            logging.info(f"Data sent through DNS tunnel: {len(data)} bytes")
            return True
        except Exception as e:
            logging.error(f"Error sending data: {str(e)}")
            return False
            
    def receive_data(self):
        """Receive data from DNS tunnel"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)  # Set timeout for responsive shutdown
            sock.bind(('0.0.0.0', 53))
            
            logging.info("DNS tunnel receiver started")
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(1024)
                    response = data.decode()
                    extracted = self.extract_data(response)
                    if extracted:
                        self.buffer.append({
                            'data': extracted,
                            'timestamp': datetime.now().isoformat(),
                            'source': addr[0]
                        })
                        # Limit buffer size
                        if len(self.buffer) > self.max_buffer_size:
                            self.buffer = self.buffer[-self.max_buffer_size:]
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Error processing received data: {str(e)}")
                    
        except Exception as e:
            logging.error(f"Error in receive loop: {str(e)}")
        finally:
            try:
                sock.close()
            except:
                pass
            
    def start(self):
        """Start the DNS tunnel"""
        if not self.running:
            try:
                self.running = True
                self.tunnel_thread = threading.Thread(target=self.receive_data)
                self.tunnel_thread.daemon = True
                self.tunnel_thread.start()
                
                logging.info(f"DNS tunnel started with domain {self.domain}")
                return {
                    'status': 'success',
                    'message': f'DNS tunnel started with domain {self.domain}',
                    'timestamp': datetime.now().isoformat()
                }
            except Exception as e:
                self.running = False
                error_msg = f"Failed to start DNS tunnel: {str(e)}"
                logging.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
        
        error_msg = 'DNS tunnel already running'
        logging.warning(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        }
        
    def stop(self):
        """Stop the DNS tunnel"""
        if self.running:
            try:
                self.running = False
                if self.tunnel_thread:
                    self.tunnel_thread.join(timeout=5)
                    
                logging.info("DNS tunnel stopped")
                return {
                    'status': 'success',
                    'message': 'DNS tunnel stopped',
                    'timestamp': datetime.now().isoformat(),
                    'data': {
                        'buffered_messages': len(self.buffer)
                    }
                }
            except Exception as e:
                error_msg = f"Error stopping DNS tunnel: {str(e)}"
                logging.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
        
        error_msg = 'DNS tunnel not running'
        logging.warning(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        }

def start_dns_tunnel(domain):
    """Start a new DNS tunnel"""
    try:
        # Validate domain
        valid, result = validate_domain(domain)
        if not valid:
            return {
                'status': 'error',
                'error': result,
                'timestamp': datetime.now().isoformat()
            }
            
        tunnel = DNSTunnel(domain)
        result = tunnel.start()
        
        if result['status'] == 'success':
            return {
                'status': 'success',
                'message': f'DNS tunnel established with {domain}',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'domain': domain,
                    'buffer_size': tunnel.max_buffer_size
                }
            }
        return result
        
    except Exception as e:
        error_msg = f"Error starting DNS tunnel: {str(e)}"
        logging.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        } 