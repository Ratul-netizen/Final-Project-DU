"""
DNS Tunneling core implementation
"""
import socket
import dns.resolver
import dns.message
import dns.name
import base64
import logging

class DNSTunnel:
    def __init__(self, domain):
        self.domain = domain
        self.socket = None
        self.running = False
        
    def start(self):
        self.running = True
        
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
            
    def encode_data(self, data):
        return base64.b64encode(data.encode()).decode()
        
    def decode_data(self, data):
        return base64.b64decode(data.encode()).decode()

def create_server(domain="example.com", port=53):
    tunnel = DNSTunnel(domain)
    return tunnel

def create_client(domain="example.com", nameserver="8.8.8.8"):
    tunnel = DNSTunnel(domain)
    return tunnel 