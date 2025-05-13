"""
DNS Tunneling module for covert communications
"""
from .tunnel import DNSTunnel, create_server, create_client

__all__ = ['DNSTunnel', 'create_server', 'create_client'] 