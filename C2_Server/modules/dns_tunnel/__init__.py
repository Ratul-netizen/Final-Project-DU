"""
DNS Tunneling module for covert communications
"""
from .. import dns_tunnel
from ..dns_tunnel import DNSTunnel, create_server, create_client

__all__ = ['DNSTunnel', 'create_server', 'create_client'] 