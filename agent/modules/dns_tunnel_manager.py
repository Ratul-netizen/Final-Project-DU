#!/usr/bin/env python3
"""
DNS Tunnel Manager
Manages DNS tunneling operations including start, stop, and status
"""

import logging
from datetime import datetime
from .dns_tunnel import DNSTunnel, start_dns_tunnel

# Global tunnel instance
_active_tunnel = None

def get_dns_tunnel_status():
    """Get the current DNS tunnel status"""
    global _active_tunnel
    
    if _active_tunnel is None:
        return {
            'status': 'success',
            'data': {
                'tunnel_active': False,
                'message': 'No DNS tunnel running'
            },
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_status'
        }
    
    return {
        'status': 'success',
        'data': {
            'tunnel_active': _active_tunnel.running,
            'domain': _active_tunnel.domain,
            'buffer_size': len(_active_tunnel.buffer),
            'max_buffer_size': _active_tunnel.max_buffer_size
        },
        'timestamp': datetime.now().isoformat(),
        'type': 'dns_tunnel_status'
    }

def start_dns_tunnel_cmd(domain):
    """Start a DNS tunnel with proper management"""
    global _active_tunnel
    
    if _active_tunnel and _active_tunnel.running:
        return {
            'status': 'error',
            'error': 'DNS tunnel already running',
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_start'
        }
    
    try:
        # Create a new tunnel instance for management
        _active_tunnel = DNSTunnel(domain)
        result = _active_tunnel.start()
        
        return {
            'status': result['status'],
            'data': result.get('message', result.get('error', 'Unknown result')),
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_start'
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': f'Failed to start DNS tunnel: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_start'
        }

def stop_dns_tunnel_cmd():
    """Stop the active DNS tunnel"""
    global _active_tunnel
    
    if not _active_tunnel or not _active_tunnel.running:
        return {
            'status': 'error',
            'error': 'No DNS tunnel running',
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_stop'
        }
    
    try:
        result = _active_tunnel.stop()
        _active_tunnel = None
        
        return {
            'status': 'success',
            'data': 'DNS tunnel stopped successfully',
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_stop'
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': f'Failed to stop DNS tunnel: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_stop'
        }

def send_data_through_tunnel(data):
    """Send data through the active DNS tunnel"""
    global _active_tunnel
    
    if not _active_tunnel or not _active_tunnel.running:
        return {
            'status': 'error',
            'error': 'No DNS tunnel running',
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_send'
        }
    
    try:
        success = _active_tunnel.send_data(data)
        if success:
            return {
                'status': 'success',
                'data': f'Data sent through DNS tunnel: {len(data)} bytes',
                'timestamp': datetime.now().isoformat(),
                'type': 'dns_tunnel_send'
            }
        else:
            return {
                'status': 'error',
                'error': 'Failed to send data through tunnel',
                'timestamp': datetime.now().isoformat(),
                'type': 'dns_tunnel_send'
            }
    except Exception as e:
        return {
            'status': 'error',
            'error': f'Error sending data: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'type': 'dns_tunnel_send'
        }
