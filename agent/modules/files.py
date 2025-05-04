import os
import base64
import logging
from datetime import datetime

def list_directory(path='.'):
    """List contents of a directory"""
    try:
        items = []
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            try:
                stats = os.stat(full_path)
                items.append({
                    'name': item,
                    'path': full_path,
                    'size': stats.st_size,
                    'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                    'type': 'directory' if os.path.isdir(full_path) else 'file'
                })
            except Exception as e:
                logging.error(f"Error getting stats for {full_path}: {str(e)}")
                
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'path': os.path.abspath(path),
            'items': items
        }
    except Exception as e:
        logging.error(f"Error listing directory: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def read_file(path):
    """Read contents of a file"""
    try:
        with open(path, 'rb') as f:
            data = base64.b64encode(f.read()).decode()
            
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'path': path,
            'data': data,
            'size': os.path.getsize(path)
        }
    except Exception as e:
        logging.error(f"Error reading file: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def write_file(path, data, is_base64=True):
    """Write data to a file"""
    try:
        mode = 'wb' if is_base64 else 'w'
        with open(path, mode) as f:
            if is_base64:
                f.write(base64.b64decode(data))
            else:
                f.write(data)
                
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'path': path,
            'size': os.path.getsize(path)
        }
    except Exception as e:
        logging.error(f"Error writing file: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def delete_file(path):
    """Delete a file"""
    try:
        os.remove(path)
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'path': path,
            'message': f'File {path} deleted successfully'
        }
    except Exception as e:
        logging.error(f"Error deleting file: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        } 