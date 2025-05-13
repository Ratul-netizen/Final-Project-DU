import os
import base64
import logging
import tempfile
from datetime import datetime
from pathlib import Path

# Constants
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB limit for file operations

def validate_path(path):
    """Validate and normalize file path"""
    try:
        # Convert to absolute path
        abs_path = os.path.abspath(path)
        # Check if path exists
        if not os.path.exists(abs_path):
            return False, f"Path does not exist: {path}"
        # Additional security checks can be added here
        return True, abs_path
    except Exception as e:
        return False, str(e)

def list_directory(path='.'):
    """List contents of a directory"""
    try:
        # Validate path
        valid, result = validate_path(path)
        if not valid:
            return {
                'status': 'error',
                'error': result,
                'timestamp': datetime.now().isoformat()
            }
        
        path = result
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
                    'type': 'directory' if os.path.isdir(full_path) else 'file',
                    'permissions': oct(stats.st_mode)[-3:]
                })
            except Exception as e:
                logging.error(f"Error getting stats for {full_path}: {str(e)}")
        
        logging.info(f"Successfully listed directory: {path} ({len(items)} items)")
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'path': path,
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
        # Validate path
        valid, result = validate_path(path)
        if not valid:
            return {
                'status': 'error',
                'error': result,
                'timestamp': datetime.now().isoformat()
            }
        
        path = result
        file_size = os.path.getsize(path)
        
        # Check file size
        if file_size > MAX_FILE_SIZE:
            error_msg = f"File size ({file_size} bytes) exceeds maximum allowed size ({MAX_FILE_SIZE} bytes)"
            logging.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
            
        with open(path, 'rb') as f:
            data = base64.b64encode(f.read()).decode()
        
        logging.info(f"Successfully read file: {path} ({file_size} bytes)")
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'path': path,
            'data': data,
            'size': file_size
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
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        
        # Write to temporary file first
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            if is_base64:
                decoded_data = base64.b64decode(data)
                # Check decoded size
                if len(decoded_data) > MAX_FILE_SIZE:
                    error_msg = f"Decoded data size exceeds maximum allowed size ({MAX_FILE_SIZE} bytes)"
                    logging.error(error_msg)
                    return {
                        'status': 'error',
                        'error': error_msg,
                        'timestamp': datetime.now().isoformat()
                    }
                temp_file.write(decoded_data)
            else:
                if len(data.encode()) > MAX_FILE_SIZE:
                    error_msg = f"Data size exceeds maximum allowed size ({MAX_FILE_SIZE} bytes)"
                    logging.error(error_msg)
                    return {
                        'status': 'error',
                        'error': error_msg,
                        'timestamp': datetime.now().isoformat()
                    }
                temp_file.write(data.encode())
        
        # Move temporary file to target location
        os.replace(temp_file.name, path)
        
        file_size = os.path.getsize(path)
        logging.info(f"Successfully wrote file: {path} ({file_size} bytes)")
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'path': path,
            'size': file_size
        }
    except Exception as e:
        # Clean up temp file if it exists
        if 'temp_file' in locals():
            try:
                os.unlink(temp_file.name)
            except:
                pass
        logging.error(f"Error writing file: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def delete_file(path):
    """Delete a file"""
    try:
        # Validate path
        valid, result = validate_path(path)
        if not valid:
            return {
                'status': 'error',
                'error': result,
                'timestamp': datetime.now().isoformat()
            }
        
        path = result
        if os.path.isdir(path):
            error_msg = f"Cannot delete directory using delete_file: {path}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
            
        os.remove(path)
        logging.info(f"Successfully deleted file: {path}")
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