"""File operations functionality"""
import os
import base64
import shutil
from datetime import datetime
import logging
from pathlib import Path

def sanitize_path(path):
    """
    Sanitize and validate file path
    Args:
        path (str): Path to sanitize
    Returns:
        str: Sanitized absolute path
    Raises:
        ValueError: If path is invalid or attempts directory traversal
    """
    try:
        # Convert to absolute path
        abs_path = os.path.abspath(path)
        
        # Get the workspace root (adjust this based on your setup)
        workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        
        # Check if path is within workspace
        if not abs_path.startswith(workspace_root):
            raise ValueError("Access denied: Path outside workspace")
            
        return abs_path
        
    except Exception as e:
        raise ValueError(f"Invalid path: {str(e)}")

def read_file(path, offset=0, length=None):
    """
    Read contents of a file
    Args:
        path (str): Path to the file
        offset (int): Starting offset in bytes
        length (int): Number of bytes to read (None for entire file)
    Returns:
        dict: File contents and metadata
    """
    try:
        # Sanitize path
        safe_path = sanitize_path(path)
        
        # Check if file exists
        if not os.path.exists(safe_path):
            return {
                'status': 'error',
                'message': 'File does not exist'
            }
            
        # Check if path is a file
        if not os.path.isfile(safe_path):
            return {
                'status': 'error',
                'message': 'Path is not a file'
            }
            
        # Get file size
        file_size = os.path.getsize(safe_path)
        
        # Validate offset
        if offset < 0 or offset > file_size:
            return {
                'status': 'error',
                'message': 'Invalid offset'
            }
            
        # Read file
        with open(safe_path, 'rb') as f:
            f.seek(offset)
            data = f.read(length) if length is not None else f.read()
            
        # Convert to base64
        encoded_data = base64.b64encode(data).decode()
        
        return {
            'status': 'success',
            'path': safe_path,
            'size': file_size,
            'offset': offset,
            'length': len(data),
            'data': encoded_data
        }
        
    except ValueError as e:
        return {
            'status': 'error',
            'message': str(e)
        }
    except Exception as e:
        logging.error(f"Error reading file: {str(e)}")
        return {
            'status': 'error',
            'message': 'Internal server error'
        }

def write_file(path, data, mode='wb'):
    """
    Write data to a file
    Args:
        path (str): Path to the file
        data (str): Base64 encoded data to write
        mode (str): Write mode ('wb' for binary, 'ab' for append)
    Returns:
        dict: Operation status
    """
    try:
        # Sanitize path
        safe_path = sanitize_path(path)
        
        # Validate mode
        if mode not in ['wb', 'ab']:
            return {
                'status': 'error',
                'message': 'Invalid write mode'
            }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        
        # Decode base64 data
        try:
            binary_data = base64.b64decode(data)
        except Exception:
            return {
                'status': 'error',
                'message': 'Invalid base64 data'
            }
        
        # Write file
        with open(safe_path, mode) as f:
            f.write(binary_data)
            
        return {
            'status': 'success',
            'path': safe_path,
            'size': len(binary_data)
        }
        
    except ValueError as e:
        return {
            'status': 'error',
            'message': str(e)
        }
    except Exception as e:
        logging.error(f"Error writing file: {str(e)}")
        return {
            'status': 'error',
            'message': 'Internal server error'
        }

def delete_file(path):
    """
    Delete a file or directory
    Args:
        path (str): Path to delete
    Returns:
        dict: Operation status
    """
    try:
        # Sanitize path
        safe_path = sanitize_path(path)
        
        if not os.path.exists(safe_path):
            return {
                'status': 'error',
                'message': 'Path does not exist'
            }
            
        if os.path.isdir(safe_path):
            shutil.rmtree(safe_path)
        else:
            os.remove(safe_path)
            
        return {
            'status': 'success',
            'message': f'Deleted {safe_path}'
        }
        
    except ValueError as e:
        return {
            'status': 'error',
            'message': str(e)
        }
    except Exception as e:
        logging.error(f"Error deleting file: {str(e)}")
        return {
            'status': 'error',
            'message': 'Internal server error'
        }

def download_file(path, chunk_size=8192):
    """
    Read a file in chunks for downloading
    Args:
        path (str): Path to the file
        chunk_size (int): Size of each chunk in bytes
    Returns:
        generator: Yields chunks of file data
    """
    try:
        # Sanitize path
        safe_path = sanitize_path(path)
        
        # Validate path
        if not os.path.exists(safe_path):
            yield {
                'status': 'error',
                'message': 'File does not exist'
            }
            return
            
        if not os.path.isfile(safe_path):
            yield {
                'status': 'error',
                'message': 'Path is not a file'
            }
            return
            
        with open(safe_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield base64.b64encode(chunk).decode()
                
    except ValueError as e:
        yield {
            'status': 'error',
            'message': str(e)
        }
    except Exception as e:
        logging.error(f"Error downloading file: {str(e)}")
        yield {
            'status': 'error',
            'message': 'Internal server error'
        }

def upload_file(path, chunk):
    """
    Write a chunk of data during file upload
    Args:
        path (str): Path to the file
        chunk (str): Base64 encoded chunk of data
    Returns:
        dict: Operation status
    """
    try:
        # Sanitize path
        safe_path = sanitize_path(path)
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        
        # Decode chunk
        try:
            binary_chunk = base64.b64decode(chunk)
        except Exception:
            return {
                'status': 'error',
                'message': 'Invalid base64 data'
            }
        
        # Append to file
        with open(safe_path, 'ab') as f:
            f.write(binary_chunk)
            
        return {
            'status': 'success',
            'path': safe_path,
            'chunk_size': len(binary_chunk)
        }
        
    except ValueError as e:
        return {
            'status': 'error',
            'message': str(e)
        }
    except Exception as e:
        logging.error(f"Error uploading file: {str(e)}")
        return {
            'status': 'error',
            'message': 'Internal server error'
        } 