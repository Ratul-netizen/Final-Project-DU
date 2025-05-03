"""File operations functionality"""
import os
import base64
import shutil
from datetime import datetime
import logging

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
        # Check if file exists
        if not os.path.exists(path):
            return {
                'status': 'error',
                'message': 'File does not exist'
            }
            
        # Get file size
        file_size = os.path.getsize(path)
        
        # Validate offset
        if offset < 0 or offset > file_size:
            return {
                'status': 'error',
                'message': 'Invalid offset'
            }
            
        # Read file
        with open(path, 'rb') as f:
            f.seek(offset)
            data = f.read(length) if length is not None else f.read()
            
        # Convert to base64
        encoded_data = base64.b64encode(data).decode()
        
        return {
            'status': 'success',
            'path': path,
            'size': file_size,
            'offset': offset,
            'length': len(data),
            'data': encoded_data
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
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
        # Decode base64 data
        binary_data = base64.b64decode(data)
        
        # Write file
        with open(path, mode) as f:
            f.write(binary_data)
            
        return {
            'status': 'success',
            'path': path,
            'size': len(binary_data)
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
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
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
            
        return {
            'status': 'success',
            'message': f'Deleted {path}'
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
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
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield base64.b64encode(chunk).decode()
    except Exception as e:
        yield {
            'status': 'error',
            'message': str(e)
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
        # Decode chunk
        binary_chunk = base64.b64decode(chunk)
        
        # Append to file
        with open(path, 'ab') as f:
            f.write(binary_chunk)
            
        return {
            'status': 'success',
            'path': path,
            'chunk_size': len(binary_chunk)
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        } 