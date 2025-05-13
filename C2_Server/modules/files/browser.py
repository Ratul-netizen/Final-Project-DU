"""File browser functionality"""
import os
import stat
from datetime import datetime
import platform

def list_directory(path='.'):
    """
    List contents of a directory
    Args:
        path (str): Path to list (default: current directory)
    Returns:
        dict: Directory listing with file/folder information
    """
    try:
        # Normalize path for the current OS
        path = os.path.normpath(path)
        
        # Get absolute path
        abs_path = os.path.abspath(path)
        
        # Check if path exists
        if not os.path.exists(abs_path):
            return {
                'status': 'error',
                'message': 'Path does not exist'
            }
            
        # Check if path is a directory
        if not os.path.isdir(abs_path):
            return {
                'status': 'error',
                'message': 'Path is not a directory'
            }
            
        # List contents
        contents = []
        for item in os.listdir(abs_path):
            item_path = os.path.join(abs_path, item)
            contents.append(get_file_info(item_path))
            
        return {
            'status': 'success',
            'path': abs_path,
            'parent': os.path.dirname(abs_path),
            'contents': contents
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

def get_file_info(path):
    """
    Get detailed information about a file or directory
    Args:
        path (str): Path to the file or directory
    Returns:
        dict: File/directory information
    """
    try:
        # Get file stats
        stats = os.stat(path)
        
        # Basic info
        info = {
            'name': os.path.basename(path),
            'path': path,
            'type': 'directory' if os.path.isdir(path) else 'file',
            'size': stats.st_size,
            'created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stats.st_atime).isoformat(),
            'permissions': stat.filemode(stats.st_mode)
        }
        
        # Add Windows-specific attributes on Windows
        if platform.system() == 'Windows':
            try:
                import win32api
                import win32con
                attrs = win32api.GetFileAttributes(path)
                info['hidden'] = bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN)
                info['system'] = bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM)
                info['archive'] = bool(attrs & win32con.FILE_ATTRIBUTE_ARCHIVE)
            except ImportError:
                pass
                
        return info
        
    except Exception as e:
        return {
            'name': os.path.basename(path),
            'path': path,
            'error': str(e)
        } 