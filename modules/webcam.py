import os
import sys
import platform
import logging
import cv2
import numpy as np
import base64
import threading
import time
from datetime import datetime
import queue

class WebcamCapture:
    def __init__(self):
        self.os_type = platform.system()
        self.setup_logging()
        self.is_running = False
        self.frame_queue = queue.Queue()
        self.capture_thread = None
        self.save_thread = None
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('webcam.log'),
                logging.StreamHandler()
            ]
        )
        
    def capture_frames(self):
        """Capture frames from webcam"""
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                logging.error("Failed to open webcam")
                return
                
            while self.is_running:
                ret, frame = cap.read()
                if ret:
                    self.frame_queue.put(frame)
                else:
                    logging.error("Failed to capture frame")
                    time.sleep(1)
                    
            cap.release()
            
        except Exception as e:
            logging.error(f"Error capturing frames: {str(e)}")
            
    def save_frames(self):
        """Save captured frames to files"""
        try:
            while self.is_running:
                if not self.frame_queue.empty():
                    frame = self.frame_queue.get()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"webcam_{timestamp}.jpg"
                    
                    # Save frame as JPEG
                    cv2.imwrite(filename, frame)
                    
                    # Optional: Upload to server
                    # self.upload_frame(filename)
                    
        except Exception as e:
            logging.error(f"Error saving frames: {str(e)}")
            
    def capture_single(self):
        """Capture a single frame"""
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                logging.error("Failed to open webcam")
                return None
                
            ret, frame = cap.read()
            cap.release()
            
            if ret:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"webcam_{timestamp}.jpg"
                cv2.imwrite(filename, frame)
                return filename
            return None
            
        except Exception as e:
            logging.error(f"Error capturing single frame: {str(e)}")
            return None
            
    def start(self):
        """Start continuous webcam capture"""
        try:
            self.is_running = True
            
            # Start capture thread
            self.capture_thread = threading.Thread(target=self.capture_frames)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # Start save thread
            self.save_thread = threading.Thread(target=self.save_frames)
            self.save_thread.daemon = True
            self.save_thread.start()
            
            logging.info("Started webcam capture")
            
        except Exception as e:
            logging.error(f"Error starting webcam capture: {str(e)}")
            
    def stop(self):
        """Stop webcam capture"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join()
        if self.save_thread:
            self.save_thread.join()
        logging.info("Stopped webcam capture") 