"""Webcam capture functionality for surveillance module"""
import cv2
import base64
import numpy as np
from datetime import datetime

def capture_webcam(camera_index=0):
    """
    Capture an image from the webcam
    Args:
        camera_index (int): Index of the camera to use (default: 0)
    Returns:
        dict: Status and base64 encoded image data
    """
    try:
        # Initialize the webcam
        cap = cv2.VideoCapture(camera_index)
        
        if not cap.isOpened():
            return {
                'status': 'error',
                'message': 'Could not access webcam'
            }
        
        # Capture a frame
        ret, frame = cap.read()
        
        # Release the webcam
        cap.release()
        
        if not ret:
            return {
                'status': 'error',
                'message': 'Failed to capture image'
            }
        
        # Convert to bytes
        _, buffer = cv2.imencode('.jpg', frame)
        img_bytes = buffer.tobytes()
        
        # Convert to base64
        img_b64 = base64.b64encode(img_bytes).decode()
        
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'data': img_b64,
            'format': 'JPG',
            'size': len(img_bytes)
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        } 