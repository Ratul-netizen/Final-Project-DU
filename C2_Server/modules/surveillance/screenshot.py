"""Screenshot functionality for surveillance module"""
import os
import base64
from datetime import datetime
try:
    from PIL import ImageGrab
except ImportError:
    # For Linux systems
    import pyscreenshot as ImageGrab

def take_screenshot():
    """
    Take a screenshot of the current screen
    Returns:
        dict: Status and base64 encoded screenshot data
    """
    try:
        # Take the screenshot
        screenshot = ImageGrab.grab()
        
        # Save to bytes
        img_bytes = screenshot.tobytes()
        
        # Convert to base64
        img_b64 = base64.b64encode(img_bytes).decode()
        
        return {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'data': img_b64,
            'format': 'PNG',
            'size': len(img_bytes)
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        } 