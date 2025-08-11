#!/usr/bin/env python3
"""
Debug script to examine screenshot data structure
"""

import json
import base64

def debug_screenshot_data():
    """Debug the screenshot data structure"""
    
    # Simulate the results structure based on the code
    # This is what would be in the results dictionary
    
    print("=== Screenshot Data Structure Analysis ===\n")
    
    # Example 1: Direct image format
    print("1. Direct image format (result.image + result.format):")
    example1 = {
        'result': {
            'image': 'base64_encoded_image_data_here',
            'format': 'png'
        },
        'timestamp': '2025-01-08T18:27:56',
        'type': 'surveillance_screenshot'
    }
    print(json.dumps(example1, indent=2))
    print()
    
    # Example 2: Direct data format
    print("2. Direct data format (result.data + result.format):")
    example2 = {
        'result': {
            'data': 'base64_encoded_image_data_here',
            'format': 'png'
        },
        'timestamp': '2025-01-08T18:27:56',
        'type': 'surveillance_screenshot'
    }
    print(json.dumps(example2, indent=2))
    print()
    
    # Example 3: Nested result structure
    print("3. Nested result structure (result.result.image + result.result.format):")
    example3 = {
        'result': {
            'result': {
                'image': 'base64_encoded_image_data_here',
                'format': 'png'
            }
        },
        'timestamp': '2025-01-08T18:27:56',
        'type': 'surveillance_screenshot'
    }
    print(json.dumps(example3, indent=2))
    print()
    
    # Example 4: Nested data structure
    print("4. Nested data structure (result.result.data + result.result.format):")
    example4 = {
        'result': {
            'result': {
                'data': 'base64_encoded_image_data_here',
                'format': 'png'
            }
        },
        'timestamp': '2025-01-08T18:27:56',
        'type': 'surveillance_screenshot'
    }
    print(json.dumps(example4, indent=2))
    print()
    
    # Example 5: String data
    print("5. String data (result as base64 string):")
    example5 = {
        'result': 'base64_encoded_image_data_here',
        'timestamp': '2025-01-08T18:27:56',
        'type': 'surveillance_screenshot'
    }
    print(json.dumps(example5, indent=2))
    print()
    
    print("=== Current API Response Structure ===\n")
    
    # Show what the current get_all_results() would return
    api_response = {
        'status': 'success',
        'results': [
            {
                'id': 'task_123',
                'agent_id': 'agent_456',
                'type': 'surveillance_screenshot',
                'result': example1['result'],
                'timestamp': example1['timestamp'],
                'status': 'SUCCESS'
            },
            {
                'id': 'task_124',
                'agent_id': 'agent_456',
                'type': 'surveillance_screenshot',
                'result': example3['result'],
                'timestamp': example3['timestamp'],
                'status': 'SUCCESS'
            }
        ]
    }
    
    print("API Response:")
    print(json.dumps(api_response, indent=2))
    print()
    
    print("=== Frontend Processing Logic ===\n")
    
    # Show how the frontend should process each example
    examples = [example1, example2, example3, example4, example5]
    
    for i, example in enumerate(examples, 1):
        print(f"Processing Example {i}:")
        result = example['result']
        
        # Simulate the frontend logic
        imageData = None
        imageFormat = 'png'
        
        if result.get('image') and result.get('format'):
            imageData = result['image']
            imageFormat = result['format']
            print(f"  ✓ Found in result.image: {imageFormat}")
        elif result.get('data') and result.get('format') and result['format'].lower() in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
            imageData = result['data']
            imageFormat = result['format']
            print(f"  ✓ Found in result.data: {imageFormat}")
        elif result.get('result') and result['result'].get('image') and result['result'].get('format'):
            imageData = result['result']['image']
            imageFormat = result['result']['format']
            print(f"  ✓ Found in result.result.image: {imageFormat}")
        elif result.get('result') and result['result'].get('data') and result['result'].get('format') and result['result']['format'].lower() in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
            imageData = result['result']['data']
            imageFormat = result['result']['format']
            print(f"  ✓ Found in result.result.data: {imageFormat}")
        elif isinstance(result, str) and len(result) > 100:
            imageData = result
            imageFormat = 'png'
            print(f"  ✓ Found as string data: {imageFormat}")
        else:
            print(f"  ✗ No image data found")
            print(f"    Available keys: {list(result.keys()) if isinstance(result, dict) else 'N/A'}")
        
        if imageData:
            print(f"  Image data length: {len(imageData) if isinstance(imageData, str) else 'N/A'}")
            print(f"  Image format: {imageFormat}")
        print()

if __name__ == "__main__":
    debug_screenshot_data()
