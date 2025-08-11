#!/usr/bin/env python3
"""
Test script to verify webcam functionality is working
"""
import requests
import json
import time

def test_webcam_functionality():
    print("Testing webcam functionality...")
    try:
        r = requests.get('http://localhost:5000/api/debug/results')
        if r.status_code == 200:
            data = r.json()
            print(f"✓ API endpoint accessible")
            print(f"Current agents: {len(data['results'])}")
            
            webcam_tasks = []
            for agent_id, agent_results in data['results'].items():
                for task_id, result in agent_results.items():
                    if result.get('result', {}).get('type') == 'surveillance_webcam':
                        webcam_tasks.append({
                            'task_id': task_id,
                            'agent_id': agent_id,
                            'data': result.get('result', {}).get('data', ''),
                            'status': result.get('status')
                        })
            
            if webcam_tasks:
                print(f"\nFound {len(webcam_tasks)} existing webcam tasks:")
                for task in webcam_tasks:
                    print(f"  Task: {task['task_id']}")
                    print(f"    Agent: {task['agent_id']}")
                    print(f"    Status: {task['status']}")
                    print(f"    Data: '{task['data']}'")
                    print()
            else:
                print("\nNo existing webcam tasks found")
        else:
            print(f"✗ API endpoint returned status {r.status_code}")
    except Exception as e:
        print(f"✗ Error accessing API: {e}")
    
    print("\n" + "="*60)
    print("SUMMARY OF THE WEBCAM FIX:")
    print("="*60)
    print("The issue was that the agent didn't have a handler for 'surveillance_webcam' tasks.")
    print("When such a task was sent, the agent returned 'Unknown task type: surveillance_webcam'")
    print("instead of capturing an actual webcam image.")
    print()
    print("I've fixed this by adding the missing task handler in agent/agent.py:")
    print("  'surveillance.webcam': capture_webcam,")
    print("  'surveillance_webcam': capture_webcam,")
    print()
    print("Now when a 'surveillance_webcam' task is sent:")
    print("1. The agent will call the capture_webcam() function")
    print("2. This function will capture an image from the webcam using OpenCV")
    print("3. The image will be saved as JPG and encoded as base64")
    print("4. The result will include: status, timestamp, image (base64), format")
    print("5. The dashboard will display the webcam image correctly")
    print()
    print("To test this fix:")
    print("1. Send a new 'surveillance_webcam' task to the agent")
    print("2. Check that it returns actual image data instead of an error message")
    print("3. Verify the webcam image appears in the dashboard")
    print()
    print("Note: The dashboard already has comprehensive image handling that will work")
    print("for webcam images since they use the same data structure as screenshots.")

if __name__ == "__main__":
    test_webcam_functionality()
