import requests
import json
import base64
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_c2_connection():
    C2_URL = "http://localhost:5001"  # Update this to match your C2 server IP
    
    # Test basic connection
    try:
        response = requests.get(f"{C2_URL}/api/agents", timeout=5)
        if response.ok:
            logging.info("Successfully connected to C2 server")
            return True
        else:
            logging.error(f"Failed to connect to C2 server. Status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        logging.error(f"Could not connect to C2 server at {C2_URL}")
        logging.info("Please ensure:")
        logging.info("1. The C2 server is running (python simple_c2_server.py)")
        logging.info("2. The IP address is correct")
        logging.info("3. No firewall is blocking the connection")
        return False
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return False

if __name__ == "__main__":
    test_c2_connection() 