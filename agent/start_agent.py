#!/usr/bin/env python3
"""
Simple agent startup script for testing
"""
import sys
import os
import logging
import time

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_agent_startup():
    """Test agent startup and basic functionality"""
    try:
        logging.info("Starting agent startup test...")
        
        # Test configuration import
        try:
            from config import C2_URL, BEACON_INTERVAL
            logging.info(f"✓ Configuration loaded: C2_URL={C2_URL}")
        except ImportError as e:
            logging.error(f"✗ Configuration import failed: {e}")
            return False
        
        # Test basic imports
        try:
            from agent import register, send_beacon, get_system_info
            logging.info("✓ Agent modules imported successfully")
        except ImportError as e:
            logging.error(f"✗ Agent module import failed: {e}")
            return False
        
        # Test system info
        try:
            system_info = get_system_info()
            logging.info(f"✓ System info gathered: {system_info.get('hostname', 'Unknown')}")
        except Exception as e:
            logging.error(f"✗ System info failed: {e}")
            return False
        
        # Test registration
        try:
            logging.info("Testing agent registration...")
            success = register()
            if success:
                logging.info("✓ Agent registration successful")
            else:
                logging.warning("⚠ Agent registration returned False")
        except Exception as e:
            logging.error(f"✗ Agent registration failed: {e}")
            return False
        
        logging.info("✅ Agent startup test completed successfully!")
        return True
        
    except Exception as e:
        logging.error(f"✗ Agent startup test failed: {e}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return False

def main():
    """Main entry point"""
    print("Agent Startup Test")
    print("=" * 50)
    
    success = test_agent_startup()
    
    if success:
        print("\n🎉 Agent startup test passed! Agent should work correctly.")
        print("\nTo start the full agent, run: python agent.py")
    else:
        print("\n💥 Agent startup test failed! Check the logs above.")
        print("\nCommon issues:")
        print("1. C2 server not running")
        print("2. Network connectivity issues")
        print("3. Missing dependencies")
        print("4. Configuration errors")

if __name__ == "__main__":
    main()
