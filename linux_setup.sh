#!/bin/bash
# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "Creating new virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
fi

# Install dependencies
pip install -r requirements.txt

# Create directories for shellcode loader generator
echo "Creating directories for shellcode loader generator..."
mkdir -p C2_Server/cpp_templates C2_Server/compiled

# Check if UPX is installed
if ! command -v upx &> /dev/null; then
    echo "UPX not found, installing using apt..."
    # Check if we have sudo or are running as root
    if [ "$(id -u)" -eq 0 ]; then
        apt-get update && apt-get install -y upx mingw-w64
    else
        sudo apt-get update && sudo apt-get install -y upx mingw-w64
    fi
fi

# Check if MinGW is installed
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "MinGW not found, installing using apt..."
    # Check if we have sudo or are running as root
    if [ "$(id -u)" -eq 0 ]; then
        apt-get install -y mingw-w64
    else
        sudo apt-get install -y mingw-w64
    fi
fi

echo "Setup complete!"
echo "You can run the C2 framework using:"
echo "python run_c2_framework.py --simple"
echo ""
echo "For more options, see TROUBLESHOOTING.md"
echo ""
echo "Run the dependency checker for shellcode loaders:"
echo "python check_loader_dependencies.py" 