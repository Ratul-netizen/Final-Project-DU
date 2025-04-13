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

echo "Setup complete! You can now run the C2 server with: python c2_server.py" 