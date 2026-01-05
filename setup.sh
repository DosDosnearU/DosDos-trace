#!/bin/bash
# Install system dependencies
pkg update && pkg upgrade -y
pkg install python python-sqlite git -y

# Install Python requirements
pip install -r requirements.txt

# Make the tool executable globally
chmod +x shadow_core.py
ln -s "$(pwd)/shadow_core.py" $PREFIX/bin/shadowcore

echo -e "\n\e[1;32m[+] Installation Complete! Run the tool by typing: shadowcore\e[0m"
