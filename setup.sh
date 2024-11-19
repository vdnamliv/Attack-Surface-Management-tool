#!/bin/bash

echo "[INFO] Starting setup script..."

# Update system packages
echo "[INFO] Updating system packages..."
sudo apt update

# Install system dependencies
echo "[INFO] Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv libpcap-dev git wget curl

# Set up Python virtual environment
echo "[INFO] Setting up Python environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "[INFO] Python virtual environment already exists."
    source venv/bin/activate
fi

# Install Go
echo "[INFO] Checking Go installation..."
if ! command -v go &> /dev/null; then
    echo "[INFO] Installing Go..."
    wget https://go.dev/dl/go1.20.4.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.4.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    source ~/.bashrc
else
    echo "[INFO] Go is already installed."
fi

# Add Go bin directory to PATH
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Go-based tools
echo "[INFO] Installing Go-based tools..."

install_go_tool() {
    local tool_name=$1
    local install_cmd=$2

    if ! command -v "$tool_name" &> /dev/null; then
        echo "[INFO] Installing $tool_name..."
        eval "$install_cmd"
    else
        echo "[INFO] $tool_name is already installed."
    fi
}

install_go_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "assetfinder" "go install -v github.com/tomnomnom/assetfinder@latest"
install_go_tool "naabu" "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

# Clone and install Sublist3r
echo "[INFO] Checking and installing Sublist3r..."
if [ ! -d "Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r || exit
    pip install -r requirements.txt
    cd ..
else
    echo "[INFO] Sublist3r is already installed."
fi

# Clone and install SecurityTrails API tool
echo "[INFO] Checking and installing SecurityTrails API tool..."
if [ ! -d "security-trails" ]; then
    git clone https://github.com/GabrielCS0/security-trails.git
    cd security-trails || exit
    pip install -r requirements.txt
    cd ..
else
    echo "[INFO] SecurityTrails API tool is already installed."
fi

echo "[INFO] Setup completed successfully."
