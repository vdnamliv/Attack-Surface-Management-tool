#!/bin/bash

# Install Python libraries from requirements.txt
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Function to install Go if not installed
install_go() {
    echo "Installing Go..."
    wget https://go.dev/dl/go1.20.4.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.4.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo "Go installed successfully."
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    install_go
else
    echo "Go is already installed."
fi

# Add Go's bin directory to PATH for current session
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Go-based tools
echo "Checking and installing Go-based tools..."

install_go_tool() {
    local tool_name=$1
    local install_cmd=$2

    if ! command -v "$tool_name" &> /dev/null; then
        echo "Installing $tool_name..."
        eval "$install_cmd"
    else
        echo "$tool_name is already installed."
    fi
}

install_go_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "assetfinder" "go install -v github.com/tomnomnom/assetfinder@latest"
install_go_tool "naabu" "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

# Clone and install Sublist3r from GitHub
echo "Checking and installing Sublist3r..."
if [ ! -d "Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r || exit
    pip install -r requirements.txt
    cd ..
else
    echo "Sublist3r is already installed."
fi

# Clone and set up SecurityTrails API tool
echo "Checking and installing SecurityTrails API tool..."
if [ ! -d "security-trails" ]; then
    git clone https://github.com/GabrielCS0/security-trails.git
    cd security-trails || exit
    pip install -r requirements.txt
    cd ..
else
    echo "SecurityTrails API tool is already installed."
fi

echo "Setup completed successfully."

