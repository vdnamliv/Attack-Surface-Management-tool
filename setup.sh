#!/bin/bash

set -e  # Dừng script nếu có lỗi

# Function to log steps
log() {
    echo -e "\n[INFO] $1\n"
}

# Install Python libraries
log "Installing Python dependencies..."
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    log "No requirements.txt found. Skipping Python dependencies."
fi

# Function to install Go
install_go() {
    log "Installing Go..."
    wget https://go.dev/dl/go1.20.4.linux-amd64.tar.gz -O /tmp/go1.20.4.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go1.20.4.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    log "Go installed successfully."
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    install_go
else
    log "Go is already installed."
fi

# Add Go's bin directory to PATH
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Go-based tools
log "Checking and installing Go-based tools..."
install_go_tool() {
    local tool_name=$1
    local install_cmd=$2
    local tool_path="$HOME/go/bin/$tool_name"

    if [ ! -f "$tool_path" ]; then
        log "Installing $tool_name..."
        eval "$install_cmd"
    else
        log "$tool_name is already installed."
    fi
}

install_go_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "assetfinder" "go install -v github.com/tomnomnom/assetfinder@latest"
install_go_tool "naabu" "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

# Install Sublist3r
log "Checking and installing Sublist3r..."
if [ ! -d "Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r || exit
    pip install -r requirements.txt
    cd ..
else
    log "Sublist3r is already installed."
fi

# Install SecurityTrails API tool
log "Checking and installing SecurityTrails API tool..."
if [ ! -d "security-trails" ]; then
    git clone https://github.com/GabrielCS0/security-trails.git
    cd security-trails || exit
    pip install -r requirements.txt
    cd ..
else
    log "SecurityTrails API tool is already installed."
fi

# Verify installation
log "Verifying tool installation..."
if ! command -v subfinder &> /dev/null; then
    log "Error: Subfinder installation failed."
else
    log "Subfinder installed successfully."
fi

if ! command -v assetfinder &> /dev/null; then
    log "Error: Assetfinder installation failed."
else
    log "Assetfinder installed successfully."
fi

if ! python3 Sublist3r/sublist3r.py -h &> /dev/null; then
    log "Error: Sublist3r installation failed."
else
    log "Sublist3r installed successfully."
fi

log "Setup completed successfully!"
