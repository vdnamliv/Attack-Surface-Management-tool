#!/bin/bash

set -e  # Dừng nếu có lỗi xảy ra

echo "[INFO] Starting Automated Attack Surface Management Tool Installer..."

# === Bước 1: Cập nhật hệ thống và cài các gói phụ thuộc cơ bản
echo "[INFO] Updating system packages..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev git wget curl

# === Bước 2: Tạo thư mục chính và clone source từ GitHub
INSTALL_DIR="$HOME/attack-surface-management"
if [ -d "$INSTALL_DIR" ]; then
    echo "[WARNING] Tool directory already exists, removing old version..."
    rm -rf "$INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[INFO] Cloning source code from GitHub..."
git clone https://github.com/your-github-username/your-repo-name.git "$INSTALL_DIR"

# === Bước 3: Thiết lập Python Virtual Environment
echo "[INFO] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# === Bước 4: Cài Go (tự động lấy phiên bản mới nhất)
echo "[INFO] Installing Go..."
GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n 1)
wget https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf ${GO_VERSION}.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# === Bước 5: Cài đặt các công cụ Go (subfinder, naabu, assetfinder)
echo "[INFO] Installing Go-based recon tools..."

mkdir -p tools

function install_go_tool {
    local tool_name=$1
    local install_cmd=$2

    if [ ! -f "tools/$tool_name" ]; then
        echo "[INFO] Installing $tool_name..."
        eval "$install_cmd"
        cp "$HOME/go/bin/$tool_name" "tools/"
    else
        echo "[INFO] $tool_name already exists in tools/."
    fi
}

install_go_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "assetfinder" "go install -v github.com/tomnomnom/assetfinder@latest"
install_go_tool "naabu" "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

# === Bước 6: Clone Sublist3r và Security Trails vào tools/
echo "[INFO] Cloning Sublist3r and Security Trails..."

if [ ! -d "tools/Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git tools/Sublist3r
    pip install -r tools/Sublist3r/requirements.txt
fi

if [ ! -d "tools/security-trails" ]; then
    git clone https://github.com/GabrielCS0/security-trails.git tools/security-trails
    pip install -r tools/security-trails/requirements.txt
fi

# === Bước 7: Hướng dẫn sử dụng
echo ""
echo "[INFO] Installation completed successfully!"
echo "[INFO] To start using the tool, run the following commands:"
echo ""
echo "    cd $INSTALL_DIR"
echo "    source venv/bin/activate"
echo "    python3 asm.py -h"
echo ""
echo "[INFO] Add your SecurityTrails API key and registered hosts in config.ini if needed."
echo ""
