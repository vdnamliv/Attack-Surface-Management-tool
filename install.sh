#!/bin/bash

set -e  # Dừng script nếu có lỗi xảy ra

echo "[INFO] Starting Automated Attack Surface Management Tool Installer..."

# === Bước 1: Thiết lập Python Virtual Environment
echo "[INFO] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# === Bước 2: Cài đặt Go (tự động lấy phiên bản mới nhất)
echo "[INFO] Installing Go..."
GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n 1)
wget https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf ${GO_VERSION}.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# === Bước 3: Cài đặt các công cụ Go (subfinder, assetfinder, naabu)
echo "[INFO] Installing Go-based recon tools..."
mkdir -p tools

install_go_tool() {
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

# === Bước 4: Clone Sublist3r và Security-Trails vào thư mục tools/
echo "[INFO] Cloning Sublist3r and Security-Trails tools..."
if [ ! -d "tools/Sublist3r" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git tools/Sublist3r
    pip install -r tools/Sublist3r/requirements.txt
else
    echo "[INFO] Sublist3r already exists in tools/."
fi

if [ ! -d "tools/security-trails" ]; then
    git clone https://github.com/GabrielCS0/security-trails.git tools/security-trails
    pip install -r tools/security-trails/requirements.txt
else
    echo "[INFO] Security-Trails already exists in tools/."
fi

# === Hướng dẫn sử dụng
echo ""
echo "[INFO] Installation completed successfully!"
echo "[INFO] To start using the tool, run the following commands:"
echo "    source venv/bin/activate"
echo "    python3 asm.py -h"
echo ""
echo "[INFO] Remember to update your config.ini as needed."
