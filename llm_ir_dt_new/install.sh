#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

# Detect OS
OS="$(uname -s)"

# ---------- Docker ----------
install_docker_linux() {
    if command -v docker &> /dev/null; then
        echo "Docker already installed: $(docker --version)"
        return 0
    fi
    echo "Installing Docker via apt..."
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    echo "Docker installed: $(docker --version)"
}

install_docker_macos() {
    if command -v docker &> /dev/null; then
        echo "Docker already installed: $(docker --version)"
        return 0
    fi
    if ! command -v brew &> /dev/null; then
        echo "ERROR: Homebrew is required to install Docker on macOS."
        echo "Install it from https://brew.sh then re-run this script."
        exit 1
    fi
    echo "Installing Docker Desktop via Homebrew..."
    brew install --cask docker
    echo "Docker Desktop installed. Please launch Docker Desktop from Applications before continuing."
}

echo "=== Installing Docker ==="
case "$OS" in
    Linux)  install_docker_linux ;;
    Darwin) install_docker_macos ;;
    *)      echo "ERROR: Unsupported OS: $OS"; exit 1 ;;
esac

echo ""
echo "=== Installing Python package ==="
cd "$DIR"
pip install -e ".[test]"

echo ""
echo "=== Building Docker images ==="
cd "$DIR"
docker compose build

echo ""
echo "=== All dependencies installed ==="
