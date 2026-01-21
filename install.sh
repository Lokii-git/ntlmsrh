#!/bin/bash
#
# NTLMSRH Installation Script
# Installs NTLMSRH to system PATH for global usage
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        NTLMSRH Installation          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    INSTALL_DIR="/usr/local/bin"
    echo -e "${GREEN}[✓]${NC} Running as root - installing to ${INSTALL_DIR}"
else
    INSTALL_DIR="$HOME/.local/bin"
    echo -e "${YELLOW}[!]${NC} Running as user - installing to ${INSTALL_DIR}"
    mkdir -p "$INSTALL_DIR"
    
    # Check if ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo -e "${YELLOW}[!]${NC} Adding $HOME/.local/bin to PATH"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true
        echo -e "${BLUE}[i]${NC} You may need to restart your shell or run: source ~/.bashrc"
    fi
fi

# Check Python version
echo -e "${BLUE}[i]${NC} Checking Python version..."
if ! python3 --version | grep -E "Python 3\.[6-9]|Python 3\.1[0-9]" > /dev/null; then
    echo -e "${RED}[✗]${NC} Python 3.6+ is required"
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Python version check passed"

# Install dependencies
echo -e "${BLUE}[i]${NC} Installing Python dependencies..."
pip3 install --user requests urllib3 || {
    echo -e "${RED}[✗]${NC} Failed to install dependencies"
    exit 1
}
echo -e "${GREEN}[✓]${NC} Dependencies installed"

# Copy script to install directory
echo -e "${BLUE}[i]${NC} Installing ntlmsrh to ${INSTALL_DIR}..."
cp ntlmsrh.py "${INSTALL_DIR}/ntlmsrh"
chmod +x "${INSTALL_DIR}/ntlmsrh"
echo -e "${GREEN}[✓]${NC} NTLMSRH installed successfully"

# Test installation
echo -e "${BLUE}[i]${NC} Testing installation..."
if "${INSTALL_DIR}/ntlmsrh" --help > /dev/null 2>&1; then
    echo -e "${GREEN}[✓]${NC} Installation test passed"
else
    echo -e "${RED}[✗]${NC} Installation test failed"
    exit 1
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Installation Completed!         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Usage:${NC}"
echo -e "  ntlmsrh 192.168.1.0/24"
echo -e "  ntlmsrh targets.txt -o report.txt"
echo -e "  ntlmsrh https://mail.company.com -j results.json"
echo ""
echo -e "${BLUE}Files will be created in your current working directory.${NC}"
echo ""