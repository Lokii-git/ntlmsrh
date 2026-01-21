# NTLMSRH Installation Guide

## 🚀 Quick Installation

### Option 1: Automatic Installation (Recommended)
```bash
cd ntlmsrh
chmod +x install.sh
sudo ./install.sh
```

### Option 2: Manual Installation
```bash
# Install to system-wide location (requires sudo)
sudo cp ntlmsrh.py /usr/local/bin/ntlmsrh
sudo chmod +x /usr/local/bin/ntlmsrh

# Install Python dependencies
pip3 install --user requests urllib3

# Test installation
ntlmsrh --help
```

### Option 3: User Installation (No sudo required)
```bash
# Create user bin directory
mkdir -p ~/.local/bin

# Copy script
cp ntlmsrh.py ~/.local/bin/ntlmsrh
chmod +x ~/.local/bin/ntlmsrh

# Add to PATH (add to ~/.bashrc or ~/.zshrc)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Install dependencies
pip3 install --user requests urllib3

# Test installation
ntlmsrh --help
```

## ✅ Verification

After installation, test from any directory:
```bash
cd /tmp
echo "192.168.1.10" > test_targets.txt
ntlmsrh test_targets.txt --timeout 2
```

The tool should work correctly regardless of your current directory.

## 🔧 Troubleshooting

### Path Issues
- Ensure `/usr/local/bin` or `~/.local/bin` is in your PATH
- Use `which ntlmsrh` to verify installation location

### Permission Issues
- Use `sudo` for system-wide installation
- Use user installation if you don't have sudo access

### Python Dependencies
- Ensure Python 3.6+ is installed: `python3 --version`
- Install dependencies: `pip3 install requests urllib3`

## 📁 File Handling

NTLMSRH now properly handles files from any directory:
- ✅ **Relative paths**: `ntlmsrh targets.txt` (uses current directory)
- ✅ **Absolute paths**: `ntlmsrh /home/user/targets.txt`
- ✅ **Output files**: Created in current working directory
- ✅ **Cross-directory**: Works when installed in /usr/bin

## 🎯 Usage After Installation

```bash
# From any directory
ntlmsrh 192.168.1.0/24
ntlmsrh iplist.txt -o report.txt
ntlmsrh targets.txt -j results.json
```

All output files (endpoints.txt, reports) are created in your current working directory.