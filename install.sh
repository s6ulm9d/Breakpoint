#!/bin/bash
# Breakpoint Installer for Linux/macOS

set -e

BINARY_NAME="breakpoint"
INSTALL_DIR="/usr/local/bin"
SOURCE_BINARY="./breakpoint"
PYTHON_REQS="./requirements.txt"

echo "[*] Breakpoint Installer"
echo "[*] IMPORTANT: High-Performance Security Auditing involves significant responsibility."
echo "[*] You must agree to the Breakpoint Ethical Use Agreement to proceed."
echo ""
echo "    1. I will only use Breakpoint on authorized targets."
echo "    2. I will not target critical infrastructure (.gov, .mil, banks, hospitals)."
echo "    3. I assume full legal responsibility for my actions."
echo ""
read -p "[?] Do you agree to these terms? (y/n): " choice
if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
    echo "[-] Installation aborted. Ethical agreement not accepted."
    exit 1
fi
echo "[+] Ethical Agreement Accepted."
echo "[*] Checking environment..."

# Check Python presence
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed. Please install Python 3.9+."
    exit 1
fi

# Install dependencies if requirements.txt exists
if [ -f "$PYTHON_REQS" ]; then
    echo "[*] Installing dependencies from $PYTHON_REQS..."
    python3 -m pip install -r "$PYTHON_REQS"
fi

# Check for binary or build it
if [ ! -f "$SOURCE_BINARY" ]; then
    echo "[!] Binary '$SOURCE_BINARY' not found."
    if [ -f "./build_binary.py" ]; then
        echo "[*] Attempting to build binary using build_binary.py..."
        python3 build_binary.py || echo "[-] Build failed. Falling back to python3 alias."
    fi
fi

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./install.sh) to install to $INSTALL_DIR"
  echo "[*] Alternatively, you can run breakpoint using: python3 -m breakpoint"
  exit 1
fi

if [ -f "$SOURCE_BINARY" ]; then
    echo "[*] Installing binary to $INSTALL_DIR..."
    mv "$SOURCE_BINARY" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    echo "[+] Success! Type '$BINARY_NAME' to start."
else
    echo "[*] Creating entry point alias in $INSTALL_DIR..."
    echo "#!/bin/bash" > "$INSTALL_DIR/$BINARY_NAME"
    echo "python3 -m breakpoint \"\$@\"" >> "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    echo "[+] Success! Type '$BINARY_NAME' to start (running via python3 module)."
fi
