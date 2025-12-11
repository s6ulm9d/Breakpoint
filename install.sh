#!/bin/bash
# Breakpoint Installer for Linux/macOS

set -e

BINARY_NAME="breakpoint"
INSTALL_DIR="/usr/local/bin"
SOURCE_BINARY="./breakpoint" # Assumes binary is in current dir

echo "[*] Breakpoint Installer"
echo "[*] Checking permissions..."

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./install.sh)"
  exit 1
fi

if [ ! -f "$SOURCE_BINARY" ]; then
    echo "[-] Error: Binary '$SOURCE_BINARY' not found in current directory."
    exit 1
fi

echo "[*] Installing to $INSTALL_DIR..."
mv "$SOURCE_BINARY" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

echo "[+] Success! Type '$BINARY_NAME' to start."
