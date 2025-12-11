#!/bin/bash
# Breakpoint Uninstaller for Linux/macOS

set -e

BINARY_PATH="/usr/local/bin/breakpoint"

echo "[*] Breakpoint Uninstaller"

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./uninstall.sh)"
  exit 1
fi

if [ -f "$BINARY_PATH" ]; then
    rm "$BINARY_PATH"
    echo "[+] Removed binary: $BINARY_PATH"
else
    echo "[*] Binary not found at default location."
fi

# Optional: Remove config if we standardized that (we didn't strictly force it to /etc yet)
echo "[+] Uninstallation complete."
