#!/usr/bin/env bash
set -euo pipefail

echo "[+] Installing Hunter-Kaido dependencies..."

# Python deps
echo "[+] Installing Python dependencies..."
python3 -m pip install --upgrade pip
pip3 install aiohttp

# Check Go
if ! command -v go >/dev/null 2>&1; then
  echo "[!] Go is not installed. Please install Go first."
  exit 1
fi

# Install external tools
echo "[+] Installing subfinder..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[+] Installing gau..."
go install github.com/lc/gau/v2/cmd/gau@latest

# Ensure GOPATH/bin is in PATH
GOBIN_PATH="$(go env GOPATH)/bin"

if ! echo "$PATH" | grep -q "$GOBIN_PATH"; then
  echo "[+] Adding GOPATH/bin to PATH (temporary for this session)"
  export PATH="$PATH:$GOBIN_PATH"
fi

echo "[+] Verifying tools..."

command -v subfinder >/dev/null 2>&1 && echo "[OK] subfinder installed" || echo "[WARN] subfinder not found in PATH"
command -v gau >/dev/null 2>&1 && echo "[OK] gau installed" || echo "[WARN] gau not found in PATH"

echo "[+] Done."
echo "[*] Run: python3 hunter-kaido.py target.com"
