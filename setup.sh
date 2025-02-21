#!/bin/bash

# -----
# The MIT License (MIT)
#
# Copyright © 2025 Koray Birenheide
# https://github.com/KBirenheide/ShieldBash
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy 
#   of this software and associated documentation files (the “Software”), 
#   to deal in the Software without restriction, including without limitation the 
#   rights to use, copy, modify, merge, publish, distribute, sublicense, 
#   and/or sell copies of the Software, and to permit persons to whom the Software 
#   is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all 
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
#   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS 
#   OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF 
#   OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
#   IN THE SOFTWARE.
# -----

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

# Define installation paths
CONFIG_DIR="/etc/shield-bash"
INSTALL_DIR="/var/lib/shield-bash"
BIN_PATH="/usr/local/bin/shield-bash"
SCRIPT_DIR="$(pwd)"

# Required dependencies
DEPENDENCIES=("stat" "find" "awk" "chmod" "chown" "ln" "mkdir" "cp" "rm" "grep" "sort")

# Detect package manager
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="apt update && apt install -y"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="dnf install -y"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    INSTALL_CMD="yum install -y"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="pacman -Sy --noconfirm"
else
    echo "Error: No supported package manager found (apt, dnf, yum, pacman)." >&2
    exit 1
fi

# Check and install missing dependencies
MISSING_DEPS=()
for dep in "${DEPENDENCIES[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
        MISSING_DEPS+=("$dep")
    fi
done

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    echo "Installing missing dependencies: ${MISSING_DEPS[*]}"
    eval "$INSTALL_CMD ${MISSING_DEPS[*]}" || {
        echo "Error: Failed to install required dependencies." >&2
        exit 1
    }
fi

# Ensure required directories exist
mkdir -p "$CONFIG_DIR"
mkdir -p "$INSTALL_DIR"

# Copy configuration and scripts instead of creating symlinks
cp -f "$SCRIPT_DIR/project-exposure-scan-list.conf" "$CONFIG_DIR/project-exposure-scan-list.conf"
cp -f "$SCRIPT_DIR/project-exposure-scan.sh" "$INSTALL_DIR/project-exposure-scan.sh"
cp -f "$SCRIPT_DIR/shield-bash.sh" "$INSTALL_DIR/shield-bash.sh"
cp -f "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/uninstall.sh"

# Ensure correct permissions
chmod 640 "$CONFIG_DIR/project-exposure-scan-list.conf"
chmod 750 "$INSTALL_DIR/project-exposure-scan.sh"
chmod 750 "$INSTALL_DIR/shield-bash.sh"
chmod 750 "$INSTALL_DIR/uninstall.sh"

# Ensure root ownership for scripts
chown root:root "$CONFIG_DIR/project-exposure-scan-list.conf"
chown root:root "$INSTALL_DIR/shield-bash.sh"
chown root:root "$INSTALL_DIR/project-exposure-scan.sh"
chown root:root "$INSTALL_DIR/uninstall.sh"

# Create a symlink in /usr/local/bin/ for global execution
ln -sf "$INSTALL_DIR/shield-bash.sh" "$BIN_PATH"

echo "Shield-Bash setup completed successfully!"
echo "You can now run 'shield-bash' from any location."