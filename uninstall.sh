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

# Configuration
NOINTERACTION=0  # Default: prompt for confirmation

# Define ANSI escape codes
BOLD_WHITE="\e[1;37m"
CYAN="\e[36m"
YELLOW="\e[33m"
GREEN="\e[32m"
RESET="\e[0m"

# Function: Display Help
show_help() {
    echo "----------------------------------------------------------------"
    echo -e "${BOLD_WHITE}Shield-Bash Uninstaller${RESET}"
    echo
    echo -e "${BOLD_WHITE}Description:${RESET}"
    echo "  This script removes all Shield-Bash components, including scripts"
    echo "  and configuration files."
    echo
    echo -e "${GREEN}Usage:${RESET} shield-bash uninstall [options]"
    echo
    echo -e "${BOLD_WHITE}Options:${RESET}"
    printf "  ${YELLOW}%-20s${RESET} %s\n" "-h, --help"      "Display this help message"
    printf "  ${YELLOW}%-20s${RESET} %s\n" "-y, --yes"       "Run uninstall without confirmation prompt"
    echo "----------------------------------------------------------------"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) show_help ;;
        -y|--yes) NOINTERACTION=1 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

# Define installation paths
CONFIG_DIR="/etc/shield-bash"
INSTALL_DIR="/var/lib/shield-bash"
BIN_PATH="/usr/local/bin/shield-bash"
BASHRC_FILE="/root/.bashrc"

# Confirm before proceeding
if [[ NOINTERACTION -eq 0 ]]; then
    read -p "Are you sure you want to uninstall Shield-Bash? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Uninstallation canceled."
        exit 0
    fi
fi

# Remove installed files and directories
rm -rf "$CONFIG_DIR"
rm -rf "$INSTALL_DIR"
rm -f "$BIN_PATH"

echo "Shield-Bash has been uninstalled successfully."