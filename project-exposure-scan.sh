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
LOG_DIR="/var/log/shield-bash"
LOG_FILE="$LOG_DIR/project-exposure.log"
CONF_FILE="/etc/shield-bash/project-exposure-scan-list.conf"
CHECK_ONLY=0  # Default: apply fixes
SILENT=0  # Default: show output
VERBOSE=0  # Default: not verbose

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Define ANSI escape codes
BOLD_WHITE="\e[1;37m"
CYAN="\e[36m"
YELLOW="\e[33m"
GREEN="\e[32m"
RESET="\e[0m"

# Function: Display Help
show_help() {
    echo "----------------------------------------------------------------"
    echo -e "${BOLD_WHITE}Project Exposure Scan (pes) - A Shield-Bash Security Tool${RESET}"
    echo
    echo -e "${BOLD_WHITE}Description:${RESET}"
    echo "  - Scans directories and files specified in" 
    echo -e "    ${YELLOW}/etc/shield-bash/project-exposure-scan-list.conf${RESET}" 
    echo "    for improper ownership and permissions."
    echo "  - Logs any exposures found to" 
    echo -e "    ${YELLOW}/var/log/shield-bash/project-exposure.log${RESET}" 
    echo "    and optionally applies fixes."
    echo
    echo -e "${GREEN}Usage:${RESET} shield-bash pes [options]"
    echo
    echo -e "${BOLD_WHITE}Options:${RESET}"
    printf "  ${YELLOW}%-20s${RESET} %s\n" "-d, --dry-run"   "List exposures without applying fixes"
    printf "  ${YELLOW}%-20s${RESET} %s\n" "-s, --silent"    "Suppress output (logs are still written)"
    printf "  ${YELLOW}%-20s${RESET} %s\n" "-v, --verbose"   "Show detailed output"
    printf "  ${YELLOW}%-20s${RESET} %s\n" "-h, --help"      "Display this help message"
    echo "----------------------------------------------------------------"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dry-run) CHECK_ONLY=1 ;;
        -s|--silent) SILENT=1 ;;
        -v|--verbose) VERBOSE=1 ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Function to log exposures
log_exposure() {
    local directory="$1"
    local issue="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [EXPOSED] $directory -> $issue" >> "$LOG_FILE"
}

# Function to apply fixes (skipped if CHECK_ONLY=1)
apply_fix() {
    if [[ "$CHECK_ONLY" -eq 0 ]]; then
        eval "$1"
    fi
}

# Read and process configuration file
while IFS="|" read -r owner_group permissions project_path || [[ -n "$owner_group" ]]; do
    # Trim whitespace
    owner_group=$(echo "$owner_group" | xargs)
    permissions=$(echo "$permissions" | xargs)
    project_path=$(echo "$project_path" | xargs)

    # Skip comments and empty lines
    [[ "$owner_group" =~ ^#.*$ || -z "$owner_group" ]] && continue

    # Extract ownership components
    owner_group_clean=$(echo "$owner_group" | cut -d':' -f1,2)
    ownership_flag=$(echo "$owner_group" | awk -F':' '{print $3}')

    # Extract permissions components
    permissions_clean=$(echo "$permissions" | cut -d':' -f1)
    perms_flag=$(echo "$permissions" | awk -F':' '{print $2}')

    # Extract expected owner and group
    expected_owner=$(echo "$owner_group_clean" | cut -d':' -f1)
    expected_group=$(echo "$owner_group_clean" | cut -d':' -f2)

    # Check if directory or file exists
    if [[ ! -e "$project_path" ]]; then
        log_exposure "$project_path" "Path does not exist"
        [[ "$SILENT" -eq 0 ]] && echo "Warning: $project_path does not exist, skipping..."
        continue
    fi

    # Check and fix ownership (including recursion)
    find "$project_path" -type d -or -type f | while IFS= read -r item; do
        actual_owner=$(stat -c "%U" "$item")
        actual_group=$(stat -c "%G" "$item")

        if [[ "$actual_owner" != "$expected_owner" || "$actual_group" != "$expected_group" ]]; then
            log_exposure "$item" "Ownership mismatch (Expected: $expected_owner:$expected_group, Found: $actual_owner:$actual_group)"
            [[ "$CHECK_ONLY" -eq 1 ]] && [[ "$SILENT" -eq 0 ]] && echo "[CHECK-ONLY] Ownership issue: $item -> Expected: $expected_owner:$expected_group, Found: $actual_owner:$actual_group"
            apply_fix "chown $expected_owner:$expected_group '$item'"
        elif [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then
            echo "[INFO] Ownership OK: $item"
        fi
    done

    # Check and fix permissions (including recursion)
    find "$project_path" -type d -or -type f | while IFS= read -r item; do
        actual_perms=$(stat -c "%a" "$item")

        if [[ "$actual_perms" != "$permissions_clean" ]]; then
            log_exposure "$item" "Permissions mismatch (Expected: $permissions_clean, Found: $actual_perms)"
            [[ "$CHECK_ONLY" -eq 1 ]] && [[ "$SILENT" -eq 0 ]] && echo "[CHECK-ONLY] Permissions issue: $item -> Expected: $permissions_clean, Found: $actual_perms"
            apply_fix "chmod $permissions_clean '$item'"
        elif [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then
            echo "[INFO] Permissions OK: $item"
        fi
    done

done < "$CONF_FILE"

[[ "$SILENT" -eq 0 ]] && echo "Project exposure scan completed. Log file: $LOG_FILE"
