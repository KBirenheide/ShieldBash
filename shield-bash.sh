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
SCRIPT_DIR="/var/lib/shield-bash"
AVAILABLE_SCRIPTS=(
    "pes:project-exposure-scan.sh"
    "uninstall:uninstall.sh"
)

# Define ANSI escape codes
BOLD_WHITE="\e[1;37m"
CYAN="\e[36m"
YELLOW="\e[33m"
GREEN="\e[32m"
RESET="\e[0m"

# Function: Display Help
show_help() {
    echo "----------------------------------------------------------------"
    echo -e "${BOLD_WHITE}Shield-Bash - Security Automation Command Suite${RESET}"
    echo
    echo -e "${BOLD_WHITE}Description:${RESET}"
    echo "  Shield-Bash is a command-line tool designed to automate security tasks"
    echo "  via a suite of bash scripts."
    echo
    echo -e "${GREEN}Usage:${RESET} shield-bash [script-alias] [options]"
    echo -e "${GREEN}Or:${RESET}    shield-bash [options]"
    echo
    echo -e "${BOLD_WHITE}Available Scripts:${RESET}"

    # Dynamically calculate column alignment
    max_length=0
    for entry in "${AVAILABLE_SCRIPTS[@]}"; do
        alias_name=$(echo "$entry" | cut -d':' -f1)
        [[ ${#alias_name} -gt $max_length ]] && max_length=${#alias_name}
    done

    # Print aligned script aliases
    for entry in "${AVAILABLE_SCRIPTS[@]}"; do
        alias_name=$(echo "$entry" | cut -d':' -f1)
        script_name=$(echo "$entry" | cut -d':' -f2)
        printf "  ${CYAN}%-${max_length}s${RESET} → %s\n" "$alias_name" "$script_name"
    done

    echo
    echo -e "${BOLD_WHITE}Flags:${RESET}"
    printf "  ${YELLOW}%-20s${RESET} %s\n" "-h, --help" "Show this help message"
    echo
    echo -e "Run ${CYAN}shield-bash [script-alias] -h${RESET} for more information on a specific script."
    echo "----------------------------------------------------------------"
}


# Ensure at least one argument is provided
if [[ $# -eq 0 ]]; then
    echo "Error: No script specified."
    echo "Use 'shield-bash -h' for help."
    exit 1
fi

# Handle help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Extract script alias and shift arguments
SCRIPT_ALIAS="$1"
shift  # Remove the first argument so the remaining ones are passed to the target script

# Search for the matching script
for entry in "${AVAILABLE_SCRIPTS[@]}"; do
    alias_name=$(echo "$entry" | cut -d':' -f1)
    script_name=$(echo "$entry" | cut -d':' -f2)

    if [[ "$SCRIPT_ALIAS" == "$alias_name" ]]; then
        SCRIPT_PATH="$SCRIPT_DIR/$script_name"

        if [[ ! -x "$SCRIPT_PATH" ]]; then
            echo "Error: $script_name is not executable or missing."
            exit 1
        fi

        # Execute the target script with any remaining arguments
        exec "$SCRIPT_PATH" "$@"
    fi
done

# If no match was found, print an error
echo "Error: Unknown script alias '$SCRIPT_ALIAS'."
echo "Use 'shield-bash -h' to see available scripts."
exit 1