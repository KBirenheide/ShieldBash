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
EDITORS=("nano" "vim" "vi" "micro" "code" "subl" "gedit" "kate" "mousepad")

# Rules
valid_log_levels=("INFO" "WARNING" "CRITICAL" "FOLLOWUP")
valid_pes_tags=("EXPOSURE" "CONFIG")
combined_validator=( "${valid_log_levels[@]}" "${valid_pes_tags[@]}" )

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
    echo -e "${BOLD_WHITE}Project Exposure Scan (PES) - A Shield-Bash Security Tool${RESET}"
    echo
    echo -e "${BOLD_WHITE}Description:${RESET}"
    echo "  - Scans directories and files specified in" 
    echo -e "    ${YELLOW}/etc/shield-bash/project-exposure-scan-list.conf${RESET}" 
    echo "    for improper ownership and permissions."
    echo "  - Logs any exposures found to" 
    echo -e "    ${YELLOW}/var/log/shield-bash/project-exposure.log${RESET}" 
    echo "    at configured log levels and optionally applies fixes."
    echo
    echo -e "${GREEN}Usage:${RESET} shield-bash pes [options]"
    echo
    echo -e "${BOLD_WHITE}Options:${RESET}"
    printf "  ${YELLOW}%-25s${RESET} %s\n" "-d, --dry-run"        "List exposures without applying fixes"
    printf "  ${YELLOW}%-25s${RESET} %s\n" "-s, --silent"         "Suppress output (logs are still written)"
    printf "  ${YELLOW}%-25s${RESET} %s\n" "-v, --verbose"        "Show detailed output"
    printf "  ${YELLOW}%-25s${RESET} %s\n" "-e, --edit"           "Promts an editor selection to edit the PES configuration"
    printf "  ${YELLOW}%-25s${RESET} %s\n" "-f, --filter TAGNAME" "Shows all log entries with provided TAGNAME."
    printf "  ${GREEN}%-25s${RESET} %s\n"  "   Tag names =>"      "${combined_validator[*]}"
    printf "  ${YELLOW}%-25s${RESET} %s\n" "-h, --help"           "Display this help message"  
      echo "----------------------------------------------------------------"
    exit 0
}

# Function: Validate Configuration File
validate_config() {
    local line=0
    if [[ ! -f "$CONF_FILE" ]]; then
        echo "[ERROR] Config file missing after edit! Check manually: $CONF_FILE"
        exit 1
    fi

    # Ignore comment lines and extract only configuration lines
    while IFS="|" read -r owner_group permissions project_path log_level || [[ -n "$owner_group" ]]; do
        let "line++"

        # Trim leading/trailing whitespace
        owner_group=$(echo "$owner_group" | xargs)
        permissions=$(echo "$permissions" | xargs)
        project_path=$(echo "$project_path" | xargs)
        log_level=$(echo "$log_level" | xargs)

        # Skip commented lines and empty lines
        [[ "$owner_group" =~ ^#.*$ || -z "$owner_group" ]] && continue

        # Validate ownership format (owner:group[:optional flags])
        if ! [[ "$owner_group" =~ ^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+(:[a-z]+)?$ ]]; then
            echo "[WARNING] Invalid owner:group format found in PES config (line ${line}): '$owner_group'"
        fi

        # Validate permissions (should be a 3 or 4-digit octal number)
        if ! [[ "$permissions" =~ ^[0-7]{3,4}(:[a-z]+)?$ ]]; then
            echo "[WARNING] Invalid permissions format found in PES config (line ${line}): '$permissions' (Expected: 3 or 4-digit octal number)"
        fi

        # Validate project path
        if [[ ! -e "$project_path" ]]; then
            echo "[WARNING] Path does not exist found in PES config (line ${line}): '$project_path'"
        fi

        # Validate log level (must be one of INFO, WARNING, CRITICAL, FOLLOWUP, CONFIG)
        valid_log_levels=("INFO" "WARNING" "CRITICAL" "FOLLOWUP" "CONFIG")
        log_level_upper=$(echo "$log_level" | tr '[:lower:]' '[:upper:]')

        if [[ ! " ${valid_log_levels[*]} " =~ " $log_level_upper " ]]; then
            echo "[WARNING] Invalid log level found in PES config (line ${line}): '$log_level' (Expected: INFO, WARNING, CRITICAL, FOLLOWUP, CONFIG)"
        fi

    done < "$CONF_FILE"
}

# Function: Edit Configuration File
edit_config() {
    detected_editors=()

    # Detect installed editors
    for editor in "${EDITORS[@]}"; do
        if command -v "$editor" &>/dev/null; then
            detected_editors+=("$editor")
        fi
    done

    # If no editors found, warn and exit
    if [[ ${#detected_editors[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No standard text editor detected.${RESET}"
        echo -e "Please manually edit the configuration file at:"
        echo -e "  ${CYAN}$CONF_FILE${RESET}"
        exit 1
    fi

    # If only one editor is found, open it directly
    if [[ ${#detected_editors[@]} -eq 1 ]]; then
        echo -e "Opening configuration with: ${CYAN}${detected_editors[0]}${RESET}"
        "${detected_editors[0]}" "$CONF_FILE"
        exit 0
    fi

    # Multiple editors found, prompt user selection
    echo -e "${BOLD_WHITE}Select a text editor to open the configuration file:${RESET}"
    for i in "${!detected_editors[@]}"; do
        printf "  [%d] %s\n" "$((i+1))" "${detected_editors[$i]}"
    done

    # Get user input
    echo -en "${GREEN}Enter your choice (1-${#detected_editors[@]}): ${RESET}"
    read -r choice

    # Validate selection
    if [[ "$choice" =~ ^[1-${#detected_editors[@]}]$ ]]; then
        selected_editor="${detected_editors[$((choice-1))]}"
        echo -e "Opening configuration with: ${CYAN}$selected_editor${RESET}"
        "$selected_editor" "$CONF_FILE"
        # Validate configuration after editing
        validate_config
        exit 0
    else
        echo -e "${YELLOW}Invalid selection. Exiting.${RESET}"
        exit 1
    fi
}

# Create filtered log file output
log_pull() {
    log_tag=$(echo "$1" | tr '[:lower:]' '[:upper:]')

    # If log file doesn't exist, exit gracefully
    if [[ ! -f "$LOG_FILE" ]]; then
        echo "[WARNING] No log file found. Logs will generate after PES runs at least once."
        exit 0
    fi
    
    # If log_tag is invalid, cat the whole file
    if [[ " ${valid_log_levels[*]} " =~ " $log_tag " ]]; then
        grep "\[$log_tag\]\[ShieldBash PES\]" $LOG_FILE
    elif [[ " ${valid_pes_tags[*]} " =~ " $log_tag " ]]; then
        grep "\[ShieldBash PES\]\[$log_tag\]" $LOG_FILE
    else
        cat $LOG_FILE
        if [[ "$SILENT" -eq 0 ]]; then echo "[WARNING] invalid tag for --filter was provided, showed full log instead."; fi
    fi

    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dry-run) 
            CHECK_ONLY=1 ;;
        -s|--silent) 
            SILENT=1 ;;
        -v|--verbose) 
            VERBOSE=1 ;;
        -e|--edit) 
            edit_config ;;
        -h|--help) 
            show_help ;;
        -f|--filter) 
            if [[ -z $2 ]]; then 
                echo "Specify a log-tag search string value for the --filter option."
                exit 1
            fi
            log_pull "$2"
            shift;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Function to log exposures
log_exposure() {
    local directory="$1"
    local issue="$2"
    local log_level="$3"

    # Normalize log level to uppercase
    log_level=$(echo "$log_level" | tr '[:lower:]' '[:upper:]')

    # If log_level is invalid, default to "INFO"
    if [[ ! " ${valid_log_levels[*]} " =~ " $log_level " ]]; then
        log_level="INFO"
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') - [$log_level][ShieldBash PES][EXPOSURE] $directory -> $issue" >> "$LOG_FILE"
}

# Function to apply fixes (skipped if CHECK_ONLY=1)
apply_fix() {
    if [[ "$CHECK_ONLY" -eq 0 ]]; then
        eval "$1"
    fi
}

# Function to log configuration file changes
check_config_modification() {
    if [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then echo "[INFO] Checking for PES configuration edits."; fi
    
    # Get last modification time of the config file (format: YYYY-MM-DD HH:MM:SS)
    config_mtime=$(stat -c "%Y" "$CONF_FILE" 2>/dev/null || date -r "$CONF_FILE" +%s)
    config_mtime_readable=$(date -d @"$config_mtime" '+%Y-%m-%d %H:%M:%S')

    # Get last user who modified the file
    config_owner=$(stat -c "%U" "$CONF_FILE" 2>/dev/null || ls -l "$CONF_FILE" | awk '{print $3}')

    # Search for a log entry with [PESconfig] and the same timestamp
    log_exists=$(grep -F "[ShieldBash PES][CONFIG]" "$LOG_FILE" | grep -F "$config_mtime_readable")

    # If no matching log exists, create a new log entry
    if [[ -z "$log_exists" ]]; then
        if [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then 
            echo "[WARNING] The PES configuration file was edited since the last PES run (or the log file has been rotated). use command ${YELLOW}shield-bash pes --pull-log=PESconfig${Reset} to see the edit history." 
        fi
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO][ShieldBash PES][CONFIG] Configuration file modified by: $config_owner at $config_mtime_readable" >> "$LOG_FILE"
    fi
}

check_config_modification
validate_config

# Read and process configuration file
while IFS="|" read -r owner_group permissions project_path log_level || [[ -n "$owner_group" ]]; do
    # Trim whitespace
    owner_group=$(echo "$owner_group" | xargs)
    permissions=$(echo "$permissions" | xargs)
    project_path=$(echo "$project_path" | xargs)
    log_level=$(echo "$log_level" | xargs)
    
    # Skip comments and empty lines
    [[ "$owner_group" =~ ^#.*$ || -z "$owner_group" ]] && continue

    # Skip with logged error in case of null path
    [[ -z "$project_path" ]] && log_exposure "Missing path column for entry" "" "ERROR" && continue

    # Skip with logged error in case of null permissions
    [[ -z "$permissions" ]] && log_exposure "Missing permissions column for entry" "" "ERROR" && continue

    # Ensure log_level has a valid default
    [[ -z "$log_level" ]] && log_level="INFO"

    # Extract ownership components
    owner_group_clean=$(echo "$owner_group" | cut -d':' -f1,2)
    
    # Extract expected owner and group and skip with logged error on null
    expected_owner="${owner_group_clean%%:*}"
    expected_group="${owner_group_clean##*:}"
    [[ -z "$expected_owner" || -z "$expected_group" ]] && log_exposure "$project_path" "Missing owner:group column for entry" "$log_level" && continue

    # Extract ownership flags
    ownership_flag=$(echo "$owner_group" | awk -F':' '{print $3}')

    # Extract permissions components
    permissions_clean=$(echo "$permissions" | cut -d':' -f1)
    perms_flag=$(echo "$permissions" | awk -F':' '{print $2}')

    # Extract expected owner and group
    expected_owner=$(echo "$owner_group_clean" | cut -d':' -f1)
    expected_group=$(echo "$owner_group_clean" | cut -d':' -f2)

    # Check if directory or file exists
    if [[ ! -e "$project_path" ]]; then
        log_exposure "$project_path" "Path does not exist" "$log_level"
        [[ "$SILENT" -eq 0 ]] && echo "Warning: $project_path does not exist, skipping..."
        continue
    fi

    # Check and fix ownership and permissions (including recursion)
    find "$project_path" -type d -or -type f | while IFS= read -r item; do
        actual_perms=$(stat -c "%a" "$item")
        actual_owner=$(stat -c "%U" "$item")
        actual_group=$(stat -c "%G" "$item")
        owner_mismatch=$log_level
        file_mismatch=$log_level

        if [[ "$actual_owner" != "$expected_owner" || "$actual_group" != "$expected_group" ]]; then
            log_exposure "$item" "Ownership mismatch (Expected: $expected_owner:$expected_group, Found: $actual_owner:$actual_group)" "$owner_mismatch"
            owner_mismatch="FOLLOWUP"
            [[ "$CHECK_ONLY" -eq 1 ]] && [[ "$SILENT" -eq 0 ]] && echo "[CHECK-ONLY] Ownership issue: $item -> Expected: $expected_owner:$expected_group, Found: $actual_owner:$actual_group"
            apply_fix "chown $expected_owner:$expected_group '$item'"
        elif [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then
            echo "[INFO] Ownership OK: $item"
        fi

        if [[ "$actual_perms" != "$permissions_clean" ]]; then
            log_exposure "$item" "Permissions mismatch (Expected: $permissions_clean, Found: $actual_perms)" "$file_mismatch"
            file_mismatch="FOLLOWUP"
            [[ "$CHECK_ONLY" -eq 1 ]] && [[ "$SILENT" -eq 0 ]] && echo "[CHECK-ONLY] Permissions issue: $item -> Expected: $permissions_clean, Found: $actual_perms"
            apply_fix "chmod $permissions_clean '$item'"
        elif [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then
            echo "[INFO] Permissions OK: $item"
        fi
    done

done < "$CONF_FILE"

[[ "$SILENT" -eq 0 ]] && echo "Project exposure scan completed. Log file: $LOG_FILE"
