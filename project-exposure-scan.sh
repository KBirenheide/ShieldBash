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
valid_recursion_flags=( "r" "d" "f" "h" "a")

# Error Resiliance
misconfigured_lines=()

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
        local has_line_misconfiguration=0

        # Skip commented lines and empty lines
        [[ "$owner_group" =~ ^#.*$ || -z "$owner_group" ]] && continue

        # Trim leading/trailing whitespace 
        owner_group=$(echo "$owner_group" | xargs)
        permissions=$(echo "$permissions" | xargs)
        project_path=$(echo "$project_path" | xargs | sed 's/\/\*$//g; s/\/$//g; s/\/\*\..*$//g')
        log_level=$(echo "$log_level" | xargs)

        # Validate ownership format (owner:group[:optional flags])
        if ! [[ "$owner_group" =~ ^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+(:[a-z]+)?$ ]]; then
            echo "[WARNING] Invalid owner:group format found in PES config (line ${line}): '$owner_group'"
            has_line_misconfiguration=1
        fi

        # Validate permissions (should be a 3 or 4-digit octal number)
        if ! [[ "$permissions" =~ ^[0-7]{3,4}(:[a-z]+)?$ ]]; then
            echo "[WARNING] Invalid permissions format found in PES config (line ${line}): '$permissions' (Expected: 3 or 4-digit octal number)"
            has_line_misconfiguration=1
        fi

        # Validate project path
        if [[ ! -e "$project_path" ]]; then
            echo "[WARNING] Path does not exist found in PES config (line ${line}): '$project_path'"
            has_line_misconfiguration=1
        fi
        if [[ ! "$project_path" =~ ^\/ ]]; then
            echo "[WARNING] Paths need to be absolute. Relative paths are skipped during exposure scans (line ${line}): '$project_path'"
            has_line_misconfiguration=1
        fi

        # Validate log level (must be one of INFO, WARNING, CRITICAL, FOLLOWUP, CONFIG)
        valid_log_levels=("INFO" "WARNING" "CRITICAL" "FOLLOWUP" "CONFIG")
        log_level_upper=$(echo "$log_level" | tr '[:lower:]' '[:upper:]')

        if [[ ! " ${valid_log_levels[*]} " =~ " $log_level_upper " ]]; then
            echo "[WARNING] Invalid log level found in PES config (line ${line}): '$log_level' (Expected: INFO, WARNING, CRITICAL, FOLLOWUP, CONFIG)"
            has_line_misconfiguration=1
        fi

        [[ $has_line_misconfiguration == 1 ]] && misconfigured_lines=("${misconfigured_lines[@]}" $line)

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
            echo -e "[WARNING] The PES configuration file was edited since the last PES run (or the log file has been rotated). use command ${YELLOW}shield-bash pes --pull-log=PESconfig${RESET} to see the edit history." 
        fi
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO][ShieldBash PES][CONFIG] Configuration file modified by: $config_owner at $config_mtime_readable" >> "$LOG_FILE"
    fi
}

# Function: Item owner validation
owner_mismatch=0
validate_owner()
{
    local actual_owner=$1
    local expected_owner=$2
    local actual_group=$3
    local expected_group=$4
    local item=$5

    if [[ "$actual_owner" != "$expected_owner" || "$actual_group" != "$expected_group" ]]; then
        log_exposure "$item" "Ownership mismatch (Expected: $expected_owner:$expected_group, Found: $actual_owner:$actual_group)" "$owner_mismatch"
        owner_mismatch="FOLLOWUP"
        [[ "$CHECK_ONLY" -eq 1 ]] && [[ "$SILENT" -eq 0 ]] && echo "[CHECK-ONLY] Ownership issue: $item -> Expected: $expected_owner:$expected_group, Found: $actual_owner:$actual_group"
        apply_fix "chown $expected_owner:$expected_group '$item'"
    elif [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then
        echo "[INFO] Ownership OK: $item"
    fi
}

# Function: validate permission settings
file_mismatch=0
validate_permissions() 
{
    local actual_perms=$1
    local permissions_clean=$2
    local item=$3

    if [[ "$actual_perms" != "$permissions_clean" ]]; then
        log_exposure "$item" "Permissions mismatch (Expected: $permissions_clean, Found: $actual_perms)" "$file_mismatch"
        file_mismatch="FOLLOWUP"
        [[ "$CHECK_ONLY" -eq 1 ]] && [[ "$SILENT" -eq 0 ]] && echo "[CHECK-ONLY] Permissions issue: $item -> Expected: $permissions_clean, Found: $actual_perms"
        apply_fix "chmod $permissions_clean '$item'"
    elif [[ "$VERBOSE" -eq 1 ]] && [[ "$SILENT" -eq 0 ]]; then
        echo "[INFO] Permissions OK: $item"
    fi
}

check_config_modification
validate_config

config_line=0 

# Read and process configuration file
while IFS="|" read -r owner_group permissions project_path log_level || [[ -n "$owner_group" ]]; do
    # skip misconfigured lines
    let "config_line++"
    if [[ " ${misconfigured_lines[*]} " =~ " ${config_line} " ]]; then
        [[ "$SILENT" -eq 0 ]] && echo "[INFO] Skipping misconfigured line $config_line in $CONF_FILE"
        continue
    fi

    # Trim whitespace
    owner_group=$(echo "$owner_group" | xargs)
    permissions=$(echo "$permissions" | xargs)
    project_path=$(echo "$project_path" | xargs)
    log_level=$(echo "$log_level" | xargs)
    
    # Initialize path flags
    co=0  # Children Only flag
    eo=0  # Extension Only flag
    ext=""  # Holds extracted extension

    # Detect wildcard patterns before sanitization
    if [[ "$project_path" =~ \/\*$ ]]; then
        co=1
    elif [[ "$project_path" =~ \/\*\.[a-zA-z0-9]+$ ]]; then
        eo=1
        # Extract file extension and turn it to upper case
        ext=$(echo "${project_path##*.}" | tr '[:lower:]' '[:upper:]')  
    fi

    # Sanitize the path (remove wildcards)
    project_path=$(echo "$project_path" | sed 's/\/\*$//g; s/\/$//g; s/\/\*\..*$//g')
    
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

    # Extract ownership flags (e.g., :ra, :rah, :rd, :rdh, etc.)
    ownership_flag=$(echo "$owner_group" | awk -F':' '{print $3}')

    # Extract permission flags (e.g., :rf, :rfh, etc.)
    perms_flag=$(echo "$permissions" | awk -F':' '{print $2}')

    # Create a scannable flag array, then leverage it to determine find command parameters
    ownership_flag=$(echo "$ownership_flag" | xargs)
    perms_flag=$(echo "$perms_flag" | xargs)
    char_array=($(echo "$ownership_flag$perms_flag" | grep -o . | sort -u))

    # Check for invalid flags
    for char in "${char_array[@]}"; do
        if [[ ! " ${valid_recursion_flags[*]} " =~ " $char " ]]; then
            [[ "$SILENT" -eq 0 ]] && echo "Warning: incorrect ownership flags (${ownership_flag}) or permission flags (${perms_flag})"
            continue 2  # Skip the current iteration of the outer while loop
        fi
    done

    # Create a scannable flag array, then leverage it to determine find command parameters
    char_array=($(echo "$ownership_flag$perms_flag" | grep -o . | sort -u))
    include_hidden=0
    find_hidden=" ! -name \".*\""
    find_parts=()


    # If hidden files SHOULD be included, clear the exclusion rule
    [[ " ${char_array[*]} " =~ " h " ]] && find_hidden=""

    # Enable flags based on detected characters
    [[ " ${char_array[*]} " =~ " d " ]] && recurse_directories=1 && find_parts+=("-type d$find_hidden")
    [[ $recurse_directories -eq 1 && $recurse_files -eq 1 ]] && find_parts+=("-o")
    [[ " ${char_array[*]} " =~ " f " ]] && recurse_files=1 && find_parts+=("-type f$find_hidden")

    # Construct find command safely by joining array elements
    find_cmd="find \"$project_path\""
    [[ ${#find_parts[@]} -gt 0 ]] && find_cmd+=" ${find_parts[*]}"

    # Handle pase-bath
    actual_perms=$(stat -c "%a" "$project_path")
    actual_owner=$(stat -c "%U" "$project_path")
    actual_group=$(stat -c "%G" "$project_path")
    [[ $co -eq 0 ]] && validate_owner "$actual_owner" "$expected_owner" "$actual_group" "$expected_group" "$project_path"
    [[ $co -eq 0 ]] && validate_permissions "$actual_perms" "$permissions_clean" "$project_path"
    [[ ! " ${char_array[*]} " =~ " r " ]] && continue

    # Check and fix ownership and permissions (including recursion)
    eval $find_cmd | while IFS= read -r item; do

        [[ -z "$item" ]] && continue
        [[ "$item" == "$project_path" ]] && continue
        item_ext=$(echo ${item##*.} | tr '[:lower:]' '[:upper:]')
        [[ $eo -eq 1 && "$item_ext" != "$ext" ]] && continue

        actual_perms=$(stat -c "%a" "$item")
        actual_owner=$(stat -c "%U" "$item")
        actual_group=$(stat -c "%G" "$item")
        owner_mismatch=$log_level
        file_mismatch=$log_level

        # Check if the item is hidden using a regex match
        is_hidden=0
        [[ "$item" =~ (^|/)\.[^/]+(/|$) ]] && is_hidden=1

        if [[ " $ownership_flag " == *h* || $is_hidden -eq 0 ]]; then
            [[ ! -z "$ownership_flag" ]] && validate_owner "$actual_owner" "$expected_owner" "$actual_group" "$expected_group" "$item"
        fi

        if [[ " $perms_flag " == *h* || $is_hidden -eq 0 ]]; then
            [[ ! -z "$perms_flag" ]] && validate_permissions "$actual_perms" "$permissions_clean" "$item"   
        fi

    done

done < "$CONF_FILE"

[[ "$SILENT" -eq 0 ]] && echo "Project exposure scan completed. Log file: $LOG_FILE"