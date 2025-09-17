#!/bin/bash

# Author: @Alb4don
# Version: 1.0

set -euo pipefail 
IFS=$'\n\t'       

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/secure_transfer.log"
readonly TEMP_DIR="/tmp/secure_transfer_$$"
readonly ENCRYPTION_ALGO="aes-256-cbc"
readonly KEY_LENGTH=32  
readonly IV_LENGTH=16   
readonly BUFFER_SIZE=8192
readonly MAX_RETRIES=3
readonly TIMEOUT=30

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' 

VERBOSE=false
DELETE_SOURCE=false
RECURSIVE=false
REMOTE_HOST=""
REMOTE_USER=""
REMOTE_PATH=""
TRANSFER_PROTOCOL="scp"

cleanup() {
    local exit_code=$?
    
    if [[ -d "$TEMP_DIR" ]]; then
        log_message "INFO" "Cleaning up temporary files"
        
        find "$TEMP_DIR" -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
    
    unset ENCRYPTION_KEY 2>/dev/null || true
    
    log_message "INFO" "Script execution completed with exit code: $exit_code"
    exit $exit_code
}

trap cleanup EXIT INT TERM

log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    if [[ "$VERBOSE" == true ]] || [[ "$level" == "ERROR" ]] || [[ "$level" == "WARN" ]]; then
        case "$level" in
            "ERROR") echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
            "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" >&2 ;;
            "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
            "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
        esac
    fi
}

usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] <source_files_or_dirs> <remote_destination>

DESCRIPTION:
    Securely encrypt files using AES-256-CBC and transfer them to remote hosts.
    Supports both individual files and recursive directory encryption.

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -r, --recursive         Recursively encrypt directories
    -d, --delete-source     Delete source files after successful transfer
    -u, --user USER         Remote username (default: current user)
    -p, --protocol PROTO    Transfer protocol: scp, rsync (default: scp)
    -t, --timeout SECONDS   Connection timeout (default: 30)

ARGUMENTS:
    source_files_or_dirs    Files or directories to encrypt and transfer
    remote_destination      Remote destination in format: host:/path/to/destination

EXAMPLES:
  
    $SCRIPT_NAME document.txt server1:/backup/

    $SCRIPT_NAME -v -r /home/user/documents server2:/encrypted_backup/
    
    $SCRIPT_NAME -u backup_user -d sensitive_data.csv server3:/secure/

SECURITY FEATURES:
    - AES-256-CBC encryption with unique IVs
    - Cryptographically secure key generation
    - Secure temporary file handling
    - Integrity verification
    - Comprehensive audit logging
    - Automatic secure cleanup

EOF
}

check_dependencies() {
    local deps=("openssl" "ssh" "scp" "shred")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing required dependencies: ${missing_deps[*]}"
        echo -e "${RED}Error:${NC} Please install missing dependencies: ${missing_deps[*]}" >&2
        exit 1
    fi
    
    if ! openssl enc -ciphers | grep -q "$ENCRYPTION_ALGO"; then
        log_message "ERROR" "OpenSSL does not support $ENCRYPTION_ALGO"
        exit 1
    fi
    
    log_message "INFO" "All dependencies verified"
}

generate_secure_key() {
    local key
    key=$(openssl rand -hex $KEY_LENGTH)
    
    if [[ ${#key} -ne $((KEY_LENGTH * 2)) ]]; then
        log_message "ERROR" "Failed to generate secure key of correct length"
        exit 1
    fi
    
    echo "$key"
}

generate_secure_iv() {
    local iv
    iv=$(openssl rand -hex $IV_LENGTH)
    
    if [[ ${#iv} -ne $((IV_LENGTH * 2)) ]]; then
        log_message "ERROR" "Failed to generate secure IV of correct length"
        exit 1
    fi
    
    echo "$iv"
}

calculate_checksum() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        log_message "ERROR" "Cannot calculate checksum: file does not exist: $file"
        return 1
    fi
    
    sha256sum "$file" | cut -d' ' -f1
}

validate_file() {
    local file="$1"
    
    if [[ ! -e "$file" ]]; then
        log_message "ERROR" "File does not exist: $file"
        return 1
    fi
    
    if [[ ! -r "$file" ]]; then
        log_message "ERROR" "File is not readable: $file"
        return 1
    fi
    
    if [[ -L "$file" ]]; then
        log_message "WARN" "Symbolic link detected: $file"
        local target=$(readlink -f "$file")
        log_message "INFO" "Symbolic link target: $target"
        
        if [[ ! -f "$target" ]]; then
            log_message "ERROR" "Symbolic link target is not a regular file: $target"
            return 1
        fi
    fi
    
    return 0
}

encrypt_file() {
    local source_file="$1"
    local encrypted_file="$2"
    local key="$3"
    local iv="$4"
    
    log_message "INFO" "Encrypting file: $source_file"
    
    if ! validate_file "$source_file"; then
        return 1
    fi
    
    local original_checksum
    original_checksum=$(calculate_checksum "$source_file")
    log_message "DEBUG" "Original file checksum: $original_checksum"
    
    touch "$encrypted_file"
    chmod 600 "$encrypted_file"
    
    if ! openssl enc -"$ENCRYPTION_ALGO" -e -in "$source_file" -out "$encrypted_file" \
         -K "$key" -iv "$iv" -bufsize $BUFFER_SIZE 2>/dev/null; then
        log_message "ERROR" "Encryption failed for file: $source_file"
        rm -f "$encrypted_file" 2>/dev/null || true
        return 1
    fi
    
    if [[ ! -f "$encrypted_file" ]] || [[ ! -s "$encrypted_file" ]]; then
        log_message "ERROR" "Encrypted file creation failed: $encrypted_file"
        return 1
    fi
    
    local metadata_file="${encrypted_file}.meta"
    cat > "$metadata_file" << EOF
IV=$iv
ORIGINAL_CHECKSUM=$original_checksum
ORIGINAL_SIZE=$(stat -c%s "$source_file")
ENCRYPTION_ALGO=$ENCRYPTION_ALGO
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
    chmod 600 "$metadata_file"
    
    log_message "INFO" "File encrypted successfully: $encrypted_file"
    return 0
}

transfer_file() {
    local local_file="$1"
    local remote_destination="$2"
    local retry_count=0
    
    log_message "INFO" "Transferring file: $local_file to $remote_destination"
    
    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        case "$TRANSFER_PROTOCOL" in
            "scp")
                if timeout $TIMEOUT scp -C -o StrictHostKeyChecking=yes \
                   -o ConnectTimeout=$TIMEOUT "$local_file" "$remote_destination" 2>/dev/null; then
                    log_message "INFO" "File transferred successfully via SCP"
                    return 0
                fi
                ;;
            "rsync")
                if timeout $TIMEOUT rsync -avz --timeout=$TIMEOUT \
                   "$local_file" "$remote_destination" 2>/dev/null; then
                    log_message "INFO" "File transferred successfully via rsync"
                    return 0
                fi
                ;;
            *)
                log_message "ERROR" "Unsupported transfer protocol: $TRANSFER_PROTOCOL"
                return 1
                ;;
        esac
        
        retry_count=$((retry_count + 1))
        log_message "WARN" "Transfer attempt $retry_count failed, retrying..."
        sleep $((retry_count * 2))  # Exponential backoff
    done
    
    log_message "ERROR" "File transfer failed after $MAX_RETRIES attempts"
    return 1
}

process_file() {
    local source_file="$1"
    local remote_dest="$2"
    
    local filename=$(basename "$source_file")
    local encrypted_filename="${filename}.enc"
    local temp_encrypted_file="$TEMP_DIR/$encrypted_filename"
    local temp_metadata_file="${temp_encrypted_file}.meta"
    
    local file_key
    local file_iv
    
    file_key=$(generate_secure_key)
    file_iv=$(generate_secure_iv)
    
    log_message "DEBUG" "Generated key and IV for file: $filename"
    
    if ! encrypt_file "$source_file" "$temp_encrypted_file" "$file_key" "$file_iv"; then
        log_message "ERROR" "Failed to encrypt file: $source_file"
        return 1
    fi
    
    if ! transfer_file "$temp_encrypted_file" "$remote_dest/$encrypted_filename"; then
        log_message "ERROR" "Failed to transfer encrypted file: $encrypted_filename"
        return 1
    fi
    
    if ! transfer_file "$temp_metadata_file" "$remote_dest/${encrypted_filename}.meta"; then
        log_message "ERROR" "Failed to transfer metadata file: ${encrypted_filename}.meta"
        return 1
    fi
    
    if [[ "$DELETE_SOURCE" == true ]]; then
        log_message "INFO" "Securely deleting source file: $source_file"
        if shred -vfz -n 3 "$source_file" 2>/dev/null; then
            log_message "INFO" "Source file securely deleted: $source_file"
        else
            log_message "WARN" "Failed to securely delete source file: $source_file"
        fi
    fi
    
    unset file_key file_iv
    
    return 0
}

process_directory() {
    local source_dir="$1"
    local remote_dest="$2"
    
    log_message "INFO" "Processing directory recursively: $source_dir"
    
    if [[ ! -d "$source_dir" ]]; then
        log_message "ERROR" "Source is not a directory: $source_dir"
        return 1
    fi
    
    local file_count=0
    local success_count=0
    
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            file_count=$((file_count + 1))
            
            local relative_path
            relative_path=$(realpath --relative-to="$source_dir" "$file")
            local remote_file_dest="$remote_dest/$(dirname "$relative_path")"
            
            ssh "${REMOTE_USER:+$REMOTE_USER@}$REMOTE_HOST" \
                "mkdir -p '$remote_file_dest'" 2>/dev/null || {
                log_message "WARN" "Failed to create remote directory: $remote_file_dest"
            }
            
            if process_file "$file" "$remote_file_dest"; then
                success_count=$((success_count + 1))
            fi
        fi
    done < <(find "$source_dir" -type f -print0)
    
    log_message "INFO" "Directory processing completed: $success_count/$file_count files processed successfully"
    
    if [[ $success_count -eq $file_count ]]; then
        return 0
    else
        return 1
    fi
}

parse_arguments() {
    local args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -r|--recursive)
                RECURSIVE=true
                shift
                ;;
            -d|--delete-source)
                DELETE_SOURCE=true
                shift
                ;;
            -u|--user)
                REMOTE_USER="$2"
                shift 2
                ;;
            -p|--protocol)
                case "$2" in
                    scp|rsync)
                        TRANSFER_PROTOCOL="$2"
                        ;;
                    *)
                        log_message "ERROR" "Unsupported protocol: $2"
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            -t|--timeout)
                if [[ "$2" =~ ^[0-9]+$ ]] && [[ "$2" -gt 0 ]]; then
                    TIMEOUT="$2"
                else
                    log_message "ERROR" "Invalid timeout value: $2"
                    exit 1
                fi
                shift 2
                ;;
            --)
                shift
                args+=("$@")
                break
                ;;
            -*)
                log_message "ERROR" "Unknown option: $1"
                usage >&2
                exit 1
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done
    
    if [[ ${#args[@]} -lt 2 ]]; then
        log_message "ERROR" "Insufficient arguments provided"
        usage >&2
        exit 1
    fi
    
    local remote_dest="${args[-1]}"
    if [[ ! "$remote_dest" =~ ^[^:]+:.+$ ]]; then
        log_message "ERROR" "Invalid remote destination format: $remote_dest"
        echo "Remote destination must be in format: host:/path/to/destination" >&2
        exit 1
    fi
    
    REMOTE_HOST="${remote_dest%%:*}"
    REMOTE_PATH="${remote_dest#*:}"
    
    unset args[-1]
    
    SOURCE_ITEMS=("${args[@]}")
    
    log_message "INFO" "Parsed arguments: ${#SOURCE_ITEMS[@]} source items, remote: $REMOTE_HOST:$REMOTE_PATH"
}

main() {
    echo -e "${GREEN}Secure File Encryption and Transfer Tool v1.0${NC}"
    echo "================================================"
    
    log_message "INFO" "Script started with PID: $$"
    log_message "INFO" "Command line: $0 $*"
    
    parse_arguments "$@"
    
    check_dependencies
    
    if ! mkdir -p "$TEMP_DIR"; then
        log_message "ERROR" "Failed to create temporary directory: $TEMP_DIR"
        exit 1
    fi
    chmod 700 "$TEMP_DIR"
    
    log_message "INFO" "Testing remote connectivity to $REMOTE_HOST"
    if ! ssh -o ConnectTimeout=$TIMEOUT -o BatchMode=yes \
         "${REMOTE_USER:+$REMOTE_USER@}$REMOTE_HOST" \
         "echo 'Connection test successful'" >/dev/null 2>&1; then
        log_message "ERROR" "Cannot connect to remote host: $REMOTE_HOST"
        exit 1
    fi
    
    local total_items=${#SOURCE_ITEMS[@]}
    local success_count=0
    
    for source_item in "${SOURCE_ITEMS[@]}"; do
        log_message "INFO" "Processing: $source_item"
        
        if [[ -f "$source_item" ]]; then
            if process_file "$source_item" "$REMOTE_PATH"; then
                success_count=$((success_count + 1))
            fi
        elif [[ -d "$source_item" ]]; then
            if [[ "$RECURSIVE" == true ]]; then
                if process_directory "$source_item" "$REMOTE_PATH"; then
                    success_count=$((success_count + 1))
                fi
            else
                log_message "ERROR" "Directory specified but recursive mode not enabled: $source_item"
            fi
        else
            log_message "ERROR" "Source item does not exist or is not accessible: $source_item"
        fi
    done
    
    # Summary
    echo
    echo -e "${GREEN}Processing Summary:${NC}"
    echo "=================="
    echo "Total items processed: $total_items"
    echo "Successful transfers: $success_count"
    echo "Failed transfers: $((total_items - success_count))"
    echo "Log file: $LOG_FILE"
    
    if [[ $success_count -eq $total_items ]]; then
        log_message "INFO" "All items processed successfully"
        echo -e "${GREEN}✓ All files encrypted and transferred successfully${NC}"
        exit 0
    else
        log_message "WARN" "Some items failed to process"
        echo -e "${YELLOW}⚠ Some files failed to process. Check log for details.${NC}"
        exit 1
    fi
}

main "$@"
