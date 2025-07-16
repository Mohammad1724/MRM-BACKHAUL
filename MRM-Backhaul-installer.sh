#!/bin/bash
set -euo pipefail

# --- Configurable paths and defaults ---
BACKHAUL_DIR="${BACKHAUL_DIR:-/opt/backhaul}"
SERVICE_NAME="backhaul"
CONFIG_FILE="${BACKHAUL_DIR}/config.toml"
TELEGRAM_CONFIG="${BACKHAUL_DIR}/telegram.conf"
LOG_FILE="${BACKHAUL_DIR}/install.log"
MONITOR_SCRIPT="${BACKHAUL_DIR}/backhaul-monitor.sh"
BACKHAUL_VERSION="latest" # Can be changed to a specific version like "v1.0.0"
GITHUB_URL="https://github.com/Musixal/Backhaul/releases"

# --- Global variables for config values (will be loaded/set) ---
# Initializing with default/empty values to avoid 'unbound variable' errors
SERVER_TYPE="" # "server" or "client"

# Common settings
USER_TOKEN=""
KEEPALIVE="75"
NODELAY="false"
SNIFFER="false"
WEB_PORT="2060"
SNIFFER_LOG="/var/log/backhaul-sniffer.log" # Updated default path for better logging practices
LOG_LEVEL="info"
BOT_TOKEN=""
CHAT_ID=""

# Server-specific settings
MAIN_PORT="3080" # This is bind_addr port
TRANSPORT="tcp"
ACCEPT_UDP="false"
TLS_CERT=""
TLS_KEY=""
PORTS_STRING="" # Comma-separated list of ports to tunnel
HEARTBEAT="5" # Default value added
CHANNEL_SIZE="1024" # Default value added

# Client-specific settings
REMOTE_IP="" # Hostname or IP
CONNECTION_POOL="8"
AGGRESSIVE_POOL="false"
RETRY_INTERVAL="3"
DIAL_TIMEOUT="10"
EDGE_IP=""

# MUX specific settings (for tcpmux, wsmux, wssmux)
MUX_CON="8" # Only for server-side
MUX_VERSION="1"
MUX_FRAMESIZE="32768"
MUX_RECEIVEBUFFER="4194304"
MUX_STREAMBUFFER="65536"

# --- Check if running as root ---
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Use sudo."
    exit 1
fi

# --- Logging function ---
log() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LOG_FILE"
}

# --- Utility Functions ---

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Confirmation prompt
confirm() {
    read -p "$1 (y/n): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# Backup existing config file
backup_config() {
    local file="$1"
    if [ -f "$file" ]; then
        local backup_file="${file}.$(date +%Y%m%d%H%M%S).bak"
        cp "$file" "$backup_file"
        log "INFO" "Backed up $file to $backup_file"
    fi
}

# Validate boolean input
validate_boolean() {
    local var_name="$1"
    local value="$2"
    if [[ "$value" =~ ^(true|false)$ ]]; then
        return 0 # Valid
    else
        log "ERROR" "$var_name must be 'true' or 'false'. Received: '$value'"
        return 1 # Invalid
    fi
}

# Validate numeric input
validate_number() {
    local var_name="$1"
    local value="$2"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        return 0 # Valid
    else
        log "ERROR" "$var_name must be a number. Received: '$value'"
        return 1 # Invalid
    fi
}

# --- Telegram Configuration Functions ---

# Read Telegram settings from telegram.conf
read_telegram_config() {
    BOT_TOKEN="" # Reset to empty
    CHAT_ID=""   # Reset to empty
    if [ -f "$TELEGRAM_CONFIG" ]; then
        # Using IFS to handle spaces in token/id more robustly if they were ever to contain them
        local line
        while IFS='=' read -r key val; do
            key=$(echo "$key" | tr -d '[:space:]')
            val=$(echo "$val" | tr -d '[:space:]"') # Remove quotes and spaces

            case "$key" in
                bot_token) BOT_TOKEN="$val" ;;
                chat_id) CHAT_ID="$val" ;;
            esac
        done < "$TELEGRAM_CONFIG"
        log "INFO" "Telegram config loaded. Bot token: ${BOT_TOKEN:+Set}, Chat ID: ${CHAT_ID:+Set}"
    else
        log "INFO" "Telegram config file not found: $TELEGRAM_CONFIG"
    fi
}

# Configure Telegram settings
configure_telegram() {
    echo -e "\n--- Telegram Monitoring Setup ---"
    local current_bot_token="$BOT_TOKEN"
    local current_chat_id="$CHAT_ID"

    if [ -n "$current_bot_token" ]; then
        read -p "Current Telegram Bot Token is set. Enter new token (or press Enter to keep current): " new_bot_token
        BOT_TOKEN="${new_bot_token:-$current_bot_token}"
    else
        read -p "Enter Telegram Bot Token (or leave empty to disable monitoring): " BOT_TOKEN
    fi

    if [ -n "$BOT_TOKEN" ]; then
        if [ -n "$current_chat_id" ]; then
            read -p "Current Telegram Chat ID is set. Enter new ID (or press Enter to keep current): " new_chat_id
            CHAT_ID="${new_chat_id:-$current_chat_id}"
        else
            read -p "Enter Telegram Chat ID: " CHAT_ID
        fi

        if [ -n "$CHAT_ID" ]; then
            log "INFO" "Telegram monitoring enabled."
            # Save to telegram.conf
            cat > "$TELEGRAM_CONFIG" <<EOF
bot_token="$BOT_TOKEN"
chat_id="$CHAT_ID"
EOF
            chmod 600 "$TELEGRAM_CONFIG" # More secure permissions
            chown backhaul:backhaul "$TELEGRAM_CONFIG"
            log "INFO" "Telegram settings saved to $TELEGRAM_CONFIG"
        else
            log "WARNING" "Telegram Chat ID cannot be empty. Monitoring disabled."
            BOT_TOKEN=""
            CHAT_ID=""
            rm -f "$TELEGRAM_CONFIG" 2>/dev/null
        fi
    else
        log "INFO" "Telegram monitoring disabled."
        rm -f "$TELEGRAM_CONFIG" 2>/dev/null
    fi
}

# Create monitoring script
create_monitor_script() {
    cat > "$MONITOR_SCRIPT" <<EOF
#!/bin/bash
set -euo pipefail

CONFIG_FILE="$CONFIG_FILE"
TELEGRAM_CONFIG="$TELEGRAM_CONFIG"
SERVICE_NAME="$SERVICE_NAME"
LOG_FILE="$LOG_FILE"

# Logging function for monitor script
monitor_log() {
    local level="\$1"
    local message="\$2"
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [\$level] \$message" >> "\$LOG_FILE"
}

# Read Telegram settings
read_monitor_telegram_config() {
    BOT_TOKEN_MON=""
    CHAT_ID_MON=""
    if [ -f "\$TELEGRAM_CONFIG" ]; then
        while IFS='=' read -r key val; do
            key=\$(echo "\$key" | tr -d '[:space:]')
            val=\$(echo "\$val" | tr -d '[:space:]"')
            case "\$key" in
                bot_token) BOT_TOKEN_MON="\$val" ;;
                chat_id) CHAT_ID_MON="\$val" ;;
            esac
        done < "\$TELEGRAM_CONFIG"
    fi
}

# Function to parse TOML-like config for ports
get_config_value() {
    local section="\$1"
    local key="\$2"
    local default_val="\$3"
    local value=""

    # Check for the key within the specified section
    # Using awk to find the section and then the key
    value=\$(awk -v section="[\$section]" -v key_name="\$key" '
        \$0 ~ section { in_section=1; next }
        /^\\[.*?\\]/ { in_section=0 }
        in_section && \$0 ~ "^[[:space:]]*" key_name "[[:space:]]*=" {
            sub(/^[[:space:]]*"?"? *key_name *=[[:space:]]*/, "", \$0) # Remove key and assignment
            sub(/[\"\' ]*\$/, "", \$0) # Remove trailing quotes/spaces
            print \$0
            exit
        }
    ' "\$CONFIG_FILE")

    echo "\${value:-\$default_val}" # Return found value or default
}


read_monitor_telegram_config
if [ -z "\$BOT_TOKEN_MON" ] || [ -z "\$CHAT_ID_MON" ]; then
    monitor_log "INFO" "Telegram monitoring is disabled or misconfigured. Exiting monitor script."
    exit 0 # Exit silently if monitoring is not set up
fi

# Load ports from config (server or client mode)
local main_port_val="3080" # Default value if not found
local web_port_val="2060"  # Default value if not found

if grep -q "^\\[server\\]" "\$CONFIG_FILE"; then
    main_port_val=\$(get_config_value "server" "bind_addr" "0.0.0.0:3080" | sed 's/.*://') # Extract port
    web_port_val=\$(get_config_value "server" "web_port" "2060")
elif grep -q "^\\[client\\]" "\$CONFIG_FILE"; then
    main_port_val=\$(get_config_value "client" "remote_addr" "0.0.0.0:3080" | sed 's/.*://')
    web_port_val=\$(get_config_value "client" "web_port" "2060")
else
    monitor_log "ERROR" "Cannot determine server/client mode from config file. Exiting monitor."
    exit 1
fi

# Check service status
if ! systemctl is-active "\$SERVICE_NAME" >/dev/null; then
    monitor_log "ERROR" "Backhaul service is DOWN."
    curl -s -X POST "https://api.telegram.org/bot\$BOT_TOKEN_MON/sendMessage" \
        -d chat_id="\$CHAT_ID_MON" \
        -d text="🚨 Alert: Backhaul service is DOWN on \$(hostname)!" >/dev/null
    exit 1
fi

# Check ports
# If web_port is 0, it means it's disabled, so only check main_port.
# If web_port is not 0, check both.
local ports_ok=true
if ! ss -tuln | grep -q ":\$main_port_val"; then
    ports_ok=false
fi

if [ "\$web_port_val" -ne 0 ]; then
    if ! ss -tuln | grep -q ":\$web_port_val"; then
        ports_ok=false
    fi
fi

if [ "\$ports_ok" = false ]; then
    monitor_log "ERROR" "One or more Backhaul ports are not open."
    local port_message="⚠️ Alert: Backhaul ports on \$(hostname) are NOT OPEN! (Main: \$main_port_val"
    if [ "\$web_port_val" -ne 0 ]; then
        port_message+=", Web: \$web_port_val"
    else
        port_message+=" (Web UI disabled)"
    fi
    port_message+=")"
    curl -s -X POST "https://api.telegram.org/bot\$BOT_TOKEN_MON/sendMessage" \
        -d chat_id="\$CHAT_ID_MON" \
        -d text="\$port_message" >/dev/null
    exit 1
fi

monitor_log "INFO" "Backhaul service and ports are running normally."
EOF
    chmod 750 "$MONITOR_SCRIPT"
    chown backhaul:backhaul "$MONITOR_SCRIPT"
    log "INFO" "Monitoring script created/updated at $MONITOR_SCRIPT"
}

# Setup cron job for monitoring
setup_monitoring_cron() {
    # Ensure monitoring script exists before adding cron
    create_monitor_script # Always re-create to ensure it's up-to-date

    read_telegram_config # Make sure global BOT_TOKEN and CHAT_ID are up-to-date

    if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
        read -p "Enable periodic monitoring via cron (runs every 5 minutes)? (y/n, default y): " enable_cron
        enable_cron=${enable_cron:-y}
        if [[ "$enable_cron" =~ ^[Yy]$ ]]; then
            # Use fgrep -v for safer cron line removal
            (crontab -l 2>/dev/null | fgrep -v "$MONITOR_SCRIPT"; echo "*/5 * * * * $MONITOR_SCRIPT") | crontab -
            log "INFO" "Cron job for monitoring set up to run every 5 minutes."
        else
            log "INFO" "Periodic monitoring via cron disabled by user."
            disable_monitoring_cron # Ensure it's disabled if user chooses 'n'
        fi
    else
        log "WARNING" "Telegram settings not fully configured. Cannot enable monitoring."
        disable_monitoring_cron # Ensure it's disabled if settings are missing
    fi
}

# Disable monitoring cron
disable_monitoring_cron() {
    if crontab -l 2>/dev/null | fgrep -q "$MONITOR_SCRIPT"; then
        (crontab -l 2>/dev/null | fgrep -v "$MONITOR_SCRIPT") | crontab -
        log "INFO" "Monitoring cron job disabled."
    else
        log "INFO" "No monitoring cron job found to disable."
    fi
    rm -f "$MONITOR_SCRIPT" # Remove the script itself
    log "INFO" "Removed monitoring script: $MONITOR_SCRIPT"
}

# Telegram status report (using globally loaded config)
telegram_status_report() {
    read_telegram_config # Re-read to ensure latest settings
    if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        log "INFO" "Telegram reporting skipped: Bot token or Chat ID is not set."
        return
    fi

    local status
    status=$(systemctl is-active "$SERVICE_NAME" || echo "inactive")
    local version="Unknown"
    if [ -x "${BACKHAUL_DIR}/backhaul" ]; then
        version=$("${BACKHAUL_DIR}/backhaul" -v 2>/dev/null | head -n 1 || echo "Unknown")
    fi

    # Ensure current config values are loaded
    load_current_config

    local main_port_status="N/A"
    local web_port_status="N/A"

    # Determine which port to check for main_port_status based on server_type
    local service_main_port
    if [ "$SERVER_TYPE" == "server" ]; then
        service_main_port="$MAIN_PORT"
    elif [ "$SERVER_TYPE" == "client" ]; then
        # For client, main_port is the remote_addr port, which isn't bound locally
        # We need to check if local listening ports (if any) are open, or just service active.
        # For a client, its "main port" (remote_addr) is usually not locally bound.
        # So we might not report "OPEN" unless it also listens on a local port.
        # For now, let's just indicate it's a client.
        service_main_port="N/A (Client Mode)"
    fi

    if [[ "$service_main_port" != "N/A (Client Mode)" ]]; then
        if ss -tuln | grep -q ":$service_main_port"; then
            main_port_status="OPEN"
        else
            main_port_status="CLOSED"
        fi
    fi

    if [ "$WEB_PORT" -ne 0 ]; then
        if ss -tuln | grep -q ":$WEB_PORT"; then
            web_port_status="OPEN"
        else
            web_port_status="CLOSED"
        fi
    else
        web_port_status="DISABLED (0)"
    fi

    local message="✨ Backhaul Status Report ($(hostname)) ✨
- Service: *$status*
- Version: *$version*
- Role: *$SERVER_TYPE*"

    if [ -n "$TRANSPORT" ]; then
        message+="\n- Transport: *$TRANSPORT*"
    fi

    if [[ "$SERVER_TYPE" == "server" ]]; then
        message+="\n- Main Port ($MAIN_PORT): *$main_port_status*"
        message+="\n- Web Port ($WEB_PORT): *$web_port_status*"
        message+="\n- Tunneled Ports: *$(if [ -n "$PORTS_STRING" ]; then echo "$PORTS_STRING"; else echo "None"; fi)*"
    elif [ "$SERVER_TYPE" == "client" ]; then
        message+="\n- Remote Server: *$REMOTE_IP:$MAIN_PORT*"
        if [ -n "$EDGE_IP" ]; then
            message+="\n- Edge IP: *$EDGE_IP*"
        fi
        message+="\n- Web Port ($WEB_PORT): *$web_port_status*" # Client also has web_port
    fi


    # Send message via curl, gracefully handle errors
    if ! curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d chat_id="$CHAT_ID" \
        -d parse_mode="Markdown" \
        -d text="$message" >/dev/null; then
        log "ERROR" "Failed to send Telegram status report."
    else
        log "INFO" "Telegram status report sent."
    fi
}

# --- Backhaul Configuration Questions ---

# Ask for Server or Client role (at the very beginning of install)
ask_server_or_client() {
    echo -e "\n--- Backhaul Role Configuration ---"
    read -p "Configure as Server or Client? (server/client): " SERVER_TYPE_INPUT
    SERVER_TYPE_INPUT=$(echo "$SERVER_TYPE_INPUT" | tr '[:upper:]' '[:lower:]')
    if [[ "$SERVER_TYPE_INPUT" != "server" && "$SERVER_TYPE_INPUT" != "client" ]]; then
        log "ERROR" "Invalid role. Please enter 'server' or 'client'."
        exit 1
    fi
    SERVER_TYPE="$SERVER_TYPE_INPUT" # Set global variable
}

# Ask for transport protocol (common for both roles)
ask_transport() {
    echo -e "\n--- Transport Protocol Configuration ---"
    echo "Available transports: tcp, tcpmux, udp, ws, wss, wsmux, wssmux"
    read -p "Choose transport protocol (default: $TRANSPORT): " trans
    if [ -n "$trans" ]; then TRANSPORT=$(echo "$trans" | tr '[:upper:]' '[:lower:]'); fi
    case "$TRANSPORT" in
        tcp|tcpmux|udp|ws|wss|wsmux|wssmux) ;;
        *) log "ERROR" "Invalid transport protocol. Please choose from the list."; exit 1 ;;
    esac
}

# Ask for common settings
ask_common_settings() {
    echo -e "\n--- Common Backhaul Settings ---"
    # Only ask for token if not already set or if user wants to change
    local current_token_display="${USER_TOKEN:+Set (current value will be hidden)}"
    read -p "Enter your shared secret token (e.g., a strong password, default: ${current_token_display:-random}): " user_t
    if [ -n "$user_t" ]; then
        USER_TOKEN="$user_t"
    elif [ -z "$USER_TOKEN" ]; then # If no input and no current token
        USER_TOKEN=$(head /dev/urandom | tr -dc A-Za-z0-9_ | head -c 16 ; echo '')
    fi

    if [ -z "$USER_TOKEN" ]; then
        log "ERROR" "Token cannot be empty."
        exit 1
    fi
    log "INFO" "Token set: ${USER_TOKEN:+Set}" # Log whether it's set without showing value

    read -p "Enter keepalive period in seconds (default: $KEEPALIVE): " keepal
    if [ -n "$keepal" ]; then KEEPALIVE="$keepal"; fi
    validate_number "Keepalive period" "$KEEPALIVE" || exit 1

    read -p "Enable No Delay (TCP_NODELAY)? (true/false, default: $NODELAY): " nodel
    if [ -n "$nodel" ]; then NODELAY=$(echo "$nodel" | tr '[:upper:]' '[:lower:]'); fi
    validate_boolean "No Delay" "$NODELAY" || exit 1

    read -p "Enable Sniffer (intercept traffic)? (true/false, default: $SNIFFER): " snif
    if [ -n "$snif" ]; then SNIFFER=$(echo "$snif" | tr '[:upper:]' '[:lower:]'); fi
    validate_boolean "Sniffer" "$SNIFFER" || exit 1
    
    if [[ "$SNIFFER" == "true" ]]; then
        read -p "Enter sniffer log file path (default: $SNIFFER_LOG): " snif_l
        SNIFFER_LOG=${snif_l:-$SNIFFER_LOG}
        mkdir -p "$(dirname "$SNIFFER_LOG")" # Ensure log directory exists
        touch "$SNIFFER_LOG" && chmod 640 "$SNIFFER_LOG" # Create and set permissions
        chown backhaul:backhaul "$SNIFFER_LOG"
    else
        SNIFFER_LOG="" # No sniffer log if sniffer is off
    fi

    read -p "Enter Web Port (set to 0 to disable, default: $WEB_PORT): " web_p
    if [ -n "$web_p" ]; then WEB_PORT="$web_p"; fi
    validate_number "Web Port" "$WEB_PORT" || exit 1

    echo "Available log levels: panic, fatal, error, warn, info, debug, trace"
    read -p "Enter Backhaul log level (default: $LOG_LEVEL): " log_l
    if [ -n "$log_l" ]; then LOG_LEVEL=$(echo "$log_l" | tr '[:upper:]' '[:lower:]'); fi
    case "$LOG_LEVEL" in
        panic|fatal|error|warn|info|debug|trace) ;;
        *) log "ERROR" "Invalid log level. Please choose from the list."; exit 1 ;;
    esac
}

# Ask for MUX specific settings
ask_mux_settings() {
    echo -e "\n--- MUX Specific Settings ---"
    read -p "Enter MUX protocol version (1 or 2, default: $MUX_VERSION): " mv
    if [ -n "$mv" ]; then MUX_VERSION="$mv"; fi
    if [[ "$MUX_VERSION" != "1" && "$MUX_VERSION" != "2" ]]; then
        log "ERROR" "MUX version must be 1 or 2."
        exit 1
    fi

    read -p "Enter MUX frame size (bytes, default: $MUX_FRAMESIZE): " mfs
    if [ -n "$mfs" ]; then MUX_FRAMESIZE="$mfs"; fi
    validate_number "MUX frame size" "$MUX_FRAMESIZE" || exit 1

    read -p "Enter MUX receive buffer size (bytes, default: $MUX_RECEIVEBUFFER): " mrb
    if [ -n "$mrb" ]; then MUX_RECEIVEBUFFER="$mrb"; fi
    validate_number "MUX receive buffer size" "$MUX_RECEIVEBUFFER" || exit 1

    read -p "Enter MUX stream buffer size (bytes, default: $MUX_STREAMBUFFER): " msb
    if [ -n "$msb" ]; then MUX_STREAMBUFFER="$msb"; fi
    validate_number "MUX stream buffer size" "$MUX_STREAMBUFFER" || exit 1
}

# Configure TLS settings (for wss/wssmux server)
configure_tls() {
    echo -e "\n--- TLS Certificate Configuration (for wss/wssmux) ---"
    
    # Pre-fill current values if available
    local current_tls_cert="$TLS_CERT"
    local current_tls_key="$TLS_KEY"

    local cert_exists=false
    local key_exists=false

    if [ -n "$current_tls_cert" ] && [ -f "$current_tls_cert" ] && [ -n "$current_tls_key" ] && [ -f "$current_tls_key" ]; then
        log "INFO" "Existing TLS certificate and key paths are configured."
        echo "Current TLS Cert: $current_tls_cert"
        echo "Current TLS Key: $current_tls_key"
        cert_exists=true
        key_exists=true
    else
        log "INFO" "No existing TLS certificate and key found/configured."
    fi

    if [[ "$cert_exists" == "true" && "$key_exists" == "true" ]]; then
        read -p "Use current TLS cert/key paths? (y/n, default y): " use_current_tls
        use_current_tls=${use_current_tls:-y}
        if [[ "$use_current_tls" =~ ^[Yy]$ ]]; then
            log "INFO" "Using existing TLS certificate and key."
            # Verify file permissions
            if ! [ -r "$current_tls_cert" ] || ! [ -r "$current_tls_key" ]; then
                log "ERROR" "Existing TLS certificate or key files are not readable. Please check permissions."
                exit 1
            fi
            TLS_CERT="$current_tls_cert" # Ensure global vars are set
            TLS_KEY="$current_tls_key"   # Ensure global vars are set
            return # Exit function, no need to ask more
        fi
    fi

    read -p "Do you want to generate a self-signed certificate (for testing)? (y/n, default n): " generate_self_signed
    generate_self_signed=${generate_self_signed:-n}

    if [[ "$generate_self_signed" =~ ^[Yy]$ ]]; then
        if ! command_exists openssl; then
            log "ERROR" "openssl is not installed. Cannot generate self-signed certificate. Please install openssl or provide your own certificates."
            exit 1
        fi
        log "INFO" "Generating self-signed certificate..."
        mkdir -p "${BACKHAUL_DIR}/certs"
        TLS_CERT="${BACKHAUL_DIR}/certs/server.crt"
        TLS_KEY="${BACKHAUL_DIR}/certs/server.key"

        openssl req -x509 -newkey rsa:4096 -keyout "$TLS_KEY" -out "$TLS_CERT" -days 365 -nodes \
            -subj "/C=IR/ST=Tehran/L=Tehran/O=Backhaul/OU=IT/CN=$(hostname)" 2>/dev/null || { # Changed subject for Iran/Tehran
            log "ERROR" "Failed to generate self-signed certificate."
            exit 1
        }
        chmod 600 "$TLS_KEY"
        chmod 644 "$TLS_CERT"
        chown backhaul:backhaul "$TLS_KEY" "$TLS_CERT"
        log "INFO" "Self-signed certificate generated at $TLS_CERT and $TLS_KEY"
    else
        read -p "Enter path to TLS Certificate file (e.g., /etc/ssl/certs/your.crt): " cert_path
        read -p "Enter path to TLS Private Key file (e.g., /etc/ssl/private/your.key): " key_path
        
        if [ -z "$cert_path" ] || [ -z "$key_path" ]; then
            log "ERROR" "TLS Certificate and Key paths cannot be empty for wss/wssmux."
            exit 1
        fi

        if [ ! -f "$cert_path" ] || [ ! -f "$key_path" ]; then
            log "ERROR" "TLS Certificate or Key file not found. Please verify paths."
            exit 1
        fi

        if ! [ -r "$cert_path" ] || ! [ -r "$key_path" ]; then
            log "ERROR" "TLS Certificate or Key files are not readable. Please check permissions."
            exit 1
        fi
        
        TLS_CERT="$cert_path"
        TLS_KEY="$key_path"
        log "INFO" "Using provided TLS certificate and key: $TLS_CERT, $TLS_KEY"
    fi
}

# Ask for server-specific settings
ask_server_specific_settings() {
    echo -e "\n--- Server Specific Settings ---"
    read -p "Enter Server Bind Port (default: $MAIN_PORT): " main_p
    if [ -n "$main_p" ]; then MAIN_PORT="$main_p"; fi
    validate_number "Server Bind Port" "$MAIN_PORT" || exit 1

    read -p "Enter heartbeat interval in seconds (default: $HEARTBEAT): " heartb
    if [ -n "$heartb" ]; then HEARTBEAT="$heartb"; fi
    validate_number "Heartbeat interval" "$HEARTBEAT" || exit 1

    read -p "Enter channel size (buffer, default: $CHANNEL_SIZE): " ch_size
    if [ -n "$ch_size" ]; then CHANNEL_SIZE="$ch_size"; fi
    validate_number "Channel size" "$CHANNEL_SIZE" || exit 1

    if [[ "$TRANSPORT" == "tcp" || "$TRANSPORT" == "tcpmux" ]]; then
        read -p "Enable accepting UDP connections over TCP transport? (true/false, default: $ACCEPT_UDP): " accept_u
        if [ -n "$accept_u" ]; then ACCEPT_UDP=$(echo "$accept_u" | tr '[:upper:]' '[:lower:]'); fi
        validate_boolean "Accept UDP" "$ACCEPT_UDP" || exit 1
    fi

    echo "Enter comma-separated ports for tunneling (e.g., 22,80,443,10000-10005). Supports advanced formats like:"
    echo "  - 443"
    echo "  - 4000=5000 (listen 4000, forward to 5000)"
    echo "  - 127.0.0.2:443=5201 (bind to specific IP:port, forward)"
    read -p "Leave empty for no port forwarding: " ports_s
    PORTS_STRING=$ports_s

    # Handle TLS cert/key if WSS/WSSMUX
    if [[ "$TRANSPORT" == "wss" || "$TRANSPORT" == "wssmux" ]]; then
        configure_tls
    fi
}

# Ask for client-specific settings
ask_client_specific_settings() {
    echo -e "\n--- Client Specific Settings ---"
    read -p "Enter Remote Server IP or Hostname (e.g., example.com, default: $REMOTE_IP): " remote_ip_input
    REMOTE_IP=${remote_ip_input:-$REMOTE_IP}
    if [ -z "$REMOTE_IP" ]; then
        log "ERROR" "Remote IP/Hostname cannot be empty for client."
        exit 1
    fi
    read -p "Enter Remote Server Port (must match server's bind_addr, default: $MAIN_PORT): " main_p
    if [ -n "$main_p" ]; then MAIN_PORT="$main_p"; fi
    validate_number "Remote Server Port" "$MAIN_PORT" || exit 1

    read -p "Enter connection pool size (default: $CONNECTION_POOL): " cp
    if [ -n "$cp" ]; then CONNECTION_POOL="$cp"; fi
    validate_number "Connection pool size" "$CONNECTION_POOL" || exit 1

    read -p "Enable aggressive connection pool management? (true/false, default: $AGGRESSIVE_POOL): " ap
    if [ -n "$ap" ]; then AGGRESSIVE_POOL=$(echo "$ap" | tr '[:upper:]' '[:lower:]'); fi
    validate_boolean "Aggressive pool" "$AGGRESSIVE_POOL" || exit 1

    read -p "Enter retry interval in seconds (default: $RETRY_INTERVAL): " ri
    if [ -n "$ri" ]; then RETRY_INTERVAL="$ri"; fi
    validate_number "Retry interval" "$RETRY_INTERVAL" || exit 1

    read -p "Enter dial timeout in seconds (default: $DIAL_TIMEOUT): " dt
    if [ -n "$dt" ]; then DIAL_TIMEOUT="$dt"; fi
    validate_number "Dial timeout" "$DIAL_TIMEOUT" || exit 1

    if [[ "$TRANSPORT" == "ws" || "$TRANSPORT" == "wss" || "$TRANSPORT" == "wsmux" || "$TRANSPORT" == "wssmux" ]]; then
        read -p "Enter Edge IP for CDN connection (optional, default: $EDGE_IP, leave empty for none): " ei
        EDGE_IP=${ei:-$EDGE_IP}
    fi
}

# Load current config values into global variables
load_current_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log "WARNING" "Config file $CONFIG_FILE not found. Using defaults."
        return
    fi

    log "INFO" "Loading current configuration from $CONFIG_FILE"

    # Determine SERVER_TYPE first
    if grep -q "^\[client\]" "$CONFIG_FILE"; then
        SERVER_TYPE="client"
    elif grep -q "^\[server\]" "$CONFIG_FILE"; then
        SERVER_TYPE="server"
    else
        log "WARNING" "Could not determine server/client role from config file. Assuming server."
        SERVER_TYPE="server" # Default to server if role not clear
    fi

    # Function to get value robustly, handling sections and types
    _get_toml_value() {
        local section_name="$1"
        local key_name="$2"
        local default_val="$3"
        local value=""
        
        # Use awk to find the section and then the key
        value=$(awk -v section="[$section_name]" -v key_name="$key_name" '
            $0 ~ section { in_section=1; next }
            /^\\[.*?\\]/ { in_section=0 }
            in_section && $0 ~ "^[[:space:]]*" key_name "[[:space:]]*=" {
                sub(/^[[:space:]]*"?"? *key_name *=[[:space:]]*/, "", $0) # Remove key and assignment
                gsub(/"/, "", $0) # Remove all quotes
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0) # Trim spaces
                print $0
                exit
            }
        ' "$CONFIG_FILE")
        echo "${value:-$default_val}"
    }

    # Common settings
    USER_TOKEN=$(_get_toml_value "$SERVER_TYPE" "token" "$USER_TOKEN")
    KEEPALIVE=$(_get_toml_value "$SERVER_TYPE" "keepalive_period" "$KEEPALIVE")
    NODELAY=$(_get_toml_value "$SERVER_TYPE" "nodelay" "$NODELAY")
    SNIFFER=$(_get_toml_value "$SERVER_TYPE" "sniffer" "$SNIFFER")
    WEB_PORT=$(_get_toml_value "$SERVER_TYPE" "web_port" "$WEB_PORT")
    SNIFFER_LOG=$(_get_toml_value "$SERVER_TYPE" "sniffer_log" "$SNIFFER_LOG")
    LOG_LEVEL=$(_get_toml_value "$SERVER_TYPE" "log_level" "$LOG_LEVEL")
    TRANSPORT=$(_get_toml_value "$SERVER_TYPE" "transport" "$TRANSPORT")

    # MUX settings (common across both roles if mux transport is used)
    # Check if these keys exist in the current config before overwriting defaults
    if grep -q "mux_version" "$CONFIG_FILE"; then
        MUX_VERSION=$(_get_toml_value "$SERVER_TYPE" "mux_version" "$MUX_VERSION")
        MUX_FRAMESIZE=$(_get_toml_value "$SERVER_TYPE" "mux_framesize" "$MUX_FRAMESIZE")
        MUX_RECEIVEBUFFER=$(_get_toml_value "$SERVER_TYPE" "mux_recievebuffer" "$MUX_RECEIVEBUFFER")
        MUX_STREAMBUFFER=$(_get_toml_value "$SERVER_TYPE" "mux_streambuffer" "$MUX_STREAMBUFFER")
    fi

    if [ "$SERVER_TYPE" == "server" ]; then
        MAIN_PORT=$(_get_toml_value "server" "bind_addr" "0.0.0.0:$MAIN_PORT" | sed 's/.*://') # Extract port
        HEARTBEAT=$(_get_toml_value "server" "heartbeat" "$HEARTBEAT")
        CHANNEL_SIZE=$(_get_toml_value "server" "channel_size" "$CHANNEL_SIZE")
        ACCEPT_UDP=$(_get_toml_value "server" "accept_udp" "$ACCEPT_UDP")
        TLS_CERT=$(_get_toml_value "server" "tls_cert" "$TLS_CERT")
        TLS_KEY=$(_get_toml_value "server" "tls_key" "$TLS_KEY")
        MUX_CON=$(_get_toml_value "server" "mux_con" "$MUX_CON")

        # Handle 'ports' array: read it back as a comma-separated string for prompt
        local ports_array_str=""
        local in_ports_section=0
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*ports[[:space:]]*= ]]; then
                in_ports_section=1
                continue
            fi
            if [[ "$in_ports_section" -eq 1 ]]; then
                if [[ "$line" =~ ^[[:space:]]*\] ]]; then # End of array
                    in_ports_section=0
                    break
                fi
                # Extract quoted string (e.g., "80", "127.0.0.1:443=5201")
                if [[ "$line" =~ ^[[:space:]]*\"(.*)\"[[:space:]]*,? ]]; then
                    ports_array_str+="${BASH_REMATCH[1]},"
                fi
            fi
        done < "$CONFIG_FILE"
        PORTS_STRING=$(echo "${ports_array_str%,}") # Remove trailing comma
        if [ -z "$PORTS_STRING" ] && grep -q "^[[:space:]]*ports[[:space:]]*=[[:space:]]*\[[[:space:]]*\]" "$CONFIG_FILE"; then
            PORTS_STRING="" # Ensure it's empty if an empty array is found
        fi

    elif [ "$SERVER_TYPE" == "client" ]; then
        REMOTE_IP=$(_get_toml_value "client" "remote_addr" "$REMOTE_IP" | sed 's/:[0-9]*$//') # Extract IP/Hostname
        MAIN_PORT=$(_get_toml_value "client" "remote_addr" "$MAIN_PORT" | sed 's/.*://') # Extract port
        EDGE_IP=$(_get_toml_value "client" "edge_ip" "$EDGE_IP")
        CONNECTION_POOL=$(_get_toml_value "client" "connection_pool" "$CONNECTION_POOL")
        AGGRESSIVE_POOL=$(_get_toml_value "client" "aggressive_pool" "$AGGRESSIVE_POOL")
        RETRY_INTERVAL=$(_get_toml_value "client" "retry_interval" "$RETRY_INTERVAL")
        DIAL_TIMEOUT=$(_get_toml_value "client" "dial_timeout" "$DIAL_TIMEOUT")
    fi
}


# --- Installation and Management Functions ---

# Install Backhaul
install_backhaul() {
    clear
    log "INFO" "Starting Backhaul installation..."

    # Ensure required commands are available
    if ! command_exists curl || ! command_exists tar || ! command_exists systemctl || ! command_exists ss || ! command_exists openssl; then
        log "ERROR" "Missing required commands (curl, tar, systemctl, ss, openssl). Please install them."
        exit 1
    fi

    # Create log file directory and file
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    log "INFO" "Log file created at $LOG_FILE"

    # Load existing config or ask for new if installing for first time
    local modify_settings="y"
    if [ -f "$CONFIG_FILE" ]; then
        load_current_config
        log "INFO" "Existing config loaded. Current role: ${SERVER_TYPE:-Unknown}. Current Transport: ${TRANSPORT:-Unknown}."
        echo "Existing configuration detected. Do you want to modify settings?"
        if ! confirm "Modify settings?"; then
            modify_settings="n"
            log "INFO" "Using existing settings for reinstallation."
            read_telegram_config # Load telegram config if not modifying main settings
        fi
    else
        log "INFO" "No existing config found. Proceeding with new configuration."
    fi

    if [[ "$modify_settings" == "y" ]]; then
        ask_server_or_client
        ask_common_settings # Common for both server and client
        ask_transport
        
        # Ask for transport-specific settings and role-specific settings
        case "$TRANSPORT" in
            tcpmux|wsmux|wssmux) ask_mux_settings ;;
        esac

        if [[ "$SERVER_TYPE" == "server" ]]; then
            ask_server_specific_settings
        elif [[ "$SERVER_TYPE" == "client" ]]; then
            ask_client_specific_settings
        fi
        configure_telegram # Always re-configure telegram if modifying settings
    fi

    # Create backhaul user if not exists BEFORE creating dirs/files for it
    if ! id backhaul &>/dev/null; then
        useradd -r -s /bin/false -d /nonexistent backhaul
        log "INFO" "User 'backhaul' created."
    fi

    # Create BACKHAUL_DIR and set permissions
    mkdir -p "$BACKHAUL_DIR"
    chmod 750 "$BACKHAUL_DIR"
    chown backhaul:backhaul "$BACKHAUL_DIR"

    # Create/Update config file
    backup_config "$CONFIG_FILE" # Backup before overwriting
    
    # Start writing the config file based on SERVER_TYPE
    if [[ "$SERVER_TYPE" == "server" ]]; then
        cat > "$CONFIG_FILE" <<EOF
[server]
bind_addr = "0.0.0.0:$MAIN_PORT"
transport = "$TRANSPORT"
token = "$USER_TOKEN"
keepalive_period = $KEEPALIVE
nodelay = $NODELAY
heartbeat = $HEARTBEAT
channel_size = $CHANNEL_SIZE
EOF
        # Add server-specific, transport-specific configs
        if [[ "$TRANSPORT" == "tcp" || "$TRANSPORT" == "tcpmux" ]]; then
            echo "accept_udp = $ACCEPT_UDP" >> "$CONFIG_FILE"
        fi
        if [[ "$TRANSPORT" == "tcpmux" || "$TRANSPORT" == "wsmux" || "$TRANSPORT" == "wssmux" ]]; then
            echo "mux_con = $MUX_CON" >> "$CONFIG_FILE"
            echo "mux_version = $MUX_VERSION" >> "$CONFIG_FILE"
            echo "mux_framesize = $MUX_FRAMESIZE" >> "$CONFIG_FILE"
            echo "mux_recievebuffer = $MUX_RECEIVEBUFFER" >> "$CONFIG_FILE"
            echo "mux_streambuffer = $MUX_STREAMBUFFER" >> "$CONFIG_FILE"
        fi
        if [[ "$TRANSPORT" == "wss" || "$TRANSPORT" == "wssmux" ]]; then
            echo "tls_cert = \"$TLS_CERT\"" >> "$CONFIG_FILE"
            echo "tls_key = \"$TLS_KEY\"" >> "$CONFIG_FILE"
        fi
        
        # Common server/client but placed here for server section logic
        echo "sniffer = $SNIFFER" >> "$CONFIG_FILE"
        echo "web_port = $WEB_PORT" >> "$CONFIG_FILE"
        if [ -n "$SNIFFER_LOG" ]; then # Only add sniffer_log if sniffer is true and log path is set
            echo "sniffer_log = \"$SNIFFER_LOG\"" >> "$CONFIG_FILE"
        fi
        echo "log_level = \"$LOG_LEVEL\"" >> "$CONFIG_FILE"

        # Ports array (Server only)
        echo "ports = [" >> "$CONFIG_FILE"
        IFS=',' read -ra ADDR <<< "$PORTS_STRING"
        for i in "${ADDR[@]}"; do
            if [ -n "$i" ]; then
                echo "\"$i\"," >> "$CONFIG_FILE"
            fi
        done
        # Remove last comma if exists
        sed -i '$ s/,$//' "$CONFIG_FILE"
        echo "]" >> "$CONFIG_FILE"

    elif [[ "$SERVER_TYPE" == "client" ]]; then
        cat > "$CONFIG_FILE" <<EOF
[client]
remote_addr = "$REMOTE_IP:$MAIN_PORT"
transport = "$TRANSPORT"
token = "$USER_TOKEN"
connection_pool = $CONNECTION_POOL
aggressive_pool = $AGGRESSIVE_POOL
keepalive_period = $KEEPALIVE
nodelay = $NODELAY
retry_interval = $RETRY_INTERVAL
dial_timeout = $DIAL_TIMEOUT
EOF
        # Client-specific, transport-specific configs
        if [ -n "$EDGE_IP" ]; then
            echo "edge_ip = \"$EDGE_IP\"" >> "$CONFIG_FILE"
        fi
        if [[ "$TRANSPORT" == "tcpmux" || "$TRANSPORT" == "wsmux" || "$TRANSPORT" == "wssmux" ]]; then
            echo "mux_version = $MUX_VERSION" >> "$CONFIG_FILE"
            echo "mux_framesize = $MUX_FRAMESIZE" >> "$CONFIG_FILE"
            echo "mux_recievebuffer = $MUX_RECEIVEBUFFER" >> "$CONFIG_FILE"
            echo "mux_streambuffer = $MUX_STREAMBUFFER" >> "$CONFIG_FILE"
        fi
        
        # Common server/client but placed here for client section logic
        echo "sniffer = $SNIFFER" >> "$CONFIG_FILE"
        if [ "$WEB_PORT" -ne 0 ]; then # Only add web_port if not disabled
            echo "web_port = $WEB_PORT" >> "$CONFIG_FILE"
        fi
        if [ -n "$SNIFFER_LOG" ]; then # Only add sniffer_log if sniffer is true and log path is set
            echo "sniffer_log = \"$SNIFFER_LOG\"" >> "$CONFIG_FILE"
        fi
        echo "log_level = \"$LOG_LEVEL\"" >> "$CONFIG_FILE"
    fi

    chmod 640 "$CONFIG_FILE"
    chown backhaul:backhaul "$CONFIG_FILE"
    log "INFO" "Configuration saved to $CONFIG_FILE"

    # Download and install Backhaul
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) log "ERROR" "Unsupported architecture: $(uname -m). Exiting."; exit 1 ;;
    esac
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    FILE_NAME="backhaul_${OS}_${ARCH}.tar.gz"
    DOWNLOAD_URL="${GITHUB_URL}/download/${BACKHAUL_VERSION}/${FILE_NAME}"

    log "INFO" "Attempting to download Backhaul from $DOWNLOAD_URL..."
    if ! curl -fL -o "/tmp/$FILE_NAME" "$DOWNLOAD_URL"; then
        log "ERROR" "Download failed for $FILE_NAME from $DOWNLOAD_URL! Please check the version or URL."
        exit 1
    fi
    log "INFO" "Downloaded /tmp/$FILE_NAME"

    if ! tar -xzf "/tmp/$FILE_NAME" -C "$BACKHAUL_DIR"; then
        log "ERROR" "Failed to extract /tmp/$FILE_NAME to $BACKHAUL_DIR"
        rm -f "/tmp/$FILE_NAME"
        exit 1
    fi
    rm -f "/tmp/$FILE_NAME"
    chmod 755 "${BACKHAUL_DIR}/backhaul"
    chown backhaul:backhaul "${BACKHAUL_DIR}/backhaul"
    log "INFO" "Backhaul executable extracted to ${BACKHAUL_DIR}/backhaul"

    # Create systemd service
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Service
After=network.target

[Service]
Type=simple
User=backhaul
Group=backhaul
ExecStart=${BACKHAUL_DIR}/backhaul -c ${CONFIG_FILE}
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=1048576
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
    log "INFO" "Systemd service file created at /etc/systemd/system/${SERVICE_NAME}.service"

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    if ! systemctl start ${SERVICE_NAME}; then
        log "ERROR" "Failed to start $SERVICE_NAME. Check logs with 'journalctl -u $SERVICE_NAME -f'."
        exit 1
    fi
    log "INFO" "Backhaul service started successfully."

    # Setup monitoring
    setup_monitoring_cron

    log "INFO" "Backhaul installed and started successfully!"
    telegram_status_report # Send initial status report
}

# Show Last Critical Errors
show_last_errors() {
    log "INFO" "Displaying last 20 critical errors from $LOG_FILE and service journal."
    echo "--- Last 20 ERROR/WARNING messages from install.log ---"
    grep -E '\[ERROR\]|\[WARNING\]' "$LOG_FILE" | tail -n 20 || echo "No errors/warnings found in install.log"

    echo -e "\n--- Last 20 lines from Backhaul service journal ---"
    journalctl -u "${SERVICE_NAME}" -n 20 --no-pager --all || echo "Could not retrieve journal logs."
    read -p "Press Enter to continue..."
}

# Emergency Recovery (Restore Backup Config)
emergency_recovery() {
    clear
    log "INFO" "Starting Emergency Recovery: Restore Backup Config."
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "No main config file found at $CONFIG_FILE. Nothing to restore."
        read -p "Press Enter to continue..."
        return
    fi # <--- اصلاح شده

    echo "Available backup config files:"
    BACKUPS=$(ls -t "${CONFIG_FILE}".*.bak 2>/dev/null)
    if [ -z "$BACKUPS" ]; then
        echo "No backup config files found for $CONFIG_FILE."
        read -p "Press Enter to continue..."
        return
    fi # <--- اصلاح شده

    echo "$BACKUPS" | nl -w 2 -s ') '
    read -p "Enter the number of the backup to restore, or 0 to cancel: " choice

    if [[ "$choice" -eq 0 ]]; then
        log "INFO" "Backup restoration cancelled."
        return
    fi # <--- اصلاح شده

    local selected_backup=$(echo "$BACKUPS" | sed -n "${choice}p")

    if [ -z "$selected_backup" ] || [ ! -f "$selected_backup" ]; then
        echo "Invalid selection."
        read -p "Press Enter to continue..."
        return
    fi

    if confirm "Are you sure you want to restore '$selected_backup'? This will overwrite current config."; then
        backup_config "$CONFIG_FILE" # Backup current before restoring
        cp "$selected_backup" "$CONFIG_FILE"
        chown backhaul:backhaul "$CONFIG_FILE"
        chmod 640 "$CONFIG_FILE"
        log "INFO" "Restored $CONFIG_FILE from $selected_backup."
        systemctl restart ${SERVICE_NAME} || log "ERROR" "Failed to restart $SERVICE_NAME after restoring config."
        log "INFO" "Service restarted with restored config."
    else
        log "INFO" "Backup restoration cancelled."
    fi
    read -p "Press Enter to continue..."
}

# --- Main Menu Functions ---

# Tunnel Management Menu
tunnel_management_menu() {
    # Ensure variables are loaded before showing menu options dependent on them
    load_current_config
    read_telegram_config

    while true; do
        clear
        echo "=== Tunnel Management ==="
        echo "1) Install/Reinstall Backhaul" # Added for consistency and ease of access
        echo "2) Remove Tunnel (stop & disable service, remove files)"
        echo "3) Edit Tunnel Config (nano)"
        echo "4) Show Last Critical Errors"
        echo "5) Emergency Recovery (Restore Backup Config)"
        echo "6) Restart Service"
        echo "7) View Service Status"
        echo "8) Toggle Periodic Monitoring (Currently $([[ -f "$TELEGRAM_CONFIG" && $(crontab -l 2>/dev/null | fgrep -q "$MONITOR_SCRIPT"; echo $?) -eq 0 ]] && echo "Enabled" || echo "Disabled"))"
        echo "9) Send Manual Telegram Status Report"
        echo "10) Back to Main Menu"
        read -p "Choose an option: " tchoice
        case $tchoice in
            1) install_backhaul ;; # Direct jump to reinstall
            2)
                if confirm "Are you sure you want to remove the tunnel (stop, disable service, and delete files)? This is irreversible."; then
                    log "INFO" "Attempting to remove Backhaul service and files."
                    disable_monitoring_cron # Disable cron and remove monitor script first
                    systemctl stop ${SERVICE_NAME} 2>/dev/null || log "WARNING" "Failed to stop $SERVICE_NAME (maybe not running)."
                    systemctl disable ${SERVICE_NAME} 2>/dev/null || log "WARNING" "Failed to disable $SERVICE_NAME (maybe not enabled)."
                    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
                    systemctl daemon-reload
                    if id backhaul &>/dev/null; then
                        log "INFO" "Removing user 'backhaul'."
                        userdel backhaul || log "WARNING" "Failed to remove user 'backhaul'. Manual removal may be needed."
                    fi
                    rm -rf "$BACKHAUL_DIR"
                    rm -f "$LOG_FILE"
                    log "INFO" "Backhaul tunnel and associated files removed."
                    echo "Backhaul tunnel removed successfully."
                    read -p "Press Enter to continue..."
                    # Exit script after removal as it's a major operation
                    exit 0
                fi
                ;;
            3)
                if [ -f "$CONFIG_FILE" ]; then
                    if ! command_exists nano; then
                        log "ERROR" "Nano is not installed. Please install it or edit $CONFIG_FILE manually."
                        read -p "Press Enter to continue..."
                        continue
                    fi
                    nano "$CONFIG_FILE"
                    log "INFO" "Config file opened for editing. Restarting service to apply changes."
                    systemctl restart ${SERVICE_NAME} || log "ERROR" "Failed to restart $SERVICE_NAME after config edit."
                    log "INFO" "Config edited and service restarted."
                    read -p "Press Enter to continue..."
                else
                    log "WARNING" "Config file not found at $CONFIG_FILE."
                    read -p "Press Enter to continue..."
                fi
                ;;
            4)
                show_last_errors
                ;;
            5)
                emergency_recovery
                ;;
            6)
                log "INFO" "Restarting Backhaul service."
                systemctl restart ${SERVICE_NAME} || log "ERROR" "Failed to restart $SERVICE_NAME."
                log "INFO" "Service restart command issued. Check status for confirmation."
                read -p "Press Enter to continue..."
                ;;
            7)
                log "INFO" "Displaying Backhaul service status."
                systemctl status ${SERVICE_NAME} --no-pager
                read -p "Press Enter to continue..."
                ;;
            8)
                read_telegram_config # Make sure we have latest telegram settings
                if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
                    if crontab -l 2>/dev/null | fgrep -q "$MONITOR_SCRIPT"; then
                        if confirm "Monitoring is enabled. Do you want to disable it?"; then
                            disable_monitoring_cron
                        fi
                    else
                        if confirm "Monitoring is disabled. Do you want to enable it?"; then
                            setup_monitoring_cron
                        fi
                    fi
                else
                    log "WARNING" "Telegram settings not configured. Please configure them first to enable monitoring."
                    if confirm "Do you want to configure Telegram settings now?"; then
                        configure_telegram
                        setup_monitoring_cron # Try to enable after configuring
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            9)
                log "INFO" "Sending manual Telegram status report."
                telegram_status_report
                read -p "Press Enter to continue..."
                ;;
            10)
                break
                ;;
            *)
                echo "Invalid option. Please try again."
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Main Menu
main_menu() {
    while true; do
        clear
        echo "=== Backhaul Installation & Management Script ==="
        echo "1) Install/Reinstall Backhaul"
        echo "2) Tunnel Management"
        echo "3) Exit"
        read -p "Choose an option: " choice
        case $choice in
            1) install_backhaul ;;
            2) tunnel_management_menu ;;
            3)
                log "INFO" "Exiting script."
                exit 0
                ;;
            *)
                echo "Invalid option. Please try again."
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# --- Script Entry Point ---
# Ensure log file exists and user is root
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"
log "INFO" "Script started."

# Start the main menu
main_menu
