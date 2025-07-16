#!/bin/bash
set -euo pipefail

# Configurable paths and defaults
BACKHAUL_DIR="${BACKHAUL_DIR:-/opt/backhaul}"
SERVICE_NAME="backhaul"
CONFIG_FILE="${BACKHAUL_DIR}/config.toml"
TELEGRAM_CONFIG="${BACKHAUL_DIR}/telegram.conf"
LOG_FILE="${BACKHAUL_DIR}/install.log"
MONITOR_SCRIPT="${BACKHAUL_DIR}/backhaul-monitor.sh"
BACKHAUL_VERSION="latest"
GITHUB_URL="https://github.com/Musixal/Backhaul/releases"

# Telegram settings
BOT_TOKEN=""
CHAT_ID=""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Use sudo."
    exit 1
fi

# Logging function
log() {
    local level="$1"
    local message="$2"
    echo "[$level] $message" | tee -a "$LOG_FILE"
}

# Read Telegram settings from telegram.conf
read_telegram_config() {
    if [ -f "$TELEGRAM_CONFIG" ]; then
        BOT_TOKEN=$(grep '^bot_token=' "$TELEGRAM_CONFIG" | cut -d '=' -f2- | tr -d '"')
        CHAT_ID=$(grep '^chat_id=' "$TELEGRAM_CONFIG" | cut -d '=' -f2- | tr -d '"')
    fi
}

# Configure Telegram settings
configure_telegram() {
    read -p "Enter Telegram Bot Token (or leave empty to disable monitoring): " BOT_TOKEN
    if [ -n "$BOT_TOKEN" ]; then
        read -p "Enter Telegram Chat ID: " CHAT_ID
        if [ -n "$CHAT_ID" ]; then
            log "INFO" "Telegram monitoring enabled."
            # Save to telegram.conf
            cat > "$TELEGRAM_CONFIG" <<EOF
bot_token="$BOT_TOKEN"
chat_id="$CHAT_ID"
EOF
            chmod 640 "$TELEGRAM_CONFIG"
            chown backhaul:backhaul "$TELEGRAM_CONFIG"
        else
            log "WARNING" "Telegram Chat ID cannot be empty. Monitoring disabled."
            BOT_TOKEN=""
            CHAT_ID=""
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
CONFIG_FILE="$CONFIG_FILE"
TELEGRAM_CONFIG="$TELEGRAM_CONFIG"
SERVICE_NAME="$SERVICE_NAME"
LOG_FILE="$LOG_FILE"

# Logging function
log() {
    local level="\$1"
    local message="\$2"
    echo "[\$level] \$message" >> "\$LOG_FILE"
}

# Read Telegram settings
if [ -f "\$TELEGRAM_CONFIG" ]; then
    BOT_TOKEN=\$(grep '^bot_token=' "\$TELEGRAM_CONFIG" | cut -d '=' -f2- | tr -d '"')
    CHAT_ID=\$(grep '^chat_id=' "\$TELEGRAM_CONFIG" | cut -d '=' -f2- | tr -d '"')
else
    log "ERROR" "Telegram config file not found. Monitoring disabled."
    exit 1
fi

# Check service status
if ! systemctl is-active "\$SERVICE_NAME" >/dev/null; then
    log "ERROR" "Backhaul service is down."
    if [ -n "\$BOT_TOKEN" ] && [ -n "\$CHAT_ID" ]; then
        curl -s -X POST "https://api.telegram.org/bot\$BOT_TOKEN/sendMessage" \
            -d chat_id="\$CHAT_ID" \
            -d text="Alert: Backhaul service is down on \$(hostname)!" >/dev/null
    fi
    exit 1
fi

# Check ports
main_port=\$(grep '^bind_addr =' "\$CONFIG_FILE" | cut -d ':' -f2 | tr -d ' "')
web_port=\$(grep '^web_port =' "\$CONFIG_FILE" | cut -d '=' -f2- | tr -d ' "')
if ! ss -tuln | grep -q ":\$main_port" || ! ss -tuln | grep -q ":\$web_port"; then
    log "ERROR" "One or more ports (main: \$main_port, web: \$web_port) are not open."
    if [ -n "\$BOT_TOKEN" ] && [ -n "\$CHAT_ID" ]; then
        curl -s -X POST "https://api.telegram.org/bot\$BOT_TOKEN/sendMessage" \
            -d chat_id="\$CHAT_ID" \
            -d text="Alert: Ports (main: \$main_port, web: \$web_port) are not open on \$(hostname)!" >/dev/null
    fi
    exit 1
fi

log "INFO" "Backhaul service and ports are running normally."
EOF
    chmod 750 "$MONITOR_SCRIPT"
    chown backhaul:backhaul "$MONITOR_SCRIPT"
    log "INFO" "Monitoring script created at $MONITOR_SCRIPT"
}

# Setup cron job for monitoring
setup_monitoring_cron() {
    if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
        read -p "Enable periodic monitoring via cron? (y/n, default y): " enable_cron
        enable_cron=${enable_cron:-y}
        if [[ "$enable_cron" =~ ^[Yy]$ ]]; then
            create_monitor_script
            # Add cron job to run every 5 minutes
            (crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT"; echo "*/5 * * * * $MONITOR_SCRIPT") | crontab -
            log "INFO" "Cron job for monitoring set up to run every 5 minutes."
        else
            log "INFO" "Periodic monitoring via cron disabled."
        fi
    fi
}

# Disable monitoring cron
disable_monitoring_cron() {
    if crontab -l 2>/dev/null | grep -q "$MONITOR_SCRIPT"; then
        (crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT") | crontab -
        log "INFO" "Monitoring cron job disabled."
    else
        log "INFO" "No monitoring cron job found."
    fi
}

# Telegram status report (updated to read from telegram.conf)
telegram_status_report() {
    read_telegram_config
    if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        return
    fi

    local status
    status=$(systemctl is-active $SERVICE_NAME)
    local version
    version=$($BACKHAUL_DIR/backhaul -v 2>/dev/null || echo "Unknown")
    local open_ports
    open_ports=$(ss -tuln | grep -E ":$main_port|:$web_port" | awk '{print $5}' | paste -sd "," -)

    local message="Backhaul Status Report:
- Service status: $status
- Version: $version
- Main port: $main_port
- Web port: $web_port
- Transport: $TRANSPORT
- Open ports: $open_ports
"

    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d chat_id="$CHAT_ID" \
        -d text="$message" >/dev/null
}

# Install Backhaul (updated to include monitoring setup)
install_backhaul() {
    clear
    log "INFO" "Starting Backhaul installation..."

    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"

    ask_server_or_client
    ask_remote_ip_if_client
    connectivity_test
    ask_ports
    ask_transport
    ask_token
    ask_sniffer
    ask_keepalive
    ask_nodelay
    ask_heartbeat
    ask_channel_size
    ask_sniffer_log
    ask_log_level
    configure_telegram

    # Create config file
    mkdir -p "$BACKHAUL_DIR"
    chmod 750 "$BACKHAUL_DIR"
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" <<EOF
[server]
bind_addr = "0.0.0.0:$main_port"
transport = "$TRANSPORT"
token = "$user_token"
keepalive_period = $keepalive
nodelay = $NODELAY
heartbeat = $heartbeat
channel_size = $channel_size
sniffer = $SNIFFER
web_port = $web_port
sniffer_log = "$sniffer_log"
log_level = "$LOG_LEVEL"
ports = $ports_string
EOF
        if [[ "$SERVER_TYPE" == "client" ]]; then
            echo -e "\n[client]\nremote_addr = \"$remote_ip:$main_port\"" >> "$CONFIG_FILE"
        fi
        chmod 640 "$CONFIG_FILE"
    else
        backup_config "$CONFIG_FILE"
        edit_config_value "$CONFIG_FILE" "bind_addr" "\"0.0.0.0:$main_port\""
        # ... other config updates ...
    fi

    # Download and install Backhaul
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) log "ERROR" "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    FILE_NAME="backhaul_${OS}_${ARCH}.tar.gz"

    log "INFO" "Downloading $FILE_NAME..."
    curl -fL -o "$FILE_NAME" "${GITHUB_URL}/${BACKHAUL_VERSION}/download/$FILE_NAME" || {
        log "ERROR" "Download failed!"
        exit 1
    }

    tar -xzf "$FILE_NAME" -C "$BACKHAUL_DIR" || {
        log "ERROR" "Failed to extract $FILE_NAME"
        rm -f "$FILE_NAME"
        exit 1
    }
    rm -f "$FILE_NAME"
    chmod 755 "${BACKHAUL_DIR}/backhaul"

    # Configure SSL if needed
    configure_ssl_if_needed || {
        log "ERROR" "SSL configuration failed."
        exit 1
    }

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

    # Create backhaul user if not exists
    if ! id backhaul &>/dev/null; then
        useradd -r -s /bin/false -d /nonexistent backhaul
    fi
    chown -R backhaul:backhaul "$BACKHAUL_DIR"
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME} || {
        log "ERROR" "Failed to start $SERVICE_NAME"
        exit 1
    }

    # Setup monitoring
    setup_monitoring_cron

    log "INFO" "Backhaul installed and started successfully!"
    telegram_status_report
}

# Tunnel Management Menu (updated with monitoring options)
tunnel_management_menu() {
    while true; do
        clear
        echo "=== Tunnel Management ==="
        echo "1) Remove Tunnel (stop & disable service)"
        echo "2) Edit Tunnel Config (nano)"
        echo "3) Show Last Critical Errors"
        echo "4) Emergency Recovery (Restore Backup Config)"
        echo "5) Restart Service"
        echo "6) View Service Status"
        echo "7) Enable/Disable Monitoring"
        echo "8) Back to Main Menu"
        read -p "Choose an option: " tchoice
        case $tchoice in
            1)
                if confirm "Are you sure you want to remove the tunnel (stop and disable service)?"; then
                    disable_monitoring_cron
                    systemctl stop ${SERVICE_NAME} || log "WARNING" "Failed to stop $SERVICE_NAME"
                    systemctl disable ${SERVICE_NAME} || log "WARNING" "Failed to disable $SERVICE_NAME"
                    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
                    systemctl daemon-reload
                    log "INFO" "Tunnel service removed."
                    read -p "Press Enter to continue..."
                fi
                ;;
            2)
                nano "$CONFIG_FILE"
                read_telegram_config
                systemctl restart ${SERVICE_NAME} || log "ERROR" "Failed to restart $SERVICE_NAME"
                log "INFO" "Config edited and service restarted."
                read -p "Press Enter to continue..."
                ;;
            3)
                show_last_errors
                ;;
            4)
                emergency_recovery
                ;;
            5)
                systemctl restart ${SERVICE_NAME} || log "ERROR" "Failed to restart $SERVICE_NAME"
                log "INFO" "Service restarted."
                read -p "Press Enter to continue..."
                ;;
            6)
                systemctl status ${SERVICE_NAME} --no-pager
                read -p "Press Enter to continue..."
                ;;
            7)
                read_telegram_config
                if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
                    if crontab -l 2>/dev/null | grep -q "$MONITOR_SCRIPT"; then
                        if confirm "Monitoring is enabled. Disable it?"; then
                            disable_monitoring_cron
                        fi
                    else
                        if confirm "Monitoring is disabled. Enable it?"; then
                            setup_monitoring_cron
                        fi
                    fi
                else
                    log "WARNING" "Telegram settings not configured. Please configure them first."
                    configure_telegram
                    setup_monitoring_cron
                fi
                read -p "Press Enter to continue..."
                ;;
            8)
                break
                ;;
            *)
                echo "Invalid option."
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}