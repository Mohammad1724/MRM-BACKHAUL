#!/bin/bash
set -e

BACKHAUL_DIR="/root/backhaul"
SERVICE_NAME="backhaul"
CONFIG_FILE="$BACKHAUL_DIR/config.toml"
SCRIPT_PATH="$(readlink -f "$0")"

# Telegram monitoring variables (global, updated via menu)
BOT_TOKEN=""
CHAT_ID=""
MONITOR_SCRIPT="/root/backhaul-monitor.sh"

# --------- Backup config file ------------
backup_config() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)"
        echo "Backup created: ${file}.bak.*"
    fi
}

# --------- Edit a key=value in toml config ------------
edit_config_value() {
    local file="$1"
    local key="$2"
    local new_value="$3"

    if grep -q "^$key" "$file"; then
        sed -i "s|^$key.*|$key = $new_value|" "$file"
    else
        echo "$key = $new_value" >> "$file"
    fi
}

# --------- Validate port number ------------
validate_port() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Invalid port: $port"
        return 1
    fi
    return 0
}

# --------- Ask for ports with validation ------------
ask_ports() {
    while true; do
        read -p "Enter main port (default 3080): " main_port
        main_port=${main_port:-3080}
        validate_port "$main_port" && break
        echo "Please enter a valid port number (1-65535)."
    done

    while true; do
        read -p "Enter web port (default 2060): " web_port
        web_port=${web_port:-2060}
        validate_port "$web_port" && break
        echo "Please enter a valid port number (1-65535)."
    done

    ports=()
    while true; do
        read -p "Enter additional port (or press Enter to finish): " extra_port
        if [ -z "$extra_port" ]; then
            break
        fi
        if validate_port "$extra_port"; then
            ports+=("$extra_port")
        else
            echo "Invalid port number, try again."
        fi
    done

    if [ ${#ports[@]} -gt 0 ]; then
        ports_string="["
        for p in "${ports[@]}"; do
            ports_string+="$p, "
        done
        ports_string="${ports_string%, }]"
    else
        ports_string="[]"
    fi
}

# --------- Install acme.sh if missing ------------
install_acme() {
    if ! command -v acme.sh &> /dev/null; then
        echo "acme.sh not found, installing..."
        curl https://get.acme.sh | sh
        export PATH="$HOME/.acme.sh:$PATH"
    fi
}

# --------- Obtain SSL certificate with acme.sh ------------
obtain_ssl() {
    local domain="$1"
    install_acme

    echo "Requesting SSL certificate for domain: $domain"
    ~/.acme.sh/acme.sh --issue --standalone -d "$domain" --force

    local cert_path="$HOME/.acme.sh/$domain/$domain.cer"
    local key_path="$HOME/.acme.sh/$domain/$domain.key"

    if [ -f "$cert_path" ] && [ -f "$key_path" ]; then
        echo "Certificate obtained successfully."
        sudo cp "$cert_path" /root/server.crt
        sudo cp "$key_path" /root/server.key
        echo "Certificates copied to /root/server.crt and /root/server.key"
        return 0
    else
        echo "Failed to obtain certificate."
        return 1
    fi
}

# --------- Configure SSL if transport requires ------------
configure_ssl_if_needed() {
    local transport=$(grep -E '^transport' "$CONFIG_FILE" | head -1 | awk -F= '{gsub(/ /,"",$2); print $2}' | tr -d '"')

    if [[ "$transport" == "wss" || "$transport" == "wssmux" ]]; then
        echo "Transport is $transport — SSL is required."
        read -p "Enter your domain name (e.g. example.com) for SSL certificate: " domain
        if [ -z "$domain" ]; then
            echo "Domain is required for SSL. Aborting SSL configuration."
            return 1
        fi

        obtain_ssl "$domain" || return 1

        edit_config_value "$CONFIG_FILE" "tls_cert" "\"/root/server.crt\""
        edit_config_value "$CONFIG_FILE" "tls_key" "\"/root/server.key\""

        echo "SSL paths updated in config."
    else
        echo "Transport is $transport — SSL not required."
    fi
}

# --------- Connectivity test (ping) ------------
connectivity_test() {
    read -p "Enter server IP or domain for connectivity test: " server_test_ip
    if [ -z "$server_test_ip" ]; then
        echo "No server IP/domain entered, skipping test."
        return
    fi
    echo "Testing connectivity to $server_test_ip ..."
    ping -c 4 "$server_test_ip"
    read -p "Is the connectivity OK? (y/n): " ok
    if [[ "$ok" != "y" && "$ok" != "Y" ]]; then
        echo "Please fix connectivity before proceeding."
        read -p "Press Enter to exit..."
        exit 1
    fi
}

# --------- Install Backhaul and configure ------------
install_backhaul() {
    clear
    echo "=== Backhaul Installation ==="
    
    connectivity_test
    
    ask_ports
    echo ""
    echo "Ports entered:"
    echo "Main port: $main_port"
    echo "Web port: $web_port"
    echo "Additional ports: $ports_string"
    echo ""

    echo "Select log level:"
    echo "1) error"
    echo "2) warning"
    echo "3) info (default)"
    echo "4) debug"
    read -p "Choose log level [3]: " log_choice
    case $log_choice in
      1) LOG_LEVEL="error" ;;
      2) LOG_LEVEL="warning" ;;
      3 | "") LOG_LEVEL="info" ;;
      4) LOG_LEVEL="debug" ;;
      *) LOG_LEVEL="info" ;;
    esac

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $(uname -m)"; read -p "Press Enter to continue..."; return ;;
    esac

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    FILE_NAME="backhaul_${OS}_${ARCH}.tar.gz"

    echo "Downloading $FILE_NAME..."
    curl -fL -O "https://github.com/Musixal/Backhaul/releases/latest/download/$FILE_NAME" || { echo "Download failed!"; read -p "Press Enter to continue..."; return; }

    mkdir -p "$BACKHAUL_DIR"
    tar -xzf "$FILE_NAME" -C "$BACKHAUL_DIR"
    rm -f "$FILE_NAME"

    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" <<EOF
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcp"
token = "your_token"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
sniffer = false
web_port = 2060
sniffer_log = "/root/backhaul.json"
log_level = "info"
ports = []
EOF
    fi

    backup_config "$CONFIG_FILE"

    edit_config_value "$CONFIG_FILE" "bind_addr" "\"0.0.0.0:${main_port}\""
    edit_config_value "$CONFIG_FILE" "web_port" "$web_port"
    edit_config_value "$CONFIG_FILE" "ports" "$ports_string"

    read -p "Enter token (default: your_token): " user_token
    user_token=${user_token:-your_token}
    edit_config_value "$CONFIG_FILE" "token" "\"$user_token\""

    edit_config_value "$CONFIG_FILE" "log_level" "\"$LOG_LEVEL\""

    configure_ssl_if_needed || { echo "SSL configuration failed."; read -p "Press Enter to continue..."; return; }

    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=${BACKHAUL_DIR}/backhaul -c ${CONFIG_FILE}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}

    echo "Backhaul installed and started successfully!"
    read -p "Press Enter to continue..."
}

# --------- Tunnel Management Menu ------------
tunnel_management_menu() {
    while true; do
        clear
        echo "=== Tunnel Management ==="
        echo "1) Remove Tunnel (stop & disable service)"
        echo "2) Edit Tunnel Config (nano)"
        echo "3) Edit Tunnel Ports (manual edit)"
        echo "4) Back to Main Menu"
        read -p "Choose an option: " tchoice
        case $tchoice in
            1)
                systemctl stop $SERVICE_NAME || echo "Service not running"
                systemctl disable $SERVICE_NAME || echo "Service not enabled"
                echo "Tunnel removed (service stopped & disabled)."
                read -p "Press Enter to continue..."
                ;;
            2|3)
                if [ -f "$CONFIG_FILE" ]; then
                    nano "$CONFIG_FILE"
                else
                    echo "Config file not found!"
                    read -p "Press Enter to continue..."
                fi
                ;;
            4) break ;;
            *) echo "Invalid option!"; sleep 1 ;;
        esac
    done
}

# --------- Backhaul Management Menu ------------
backhaul_management_menu() {
    while true; do
        clear
        echo "=== Backhaul Management ==="
        echo "1) Start Backhaul Service"
        echo "2) Stop Backhaul Service"
        echo "3) Restart Backhaul Service"
        echo "4) Show Backhaul Status"
        echo "5) Show Backhaul Logs"
        echo "6) Back to Main Menu"
        read -p "Choose an option: " bchoice
        case $bchoice in
            1)
                systemctl start $SERVICE_NAME
                echo "Backhaul service started."
                read -p "Press Enter to continue..."
                ;;
            2)
                systemctl stop $SERVICE_NAME
                echo "Backhaul service stopped."
                read -p "Press Enter to continue..."
                ;;
            3)
                systemctl restart $SERVICE_NAME
                echo "Backhaul service restarted."
                read -p "Press Enter to continue..."
                ;;
            4)
                systemctl status $SERVICE_NAME --no-pager
                echo ""
                read -p "Press Enter to continue..."
                ;;
            5)
                echo "Showing logs (Ctrl+C to exit)..."
                journalctl -u $SERVICE_NAME -f
                ;;
            6) break ;;
            *) echo "Invalid option!"; sleep 1 ;;
        esac
    done
}

# --------- Remove Backhaul Completely ------------
remove_backhaul_completely() {
    echo "Removing Backhaul completely..."
    systemctl stop $SERVICE_NAME || echo "Service not running"
    systemctl disable $SERVICE_NAME || echo "Service not enabled"
    rm -rf "$BACKHAUL_DIR"
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    systemctl daemon-reload
    echo "Backhaul completely removed."
    read -p "Press Enter to continue..."
}

# --------- Update Backhaul Binary ------------
update_backhaul() {
    echo "Updating Backhaul binary..."
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $(uname -m)"; read -p "Press Enter to continue..."; return ;;
    esac

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    FILE_NAME="backhaul_${OS}_${ARCH}.tar.gz"

    curl -fL -O "https://github.com/Musixal/Backhaul/releases/latest/download/$FILE_NAME" || { echo "Download failed!"; read -p "Press Enter to continue..."; return; }

    mkdir -p "$BACKHAUL_DIR"
    tar -xzf "$FILE_NAME" -C "$BACKHAUL_DIR"
    rm -f "$FILE_NAME"

    systemctl restart $SERVICE_NAME
    echo "Backhaul updated and service restarted."
    read -p "Press Enter to continue..."
}

# --------- Remove Installer Script ------------
remove_installer_script() {
    echo "Removing installer script file: $SCRIPT_PATH"
    rm -f "$SCRIPT_PATH"
    echo "Installer script removed. Exiting..."
    exit 0
}

# --------- Telegram Monitoring Script Creator ------------
create_monitor_script() {
cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash

BOT_TOKEN="__BOT_TOKEN__"
CHAT_ID="__CHAT_ID__"
SERVICE_NAME="backhaul"

send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
         -d chat_id="${CHAT_ID}" \
         -d text="${message}" >/dev/null
}

check_service() {
    if ! systemctl is-active --quiet $SERVICE_NAME; then
        send_telegram "🚨 Alert: Backhaul service is NOT running on $(hostname)! Restarting service..."
        systemctl restart $SERVICE_NAME
        sleep 3
        if systemctl is-active --quiet $SERVICE_NAME; then
            send_telegram "✅ Backhaul service restarted successfully on $(hostname)."
        else
            send_telegram "❌ Failed to restart Backhaul service on $(hostname). Manual intervention needed."
        fi
    fi
}

check_logs() {
    if journalctl -u $SERVICE_NAME -n 100 | grep -iE "error|fail|critical|warning" >/dev/null; then
        send_telegram "⚠️ Warning: Backhaul logs show errors or warnings on $(hostname)!"
    fi
}

check_service
check_logs
EOF

    sed -i "s|__BOT_TOKEN__|$BOT_TOKEN|" "$MONITOR_SCRIPT"
    sed -i "s|__CHAT_ID__|$CHAT_ID|" "$MONITOR_SCRIPT"

    chmod +x "$MONITOR_SCRIPT"
}

enable_monitoring() {
    (crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT"; echo "*/5 * * * * $MONITOR_SCRIPT") | crontab -
    echo "Monitoring enabled. Running every 5 minutes."
    read -p "Press Enter to continue..."
}

disable_monitoring() {
    crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT" | crontab -
    echo "Monitoring disabled."
    read -p "Press Enter to continue..."
}

show_monitoring_status() {
    if crontab -l 2>/dev/null | grep -q "$MONITOR_SCRIPT"; then
        echo "Monitoring is ENABLED."
    else
        echo "Monitoring is DISABLED."
    fi
    read -p "Press Enter to continue..."
}

telegram_monitoring_menu() {
    clear
    echo "=== Telegram Monitoring Menu ==="
    echo "Current BOT_TOKEN: $([ -z "$BOT_TOKEN" ] && echo 'Not set' || echo 'Set')"
    echo "Current CHAT_ID: $([ -z "$CHAT_ID" ] && echo 'Not set' || echo 'Set')"
    echo ""
    echo "1) Set Telegram BOT Token"
    echo "2) Set Telegram Chat ID"
    echo "3) Enable Monitoring"
    echo "4) Disable Monitoring"
    echo "5) Show Monitoring Status"
    echo "6) Back to Main Menu"
