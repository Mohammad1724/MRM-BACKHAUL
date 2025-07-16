#!/bin/bash set -e

BACKHAUL_DIR="/root/backhaul" SERVICE_NAME="backhaul" CONFIG_FILE="$BACKHAUL_DIR/config.toml" SCRIPT_PATH="$(readlink -f "$0")"

Telegram monitoring variables

BOT_TOKEN="" CHAT_ID="" MONITOR_SCRIPT="/root/backhaul-monitor.sh"

---------------- Backup config file ----------------

backup_config() { local file="$1" if [ -f "$file" ]; then cp "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)" echo "Backup created: ${file}.bak.*" fi }

---------------- Edit key in toml ----------------

edit_config_value() { local file="$1" local key="$2" local new_value="$3"

if grep -q "^$key" "$file"; then
    sed -i "s|^$key.*|$key = $new_value|" "$file"
else
    echo "$key = $new_value" >> "$file"
fi

}

---------------- Validate port ----------------

validate_port() { local port="$1" [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] }

---------------- Transport selection ----------------

choose_transport() { echo "Select transport method:" echo "1) tcp" echo "2) tcpmux" echo "3) udp" echo "4) ws" echo "5) wss" echo "6) wsmux" read -p "Choose transport [1]: " t_choice case $t_choice in 2) transport="tcpmux" ;; 3) transport="udp" ;; 4) transport="ws" ;; 5) transport="wss" ;; 6) transport="wsmux" ;; *) transport="tcp" ;; esac }

---------------- Install acme.sh ----------------

install_acme() { if ! command -v acme.sh &> /dev/null; then echo "Installing acme.sh..." curl https://get.acme.sh | sh export PATH="$HOME/.acme.sh:$PATH" fi }

---------------- Obtain SSL ----------------

obtain_ssl() { local domain="$1" install_acme ~/.acme.sh/acme.sh --issue --standalone -d "$domain" --force local cert_path="$HOME/.acme.sh/$domain/$domain.cer" local key_path="$HOME/.acme.sh/$domain/$domain.key"

if [ -f "$cert_path" ] && [ -f "$key_path" ]; then
    cp "$cert_path" /root/server.crt
    cp "$key_path" /root/server.key
    return 0
else
    return 1
fi

}

---------------- SSL config if needed ----------------

configure_ssl_if_needed() { [[ "$role" != "server" ]] && return local transport_val=$(grep -E '^transport' "$CONFIG_FILE" | awk -F= '{gsub(/ /,"",$2); print $2}' | tr -d '"') if [[ "$transport_val" == "wss" || "$transport_val" == "wsmux" ]]; then read -p "Enter domain for SSL cert: " domain [ -z "$domain" ] && echo "Domain required." && return 1 obtain_ssl "$domain" || return 1 edit_config_value "$CONFIG_FILE" "tls_cert" ""/root/server.crt"" edit_config_value "$CONFIG_FILE" "tls_key" ""/root/server.key"" fi }

---------------- Install backhaul ----------------

install_backhaul() { clear read -p "Is this a Server (Iran) or Client (Foreign)? [server/client]: " role role=${role,,} [[ "$role" != "server" && "$role" != "client" ]] && echo "Invalid role" && return

ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && ARCH="arm64"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
FILE_NAME="backhaul_${OS}_${ARCH}.tar.gz"

curl -fL -O "https://github.com/Musixal/Backhaul/releases/latest/download/$FILE_NAME"
mkdir -p "$BACKHAUL_DIR"
tar -xzf "$FILE_NAME" -C "$BACKHAUL_DIR"
rm -f "$FILE_NAME"
backup_config "$CONFIG_FILE"

if [ "$role" == "client" ]; then
    read -p "Enter server IP:PORT: " remote_addr
    choose_transport
    read -p "Token: " token
    read -p "Pool size [4]: " pool
    pool=${pool:-4}
    cat > "$CONFIG_FILE" <<EOF

[client] remote_addr = "$remote_addr" transport = "$transport" token = "$token" connection_pool = $pool keepalive_period = 75 dial_timeout = 10 retry_interval = 3 nodelay = true sniffer = false EOF else read -p "Main tunnel port [3080]: " main_port main_port=${main_port:-3080} choose_transport read -p "Token [your_token]: " token token=${token:-your_token} read -p "Web port [2060]: " web_port web_port=${web_port:-2060} ports=() while true; do read -p "Extra port (Enter to stop): " p [ -z "$p" ] && break validate_port "$p" && ports+=("$p") done ports_string="[${ports[*]}]" cat > "$CONFIG_FILE" <<EOF [server] bind_addr = "0.0.0.0:$main_port" transport = "$transport" token = "$token" keepalive_period = 75 nodelay = true heartbeat = 40 channel_size = 2048 sniffer = false web_port = $web_port sniffer_log = "/root/backhaul.json" log_level = "info" ports = $ports_string EOF configure_ssl_if_needed || echo "SSL config failed." fi

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF

[Unit] Description=Backhaul Reverse Tunnel After=network.target [Service] Type=simple ExecStart=${BACKHAUL_DIR}/backhaul -c ${CONFIG_FILE} Restart=always RestartSec=3 LimitNOFILE=1048576 [Install] WantedBy=multi-user.target EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME
echo "✅ Installed and started."
read -p "Press Enter to continue..."

}

---------------- Telegram Monitoring ----------------

create_monitor_script() { cat > "$MONITOR_SCRIPT" <<EOF #!/bin/bash BOT_TOKEN="$BOT_TOKEN" CHAT_ID="$CHAT_ID" SERVICE_NAME="$SERVICE_NAME"

send_telegram() { local msg="$1" curl -s -X POST https://api.telegram.org/bot${BOT_TOKEN}/sendMessage -d chat_id=${CHAT_ID} -d text="$msg" >/dev/null }

if ! systemctl is-active --quiet $SERVICE_NAME; then send_telegram "🚨 $SERVICE_NAME is down on $(hostname). Restarting..." systemctl restart $SERVICE_NAME sleep 3 systemctl is-active --quiet $SERVICE_NAME && 
send_telegram "✅ $SERVICE_NAME restarted successfully." || 
send_telegram "❌ Failed to restart $SERVICE_NAME." fi

journalctl -u $SERVICE_NAME -n 50 | grep -iE 'error|fail|critical|warning' && 
send_telegram "⚠️ Warnings/errors detected in $SERVICE_NAME logs." EOF chmod +x "$MONITOR_SCRIPT" }

enable_monitoring() { create_monitor_script (crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT"; echo "*/5 * * * * $MONITOR_SCRIPT") | crontab - echo "Monitoring enabled." read -p "Enter to continue..." }

disable_monitoring() { crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT" | crontab - echo "Monitoring disabled." read -p "Enter to continue..." }

set_telegram_credentials() { read -p "Enter BOT_TOKEN: " BOT_TOKEN read -p "Enter CHAT_ID: " CHAT_ID create_monitor_script }

---------------- Service Management ----------------

service_menu() { while true; do clear echo "=== Backhaul Service Menu ===" echo "1) Start" echo "2) Stop" echo "3) Restart" echo "4) Status" echo "5) Logs" echo "6) Enable Telegram Monitoring" echo "7) Disable Telegram Monitoring" echo "8) Set Telegram BOT & Chat ID" echo "9) Back" read -p "Select: " opt case $opt in 1) systemctl start $SERVICE_NAME ;; 2) systemctl stop $SERVICE_NAME ;; 3) systemctl restart $SERVICE_NAME ;; 4) systemctl status $SERVICE_NAME ; read -p "Enter to continue..." ;; 5) journalctl -u $SERVICE_NAME -f ;; 6) enable_monitoring ;; 7) disable_monitoring ;; 8) set_telegram_credentials ;; 9) break ;; esac done }

---------------- Remove completely ----------------

remove_backhaul() { systemctl stop $SERVICE_NAME systemctl disable $SERVICE_NAME rm -rf "$BACKHAUL_DIR" rm -f /etc/systemd/system/$SERVICE_NAME.service "$MONITOR_SCRIPT" crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT" | crontab - systemctl daemon-reload echo "Backhaul removed." read -p "Enter to continue..." }

---------------- Update binary ----------------

update_backhaul() { ARCH=$(uname -m) [[ "$ARCH" == "x86_64" ]] && ARCH="amd64" [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && ARCH="arm64" OS=$(uname -s | tr '[:upper:]' '[:lower:]') FILE_NAME="backhaul_${OS}_${ARCH}.tar.gz" curl -fL -O "https://github.com/Musixal/Backhaul/releases/latest/download/$FILE_NAME" tar -xzf "$FILE_NAME" -C "$BACKHAUL_DIR" rm -f "$FILE_NAME" systemctl restart $SERVICE_NAME echo "✅ Updated and restarted." read -p "Enter to continue..." }

---------------- Main Menu ----------------

main_menu() { while true; do clear echo "=== Backhaul Manager ===" echo "1) Install" echo "2) Manage Service" echo "3) Update Binary" echo "4) Remove Completely" echo "5) Exit" read -p "Choose: " c case $c in 1) install_backhaul ;; 2) service_menu ;; 3) update_backhaul ;; 4) remove_backhaul ;; 5) exit 0 ;; esac done }

main_menu

