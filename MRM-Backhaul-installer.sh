#!/bin/bash
set -e

BACKHAUL_DIR="/root/backhaul"
CONFIG_DIR="$BACKHAUL_DIR/configs"
SERVICE_NAME="backhaul"
SCRIPT_PATH="$(readlink -f "$0")"
BOT_TOKEN=""
CHAT_ID=""
LANG="en"

# -------- Language --------
ask_lang() {
    echo "Select language / زبان را انتخاب کنید:"
    echo "1) English"
    echo "2) فارسی"
    read -p "Choice [1]: " lang_choice
    case $lang_choice in
        2) LANG="fa" ;;
        *) LANG="en" ;;
    esac
}

msg() {
    local en="$1"
    local fa="$2"
    [[ "$LANG" == "fa" ]] && echo "$fa" || echo "$en"
}

# -------- Confirm Deletion --------
confirm_delete() {
    local target="$1"
    read -p "$(msg "Confirm delete $target? [y/N]: " "آیا از حذف $target مطمئن هستید؟ [y/N]: ")" confirm
    [[ "$confirm" == "y" || "$confirm" == "Y" ]]
}

# -------- Backup Config --------
backup_config() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)"
    fi
}

# -------- Validate Port --------
validate_port() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

# -------- Ask Port with Validation --------
ask_port() {
    local prompt="$1"
    local default="$2"
    local port=""
    while true; do
        read -p "$prompt" port
        port=${port:-$default}
        if validate_port "$port"; then
            echo "$port"
            break
        else
            echo "$(msg 'Invalid port, try again.' 'پورت نامعتبر است، دوباره وارد کنید.')"
        fi
    done
}

# -------- Ask Role --------
ask_role() {
    echo "Select role:"
    echo "1) Server (Iran side)"
    echo "2) Client (Foreign VPS)"
    read -p "$(msg 'Choose role [1/2]: ' 'نقش را انتخاب کنید [1/2]: ')" role
    case "$role" in
        2) NODE_ROLE="client" ;;
        *) NODE_ROLE="server" ;;
    esac
}

# -------- Ask Transport --------
ask_transport() {
    echo "Select transport:"
    echo "1) tcp"
    echo "2) tcpmux"
    echo "3) udp"
    echo "4) ws"
    echo "5) wss"
    echo "6) wsmux"
    read -p "$(msg 'Choice [1-6]: ' 'انتخاب [1-6]: ')" choice
    case "$choice" in
        2) TRANSPORT="tcpmux" ;;
        3) TRANSPORT="udp" ;;
        4) TRANSPORT="ws" ;;
        5) TRANSPORT="wss" ;;
        6) TRANSPORT="wsmux" ;;
        *) TRANSPORT="tcp" ;;
    esac
}

# -------- Download Backhaul --------
download_backhaul() {
    ARCH=$(uname -m)
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "$(msg 'Unsupported architecture' 'معماری پشتیبانی نشده')" ; read -p "$(msg 'Press Enter' 'برای ادامه اینتر بزنید')" ; return 1 ;;
    esac
    FILE_NAME="backhaul_${OS}_${ARCH}.tar.gz"
    echo "$(msg "Downloading $FILE_NAME..." "درحال دانلود $FILE_NAME ...")"
    curl -fL -O "https://github.com/Musixal/Backhaul/releases/latest/download/$FILE_NAME" || { echo "$(msg 'Download failed' 'دانلود شکست خورد')" ; read -p "$(msg 'Press Enter' 'اینتر بزنید')" ; return 1 ; }
    mkdir -p "$BACKHAUL_DIR"
    tar -xzf "$FILE_NAME" -C "$BACKHAUL_DIR"
    rm -f "$FILE_NAME"
}

# -------- Create Config --------
create_config() {
    mkdir -p "$CONFIG_DIR"
    if [[ "$NODE_ROLE" == "server" ]]; then
        main_port=$(ask_port "$(msg 'Enter main port (default 3080): ' 'پورت اصلی (پیش‌فرض ۳۰۸۰): ')" 3080)
        web_port=$(ask_port "$(msg 'Enter web port (default 2060): ' 'پورت وب (پیش‌فرض ۲۰۶۰): ')" 2060)
        read -p "$(msg 'Enable sniffer? (y/N): ' 'فعال کردن sniffer؟ (y/N): ')" sn
        [[ "$sn" == "y" || "$sn" == "Y" ]] && sniffer=true || sniffer=false
        read -p "$(msg 'Enter token (default your_token): ' 'توکن را وارد کنید (پیش‌فرض your_token): ')" token
        token=${token:-your_token}
        ports_array=()
        while true; do
            extra_port=$(ask_port "$(msg 'Enter additional port or empty to finish: ' 'پورت اضافی یا خالی برای پایان: ')" "")
            if [ -z "$extra_port" ]; then break; fi
            ports_array+=("$extra_port")
        done
        ports_string="[]"
        if [ ${#ports_array[@]} -gt 0 ]; then
            ports_string="["
            for p in "${ports_array[@]}"; do
                ports_string+="$p, "
            done
            ports_string="${ports_string%, }]"
        fi
        cat > "$CONFIG_DIR/server_config.toml" <<EOF
[server]
bind_addr = "0.0.0.0:$main_port"
transport = "$TRANSPORT"
token = "$token"
web_port = $web_port
sniffer = $sniffer
sniffer_log = "/root/backhaul.json"
log_level = "info"
ports = $ports_string
EOF
        ACTIVE_CONFIG="$CONFIG_DIR/server_config.toml"
    else
        read -p "$(msg 'Enter remote server address (IP:port): ' 'آدرس سرور ریموت (IP:port) را وارد کنید: ')" remote_addr
        read -p "$(msg 'Enter token (default your_token): ' 'توکن را وارد کنید (پیش‌فرض your_token): ')" token
        token=${token:-your_token}
        read -p "$(msg 'Enter connection pool (default 4): ' 'Connection pool را وارد کنید (پیش‌فرض 4): ')" pool
        pool=${pool:-4}
        cat > "$CONFIG_DIR/client_config.toml" <<EOF
[client]
remote_addr = "$remote_addr"
transport = "$TRANSPORT"
token = "$token"
connection_pool = $pool
nodelay = true
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
EOF
        ACTIVE_CONFIG="$CONFIG_DIR/client_config.toml"
    fi
}

# -------- Setup systemd service for active config --------
setup_systemd_service() {
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Service
After=network.target

[Service]
ExecStart=$BACKHAUL_DIR/backhaul -c $ACTIVE_CONFIG
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl restart $SERVICE_NAME
}

# -------- Install Backhaul --------
install_backhaul() {
    ask_role
    ask_transport
    if ! download_backhaul; then
        return
    fi
    create_config
    setup_systemd_service
    msg "✅ Backhaul installed and running." "✅ بک‌هال نصب و در حال اجرا است."
    read -p "$(msg 'Press Enter to continue...' 'برای ادامه اینتر بزنید...')"
}

# -------- Show last errors --------
show_last_errors() {
    clear
    msg "Last Backhaul Errors:" "آخرین خطاهای بک‌هال:"
    journalctl -u $SERVICE_NAME -n 100 --no-pager | grep -iE "error|fail|critical|warn" || msg "No recent critical errors found." "خطای بحرانی اخیر یافت نشد."
    read -p "$(msg 'Press Enter to continue...' 'برای ادامه اینتر بزنید...')"
}

# -------- Connection Test --------
connection_test() {
    read -p "$(msg 'Enter IP or domain to test connection: ' 'آدرس IP یا دامنه برای تست اتصال: ')" host
    if [ -z "$host" ]; then
        msg "No host provided, skipping." "آدرسی وارد نشده، رد می‌شود."
        read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
        return
    fi
    msg "Pinging $host..." "در حال پینگ $host ..."
    ping -c 4 "$host"
    msg "Traceroute to $host:" "تریس‌ر‌وت به $host:"
    traceroute "$host" || true
    read -p "$(msg 'Press Enter to continue...' 'برای ادامه اینتر بزنید...')"
}

# -------- Start Backhaul Service --------
start_service() {
    systemctl start $SERVICE_NAME
    msg "Backhaul service started." "سرویس بک‌هال شروع شد."
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

# -------- Stop Backhaul Service --------
stop_service() {
    systemctl stop $SERVICE_NAME
    msg "Backhaul service stopped." "سرویس بک‌هال متوقف شد."
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

# -------- Restart Backhaul Service --------
restart_service() {
    systemctl restart $SERVICE_NAME
    msg "Backhaul service restarted." "سرویس بک‌هال راه‌اندازی مجدد شد."
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

# -------- Show Status --------
show_status() {
    systemctl status $SERVICE_NAME --no-pager
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

# -------- Show Logs --------
show_logs() {
    echo "$(msg 'Showing logs (Ctrl+C to exit)...' 'نمایش لاگ‌ها (برای خروج Ctrl+C) ...')"
    journalctl -u $SERVICE_NAME -f
}

# -------- Remove Backhaul Completely --------
remove_backhaul() {
    if confirm_delete "Backhaul and all configs"; then
        systemctl stop $SERVICE_NAME || true
        systemctl disable $SERVICE_NAME || true
        rm -rf "$BACKHAUL_DIR"
        rm -f /etc/systemd/system/${SERVICE_NAME}.service
        systemctl daemon-reload
        msg "Backhaul completely removed." "بک‌هال به طور کامل حذف شد."
    else
        msg "Deletion cancelled." "حذف لغو شد."
    fi
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

# -------- Telegram Monitoring Script --------
MONITOR_SCRIPT="/root/backhaul-monitor.sh"

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
        send_telegram "🚨 Alert: Backhaul service is NOT running on $(hostname)! Restarting..."
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
    msg "Monitoring enabled. Running every 5 minutes." "مانیتورینگ فعال شد. هر ۵ دقیقه اجرا می‌شود."
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

disable_monitoring() {
    crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT" | crontab -
    msg "Monitoring disabled." "مانیتورینگ غیرفعال شد."
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

show_monitoring_status() {
    if crontab -l 2>/dev/null | grep -q "$MONITOR_SCRIPT"; then
        msg "Monitoring is ENABLED." "مانیتورینگ فعال است."
    else
        msg "Monitoring is DISABLED." "مانیتورینگ غیرفعال است."
    fi
    read -p "$(msg 'Press Enter...' 'اینتر بزنید...')"
}

telegram_monitoring_menu() {
    while true; do
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
        read -p "Choose an option: " tchoice

        case $tchoice in
            1)
                read -p "Enter Telegram Bot Token: " BOT_TOKEN
                if [ -n "$BOT_TOKEN" ]; then
                    create_monitor_script
                    echo "Bot Token set and monitoring script updated."
                else
                    echo "No token entered."
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                read -p "Enter Telegram Chat ID: " CHAT_ID
                if [ -n "$CHAT_ID" ]; then
                    create_monitor_script
                    echo "Chat ID set and monitoring script updated."
                else
                    echo "No chat ID entered."
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
                    echo "Both BOT_TOKEN and CHAT_ID must be set first!"
                    read -p "Press Enter to continue..."
                else
                    create_monitor_script
                    enable_monitoring
                fi
                ;;
            4) disable_monitoring ;;
            5) show_monitoring_status ;;
            6) break ;;
            *) echo "Invalid option!"; sleep 1 ;;
        esac
    done
}

# -------- Tunnel Management --------
tunnel_management_menu() {
    mkdir -p "$CONFIG_DIR"
    while true; do
        clear
        echo "=== Tunnel Management ==="
        echo "Existing profiles:"
        local i=1
        local profiles=()
        for f in "$CONFIG_DIR"/*.toml; do
            [ -f "$f" ] || continue
            profiles+=("$f")
            echo "$i) $(basename "$f")"
            i=$((i+1))
        done
        echo "$i) Add New Profile"
        echo "$((i+1))) Back to Main Menu"
        read -p "Choose a profile: " choice
        if [ "$choice" -eq "$i" ]; then
            # Add new profile