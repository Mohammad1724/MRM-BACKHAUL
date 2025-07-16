#!/bin/bash
 set -e

BACKHAUL_DIR="/root/backhaul" SERVICE_NAME="backhaul" CONFIG_FILE="$BACKHAUL_DIR/config.toml" SCRIPT_PATH="$(readlink -f "$0")"

BOT_TOKEN="" CHAT_ID="" MONITOR_SCRIPT="/root/backhaul-monitor.sh" LANG=en

---------------- Language Messages ----------------

ask_lang() { echo "Select language / زبان را انتخاب کنید:" echo "1) English" echo "2) فارسی" read -p "Choice [1]: " lang_choice case $lang_choice in 2) LANG=fa ;; *) LANG=en ;; esac }

msg() { local en="$1" local fa="$2" [[ "$LANG" == "fa" ]] && echo "$fa" || echo "$en" }

prompt() { local en="$1" local fa="$2" local var="$3" read -p "$(msg "$en" "$fa")" $var }

---------------- Config Editor ----------------

edit_config_value() { local file="$1"; local key="$2"; local val="$3" grep -q "^$key" "$file" && sed -i "s|^$key.*|$key = $val|" "$file" || echo "$key = $val" >> "$file" }

---------------- Validate Port ----------------

validate_port() { local port="$1" [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] }

---------------- Transport Selection ----------------

choose_transport() { msg "Choose transport:" "انتخاب نوع‌ترنسپورت:" echo "1) tcp" echo "2) tcpmux" echo "3) udp" echo "4) ws" echo "5) wss" echo "6) wsmux" read -p "Choice [1]: " t_choice case $t_choice in 2) transport="tcpmux" ;; 3) transport="udp" ;; 4) transport="ws" ;; 5) transport="wss" ;; 6) transport="wsmux" ;; *) transport="tcp" ;; esac }

---------------- SSL Configuration ----------------

install_acme() { command -v acme.sh &>/dev/null || (curl https://get.acme.sh | sh) export PATH="$HOME/.acme.sh:$PATH" }

obtain_ssl() { local domain="$1" install_acme ~/.acme.sh/acme.sh --issue --standalone -d "$domain" --force cp "$HOME/.acme.sh/$domain/$domain.cer" /root/server.crt cp "$HOME/.acme.sh/$domain/$domain.key" /root/server.key }

configure_ssl_if_needed() { [[ "$role" != "server" ]] && return [[ "$transport" == "wss" || "$transport" == "wsmux" ]] || return prompt "Enter domain for SSL: " "دامنه جهت صدور گواهینامه SSL را وارد کنید: " domain [ -z "$domain" ] && return 1 obtain_ssl "$domain" edit_config_value "$CONFIG_FILE" "tls_cert" ""/root/server.crt"" edit_config_value "$CONFIG_FILE" "tls_key" ""/root/server.key"" }

---------------- Telegram Summary ----------------

send_summary_to_telegram() { [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]] && return msg="✅ Backhaul installed\nRole: $role\nTransport: $transport\nToken: $token" [[ "$role" == "server" ]] && msg+="\nPort: $main_port\nWeb Port: $web_port" curl -s -X POST https://api.telegram.org/bot${BOT_TOKEN}/sendMessage 
-d chat_id=${CHAT_ID} -d text="$msg" >/dev/null }

---------------- Install ----------------

install_backhaul() { clear prompt "Is this Server or Client? [server/client]: " "سرور است یا کلاینت؟ [server/client]: " role role=${role,,} [[ "$role" != "server" && "$role" != "client" ]] && msg "Invalid role!" "نقش نامعتبر!" && return

ARCH=$(uname -m); OS=$(uname -s | tr '[:upper:]' '[:lower:]')
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && ARCH="arm64"
FILE="backhaul_${OS}_${ARCH}.tar.gz"
curl -fLO "https://github.com/Musixal/Backhaul/releases/latest/download/$FILE"
mkdir -p "$BACKHAUL_DIR" && tar -xzf "$FILE" -C "$BACKHAUL_DIR" && rm -f "$FILE"

if [[ "$role" == "client" ]]; then
    prompt "Enter server IP:PORT: " "آدرس سرور (IP:PORT): " remote_addr
    choose_transport
    prompt "Token: " "توکن: " token
    pool=4; prompt "Connection pool [4]: " "تعداد کانکشن همزمان [4]: " pool
    cat > "$CONFIG_FILE" <<EOF

[client] remote_addr = "$remote_addr" transport = "$transport" token = "$token" connection_pool = $pool keepalive_period = 75 dial_timeout = 10 retry_interval = 3 nodelay = true sniffer = false EOF else prompt "Main port [3080]: " "پورت اصلی [3080]: " main_port; main_port=${main_port:-3080} choose_transport prompt "Token [your_token]: " "توکن [your_token]: " token; token=${token:-your_token} prompt "Web port [2060]: " "پورت وب [2060]: " web_port; web_port=${web_port:-2060} msg "Enable sniffer? (y/n): " "Sniffer فعال باشد؟ (y/n):" read snf snf_enabled=false; [[ "$snf" == "y" || "$snf" == "Y" ]] && snf_enabled=true

ports=(); while true; do
        prompt "Extra port (Enter to stop): " "پورت اضافه (Enter برای توقف): " p
        [ -z "$p" ] && break
        validate_port "$p" && ports+=("$p")
    done
    ports_str="[${ports[*]}]"

    cat > "$CONFIG_FILE" <<EOF

[server] bind_addr = "0.0.0.0:$main_port" transport = "$transport" token = "$token" keepalive_period = 75 nodelay = true heartbeat = 40 channel_size = 2048 sniffer = $snf_enabled web_port = $web_port sniffer_log = "/root/backhaul.json" log_level = "info" ports = $ports_str EOF

configure_ssl_if_needed
fi

cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF

[Unit] Description=Backhaul Reverse Tunnel After=network.target [Service] ExecStart=$BACKHAUL_DIR/backhaul -c $CONFIG_FILE Restart=always RestartSec=3 [Install] WantedBy=multi-user.target EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

msg "✅ Backhaul installed and started." "بکهال نصب و اجرا شد ✅"
send_summary_to_telegram
read -p "Press Enter to continue..."

}

---------------- Main Menu ----------------

main_menu() { ask_lang while true; do clear msg "=== Backhaul Manager ===" "=== مدیریت بک‌هال ===" echo "1) Install" echo "2) Exit" read -p "Choose: " c case $c in 1) install_backhaul ;; 2) exit 0 ;; esac done }

main_menu

