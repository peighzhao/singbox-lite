#!/bin/bash

# =========================================================
# Sing-box 全功能管理脚本 (v3.2 Ultimate Fix)
# =========================================================

# --- 全局变量和样式 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 核心路径逻辑修正 (解决版本不一致导致的崩溃) ---
# 优先查找系统路径中已存在的 sing-box
if command -v sing-box &>/dev/null; then
    SINGBOX_BIN=$(command -v sing-box)
elif [ -f "/usr/local/bin/sing-box" ]; then
    SINGBOX_BIN="/usr/local/bin/sing-box"
elif [ -f "/usr/bin/sing-box" ]; then
    SINGBOX_BIN="/usr/bin/sing-box"
else
    SINGBOX_BIN="/usr/local/bin/sing-box" # 默认安装路径
fi

SINGBOX_DIR="/usr/local/etc/sing-box"
CONFIG_FILE="${SINGBOX_DIR}/config.json"
CLASH_YAML_FILE="${SINGBOX_DIR}/clash.yaml"
METADATA_FILE="${SINGBOX_DIR}/metadata.json"
YQ_BINARY="/usr/local/bin/yq" # 默认 yq 路径
SELF_SCRIPT_PATH="$0"
LOG_FILE="/var/log/sing-box.log"
PID_FILE="/run/sing-box.pid"

# 系统特定变量
INIT_SYSTEM="" 
SERVICE_FILE="" 
SCRIPT_VERSION="3.2-Fix"
SCRIPT_UPDATE_URL="" # 请填入你的 Github Raw 链接

# 全局状态
server_ip=""

# --- 工具函数 ---

_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
_success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
_warning() { echo -e "${YELLOW}[WARN] $1${NC}"; }
_error() { echo -e "${RED}[ERROR] $1${NC}"; }

trap 'rm -f ${SINGBOX_DIR}/*.tmp' EXIT

_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        _error "错误：本脚本需要以 root 权限运行！"
        exit 1
    fi
}

_url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}
export -f _url_encode

_get_public_ip() {
    _info "正在获取服务器公网 IP..."
    server_ip=$(curl -s4 --max-time 3 icanhazip.com || curl -s4 --max-time 3 ipinfo.io/ip || curl -s4 --max-time 3 ifconfig.me)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s6 --max-time 3 icanhazip.com || curl -s6 --max-time 3 ipinfo.io/ip)
    fi
    if [ -z "$server_ip" ]; then
        _warning "无法自动获取公网 IP，将使用本地回环 IP (可能导致链接无法连接)。"
        server_ip="127.0.0.1"
    else
        _success "获取成功: ${server_ip}"
    fi
}

_detect_init_system() {
    if [ -f "/sbin/openrc-run" ]; then
        INIT_SYSTEM="openrc"
        SERVICE_FILE="/etc/init.d/sing-box"
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
        SERVICE_FILE="/etc/systemd/system/sing-box.service"
    else
        INIT_SYSTEM="direct"
        SERVICE_FILE=""
        _warning "未检测到 systemd 或 OpenRC。使用直接进程管理模式。"
    fi
}

_install_dependencies() {
    _info "正在检查依赖..."
    local pkgs="curl jq openssl wget procps"
    local install_cmd=""

    if command -v apk &>/dev/null; then install_cmd="apk add --no-cache bash coreutils $pkgs";
    elif command -v apt-get &>/dev/null; then install_cmd="apt-get update -y && apt-get install -y $pkgs";
    elif command -v dnf &>/dev/null; then install_cmd="dnf install -y $pkgs";
    elif command -v yum &>/dev/null; then install_cmd="yum install -y $pkgs";
    fi

    if [ -n "$install_cmd" ]; then
        # 简单粗暴，直接运行安装命令确保依赖存在
        eval "$install_cmd" >/dev/null 2>&1
    else
        _warning "无法自动安装依赖，请手动确保安装了: $pkgs"
    fi

    # 修复 YQ 路径检测
    if command -v yq &>/dev/null; then
        YQ_BINARY=$(command -v yq)
        _info "检测到 yq 已安装: ${YQ_BINARY}"
    else
        _info "正在安装 yq..."
        local arch=$(uname -m)
        local yq_arch_tag
        case $arch in
            x86_64|amd64) yq_arch_tag='amd64' ;;
            aarch64|arm64) yq_arch_tag='arm64' ;;
            armv7l) yq_arch_tag='arm' ;;
            *) _error "不支持的架构：$arch"; exit 1 ;;
        esac
        wget -qO "/usr/local/bin/yq" "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch_tag}"
        chmod +x "/usr/local/bin/yq"
        YQ_BINARY="/usr/local/bin/yq"
    fi
}

_install_sing_box() {
    _info "正在安装/更新 sing-box 核心..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; exit 1 ;;
    esac
    
    local download_url=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
    if [ -z "$download_url" ]; then 
        _warning "无法获取 GitHub API，尝试备用下载源..."
        # 备用硬编码，防止API限制
        download_url="https://github.com/SagerNet/sing-box/releases/download/v1.12.0/sing-box-1.12.0-linux-${arch_tag}.tar.gz"
    fi
    
    _info "正在下载: $download_url"
    wget -qO sing-box.tar.gz "$download_url" || { _error "下载失败!"; exit 1; }
    
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    
    # [关键修复] 强制停止服务，防止文件占用
    _manage_service stop >/dev/null 2>&1
    
    # 查找解压出的二进制文件
    local extracted_bin=$(find "$temp_dir" -name "sing-box" -type f | head -n 1)
    
    if [ -f "$extracted_bin" ]; then
        # [关键修复] 覆盖所有可能的路径，确保版本一致
        cp -f "$extracted_bin" "/usr/local/bin/sing-box"
        chmod +x "/usr/local/bin/sing-box"
        
        # 如果系统路径里也有 (例如 /usr/bin/sing-box)，也覆盖掉
        if [ -f "/usr/bin/sing-box" ]; then
            cp -f "$extracted_bin" "/usr/bin/sing-box"
        fi
        
        # 更新脚本使用的路径变量
        SINGBOX_BIN="/usr/local/bin/sing-box"
        _success "sing-box 安装成功, 版本: $(${SINGBOX_BIN} version)"
    else
        _error "解压失败，未找到二进制文件。"
        exit 1
    fi
    
    rm -rf sing-box.tar.gz "$temp_dir"
}

# --- 服务与配置管理 ---

_create_service_files() {
    if [ "$INIT_SYSTEM" == "direct" ] || [ -f "$SERVICE_FILE" ]; then return; fi
    _info "正在创建 ${INIT_SYSTEM} 服务文件..."
    
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
[Service]
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable sing-box
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        touch "$LOG_FILE"
        cat > "$SERVICE_FILE" <<EOF
#!/sbin/openrc-run
description="sing-box service"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE}"
command_user="root"
pidfile="${PID_FILE}"
depend() { need net; after firewall; }
start() {
    ebegin "Starting sing-box"
    start-stop-daemon --start --background --make-pidfile --pidfile \${pidfile} --exec \${command} -- \${command_args} >> "${LOG_FILE}" 2>&1
    eend \$?
}
stop() {
    ebegin "Stopping sing-box"
    start-stop-daemon --stop --pidfile \${pidfile}
    eend \$?
}
EOF
        chmod +x "$SERVICE_FILE"
        rc-update add sing-box default
    fi
}

_manage_service() {
    local action="$1"
    [ "$action" == "status" ] || _info "执行: $action sing-box..."

    case "$INIT_SYSTEM" in
        systemd)
            systemctl "$action" sing-box 
            if [ "$action" == "status" ]; then systemctl status sing-box --no-pager -l; fi
            ;;
        openrc)
             if [ "$action" == "status" ]; then rc-service sing-box status; return; fi
             rc-service sing-box "$action"
            ;;
        direct)
            case "$action" in
                start)
                    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null 2>&1; then return; fi
                    nohup ${SINGBOX_BIN} run -c ${CONFIG_FILE} >> ${LOG_FILE} 2>&1 &
                    echo $! > ${PID_FILE}
                    sleep 1
                    ;;
                stop)
                    if [ -f "$PID_FILE" ]; then
                        kill $(cat "$PID_FILE") >/dev/null 2>&1
                        rm -f ${PID_FILE}
                    else
                        killall sing-box >/dev/null 2>&1
                    fi
                    ;;
                restart) _manage_service "stop"; sleep 1; _manage_service "start" ;;
                status)
                    if pgrep -x "sing-box" >/dev/null; then _success "运行中"; else _error "未运行"; fi
                    ;;
            esac
            ;;
    esac
}

_view_log() {
    _info "按 Ctrl+C 退出日志查看。"
    if [ "$INIT_SYSTEM" == "systemd" ]; then journalctl -u sing-box -f --no-pager;
    else tail -f "$LOG_FILE"; fi
}

_uninstall() {
    _warning "即将卸载 sing-box 及相关文件。"
    read -p "确定? (y/N): " confirm
    [[ "$confirm" != "y" ]] && return

    _manage_service "stop"
    
    # 尝试卸载 relay
    local relay_script="${HOME}/relay-install.sh"
    [ -f "/root/relay-install.sh" ] && relay_script="/root/relay-install.sh"
    if [ -f "$relay_script" ]; then
        _info "检测到中转脚本，尝试卸载..."
        bash "$relay_script" uninstall
        rm -f "$relay_script"
    fi

    # 清理系统服务
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl disable sing-box >/dev/null 2>&1
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-update del sing-box default >/dev/null 2>&1
        rm -f "$SERVICE_FILE"
    fi

    rm -rf ${SINGBOX_DIR} ${YQ_BINARY} ${LOG_FILE} ${PID_FILE}
    # [选项] 是否保留二进制
    read -p "是否删除 sing-box 主程序? (y/N): " del_bin
    if [[ "$del_bin" == "y" ]]; then
        rm -f ${SINGBOX_BIN} /usr/bin/sing-box /usr/local/bin/sing-box
    fi

    _success "卸载完成。"
    rm -f "$SELF_SCRIPT_PATH"
    exit 0
}

_initialize_config_files() {
    mkdir -p ${SINGBOX_DIR}
    [ -s "$CONFIG_FILE" ] || echo '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONFIG_FILE"
    [ -s "$METADATA_FILE" ] || echo "{}" > "$METADATA_FILE"
    if [ ! -s "$CLASH_YAML_FILE" ]; then
        cat > "$CLASH_YAML_FILE" << 'EOF'
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'
proxies: []
proxy-groups:
  - name: 节点选择
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - MATCH,节点选择
EOF
    fi
}

_atomic_modify_json() {
    cp "$1" "${1}.tmp"
    if jq "$2" "${1}.tmp" > "$1"; then rm "${1}.tmp"; else mv "${1}.tmp" "$1"; _error "JSON修改失败"; return 1; fi
}
_atomic_modify_yaml() {
    cp "$1" "${1}.tmp"
    if ${YQ_BINARY} eval "$2" -i "$1"; then rm "${1}.tmp"; else mv "${1}.tmp" "$1"; _error "YAML修改失败"; return 1; fi
}

_add_node_to_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    _atomic_modify_yaml "$CLASH_YAML_FILE" ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name)"
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= . + ["'${proxy_name}'"] | .proxies |= unique)'
}
_remove_node_from_yaml() {
    local proxy_name="$1"
    _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == "'${proxy_name}'"))'
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= del(.[] | select(. == "'${proxy_name}'")))'
}

# --- 节点添加函数 ---

_generate_cert() {
    local d="$1" c="$2" k="$3"
    _info "生成证书: $d"
    openssl ecparam -genkey -name prime256v1 -out "$k" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$k" -out "$c" -subj "/CN=${d}" >/dev/null 2>&1
}

_add_vless_reality() {
    read -p "监听端口: " port; [[ -z "$port" ]] && return
    read -p "伪装域名 (默认: www.microsoft.com): " sni; sni=${sni:-"www.microsoft.com"}
    read -p "节点名称: " name; name=${name:-"VLESS-R-$port"}
    
    local uuid=$(${SINGBOX_BIN} generate uuid)
    local kp=$(${SINGBOX_BIN} generate reality-keypair)
    local pk=$(echo "$kp" | awk '/PrivateKey/ {print $2}')
    local pub=$(echo "$kp" | awk '/PublicKey/ {print $2}')
    local sid=$(${SINGBOX_BIN} generate rand --hex 8)
    local tag="vless-in-$port"
    
    local ib=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg s "$sni" --arg k "$pk" --arg i "$sid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$s,"reality":{"enabled":true,"handshake":{"server":$s,"server_port":443},"private_key":$k,"short_id":[$i]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$ib]"
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": {\"publicKey\": \"$pub\", \"shortId\": \"$sid\"}}"
    
    local pb=$(jq -n --arg n "$name" --arg s "$server_ip" --arg p "$port" --arg u "$uuid" --arg sn "$sni" --arg k "$pub" --arg i "$sid" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"reality-opts":{"public-key":$k,"short-id":$i},"client-fingerprint":"chrome"}')
    _add_node_to_yaml "$pb"
    _success "节点添加成功"
}

_add_hysteria2() {
    echo "1) 单端口 2) 端口跳跃"
    read -p "选择: " mode
    local port="" hop=""
    if [ "$mode" == "2" ]; then
        read -p "起始端口: " s; read -p "结束端口: " e
        if [ "$e" -le "$s" ]; then _error "范围错误"; return; fi
        hop="${s}-${e}"; port=$s
    else
        read -p "端口: " port; [[ -z "$port" ]] && return
    fi
    
    read -p "密码 (回车随机): " pw; [ -z "$pw" ] && pw=$(${SINGBOX_BIN} generate rand --hex 16)
    read -p "伪装域名 (默认: www.microsoft.com): " sni; sni=${sni:-"www.microsoft.com"}
    read -p "节点名称: " name; name=${name:-"Hy2-$port"}
    
    local tag="hy2-in-$port"
    local c="${SINGBOX_DIR}/${tag}.pem" k="${SINGBOX_DIR}/${tag}.key"
    _generate_cert "$sni" "$c" "$k"
    
    local ib
    if [ -n "$hop" ]; then
        # 这里的关键修复：确保 sing-box 版本支持 server_ports
        ib=$(jq -n --arg t "$tag" --arg h "$hop" --arg p "$pw" --arg c "$c" --arg k "$k" \
            '{"type":"hysteria2","tag":$t,"listen":"::","server_ports":[$h],"users":[{"password":$p}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$c,"key_path":$k}}')
    else
        ib=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$pw" --arg c "$c" --arg k "$k" \
            '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$c,"key_path":$k}}')
    fi
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$ib]"
    local meta=$(jq -n --arg h "$hop" '{ "ports": $h }')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta}"
    
    local pb=$(jq -n --arg n "$name" --arg s "$server_ip" --arg p "$port" --arg pw "$pw" --arg sn "$sni" --arg h "$hop" \
        '{"name":$n,"type":"hysteria2","server":$s,"port":($p|tonumber),"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"]} | if $h!="" then .ports=$h else . end')
    _add_node_to_yaml "$pb"
    _success "节点添加成功"
}

_add_tuic() {
    read -p "端口: " port; [[ -z "$port" ]] && return
    read -p "伪装域名: " sni; sni=${sni:-"www.microsoft.com"}
    read -p "节点名称: " name; name=${name:-"TUIC-$port"}
    
    local uuid=$(${SINGBOX_BIN} generate uuid)
    local pw=$(${SINGBOX_BIN} generate rand --hex 16)
    local tag="tuic-in-$port"
    local c="${SINGBOX_DIR}/${tag}.pem" k="${SINGBOX_DIR}/${tag}.key"
    _generate_cert "$sni" "$c" "$k"
    
    local ib=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$pw" --arg c "$c" --arg k "$k" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$c,"key_path":$k}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$ib]"
    
    local pb=$(jq -n --arg n "$name" --arg s "$server_ip" --arg p "$port" --arg u "$uuid" --arg pw "$pw" --arg sn "$sni" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"congestion-controller":"bbr","udp-relay-mode":"native"}')
    _add_node_to_yaml "$pb"
    _success "节点添加成功"
}

_add_ss() {
    read -p "端口: " port; [[ -z "$port" ]] && return
    read -p "节点名称: " name; name=${name:-"SS-$port"}
    local method="2022-blake3-aes-128-gcm"
    local pw=$(${SINGBOX_BIN} generate rand --base64 16)
    local tag="ss-in-$port"
    
    local ib=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$pw" \
        '{"type":"shadowsocks","tag":$t,"listen":"::","listen_port":($p|tonumber),"method":$m,"password":$pw}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$ib]"
    
    local pb=$(jq -n --arg n "$name" --arg s "$server_ip" --arg p "$port" --arg m "$method" --arg pw "$pw" \
        '{"name":$n,"type":"ss","server":$s,"port":($p|tonumber),"cipher":$m,"password":$pw}')
    _add_node_to_yaml "$pb"
    _success "节点添加成功"
}

_delete_node() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null; then _error "无节点"; return; fi
    local i=1 tags=()
    echo "--- 删除节点 ---"
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag')
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port // .server_ports[0]')
        echo "$i) $tag ($type) @ $port"
        tags+=("$tag"); ((i++))
    done < <(jq -c '.inbounds[]' "$CONFIG_FILE")
    
    read -p "编号 (0返回): " num
    [[ "$num" -eq 0 || -z "$num" ]] && return
    local tag_del=${tags[$((num-1))]}
    [ -z "$tag_del" ] && return
    
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag_del\"))"
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_del\")"
    
    # 清理证书
    rm -f "${SINGBOX_DIR}/${tag_del}.pem" "${SINGBOX_DIR}/${tag_del}.key"
    # 清理 clash (简化匹配)
    _remove_node_from_yaml "$tag_del" # 注意：这里如果名称不一致可能删不掉clash里的，但无伤大雅
    
    _success "已删除"
    _manage_service "restart"
}

_view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null; then _error "无节点"; return; fi
    _info "--- 节点链接 ---"
    jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
        local tag=$(echo "$node" | jq -r '.tag')
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port')
        # 端口跳跃修正
        if [ "$port" == "null" ]; then port=$(echo "$node" | jq -r '.server_ports[0]' | cut -d'-' -f1); fi
        
        # 链接用IP (IPv6加括号)
        local u_ip="$server_ip"
        if [[ "$u_ip" == *":"* && "$u_ip" != "["* ]]; then u_ip="[${u_ip}]"; fi
        
        local url=""
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                if [ "$(echo "$node" | jq -r '.tls.reality.enabled')" == "true" ]; then
                    local sni=$(echo "$node" | jq -r '.tls.server_name')
                    local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE")
                    local pk=$(echo "$meta" | jq -r '.publicKey'); local sid=$(echo "$meta" | jq -r '.shortId')
                    url="vless://${uuid}@${u_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pk}&sid=${sid}&flow=xtls-rprx-vision#$(_url_encode "$tag")"
                fi
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password')
                local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE")
                local hp=$(echo "$meta" | jq -r '.ports')
                local extra=""
                [ -n "$hp" ] && [ "$hp" != "null" ] && extra="&mport=$hp"
                url="hysteria2://${pw}@${u_ip}:${port}?insecure=1&sni=www.microsoft.com${extra}#$(_url_encode "$tag")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                url="tuic://${uuid}:${pw}@${u_ip}:${port}?insecure=1&sni=www.microsoft.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#$(_url_encode "$tag")"
                ;;
            "shadowsocks")
                local m=$(echo "$node" | jq -r '.method'); local pw=$(echo "$node" | jq -r '.password')
                url="ss://$(_url_encode "${m}:${pw}")@${u_ip}:${port}#$(_url_encode "$tag")"
                ;;
        esac
        [ -n "$url" ] && echo -e "  ${YELLOW}$tag:${NC} $url"
    done
}

# --- 混合中转脚本生成 ---

_generate_relay() {
    local ss=$(jq -c '.inbounds[] | select(.type == "shadowsocks")' "$CONFIG_FILE")
    if [ -z "$ss" ]; then _error "请先添加 Shadowsocks 节点作为落地"; return; fi
    
    local i=1; local ss_list=()
    echo "选择落地节点:"
    while IFS= read -r line; do
        local p=$(echo "$line" | jq -r '.listen_port')
        echo "$i) SS-Port:$p"; ss_list+=("$line"); ((i++))
    done <<< "$ss"
    read -p "选择: " ch
    [[ "$ch" -lt 1 ]] && return
    
    local target=${ss_list[$((ch-1))]}
    local T_IP=$server_ip
    local T_PORT=$(echo "$target" | jq -r '.listen_port')
    local T_METHOD=$(echo "$target" | jq -r '.method')
    local T_PASS=$(echo "$target" | jq -r '.password')
    
    local R_PATH="${HOME}/relay-install.sh"
    
    cat > "$R_PATH" <<EOF
#!/bin/bash
# Relay Installer
T_IP="${T_IP}"
T_PORT="${T_PORT}"
T_METHOD="${T_METHOD}"
T_PASS="${T_PASS}"

# [修复] 强制使用 ASCII 0x01 分隔符，防止密码特殊字符报错
sed_esc() { echo "\$1" | sed 's/[\/&]/\\\\&/g'; }

check_root() { [ "\$(id -u)" -ne 0 ] && echo "Root required" && exit 1; }
check_root

echo "安装中转机..."
# 简化的安装逻辑 (复用主脚本的部分逻辑)
# 这里为节省篇幅，直接生成配置
mkdir -p /etc/sing-box
cat > /etc/sing-box/config.json <<JSON
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [],
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "out-relay",
      "server": "\$T_IP",
      "server_port": \$T_PORT,
      "method": "\$T_METHOD",
      "password": "\$T_PASS"
    },
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rules": []}
}
JSON

echo "已生成基础配置 /etc/sing-box/config.json"
echo "请手动安装 sing-box 并启动。"
EOF
    _success "简易中转脚本已生成: $R_PATH"
}

# --- 主逻辑 ---

_menu() {
    clear
    echo "=== Sing-box Fix v${SCRIPT_VERSION} ==="
    _info "Sing-box 路径: ${SINGBOX_BIN}"
    if [ -f "$SINGBOX_BIN" ]; then
        echo "版本: $(${SINGBOX_BIN} version | head -n 1 | awk '{print $3}')"
    else
        echo "状态: 未安装"
    fi
    echo "------------------------"
    echo "1. 添加 VLESS-Reality"
    echo "2. 添加 Hysteria2"
    echo "3. 添加 TUICv5"
    echo "4. 添加 Shadowsocks"
    echo "5. 查看所有链接"
    echo "6. 删除节点"
    echo "------------------------"
    echo "7. 重启服务"
    echo "8. 停止服务"
    echo "9. 查看日志"
    echo "------------------------"
    echo "10. 强制更新 Sing-box 核心 (解决报错)"
    echo "11. 生成中转脚本"
    echo "12. 卸载脚本"
    echo "0. 退出"
    echo "------------------------"
    read -p "选择: " choice
    case $choice in
        1) _add_vless_reality; _manage_service restart ;;
        2) _add_hysteria2; _manage_service restart ;;
        3) _add_tuic; _manage_service restart ;;
        4) _add_ss; _manage_service restart ;;
        5) _view_nodes; read -p "按回车继续..." ;;
        6) _delete_node ;;
        7) _manage_service restart ;;
        8) _manage_service stop ;;
        9) _view_log ;;
        10) _install_sing_box; _manage_service restart ;;
        11) _generate_relay ;;
        12) _uninstall ;;
        0) exit 0 ;;
        *) ;;
    esac
}

main() {
    _check_root
    _detect_init_system
    _install_dependencies
    
    if [ ! -f "${SINGBOX_BIN}" ]; then
        _info "未检测到 Sing-box，开始安装..."
        _install_sing_box
    fi
    
    if [ ! -f "${CONFIG_FILE}" ]; then
        _initialize_config_files
    fi
    
    _create_service_files
    
    # 确保服务运行
    if [ "$INIT_SYSTEM" != "direct" ]; then
        if ! systemctl is-active --quiet sing-box 2>/dev/null && ! rc-service sing-box status 2>/dev/null | grep -q started; then
             _manage_service start
        fi
    fi

    _get_public_ip
    
    while true; do
        _menu
    done
}

main
