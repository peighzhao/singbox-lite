#!/bin/bash

# =========================================================
# Sing-box 全功能管理脚本 (修复版)
# =========================================================

# --- 全局变量和样式 ---
# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 文件路径常量
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_DIR="/usr/local/etc/sing-box"
CONFIG_FILE="${SINGBOX_DIR}/config.json"
CLASH_YAML_FILE="${SINGBOX_DIR}/clash.yaml"
METADATA_FILE="${SINGBOX_DIR}/metadata.json"
# 默认路径，会在依赖检查中动态更新
YQ_BINARY="/usr/local/bin/yq"
SELF_SCRIPT_PATH="$0"
LOG_FILE="/var/log/sing-box.log"
PID_FILE="/run/sing-box.pid"

# 系统特定变量
INIT_SYSTEM="" # 将存储 'systemd', 'openrc' 或 'direct'
SERVICE_FILE="" # 将根据 INIT_SYSTEM 设置

# 脚本元数据
SCRIPT_VERSION="3.1-Fixed" 
# 注意：请替换为您实际的 GitHub URL，否则更新功能不可用
SCRIPT_UPDATE_URL="https://raw.githubusercontent.com/your-repo/singbox-lite/main/singbox.sh" 

# 全局状态变量
server_ip=""

# --- 工具函数 ---

# 打印消息
_echo_style() {
    local color_prefix="$1"
    local message="$2"
    echo -e "${color_prefix}${message}${NC}"
}

_info() { _echo_style "${CYAN}" "$1"; }
_success() { _echo_style "${GREEN}" "$1"; }
_warning() { _echo_style "${YELLOW}" "$1"; }
_error() { _echo_style "${RED}" "$1"; }

# 捕获退出信号，清理临时文件
trap 'rm -f ${SINGBOX_DIR}/*.tmp' EXIT

# 检查root权限
_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        _error "错误：本脚本需要以 root 权限运行！"
        exit 1
    fi
}

# --- URL 编码助手 ---
_url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}
export -f _url_encode

# 获取公网IP
_get_public_ip() {
    _info "正在获取服务器公网 IP..."
    # 增加备用源和错误处理
    server_ip=$(curl -s4 --max-time 3 icanhazip.com || curl -s4 --max-time 3 ipinfo.io/ip || curl -s4 --max-time 3 ifconfig.me)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s6 --max-time 3 icanhazip.com || curl -s6 --max-time 3 ipinfo.io/ip)
    fi
    if [ -z "$server_ip" ]; then
        _warning "无法自动获取公网 IP，将尝试使用本地 IP。"
        server_ip="127.0.0.1"
    else
        _success "获取成功: ${server_ip}"
    fi
}

# --- 系统环境适配 ---

_detect_init_system() {
    if [ -f "/sbin/openrc-run" ]; then
        INIT_SYSTEM="openrc"
        SERVICE_FILE="/etc/init.d/sing-box"
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
        SERVICE_FILE="/etc/systemd/system/sing-box.service"
    else
        INIT_SYSTEM="direct"
        SERVICE_FILE="" # 在直接管理模式下无服务文件
        _warning "未检测到 systemd 或 OpenRC。将使用直接进程管理模式。"
        _warning "注意：在此模式下，sing-box 服务无法开机自启。"
    fi
    # _info "检测到管理模式为: ${INIT_SYSTEM}"
}

_install_dependencies() {
    _info "正在检查并安装所需依赖..."
    local pkgs_to_install=""
    local required_pkgs="curl jq openssl wget procps"
    local pm=""

    if command -v apk &>/dev/null; then
        pm="apk"
        required_pkgs="bash coreutils ${required_pkgs}"
    elif command -v apt-get &>/dev/null; then pm="apt-get";
    elif command -v dnf &>/dev/null; then pm="dnf";
    elif command -v yum &>/dev/null; then pm="yum";
    else _warning "未能识别的包管理器, 无法自动安装依赖。请确保已安装: $required_pkgs"; fi

    if [ -n "$pm" ]; then
        if [ "$pm" == "apk" ]; then
            for pkg in $required_pkgs; do ! apk -e info "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            if [ -n "$pkgs_to_install" ]; then
                _info "正在安装缺失的依赖:$pkgs_to_install"
                apk update && apk add --no-cache $pkgs_to_install || { _error "依赖安装失败"; exit 1; }
            fi
        else # for apt, dnf, yum
            if [ "$pm" == "apt-get" ]; then
                for pkg in $required_pkgs; do ! dpkg -s "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            else
                for pkg in $required_pkgs; do ! rpm -q "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            fi

            if [ -n "$pkgs_to_install" ]; then
                _info "正在安装缺失的依赖:$pkgs_to_install"
                [ "$pm" == "apt-get" ] && $pm update -y
                $pm install -y $pkgs_to_install || { _error "依赖安装失败"; exit 1; }
            fi
        fi
    fi

    # [修复] 这里的逻辑：先检查 yq 是否存在，存在则更新路径变量，否则下载
    if command -v yq &>/dev/null; then
        YQ_BINARY=$(command -v yq)
        _info "检测到 yq 已安装: ${YQ_BINARY}"
    else
        _info "正在安装 yq (用于YAML处理)..."
        local arch=$(uname -m)
        local yq_arch_tag
        case $arch in
            x86_64|amd64) yq_arch_tag='amd64' ;;
            aarch64|arm64) yq_arch_tag='arm64' ;;
            armv7l) yq_arch_tag='arm' ;;
            *) _error "yq 安装失败: 不支持的架构：$arch"; exit 1 ;;
        esac
        
        # 强制指定安装到 /usr/local/bin 方便管理，或者使用之前定义的 YQ_BINARY
        wget -qO "/usr/local/bin/yq" "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch_tag}" || { _error "yq 下载失败"; exit 1; }
        chmod +x "/usr/local/bin/yq"
        YQ_BINARY="/usr/local/bin/yq"
    fi
    _success "所有依赖均已满足。"
}

_install_sing_box() {
    _info "正在安装最新稳定版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; exit 1 ;;
    esac
    
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
    if [ -z "$download_url" ]; then _error "无法获取 sing-box 下载链接。"; exit 1; fi
    
    wget -qO sing-box.tar.gz "$download_url" || { _error "下载失败!"; exit 1; }
    
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    # 通配符移动，防止版本号变化导致路径错误
    mv "$temp_dir"/sing-box-*/sing-box ${SINGBOX_BIN}
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x ${SINGBOX_BIN}
    
    _success "sing-box 安装成功, 版本: $(${SINGBOX_BIN} version)"
}

# --- 服务与配置管理 ---

_create_systemd_service() {
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
}

_create_openrc_service() {
    cat > "$SERVICE_FILE" <<EOF
#!/sbin/openrc-run

description="sing-box service"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE}"
command_user="root"
pidfile="${PID_FILE}"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting sing-box"
    start-stop-daemon --start --background \\
        --make-pidfile --pidfile \${pidfile} \\
        --exec \${command} -- \${command_args} >> "${LOG_FILE}" 2>&1
    eend \$?
}

stop() {
    ebegin "Stopping sing-box"
    start-stop-daemon --stop --pidfile \${pidfile}
    eend \$?
}
EOF
    chmod +x "$SERVICE_FILE"
}

_create_service_files() {
    if [ "$INIT_SYSTEM" == "direct" ]; then
        return
    fi
    if [ -f "$SERVICE_FILE" ]; then return; fi
    
    _info "正在创建 ${INIT_SYSTEM} 服务文件..."
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _create_systemd_service
        systemctl daemon-reload
        systemctl enable sing-box
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        touch "$LOG_FILE"
        _create_openrc_service
        rc-update add sing-box default
    fi
    _success "${INIT_SYSTEM} 服务创建并启用成功。"
}


_manage_service() {
    local action="$1"
    [ "$action" == "status" ] || _info "正在使用 ${INIT_SYSTEM} 执行: $action..."

    case "$INIT_SYSTEM" in
        systemd)
            case "$action" in
                start|stop|restart|enable|disable) systemctl "$action" sing-box ;;
                status) systemctl status sing-box --no-pager -l; return ;;
                *) _error "无效的服务管理命令: $action"; return ;;
            esac
            ;;
        openrc)
             if [ "$action" == "status" ]; then
                rc-service sing-box status
                return
             fi
             rc-service sing-box "$action"
            ;;
        direct)
            case "$action" in
                start)
                    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _warning "sing-box 似乎已在运行。"
                        return
                    fi
                    touch "$LOG_FILE"
                    nohup ${SINGBOX_BIN} run -c ${CONFIG_FILE} >> ${LOG_FILE} 2>&1 &
                    echo $! > ${PID_FILE}
                    sleep 1
                    if ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _success "sing-box 启动成功, PID: $(cat ${PID_FILE})。"
                    else
                        _error "sing-box 启动失败，请检查日志: ${LOG_FILE}"
                        rm -f ${PID_FILE}
                    fi
                    ;;
                stop)
                    if [ ! -f "$PID_FILE" ]; then
                        _warning "未找到 PID 文件，可能未在运行。"
                        return
                    fi
                    local pid=$(cat "$PID_FILE")
                    if ps -p $pid > /dev/null; then
                        kill $pid
                        sleep 1
                        if ps -p $pid > /dev/null; then
                           _warning "无法正常停止，正在强制终止..."
                           kill -9 $pid
                        fi
                    fi
                    rm -f ${PID_FILE}
                    ;;
                restart)
                    _manage_service "stop"
                    _manage_service "start"
                    ;;
                status)
                    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _success "sing-box 正在运行, PID: $(cat ${PID_FILE})。"
                    else
                        _error "sing-box 未运行。"
                    fi
                    return
                    ;;
                 *) _error "无效的命令: $action"; return ;;
            esac
            ;;
    esac
    _success "sing-box 服务已 $action"
}

_view_log() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _info "按 Ctrl+C 退出日志查看。"
        journalctl -u sing-box -f --no-pager
    else
        if [ ! -f "$LOG_FILE" ]; then
            _warning "日志文件 ${LOG_FILE} 不存在。"
            return
        fi
        _info "按 Ctrl+C 退出日志查看 (日志文件: ${LOG_FILE})。"
        tail -f "$LOG_FILE"
    fi
}

_uninstall() {
    _warning "！！！警告！！！"
    _warning "本操作将停止并禁用 [主脚本] 服务 (sing-box)，"
    _warning "删除所有相关文件 (包括 sing-box 主程序和 yq) 以及本脚本自身。"
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm_main
    
    if [[ "$confirm_main" != "y" && "$confirm_main" != "Y" ]]; then
        _info "卸载已取消。"
        return
    fi

    # [!!!] 新逻辑：增加一个保护标记，决定是否删除 sing-box 主程序
    local keep_singbox_binary=false
    
    local relay_script_path="${HOME}/relay-install.sh"
    # 如果 HOME 是 root, 路径就是 /root/relay-install.sh
    if [ -f "/root/relay-install.sh" ]; then relay_script_path="/root/relay-install.sh"; fi

    local relay_config_dir="/etc/sing-box" 
    local relay_detected=false

    if [ -f "$relay_script_path" ] || [ -d "$relay_config_dir" ]; then
        # 简单检查是否有 relay 的特征文件
        if [ -f "${relay_config_dir}/vless_links.txt" ] || [ -f "${relay_config_dir}/hy2_links.txt" ]; then
             relay_detected=true
        fi
    fi

    if [ "$relay_detected" = true ]; then
        _warning "检测到 [线路机] 脚本/配置。是否一并卸载？"
        read -p "$(echo -e ${YELLOW}"是否同时卸载线路机服务? (y/N): "${NC})" confirm_relay
        
        if [[ "$confirm_relay" == "y" || "$confirm_relay" == "Y" ]]; then
            _info "正在卸载 [线路机]..."
            if [ -f "$relay_script_path" ]; then
                _info "正在执行: bash ${relay_script_path} uninstall"
                bash "${relay_script_path}" uninstall
                rm -f "$relay_script_path"
            else
                _warning "未找到 relay-install.sh，尝试手动清理线路机配置..."
                local relay_service_name="sing-box-relay"
                
                # 手动清理逻辑增强
                _info "尝试停止服务: ${relay_service_name}"
                if [ "$INIT_SYSTEM" == "systemd" ]; then
                    systemctl stop $relay_service_name >/dev/null 2>&1
                    systemctl disable $relay_service_name >/dev/null 2>&1
                    rm -f /etc/systemd/system/${relay_service_name}.service
                    systemctl daemon-reload
                elif [ "$INIT_SYSTEM" == "openrc" ]; then
                    rc-service $relay_service_name stop >/dev/null 2>&1
                    rc-update del $relay_service_name default >/dev/null 2>&1
                    rm -f /etc/init.d/${relay_service_name}
                fi
                # 删除配置目录
                rm -rf "$relay_config_dir"
            fi
            _success "[线路机] 卸载完毕。"
            keep_singbox_binary=false 
        else
            _info "您选择了 [保留] 线路机服务。"
            _warning "为了保持线路机服务 [sing-box-relay] 正常运行："
            _success "sing-box 主程序 (${SINGBOX_BIN}) 将被 [保留]。"
            keep_singbox_binary=true 
            # ... (保留提示信息不变)
            read -p "请仔细阅读以上信息，按任意键以继续卸载 [主脚本]..."
        fi
    fi

    _info "正在卸载 [主脚本] (sing-box)..."
    _manage_service "stop"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl disable sing-box >/dev/null 2>&1
        systemctl daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-update del sing-box default >/dev/null 2>&1
    fi
    
    _info "正在删除主配置、yq、日志文件..."
    rm -rf ${SINGBOX_DIR} ${YQ_BINARY} ${SERVICE_FILE} ${LOG_FILE} ${PID_FILE}

    if [ "$keep_singbox_binary" = false ]; then
        _info "正在删除 sing-box 主程序..."
        rm -f ${SINGBOX_BIN}
    else
        _success "已 [保留] sing-box 主程序 (${SINGBOX_BIN})。"
    fi
    
    _success "清理完成。脚本已自毁。再见！"
    rm -f "${SELF_SCRIPT_PATH}"
    exit 0
}

_initialize_config_files() {
    mkdir -p ${SINGBOX_DIR}
    [ -s "$CONFIG_FILE" ] || echo '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONFIG_FILE"
    [ -s "$METADATA_FILE" ] || echo "{}" > "$METADATA_FILE"
    if [ ! -s "$CLASH_YAML_FILE" ]; then
        _info "正在创建全新的 clash.yaml 配置文件..."
        # 简化版 clash.yaml 模板
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
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
EOF
    fi
}

_generate_self_signed_cert() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"

    _info "正在为 ${domain} 生成自签名证书..."
    openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${domain}" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        _error "为 ${domain} 生成证书失败！"
        rm -f "$cert_path" "$key_path"
        return 1
    fi
    _success "证书 ${cert_path} 和私钥 ${key_path} 已成功生成。"
    return 0
}

_atomic_modify_json() {
    local file_path="$1"
    local jq_filter="$2"
    cp "$file_path" "${file_path}.tmp"
    if jq "$jq_filter" "${file_path}.tmp" > "$file_path"; then
        rm "${file_path}.tmp"
    else
        _error "修改JSON文件 '$file_path' 失败！配置已回滚。"
        mv "${file_path}.tmp" "$file_path"
        return 1
    fi
}

_atomic_modify_yaml() {
    local file_path="$1"
    local yq_filter="$2"
    cp "$file_path" "${file_path}.tmp"
    if ${YQ_BINARY} eval "$yq_filter" -i "$file_path"; then
        rm "${file_path}.tmp"
    else
        _error "修改YAML文件 '$file_path' 失败！配置已回滚。"
        mv "${file_path}.tmp" "$file_path"
        return 1
    fi
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

_add_vless_ws_tls() {
    _info "--- VLESS (WebSocket+TLS) 设置向导 ---"
    
    _info "请输入客户端用于“连接”的地址:"
    _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
    read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
    local raw_addr=${connection_address:-$server_ip}
    
    # [修复] 区分配置文件用的地址(无括号)和链接用的地址(IPv6有括号)
    local config_server_addr="$raw_addr"
    
    _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    read -p "请输入监听端口 : " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1

    read -p "请输入 WebSocket 路径 (回车则随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已为您生成随机 WebSocket 路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    _info "请输入证书文件 .pem/.crt 的完整路径: "
    read -p "证书路径: " cert_path
    [[ ! -f "$cert_path" ]] && _error "文件不存在" && return 1
    read -p "私钥路径: " key_path
    [[ ! -f "$key_path" ]] && _error "文件不存在" && return 1
    
    read -p "$(echo -e ${YELLOW}"是否使用自签名/Cloudflare源证书 (跳过验证)? (y/N): "${NC})" use_origin_cert
    local skip_verify=false
    if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then skip_verify=true; fi
    
    local default_name="VLESS-WS-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-ws-in-${port}"
    
    local inbound_json=$(jq -n \
        --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg cp "$cert_path" --arg kp "$key_path" --arg wsp "$ws_path" \
        '{ "type": "vless", "tag": $t, "listen": "::", "listen_port": ($p|tonumber), "users": [{"uuid": $u, "flow": ""}], "tls": { "enabled": true, "certificate_path": $cp, "key_path": $kp }, "transport": { "type": "ws", "path": $wsp } }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n \
            --arg n "$name" --arg s "$config_server_addr" --arg p "$port" --arg u "$uuid" --arg sn "$camouflage_domain" --arg wsp "$ws_path" --arg skip_verify_bool "$skip_verify" --arg host_header "$camouflage_domain" \
            '{ "name": $n, "type": "vless", "server": $s, "port": ($p|tonumber), "uuid": $u, "tls": true, "udp": true, "skip-cert-verify": ($skip_verify_bool == "true"), "network": "ws", "servername": $sn, "ws-opts": { "path": $wsp, "headers": { "Host": $host_header } } }')
            
    _add_node_to_yaml "$proxy_json"
    _success "节点 [${name}] 添加成功!"
}

_add_trojan_ws_tls() {
    _info "--- Trojan (WebSocket+TLS) 设置向导 ---"
    read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
    local raw_addr=${connection_address:-$server_ip}
    local config_server_addr="$raw_addr"

    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    read -p "请输入监听端口 : " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1

    read -p "请输入 WebSocket 路径 (回车随机): " ws_path
    if [ -z "$ws_path" ]; then ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8); else [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"; fi

    read -p "证书路径: " cert_path
    [[ ! -f "$cert_path" ]] && _error "文件不存在" && return 1
    read -p "私钥路径: " key_path
    [[ ! -f "$key_path" ]] && _error "文件不存在" && return 1
    
    read -p "$(echo -e ${YELLOW}"是否跳过证书验证? (y/N): "${NC})" use_origin_cert
    local skip_verify=false
    if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then skip_verify=true; fi

    read -p "请输入 Trojan 密码 (回车随机): " password
    [ -z "$password" ] && password=$(${SINGBOX_BIN} generate rand --hex 16)

    local default_name="Trojan-WS-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local tag="trojan-ws-in-${port}"
    
    local inbound_json=$(jq -n \
        --arg t "$tag" --arg p "$port" --arg pw "$password" --arg cp "$cert_path" --arg kp "$key_path" --arg wsp "$ws_path" \
        '{ "type": "trojan", "tag": $t, "listen": "::", "listen_port": ($p|tonumber), "users": [{"password": $pw}], "tls": { "enabled": true, "certificate_path": $cp, "key_path": $kp }, "transport": { "type": "ws", "path": $wsp } }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n \
            --arg n "$name" --arg s "$config_server_addr" --arg p "$port" --arg pw "$password" --arg sn "$camouflage_domain" --arg wsp "$ws_path" --arg skip_verify_bool "$skip_verify" --arg host_header "$camouflage_domain" \
            '{ "name": $n, "type": "trojan", "server": $s, "port": ($p|tonumber), "password": $pw, "udp": true, "skip-cert-verify": ($skip_verify_bool == "true"), "network": "ws", "sni": $sn, "ws-opts": { "path": $wsp, "headers": { "Host": $host_header } } }')
            
    _add_node_to_yaml "$proxy_json"
    _success "节点 [${name}] 添加成功!"
}

_add_vless_reality() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入伪装域名 (默认: www.microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"www.microsoft.com"}
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    local default_name="VLESS-REALITY-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local keypair=$(${SINGBOX_BIN} generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(${SINGBOX_BIN} generate rand --hex 8)
    local tag="vless-in-${port}"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\"}}" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$node_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (REALITY) 节点 [${name}] 添加成功!"
}

_add_vless_tcp() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    local default_name="VLESS-TCP-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-tcp-in-${port}"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":""}],"tls":{"enabled":false}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$node_ip" --arg p "$port" --arg u "$uuid" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":false,"network":"tcp"}')
    _add_node_to_yaml "$proxy_json"
    _success "VLESS (TCP) 节点 [${name}] 添加成功!"
}

_add_hysteria2() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    echo -e "请选择端口模式："
    echo -e " 1) 单端口"
    echo -e " 2) 端口跳跃 (Port Hopping)"
    read -p "请选择 [1-2]: " port_mode
    
    local port=""
    local hop_ports=""
    
    if [[ "$port_mode" == "2" ]]; then
        read -p "请输入起始端口 (必填): " port_start
        read -p "请输入结束端口 (必填): " port_end
        if [[ -z "$port_start" || -z "$port_end" ]]; then _error "端口均必填！"; return 1; fi
        if [[ "$port_end" -le "$port_start" ]]; then _error "结束端口必须大于起始端口！"; return 1; fi
        hop_ports="${port_start}-${port_end}"
        port=$port_start # 用于命名和标识
        _info "已启用端口跳跃: ${hop_ports}"
    else
        read -p "请输入监听端口 (必填): " input_port
        if [[ -z "$input_port" ]]; then _error "监听端口不能为空！"; return 1; fi
        port=$input_port
    fi

    read -p "请输入伪装域名 (默认: www.microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"www.microsoft.com"}

    local tag="hy2-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1
    
    read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
    read -p "请输入上传速度 (默认 100 Mbps): " up_speed; up_speed=${up_speed:-"100 Mbps"}
    read -p "请输入下载速度 (默认 200 Mbps): " down_speed; down_speed=${down_speed:-"200 Mbps"}
    
    local obfs_password=""
    read -p "是否开启 QUIC 流量混淆 (salamander)? (y/N): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        _info "已启用 Salamander 混淆。"
    fi
    
    local default_name="Hysteria2-${port}"
    if [[ -n "$hop_ports" ]]; then default_name="Hy2-Hop-${hop_ports}"; fi
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}
    
    local inbound_json
    if [[ -n "$hop_ports" ]]; then
        inbound_json=$(jq -n --arg t "$tag" --arg hp "$hop_ports" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"hysteria2","tag":$t,"listen":"::","server_ports":[$hp],"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    else
        inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    fi
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local meta_json=$(jq -n --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" --arg hp "$hop_ports" \
        '{ "up": $up, "down": $down } | if $op != "" then .obfsPassword = $op else . end | if $hp != "" then .ports = $hp else . end')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$node_ip" --arg p "$port" --arg pw "$password" --arg sn "$server_name" --arg up "$up_speed" --arg down "$down_speed" --arg op "$obfs_password" --arg hp "$hop_ports" \
        '{"name":$n,"type":"hysteria2","server":$s,"port":($p|tonumber),"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"up":$up,"down":$down} 
        | if $op != "" then .obfs="salamander" | .["obfs-password"]=$op else . end 
        | if $hp != "" then .ports = $hp end')
    _add_node_to_yaml "$proxy_json"
    
    _success "Hysteria2 节点 [${name}] 添加成功!"
}

_add_tuic() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    read -p "请输入伪装域名 (默认: www.microsoft.com): " camouflage_domain
    local server_name=${camouflage_domain:-"www.microsoft.com"}

    local tag="tuic-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1

    local uuid=$(${SINGBOX_BIN} generate uuid); local password=$(${SINGBOX_BIN} generate rand --hex 16)
    local default_name="TUICv5-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$node_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sn "$server_name" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    _add_node_to_yaml "$proxy_json"
    _success "TUICv5 节点 [${name}] 添加成功!"
}

_add_shadowsocks_menu() {
    clear
    echo "========================================"
    _info "          添加 Shadowsocks 节点"
    echo "========================================"
    echo " 1) shadowsocks (aes-256-gcm)"
    echo " 2) shadowsocks-2022 (2022-blake3-aes-128-gcm)"
    echo "----------------------------------------"
    echo " 0) 返回"
    echo "========================================"
    read -p "请选择加密方式 [0-2]: " choice

    local method="" password="" name_prefix=""
    case $choice in
        1) method="aes-256-gcm"; password=$(${SINGBOX_BIN} generate rand --hex 16); name_prefix="SS-aes-256-gcm" ;;
        2) method="2022-blake3-aes-128-gcm"; password=$(${SINGBOX_BIN} generate rand --base64 16); name_prefix="SS-2022" ;;
        0) return 1 ;;
        *) _error "无效输入"; return 1 ;;
    esac

    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    local default_name="${name_prefix}-${port}"
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    local tag="${name_prefix}-in-${port}"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"type":"shadowsocks","tag":$t,"listen":"::","listen_port":($p|tonumber),"method":$m,"password":$pw}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$node_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
        '{"name":$n,"type":"ss","server":$s,"port":($p|tonumber),"cipher":$m,"password":$pw}')
    _add_node_to_yaml "$proxy_json"

    _success "Shadowsocks (${method}) 节点 [${name}] 添加成功!"
    return 0
}

_add_socks() {
    read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
    local node_ip=${custom_ip:-$server_ip}
    
    read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    read -p "请输入用户名 (默认随机): " username; username=${username:-$(${SINGBOX_BIN} generate rand --hex 8)}
    read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
    local tag="socks-in-${port}"; local name="SOCKS5-${port}"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"type":"socks","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"username":$u,"password":$pw}]}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$node_ip" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"name":$n,"type":"socks5","server":$s,"port":($p|tonumber),"username":$u,"password":$pw}')
    _add_node_to_yaml "$proxy_json"
    _success "SOCKS5 节点添加成功!"
}

_view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    
    _info "--- 当前节点信息 (共 $(jq '.inbounds | length' "$CONFIG_FILE") 个) ---"
    
    jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') 
        local type=$(echo "$node" | jq -r '.type') 
        
        # 智能获取端口
        local port=$(echo "$node" | jq -r '.listen_port')
        if [[ "$port" == "null" ]]; then
            local port_range=$(echo "$node" | jq -r '.server_ports[0] // empty')
            [[ -n "$port_range" ]] && port=$(echo "$port_range" | cut -d'-' -f1)
        fi
        
        if [[ -z "$port" || "$port" == "null" ]]; then _error "无法解析节点端口，跳过: $tag"; continue; fi
        
        # 查找名称
        local proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}') | .name' ${CLASH_YAML_FILE} | head -n 1)
        if [[ -z "$proxy_name_to_find" ]]; then
            proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | grep -i "${type}" | head -n 1)
        fi
        local display_name=${proxy_name_to_find:-$tag}

        # 查找 IP 并处理 IPv6 括号
        local display_server=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
        # 如果 clash.yaml 里没有记录 IP (或者查不到)，使用全局变量
        if [[ -z "$display_server" || "$display_server" == "null" ]]; then display_server=${server_ip}; fi

        # 构造用于链接的 IP (IPv6 需要加括号)
        local url_ip="$display_server"
        if [[ "$url_ip" == *":"* ]] && [[ "$url_ip" != "["* ]]; then url_ip="[${url_ip}]"; fi

        echo "-------------------------------------"
        _info " 节点: ${display_name}"
        local url=""
        case "$type" in
            "vless")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid')
                local transport_type=$(echo "$node" | jq -r '.transport.type')
                if [ "$transport_type" == "ws" ]; then
                    local host_header=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .ws-opts.headers.Host' ${CLASH_YAML_FILE} | head -n 1)
                    local ws_path=$(echo "$node" | jq -r '.transport.path')
                    url="vless://${uuid}@${url_ip}:${port}?encryption=none&security=tls&type=ws&host=${host_header}&path=$(_url_encode "$ws_path")#$(_url_encode "$display_name")"
                elif [ "$(echo "$node" | jq -r '.tls.reality.enabled')" == "true" ]; then
                    local sn=$(echo "$node" | jq -r '.tls.server_name'); local flow=$(echo "$node" | jq -r '.users[0].flow')
                    local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE"); local pk=$(echo "$meta" | jq -r '.publicKey'); local sid=$(echo "$meta" | jq -r '.shortId')
                    url="vless://${uuid}@${url_ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sn}&fp=chrome&flow=${flow}&pbk=${pk}&sid=${sid}#$(_url_encode "$display_name")"
                else
                    url="vless://${uuid}@${url_ip}:${port}?type=tcp&security=none#$(_url_encode "$display_name")"
                fi
                ;;
            "trojan")
                local password=$(echo "$node" | jq -r '.users[0].password')
                local transport_type=$(echo "$node" | jq -r '.transport.type')
                if [ "$transport_type" == "ws" ]; then
                     local host_header=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .ws-opts.headers.Host' ${CLASH_YAML_FILE} | head -n 1)
                     local ws_path=$(echo "$node" | jq -r '.transport.path')
                     local sni=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                     url="trojan://$(_url_encode "$password")@${url_ip}:${port}?encryption=none&security=tls&type=ws&host=${host_header}&path=$(_url_encode "$ws_path")&sni=${sni}#$(_url_encode "$display_name")"
                else
                    _info "  类型: Trojan (TCP), 地址: $display_server, 端口: $port, 密码: [已隐藏]"
                fi
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password');
                local sn=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                [[ -z "$sn" || "$sn" == "null" ]] && sn=""
                local meta=$(jq -r --arg t "$tag" '.[$t]' "$METADATA_FILE");
                local op=$(echo "$meta" | jq -r '.obfsPassword'); local hp=$(echo "$meta" | jq -r '.ports')
                local extra_param="&insecure=1"
                [[ -n "$op" && "$op" != "null" ]] && extra_param="${extra_param}&obfs=salamander&obfs-password=${op}"
                [[ -n "$hp" && "$hp" != "null" ]] && extra_param="${extra_param}&mport=${hp}"
                url="hysteria2://${pw}@${url_ip}:${port}?sni=${sn}${extra_param}#$(_url_encode "$display_name")"
                ;;
            "tuic")
                local uuid=$(echo "$node" | jq -r '.users[0].uuid'); local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
                url="tuic://${uuid}:${pw}@${url_ip}:${port}?sni=${sn}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$display_name")"
                ;;
            "shadowsocks")
                local m=$(echo "$node" | jq -r '.method'); local pw=$(echo "$node" | jq -r '.password')
                if [[ "$m" == "2022-blake3-aes-128-gcm" ]]; then
                     url="ss://$(_url_encode "${m}:${pw}")@${url_ip}:${port}#$(_url_encode "$display_name")"
                else
                    local b64=$(echo -n "${m}:${pw}" | base64 | tr -d '\n')
                    url="ss://${b64}@${url_ip}:${port}#$(_url_encode "$display_name")"
                fi
                ;;
            "socks")
                local u=$(echo "$node" | jq -r '.users[0].username'); local p=$(echo "$node" | jq -r '.users[0].password')
                _info "  类型: SOCKS5, 地址: $display_server, 端口: $port, 用户: $u, 密码: $p"
                ;;
        esac
        [ -n "$url" ] && echo -e "  ${YELLOW}分享链接:${NC} ${url}"
    done
    echo "-------------------------------------"
}

_delete_node() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    _info "--- 节点删除 ---"
    
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local display_names=()
    
    local i=1
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') 
        local type=$(echo "$node" | jq -r '.type') 
        local port=$(echo "$node" | jq -r '.listen_port')
        
        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")

        local proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}') | .name' ${CLASH_YAML_FILE} | head -n 1)
        local display_name=${proxy_name_to_find:-$tag}
        display_names+=("$display_name")
        
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${port}"
        ((i++))
    done < <(jq -c '.inbounds[]' "$CONFIG_FILE")

    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    
    local count=${#inbound_tags[@]}
    if [ "$num" -gt "$count" ]; then _error "编号超出范围。"; return; fi

    local index=$((num - 1))
    local tag_to_del=${inbound_tags[$index]}
    local type_to_del=${inbound_types[$index]}
    local port_to_del=${inbound_ports[$index]}
    local display_name_to_del=${display_names[$index]}

    local proxy_name_to_del=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port_to_del}') | .name' ${CLASH_YAML_FILE} | head -n 1)
    
    read -p "$(echo -e ${YELLOW}"确定要删除节点 ${display_name_to_del} 吗? (y/N): "${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then return; fi
    
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[${index}])" || return
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_del\")" || return
    
    if [ -n "$proxy_name_to_del" ]; then _remove_node_from_yaml "$proxy_name_to_del"; fi

    if [ "$type_to_del" == "hysteria2" ] || [ "$type_to_del" == "tuic" ]; then
        rm -f "${SINGBOX_DIR}/${tag_to_del}.pem" "${SINGBOX_DIR}/${tag_to_del}.key"
    fi
    
    _success "节点 ${display_name_to_del} 已删除！"
    _manage_service "restart"
}

_check_config() {
    _info "正在检查 sing-box 配置文件..."
    local result=$(${SINGBOX_BIN} check -c ${CONFIG_FILE})
    if [[ $? -eq 0 ]]; then
        _success "配置文件 (${CONFIG_FILE}) 格式正确。"
    else
        _error "配置文件检查失败:"
        echo "$result"
    fi
}

_update_script() {
    _info "--- 更新此管理脚本 ---"
    _info "正在从 GitHub 下载最新脚本..."
    local temp_script_path="${SELF_SCRIPT_PATH}.tmp"
    
    if wget -qO "$temp_script_path" "$SCRIPT_UPDATE_URL"; then
        if [ ! -s "$temp_script_path" ]; then
            _error "下载失败或文件为空！请检查您的 SCRIPT_UPDATE_URL 链接。"
            rm -f "$temp_script_path"
            return 1
        fi
        chmod +x "$temp_script_path"
        mv "$temp_script_path" "$SELF_SCRIPT_PATH"
        _success "脚本更新成功！"
        echo -e "${YELLOW}bash ${SELF_SCRIPT_PATH}${NC}"
        exit 0
    else
        _error "下载失败！请检查网络或 GitHub 链接。"
        rm -f "$temp_script_path"
        return 1
    fi
}

_update_singbox_core() {
    _info "--- 更新 Sing-box 核心 ---"
    _install_sing_box
    if [ $? -eq 0 ]; then
        _success "Sing-box 核心更新成功！"
        _manage_service "restart"
        _warning "如果存在线路机服务，请手动重启它。"
    else
        _error "Sing-box 核心更新失败。"
    fi
}

_generate_relay_script() {
    _info "--- 生成 [混合模式] 中转落地脚本 (第 1/2 步) ---"
    local ss_inbounds=$(jq -c '.inbounds[] | select(.type == "shadowsocks")' "$CONFIG_FILE")
    if [ -z "$ss_inbounds" ]; then
        _error "错误：未在本机找到任何 Shadowsocks (SS) 节点。"
        return 1
    fi

    _info "请选择一个本机的 SS 节点作为“落地” (中转的出口)："
    local ss_options=()
    local i=1
    while IFS= read -r line; do
        local port=$(echo "$line" | jq -r '.listen_port')
        local method=$(echo "$line" | jq -r '.method')
        local proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}') | .name' ${CLASH_YAML_FILE} | head -n 1)
        local display_name=${proxy_name_to_find:-$tag}
        echo -e " ${CYAN}$i)${NC} ${display_name} (端口: ${port}, 方法: ${method})"
        ss_options+=("$line")
        ((i++))
    done <<< "$ss_inbounds"
    echo " 0) 返回"
    read -p "请输入选项: " choice

    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then return; fi

    local selected_json=${ss_options[$((choice-1))]}
    local INBOUND_METHOD=$(echo "$selected_json" | jq -r '.method')
    local INBOUND_PASSWORD=$(echo "$selected_json" | jq -r '.password')
    local INBOUND_PORT=$(echo "$selected_json" | jq -r '.listen_port')
    local INBOUND_IP=$server_ip
    
    _success "已选择落地节点：${INBOUND_IP}:${INBOUND_PORT} (方法: ${INBOUND_METHOD})"

    _info "--- 正在生成 [混合模式] 模板 (第 2/2 步) ---"
    local RELAY_SCRIPT_PATH="${HOME}/relay-install.sh"
    
    _generate_relay_script_hybrid "$INBOUND_IP" "$INBOUND_PORT" "$INBOUND_METHOD" "$INBOUND_PASSWORD" "$RELAY_SCRIPT_PATH"
    
    if [ $? -eq 0 ]; then
        echo ""
        _success "✅ 线路机脚本已成功生成在: ${RELAY_SCRIPT_PATH}"
        _info "请将此文件传输到“线路机”的 /root 目录并运行。"
    else
        _error "线路机脚本生成失败。"
    fi
}

_generate_relay_script_hybrid() {
    local INBOUND_IP="$1"
    local INBOUND_PORT="$2"
    local INBOUND_METHOD="$3"
    local INBOUND_PASSWORD="$4"
    local RELAY_SCRIPT_PATH="$5"

    cat > "$RELAY_SCRIPT_PATH" << 'RELAY_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail
# --- 占位符 (将被替换) ---
INBOUND_IP="__INBOUND_IP__"
INBOUND_PORT="__INBOUND_PORT__"
INBOUND_METHOD="__INBOUND_METHOD__"
INBOUND_PASSWORD="__INBOUND_PASSWORD__"
# --- 颜色 ---
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

_url_encode() { echo -n "$1" | jq -s -R -r @uri; }
export -f _url_encode

SERVICE_NAME="sing-box-relay"
CONFIG_DIR="/etc/sing-box" 
CONFIG_FILE="${CONFIG_DIR}/config.json"
LINK_FILE_VLESS="${CONFIG_DIR}/vless_links.txt"
LINK_FILE_HY2="${CONFIG_DIR}/hy2_links.txt"
LINK_FILE_TUIC="${CONFIG_DIR}/tuic_links.txt"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
PID_FILE="/run/${SERVICE_NAME}.pid"
SINGBOX_BIN="/usr/local/bin/sing-box"

_detect_init_system() {
    if [ -f "/sbin/openrc-run" ]; then echo "openrc";
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then echo "systemd";
    else echo "direct"; fi
}

action_uninstall() {
    info "正在卸载 sing-box (中转机: ${SERVICE_NAME})..."
    local INIT_SYSTEM=$(_detect_init_system)
    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop $SERVICE_NAME >/dev/null 2>&1
            systemctl disable $SERVICE_NAME >/dev/null 2>&1
            rm -f /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload
            ;;
        openrc)
            rc-service $SERVICE_NAME stop >/dev/null 2>&1
            rc-update del $SERVICE_NAME default >/dev/null 2>&1
            rm -f /etc/init.d/${SERVICE_NAME}
            ;;
        direct)
            if [ -f "$PID_FILE" ]; then kill $(cat "$PID_FILE") >/dev/null 2>&1 || true; fi
            ;;
    esac
    rm -rf "$CONFIG_DIR" 
    rm -f $LOG_FILE $PID_FILE
    info "脚本正在自删除..."
    rm -f "$0"
    exit 0
}

action_view() {
    local link_found=false
    if [ -f "$LINK_FILE_VLESS" ]; then
        link_found=true
        info "--- VLESS Reality 中转链接 ---"
        cat "$LINK_FILE_VLESS" | cut -d':' -f2-
    fi
    if [ -f "$LINK_FILE_HY2" ]; then
        link_found=true
        info "--- Hysteria2 中转链接 ---"
        cat "$LINK_FILE_HY2" | cut -d':' -f2-
    fi
    if [ -f "$LINK_FILE_TUIC" ]; then
        link_found=true
        info "--- TUICv5 中转链接 ---"
        cat "$LINK_FILE_TUIC" | cut -d':' -f2-
    fi
    if [ "$link_found" = false ]; then err "未找到任何链接文件。"; return 1; fi
}

_restart_relay_service() {
    local INIT_SYSTEM=$(_detect_init_system)
    info "正在重启服务..."
    case "$INIT_SYSTEM" in
        systemd) systemctl restart $SERVICE_NAME ;;
        openrc) rc-service $SERVICE_NAME restart ;;
        direct)
            if [ -f "$PID_FILE" ]; then kill $(cat "$PID_FILE") >/dev/null 2>&1 || true; rm -f "$PID_FILE"; fi
            nohup $SINGBOX_BIN run -c $CONFIG_FILE >> $LOG_FILE 2>&1 &
            echo $! > $PID_FILE
            ;;
    esac
    sleep 1
}

_generate_self_signed_cert() {
    openssl ecparam -genkey -name prime256v1 -out "$3" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$3" -out "$2" -subj "/CN=${1}" >/dev/null 2>&1
}

_action_add_vless() {
    info "--- 添加 VLESS+REALITY 中转 ---"
    read -p "  > 监听端口 (回车随机): " NEW_LISTEN_PORT
    [ -z "$NEW_LISTEN_PORT" ] && NEW_LISTEN_PORT=$((RANDOM % 45001 + 20000))
    read -p "  > 伪装SNI (默认 www.microsoft.com): " NEW_SNI
    [ -z "$NEW_SNI" ] && NEW_SNI="www.microsoft.com"
    local default_name="VLESS-R-${NEW_LISTEN_PORT}"
    read -p "  > 节点名称 (默认: ${default_name}): " name
    name=${name:-$default_name}

    local VLESS_TAG="vless-in-${NEW_LISTEN_PORT}"
    local SS_TAG="relay-out-${NEW_LISTEN_PORT}"
    local UUID=$($SINGBOX_BIN generate uuid)
    local REALITY_KEYS=$($SINGBOX_BIN generate reality-keypair)
    local REALITY_PK=$(echo "$REALITY_KEYS" | awk '/PrivateKey/ {print $2}')
    local REALITY_PUB=$(echo "$REALITY_KEYS" | awk '/PublicKey/ {print $2}')
    local REALITY_SID=$($SINGBOX_BIN generate rand 8 --hex)

    local new_inbound_json=$(jq -n --arg t "$VLESS_TAG" --arg p "$NEW_LISTEN_PORT" --arg u "$UUID" --arg sn "$NEW_SNI" --arg pk "$REALITY_PK" --arg sid "$REALITY_SID" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"sniff":true,"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    local new_outbound_json=$(jq -n --arg t "$SS_TAG" --arg ip "$INBOUND_IP" --arg p "$INBOUND_PORT" --arg m "$INBOUND_METHOD" --arg pw "$INBOUND_PASSWORD" \
        '{"type":"shadowsocks","tag":$t,"server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
    local new_rule_json=$(jq -n --arg it "$VLESS_TAG" --arg ot "$SS_TAG" '{ "inbound": $it, "outbound": $ot }')

    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq ".inbounds += [$new_inbound_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".outbounds |= .[0:-1] + [$new_outbound_json] + .[-1:]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$new_rule_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    _restart_relay_service
    local PUB_IP=$(curl -s4 icanhazip.com || curl -s4 ipinfo.io/ip)
    [[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"
    local VLESS_LINK="vless://$UUID@$PUB_IP:$NEW_LISTEN_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$NEW_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID#$(_url_encode "$name")"
    echo "${VLESS_TAG}:${VLESS_LINK}" >> "$LINK_FILE_VLESS"
    info "链接: ${VLESS_LINK}"
}

_action_add_hy2() {
    info "--- 添加 Hysteria2 中转 ---"
    read -p "  > 监听端口 (回车随机): " NEW_LISTEN_PORT
    [ -z "$NEW_LISTEN_PORT" ] && NEW_LISTEN_PORT=$((RANDOM % 45001 + 20000))
    read -p "  > 密码 (回车随机): " NEW_PASSWORD
    [ -z "$NEW_PASSWORD" ] && NEW_PASSWORD=$($SINGBOX_BIN generate rand 16 --hex)
    read -p "  > SNI (默认 www.microsoft.com): " NEW_SNI
    [ -z "$NEW_SNI" ] && NEW_SNI="www.microsoft.com"
    local default_name="Hy2-${NEW_LISTEN_PORT}"
    read -p "  > 节点名称 (默认: ${default_name}): " name
    name=${name:-$default_name}

    local HY2_TAG="hy2-in-${NEW_LISTEN_PORT}"
    local SS_TAG="relay-out-${NEW_LISTEN_PORT}"
    local CERT_PATH="${CONFIG_DIR}/${HY2_TAG}.pem"
    local KEY_PATH="${CONFIG_DIR}/${HY2_TAG}.key"
    _generate_self_signed_cert "$NEW_SNI" "$CERT_PATH" "$KEY_PATH"
    
    local new_inbound_json=$(jq -n --arg t "$HY2_TAG" --arg p "$NEW_LISTEN_PORT" --arg pw "$NEW_PASSWORD" --arg cert "$CERT_PATH" --arg key "$KEY_PATH" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"sniff":true,"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    local new_outbound_json=$(jq -n --arg t "$SS_TAG" --arg ip "$INBOUND_IP" --arg p "$INBOUND_PORT" --arg m "$INBOUND_METHOD" --arg pw "$INBOUND_PASSWORD" \
        '{"type":"shadowsocks","tag":$t,"server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
    local new_rule_json=$(jq -n --arg it "$HY2_TAG" --arg ot "$SS_TAG" '{ "inbound": $it, "outbound": $ot }')

    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq ".inbounds += [$new_inbound_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".outbounds |= .[0:-1] + [$new_outbound_json] + .[-1:]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$new_rule_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    _restart_relay_service
    local PUB_IP=$(curl -s4 icanhazip.com || curl -s4 ipinfo.io/ip)
    [[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"
    local HY2_LINK="hysteria2://${NEW_PASSWORD}@${PUB_IP}:${NEW_LISTEN_PORT}?sni=${NEW_SNI}&insecure=1#$(_url_encode "$name")"
    echo "${HY2_TAG}:${HY2_LINK}" >> "$LINK_FILE_HY2"
    info "链接: ${HY2_LINK}"
}

_action_add_tuic() {
    info "--- 添加 TUICv5 中转 ---"
    read -p "  > 监听端口 (回车随机): " NEW_LISTEN_PORT
    [ -z "$NEW_LISTEN_PORT" ] && NEW_LISTEN_PORT=$((RANDOM % 45001 + 20000))
    read -p "  > UUID (回车随机): " NEW_UUID
    [ -z "$NEW_UUID" ] && NEW_UUID=$($SINGBOX_BIN generate uuid)
    read -p "  > 密码 (回车随机): " NEW_PASSWORD
    [ -z "$NEW_PASSWORD" ] && NEW_PASSWORD=$($SINGBOX_BIN generate rand 16 --hex)
    read -p "  > SNI (默认 www.microsoft.com): " NEW_SNI
    [ -z "$NEW_SNI" ] && NEW_SNI="www.microsoft.com"
    local default_name="TUICv5-${NEW_LISTEN_PORT}"
    read -p "  > 节点名称 (默认: ${default_name}): " name
    name=${name:-$default_name}

    local TUIC_TAG="tuic-in-${NEW_LISTEN_PORT}"
    local SS_TAG="relay-out-${NEW_LISTEN_PORT}"
    local CERT_PATH="${CONFIG_DIR}/${TUIC_TAG}.pem"
    local KEY_PATH="${CONFIG_DIR}/${TUIC_TAG}.key"
    _generate_self_signed_cert "$NEW_SNI" "$CERT_PATH" "$KEY_PATH"
    
    local new_inbound_json=$(jq -n --arg t "$TUIC_TAG" --arg p "$NEW_LISTEN_PORT" --arg u "$NEW_UUID" --arg pw "$NEW_PASSWORD" --arg cert "$CERT_PATH" --arg key "$KEY_PATH" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"sniff":true,"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    local new_outbound_json=$(jq -n --arg t "$SS_TAG" --arg ip "$INBOUND_IP" --arg p "$INBOUND_PORT" --arg m "$INBOUND_METHOD" --arg pw "$INBOUND_PASSWORD" \
        '{"type":"shadowsocks","tag":$t,"server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
    local new_rule_json=$(jq -n --arg it "$TUIC_TAG" --arg ot "$SS_TAG" '{ "inbound": $it, "outbound": $ot }')

    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    jq ".inbounds += [$new_inbound_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".outbounds |= .[0:-1] + [$new_outbound_json] + .[-1:]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    jq ".route.rules += [$new_rule_json]" "${CONFIG_FILE}.tmp" > "${CONFIG_FILE}.tmp2" && mv "${CONFIG_FILE}.tmp2" "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    _restart_relay_service
    local PUB_IP=$(curl -s4 icanhazip.com || curl -s4 ipinfo.io/ip)
    [[ "$PUB_IP" == *":"* ]] && PUB_IP="[$PUB_IP]"
    local TUIC_LINK="tuic://${NEW_UUID}:${NEW_PASSWORD}@${PUB_IP}:${NEW_LISTEN_PORT}?sni=${NEW_SNI}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$name")"
    echo "${TUIC_TAG}:${TUIC_LINK}" >> "$LINK_FILE_TUIC"
    info "链接: ${TUIC_LINK}"
}

action_add() {
    echo "1) VLESS 2) Hysteria2 3) TUICv5"
    read -p "选择: " ch
    case "$ch" in 1) _action_add_vless;; 2) _action_add_hy2;; 3) _action_add_tuic;; esac
}

action_delete() {
    info "暂只支持通过重置脚本来删除。"
}

case "${1:-}" in
    uninstall) action_uninstall; exit 0 ;;
    view) action_view; exit 0 ;;
    add) action_add; exit 0 ;;
    delete) action_delete; exit 0 ;; 
    restart) _restart_relay_service; exit 0 ;; 
    "") ;;
    *) err "Invalid arg"; exit 1 ;;
esac

if [ "$(id -u)" != "0" ]; then err "Root required"; exit 1; fi

detect_os() {
    if [ -f /etc/os-release ]; then . /etc/os-release; case "$ID" in alpine) OS=alpine ;; debian|ubuntu) OS=debian ;; centos|rhel|fedora) OS=redhat ;; esac; fi
}
detect_os
install_deps() {
    case "$OS" in
        alpine) apk update && apk add --no-cache curl jq bash openssl ca-certificates wget ;;
        debian) apt-get update -y && apt-get install -y curl jq bash openssl ca-certificates wget ;;
        redhat) yum install -y curl jq bash openssl ca-certificates wget ;;
    esac
}
install_deps
if [ ! -f "$SINGBOX_BIN" ]; then
    arch=$(uname -m); case $arch in x86_64) a='amd64';; aarch64) a='arm64';; *) exit 1;; esac
    url=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-${a}.tar.gz\")) | .browser_download_url")
    wget -qO sb.tar.gz "$url" && tar -xzf sb.tar.gz && mv sing-box-*/sing-box $SINGBOX_BIN && rm -rf sb.tar.gz sing-box-* && chmod +x $SINGBOX_BIN
fi

mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_FILE" <<EOF
{ "log": { "level": "info", "timestamp": true }, "inbounds": [], "outbounds": [ { "type": "shadowsocks", "tag": "init-ss", "server": "$INBOUND_IP", "server_port": $INBOUND_PORT, "method": "$INBOUND_METHOD", "password": "$INBOUND_PASSWORD" }, { "type": "direct", "tag": "direct" } ], "route": { "rules": [] } }
EOF

info "正在配置初始服务..."
action_add

INIT_SYSTEM=$(_detect_init_system)
if [ "$INIT_SYSTEM" == "systemd" ]; then
    cat > /etc/systemd/system/${SERVICE_NAME}.service << SYSTEMD
[Unit]
Description=Sing-box Relay
After=network.target
[Service]
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
[Install]
WantedBy=multi-user.target
SYSTEMD
    systemctl daemon-reload && systemctl enable $SERVICE_NAME && systemctl restart $SERVICE_NAME
elif [ "$INIT_SYSTEM" == "openrc" ]; then
    cat > /etc/init.d/${SERVICE_NAME} << SVC
#!/sbin/openrc-run
name="${SERVICE_NAME}"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE}"
command_background="yes"
pidfile="${PID_FILE}"
depend() { need net; }
SVC
    chmod +x /etc/init.d/${SERVICE_NAME} && rc-update add $SERVICE_NAME default && rc-service $SERVICE_NAME restart
else
    nohup $SINGBOX_BIN run -c $CONFIG_FILE >> $LOG_FILE 2>&1 &
fi
info "安装完成。"
RELAY_TEMPLATE

    # [重要修复] 使用 ASCII 控制字符 0x01 作为分隔符，防止密码中包含特殊字符导致 sed 失败
    sed -i "s"$'\001'"__INBOUND_IP__"$'\001'"$INBOUND_IP"$'\001'"g" "$RELAY_SCRIPT_PATH"
    sed -i "s"$'\001'"__INBOUND_PORT__"$'\001'"$INBOUND_PORT"$'\001'"g" "$RELAY_SCRIPT_PATH"
    sed -i "s"$'\001'"__INBOUND_METHOD__"$'\001'"$INBOUND_METHOD"$'\001'"g" "$RELAY_SCRIPT_PATH"
    sed -i "s"$'\001'"__INBOUND_PASSWORD__"$'\001'"$INBOUND_PASSWORD"$'\001'"g" "$RELAY_SCRIPT_PATH"

    return 0
}

_manage_relay_installation() {
    _info "--- 线路机脚本管理 (请在线路机上运行) ---"
    local relay_script="${HOME}/relay-install.sh"
    if [ -f "/root/relay-install.sh" ]; then relay_script="/root/relay-install.sh"; fi

    if [ ! -f "$relay_script" ]; then
        _error "错误：未找到 [relay-install.sh] 脚本。"
        _info "请先生成脚本并上传到本机。"
        return 1
    fi

    chmod +x "$relay_script"

    while true; do
        clear
        echo "===================================================="
        _info "      线路机 (中转机) 快捷管理"
        echo "===================================================="
        echo "  1) 安装 / 重置"
        echo "  2) 添加新中转路由"
        echo "  3) 查看所有链接"
        echo "  4) 重启服务"
        echo "  5) 卸载"
        echo "  0) 返回"
        read -p "选择: " choice
        case $choice in
            1) bash "${relay_script}"; break ;;
            2) bash "${relay_script}" add; break ;;
            3) bash "${relay_script}" view; break ;;
            4) bash "${relay_script}" restart; break ;;
            5) bash "${relay_script}" uninstall; break ;;
            0) return ;;
            *) ;;
        esac
    done
}

_main_menu() {
    while true; do
        clear
        echo "===================================================="
        _info "      sing-box 全功能管理脚本 v${SCRIPT_VERSION}"
        echo "===================================================="
        _info "【节点管理】"
        echo "  1) 添加节点"
        echo "  2) 查看节点分享链接"
        echo "  3) 删除节点"
        echo "----------------------------------------------------"
        _info "【服务控制】"
        echo "  4. 重启 sing-box"
        echo "  5) 停止 sing-box"
        echo "  6) 查看 sing-box 运行状态"
        echo "  7) 查看 sing-box 实时日志"
        echo "----------------------------------------------------"
        _info "【脚本与配置】"
        echo "  8) 检查配置文件"
        echo -e "  9) ${GREEN}生成 [混合模式] 中转脚本${NC} (在“落地机”运行)"
        echo -e " 10) ${CYAN}管理 [混合模式] 中转脚本${NC} (在“线路机”运行)"
        echo "----------------------------------------------------"
        _info "【更新与卸载】"
        echo -e " 11) ${GREEN}更新脚本${NC}"
        echo -e " 12) ${GREEN}更新 Sing-box 核心${NC}"
        echo -e " 13) ${RED}卸载 sing-box 及脚本${NC}"
        echo "----------------------------------------------------"
        echo "  0) 退出脚本"
        echo "===================================================="
        read -p "请输入选项 [0-13]: " choice

        case $choice in
            1) _show_add_node_menu ;;
            2) _view_nodes ;;
            3) _delete_node ;;
            4) _manage_service "restart" ;;
            5) _manage_service "stop" ;;
            6) _manage_service "status" ;;
            7) _view_log ;;
            8) _check_config ;;
            9) _generate_relay_script ;; 
            10) _manage_relay_installation ;;
            11) _update_script ;;
            12) _update_singbox_core ;;
            13) _uninstall ;; 
            0) exit 0 ;;
            *) _error "无效输入，请重试。" ;;
        esac
        echo
        read -n 1 -s -r -p "按任意键返回主菜单..."
    done
}

_show_add_node_menu() {
    local needs_restart=false
    local action_result
    clear
    echo "========================================"
    _info "           sing-box 添加节点"
    echo "========================================"
    echo " 1) VLESS (Vision+REALITY)"
    echo " 2) VLESS (WebSocket+TLS)"
    echo " 3) Trojan (WebSocket+TLS)"
    echo " 4) VLESS (TCP)"
    echo " 5) Hysteria2"
    echo " 6) TUICv5"
    echo " 7) Shadowsocks"
    echo " 8) SOCKS5"
    echo "----------------------------------------"
    echo " 0) 返回主菜单"
    echo "========================================"
    read -p "请输入选项 [0-8]: " choice

    case $choice in
        1) _add_vless_reality; action_result=$? ;;
        2) _add_vless_ws_tls; action_result=$? ;;
		3) _add_trojan_ws_tls; action_result=$? ;;
        4) _add_vless_tcp; action_result=$? ;;
        5) _add_hysteria2; action_result=$? ;;
        6) _add_tuic; action_result=$? ;;
        7) _add_shadowsocks_menu; action_result=$? ;;
        8) _add_socks; action_result=$? ;;
        0) return ;;
        *) _error "无效输入，请重试。" ;;
    esac

    if [ "$action_result" -eq 0 ]; then
        _info "配置已更新"
        _manage_service "restart"
    fi
}

main() {
    _check_root
    _detect_init_system
    _install_dependencies

    local first_install=false
    if [ ! -f "${SINGBOX_BIN}" ]; then
        _info "检测到 sing-box 未安装..."
        _install_sing_box
        first_install=true
    fi
    
    if [ ! -f "${CONFIG_FILE}" ] || [ ! -f "${CLASH_YAML_FILE}" ]; then
         _info "检测到主配置文件缺失，正在初始化..."
         _initialize_config_files
    fi

	_create_service_files
	
    if [ "$first_install" = true ]; then
        _info "首次安装完成！正在启动 sing-box (主服务)..."
        _manage_service "start"
    fi
    
    _get_public_ip
    _main_menu
}

main
