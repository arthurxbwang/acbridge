#!/bin/bash

# acbridge - 一键安装与更新脚本
# 适用系统: Debian, Ubuntu, CentOS, RHEL, Rocky Linux 等

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

echo -e "${BLUE}==================================================${PLAIN}"
echo -e "${GREEN}      acbridge (AllinSSL Caddy Bridge) 安装脚本      ${PLAIN}"
echo -e "${BLUE}==================================================${PLAIN}"

# 必须以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}错误：必须以 root 权限运行此脚本。请使用 sudo 或切换至 root 用户。${PLAIN}"
    exit 1
fi

# 1. 交互式配置输入

# 1.1 安装位置
read -p "请输入安装目录 [默认: /opt/acbridge]: " INSTALL_DIR < /dev/tty
INSTALL_DIR=${INSTALL_DIR:-/opt/acbridge}

# 1.2 服务运行端口
read -p "请输入 acbridge 监听端口 [默认: 9443]: " PORT < /dev/tty
PORT=${PORT:-9443}

# 1.3 Caddy Admin API 地址
read -p "请输入 Caddy Admin API 地址 [默认: http://127.0.0.1:2019]: " CADDY_URL < /dev/tty
CADDY_URL=${CADDY_URL:-http://127.0.0.1:2019}

# 1.4 API Token
DEFAULT_TOKEN=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
read -p "请输入 API 验证 Token (回车将随机生成) [默认: $DEFAULT_TOKEN]: " TOKEN < /dev/tty
TOKEN=${TOKEN:-$DEFAULT_TOKEN}

# 1.5 同步频率
read -p "请输入与 Caddy 的同步检查频率 (秒) [默认: 30]: " SYNC_INTERVAL < /dev/tty
SYNC_INTERVAL=${SYNC_INTERVAL:-30}

echo -e "\n${YELLOW}=== 确认安装配置 ===${PLAIN}"
echo -e "安装目录: ${GREEN}${INSTALL_DIR}${PLAIN}"
echo -e "服务端口: ${GREEN}${PORT}${PLAIN}"
echo -e "Caddy API: ${GREEN}${CADDY_URL}${PLAIN}"
echo -e "安全 Token: ${GREEN}${TOKEN}${PLAIN}"
echo -e "同步频率: ${GREEN}${SYNC_INTERVAL} 秒${PLAIN}"
echo -e "${YELLOW}====================${PLAIN}"
read -p "确认无误？按回车键继续，按 Ctrl+C 退出..." < /dev/tty

# 2. 检查与安装系统依赖
echo -e "\n${BLUE}[1/5] 检查系统依赖...${PLAIN}"

# 检测包管理器
if command -v apt-get >/dev/null 2>&1; then
    PM="apt"
elif command -v yum >/dev/null 2>&1; then
    PM="yum"
else
    echo -e "${RED}未找到支持的包管理器 (apt/yum)。请手动安装 git 和 golang。${PLAIN}"
    exit 1
fi

# 检查 git
if ! command -v git >/dev/null 2>&1; then
    echo -e "${YELLOW}未检测到 git，正在为您安装...${PLAIN}"
    if [ "$PM" = "apt" ]; then
        apt-get update && apt-get install -y git
    else
        yum install -y git
    fi
fi

# 检查 golang
if ! command -v go >/dev/null 2>&1; then
    echo -e "${YELLOW}未检测到 Go 语言环境，正在为您安装最新版...${PLAIN}"
    if [ "$PM" = "apt" ]; then
        apt-get update && apt-get install -y golang-go
    else
        yum install -y golang
    fi
    # 再次检查
    if ! command -v go >/dev/null 2>&1; then
        echo -e "${RED}错误：Go 语言环境安装失败，请手动安装后重试。${PLAIN}"
        exit 1
    fi
fi

echo -e "Go 编译器版本: ${GREEN}$(go version)${PLAIN}"

# 3. 拉取最新的代码并编译
echo -e "\n${BLUE}[2/5] 从 GitHub 拉取代码并编译...${PLAIN}"

BUILD_DIR="/tmp/acbridge_build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 优先通过 HTTPS 克隆
REPO_URL="https://github.com/arthurxbwang/acbridge.git"
echo -e "克隆仓库: ${REPO_URL}"
git clone --depth=1 "$REPO_URL" "$BUILD_DIR"

if [ $? -ne 0 ]; then
    echo -e "${RED}错误：代码克隆失败，请检查网络连接是否可访问 GitHub。${PLAIN}"
    rm -rf "$BUILD_DIR"
    exit 1
fi

# 编译
cd "$BUILD_DIR" || exit 1
echo -e "开始编译 Go 二进制程序..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o acbridge

if [ $? -ne 0 ]; then
    echo -e "${RED}错误：代码编译失败。${PLAIN}"
    rm -rf "$BUILD_DIR"
    exit 1
fi

# 4. 安装文件到目标位置
echo -e "\n${BLUE}[3/5] 安装程序到目标路径...${PLAIN}"

# 创建目标目录
mkdir -p "$INSTALL_DIR"
mkdir -p "/var/lib/acbridge/certs"

# 复制编译好的二进制文件
mv "$BUILD_DIR/acbridge" "$INSTALL_DIR/acbridge"
chmod +x "$INSTALL_DIR/acbridge"

# 清理临时编译目录
rm -rf "$BUILD_DIR"

echo -e "二进制已成功安装至: ${GREEN}$INSTALL_DIR/acbridge${PLAIN}"

# 5. 配置 Systemd 服务
echo -e "\n${BLUE}[4/5] 配置 Systemd 服务...${PLAIN}"

SERVICE_FILE="/etc/systemd/system/acbridge.service"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=acbridge - AllinSSL to Caddy SSL Bridge
After=network.target caddy.service
Wants=caddy.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/acbridge -addr :$PORT -token $TOKEN -caddy $CADDY_URL -cert-dir /var/lib/acbridge/certs -sync-interval $SYNC_INTERVAL
Restart=always
RestartSec=5

# 安全限制
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# 6. 启动服务并设置自启
echo -e "\n${BLUE}[5/5] 启动服务并启用开机自启...${PLAIN}"
systemctl daemon-reload
systemctl enable acbridge
systemctl restart acbridge

# 确认服务运行状态
sleep 2
if systemctl is-active --quiet acbridge; then
    echo -e "\n${GREEN}==================================================${PLAIN}"
    echo -e "${GREEN}🎉 acbridge 安装及启动成功！${PLAIN}"
    echo -e "=================================================="
    echo -e "1. 接口地址   : ${BLUE}https://<服务器IP>:$PORT${PLAIN}"
    echo -e "2. 验证 Token : ${GREEN}$TOKEN${PLAIN}"
    echo -e "3. 证书备份目录: ${BLUE}/var/lib/acbridge/certs${PLAIN}"
    echo -e "4. Caddy API  : ${BLUE}$CADDY_URL${PLAIN}"
    echo -e "5. 运行状态   : ${GREEN}运行中 (Active)${PLAIN}"
    echo -e "--------------------------------------------------"
    echo -e "【AllinSSL 配置提示】"
    echo -e "请在 AllinSSL 的“授权 API”中添加 “雷池 (SafeLine)” WAF 实例："
    echo -e "  - 访问地址: https://<服务器IP>:$PORT"
    echo -e "  - API Token: $TOKEN"
    echo -e "--------------------------------------------------"
    echo -e "【管理命令】"
    echo -e "  - 查看服务状态: ${YELLOW}systemctl status acbridge${PLAIN}"
    echo -e "  - 查看实时日志: ${YELLOW}journalctl -u acbridge -f${PLAIN}"
    echo -e "  - 重启服务    : ${YELLOW}systemctl restart acbridge${PLAIN}"
    echo -e "${GREEN}==================================================${PLAIN}"
else
    echo -e "\n${RED}⚠️ 警告：acbridge 服务已安装但未能正常启动。${PLAIN}"
    echo -e "请运行 ${YELLOW}journalctl -u acbridge -n 50 --no-pager${PLAIN} 查看错误日志。"
fi
