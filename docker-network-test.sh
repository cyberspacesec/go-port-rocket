#!/bin/bash
set -e

# ANSI Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo " _____         ______           _     ______            _        _   "
echo "|  __ \       |  ____|         | |   |  ____|          | |      | |  "
echo "| |  \/ ___   | |__   ___  _ __| |_  | |__   ___   ___ | | _____| |_ "
echo "| | __ / _ \  |  __| / _ \| '__| __| |  __| / _ \ / __|| |/ / _ \ __|"
echo "| |_\ \ (_) | | |___| (_) | |  | |_  | |___| (_) | (__ |   <  __/ |_ "
echo " \____/\___/  |______\___/|_|   \__| |______\___/ \___||_|\_\___|\__|"
echo "--------------------------------------------------------"
echo -e "${NC}"
echo -e "${GREEN}Docker 网络诊断工具${NC}"
echo ""

# 检查命令行参数
USE_PROXY=false
PROXY_SERVER=""

# 显示帮助
function show_help {
    echo -e "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help             显示此帮助信息"
    echo "  -p, --proxy SERVER     测试时使用代理服务器 (例如: http://127.0.0.1:7890)"
    echo ""
    echo "示例:"
    echo "  $0"
    echo "  $0 --proxy http://127.0.0.1:7890"
    echo ""
}

# 解析命令行参数
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) show_help; exit 0 ;;
        -p|--proxy) USE_PROXY=true; PROXY_SERVER="$2"; shift ;;
        *) echo "未知的参数: $1"; show_help; exit 1 ;;
    esac
    shift
done

# 检查Docker是否已安装
echo -e "${BLUE}[1/5]${NC} 检查Docker安装状态..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}错误:${NC} Docker未安装。请先安装Docker。"
    echo "安装指南: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker已安装!"

# 检查Docker服务是否运行
echo -e "${BLUE}[2/5]${NC} 检查Docker服务状态..."
if ! docker info &> /dev/null; then
    echo -e "${RED}错误:${NC} Docker服务未运行。"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo -e "${YELLOW}提示:${NC} 请尝试执行以下命令启动Docker服务:"
        echo "  sudo systemctl start docker"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${YELLOW}提示:${NC} 请启动Docker Desktop应用程序"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        echo -e "${YELLOW}提示:${NC} 请启动Docker Desktop应用程序"
    fi
    
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker服务正在运行!"

# 设置代理
if [ "$USE_PROXY" = true ]; then
    echo -e "${BLUE}[信息]${NC} 使用代理服务器: $PROXY_SERVER"
    export https_proxy=$PROXY_SERVER
    export http_proxy=$PROXY_SERVER
    export all_proxy=$PROXY_SERVER
fi

# 测试基本网络连接
echo -e "${BLUE}[3/5]${NC} 测试基本网络连接..."
if ping -c 3 -W 5 8.8.8.8 &> /dev/null; then
    echo -e "${GREEN}✓${NC} 基本网络连接正常!"
else
    echo -e "${RED}✗${NC} 基本网络连接失败。"
    echo -e "${YELLOW}提示:${NC} 请检查您的网络连接或尝试使用代理。"
    if [ "$USE_PROXY" = false ]; then
        echo "       可以使用 -p 参数指定代理服务器重新测试。"
    fi
fi

# 测试DNS解析
echo -e "${BLUE}[4/5]${NC} 测试DNS解析..."
if host -W 5 google.com &> /dev/null || nslookup google.com &> /dev/null; then
    echo -e "${GREEN}✓${NC} DNS解析正常!"
else
    echo -e "${RED}✗${NC} DNS解析失败。"
    echo -e "${YELLOW}提示:${NC} 可能存在DNS问题。请检查您的DNS设置。"
    echo "       您可以尝试在/etc/docker/daemon.json中配置DNS:"
    echo '       {"dns": ["8.8.8.8", "8.8.4.4"]}'
    echo "       然后重启Docker服务。"
fi

# 测试Docker Hub连接
echo -e "${BLUE}[5/5]${NC} 测试连接到Docker Hub..."
if docker pull hello-world:latest &> /dev/null; then
    echo -e "${GREEN}✓${NC} 成功连接到Docker Hub并拉取测试镜像!"
    docker rmi hello-world:latest &> /dev/null
else
    echo -e "${RED}✗${NC} 无法连接到Docker Hub或拉取镜像。"
    echo -e "${YELLOW}可能原因和解决方案:${NC}"
    echo "  1. 网络连接问题：检查您的网络设置和防火墙规则"
    echo "  2. 代理设置问题：如果您在代理环境中，请确保正确配置Docker的代理设置"
    echo "     - 创建或编辑 ~/.docker/config.json:"
    echo '     {"proxies":{"default":{"httpProxy":"http://proxy:port","httpsProxy":"http://proxy:port","noProxy":"localhost,127.0.0.1"}}}'
    echo "  3. Docker配置问题：尝试重启Docker服务"
    echo "  4. 镜像仓库问题：尝试使用其他镜像源，如阿里云镜像"
    echo "     - 创建或编辑 /etc/docker/daemon.json:"
    echo '     {"registry-mirrors": ["https://registry.cn-hangzhou.aliyuncs.com"]}'
    echo "     然后重启Docker服务"
fi

echo ""
echo -e "${BLUE}诊断完成!${NC}"
echo ""
echo "如果您仍然遇到Docker网络问题，请尝试以下解决方案："
echo -e "${YELLOW}1. 使用代理构建或拉取镜像${NC}"
echo "   ./build-docker.sh --proxy http://your-proxy:port"
echo -e "${YELLOW}2. 配置Docker使用固定DNS${NC}"
echo "   在/etc/docker/daemon.json中添加: {\"dns\": [\"8.8.8.8\", \"8.8.4.4\"]}"
echo -e "${YELLOW}3. 使用国内镜像源${NC}"
echo "   在/etc/docker/daemon.json中添加: {\"registry-mirrors\": [\"https://registry.cn-hangzhou.aliyuncs.com\"]}"
echo -e "${YELLOW}4. 检查防火墙设置${NC}"
echo "   确保Docker网络未被防火墙阻止"
echo ""
echo "修改配置后，记得重启Docker服务以应用更改。" 