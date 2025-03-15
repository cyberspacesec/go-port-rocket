#!/bin/bash
set -e

# ANSI Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo " _____         ______           _     ______            _        _   "
echo "|  __ \       |  ____|         | |   |  ____|          | |      | |  "
echo "| |  \/ ___   | |__   ___  _ __| |_  | |__   ___   ___ | | _____| |_ "
echo "| | __ / _ \  |  __| / _ \| '__| __| |  __| / _ \ / __|| |/ / _ \ __|"
echo "| |_\ \ (_) | | |___| (_) | |  | |_  | |___| (_) | (__ |   <  __/ |_ "
echo " \____/\___/  |______\___/|_|   \__| |______\___/ \___||_|\_\___|\__|"
echo "--------------------------------------------------------"
echo -e "${NC}"
echo -e "${GREEN}Go Port Rocket Docker 构建助手${NC}"
echo ""

# 默认镜像名称
DEFAULT_IMAGE_NAME="go-port-rocket"
# 默认标签
DEFAULT_TAG="latest"

# 解析命令行参数
IMAGE_NAME=$DEFAULT_IMAGE_NAME
TAG=$DEFAULT_TAG
USE_PROXY=false
PROXY_SERVER=""
BUILD_ARGS=""

# 显示帮助
function show_help {
    echo -e "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help             显示此帮助信息"
    echo "  -i, --image NAME       指定镜像名称 (默认: go-port-rocket)"
    echo "  -t, --tag TAG          指定镜像标签 (默认: latest)"
    echo "  -p, --proxy SERVER     使用代理服务器 (例如: http://127.0.0.1:7890)"
    echo "  -a, --arg KEY=VALUE    添加自定义构建参数"
    echo "  --no-cache             不使用缓存构建镜像"
    echo ""
    echo "示例:"
    echo "  $0 --image my-rocket --tag v1.0.0"
    echo "  $0 --proxy http://127.0.0.1:7890"
    echo ""
}

# 解析命令行参数
NO_CACHE=""
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) show_help; exit 0 ;;
        -i|--image) IMAGE_NAME="$2"; shift ;;
        -t|--tag) TAG="$2"; shift ;;
        -p|--proxy) USE_PROXY=true; PROXY_SERVER="$2"; shift ;;
        -a|--arg) BUILD_ARGS="$BUILD_ARGS --build-arg $2"; shift ;;
        --no-cache) NO_CACHE="--no-cache" ;;
        *) echo "未知的参数: $1"; show_help; exit 1 ;;
    esac
    shift
done

# 检查Docker是否已安装
echo -e "${BLUE}[1/4]${NC} 检查Docker安装状态..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}错误:${NC} Docker未安装。请先安装Docker。"
    echo "安装指南: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker已安装!"

# 检查Docker服务是否运行
echo -e "${BLUE}[2/4]${NC} 检查Docker服务状态..."
if ! docker info &> /dev/null; then
    echo -e "${RED}错误:${NC} Docker服务未运行。"
    
    # 根据不同操作系统提供启动Docker的指南
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

# 检查网络连接
echo -e "${BLUE}[3/4]${NC} 检查网络连接..."
if ! ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
    echo -e "${YELLOW}警告:${NC} 网络连接可能存在问题。"
    echo -e "${YELLOW}提示:${NC} 您可能需要使用代理来构建Docker镜像。"
    echo -e "       可以使用 ${GREEN}-p${NC} 或 ${GREEN}--proxy${NC} 参数指定代理服务器。"
    
    # 如果没有指定代理，询问是否继续
    if [ "$USE_PROXY" = false ]; then
        echo ""
        read -p "是否继续构建? (y/n): " CONTINUE
        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            echo "构建已取消。"
            exit 0
        fi
    fi
fi

# 设置代理
if [ "$USE_PROXY" = true ]; then
    echo -e "${BLUE}[信息]${NC} 使用代理服务器: $PROXY_SERVER"
    export https_proxy=$PROXY_SERVER
    export http_proxy=$PROXY_SERVER
    export all_proxy=$PROXY_SERVER
fi

# 开始构建
echo -e "${BLUE}[4/4]${NC} 开始构建Docker镜像 ${GREEN}${IMAGE_NAME}:${TAG}${NC}..."
echo ""

# 构建命令
BUILD_CMD="docker build $NO_CACHE $BUILD_ARGS -t ${IMAGE_NAME}:${TAG} ."
echo -e "${YELLOW}执行命令:${NC} $BUILD_CMD"
echo ""

# 执行构建并捕获输出和错误码
echo -e "${BLUE}[构建日志]${NC}"
echo "-------------------------"
if $BUILD_CMD; then
    echo "-------------------------"
    echo -e "${GREEN}✓ 构建成功!${NC} 镜像 ${IMAGE_NAME}:${TAG} 已创建。"
    echo ""
    echo -e "您可以使用以下命令运行容器:"
    echo -e "${YELLOW}docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN ${IMAGE_NAME}:${TAG} --help${NC}"
    echo ""
    echo -e "执行端口扫描 (需要网络权限):"
    echo -e "${YELLOW}docker run --rm --network host --cap-add=NET_RAW --cap-add=NET_ADMIN ${IMAGE_NAME}:${TAG} scan -t 127.0.0.1 -p 80,443${NC}"
    echo ""
    exit 0
else
    BUILD_EXIT_CODE=$?
    echo "-------------------------"
    echo -e "${RED}✗ 构建失败${NC} (错误码: $BUILD_EXIT_CODE)"
    echo ""
    
    # 提供常见错误的解决方案
    case $BUILD_EXIT_CODE in
        125)
            echo -e "${YELLOW}可能原因:${NC} Docker守护进程错误。请尝试重启Docker服务。"
            ;;
        *)
            # 检查是否是网络相关的常见错误
            if grep -q "failed to fetch|connection refused|network error|timeout|could not resolve|TLS handshake timeout" <<< "$BUILD_CMD 2>&1"; then
                echo -e "${YELLOW}可能原因:${NC} 网络连接问题。"
                echo -e "${YELLOW}解决方案:${NC}"
                echo "  1. 检查您的网络连接"
                echo "  2. 尝试使用代理构建:"
                echo "     $0 --proxy http://127.0.0.1:7890"
                echo "  3. 如果使用公司网络，请确认防火墙设置"
                echo "  4. 尝试使用--no-cache选项重新构建"
            else
                echo -e "${YELLOW}解决方案:${NC}"
                echo "  1. 检查Dockerfile是否有语法错误"
                echo "  2. 确保您有足够的磁盘空间"
                echo "  3. 尝试使用--no-cache选项重新构建"
                echo "  4. 查看上面的错误日志以获取具体问题"
            fi
            ;;
    esac
    
    exit $BUILD_EXIT_CODE
fi 