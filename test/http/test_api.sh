#!/bin/bash

# HTTP API测试脚本
# 此脚本通过直接调用HTTP API端点来测试API功能

set -e  # 任何命令失败都会导致脚本退出

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 测试计数器
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 配置
API_HOST=${TEST_API_HOST:-"http://localhost:8080"}
AUTH_ENABLED=${TEST_AUTH_ENABLED:-"false"}
AUTH_TOKEN=""

# 测试函数
function test_endpoint {
    NAME=$1
    METHOD=$2
    ENDPOINT=$3
    PAYLOAD=$4
    EXPECTED_CODE=${5:-200}
    EXPECTED_CONTENT=$6
    
    echo -e "${BLUE}[测试]${NC} $NAME"
    echo -e "  $METHOD $ENDPOINT"
    
    # 添加身份验证头（如果启用）
    AUTH_HEADER=""
    if [[ "$AUTH_ENABLED" == "true" && -n "$AUTH_TOKEN" ]]; then
        AUTH_HEADER="-H \"Authorization: Bearer $AUTH_TOKEN\""
    fi
    
    # 准备命令
    if [[ "$METHOD" == "GET" ]]; then
        CMD="curl -s -o response.json -w \"%{http_code}\" ${AUTH_HEADER} \"${API_HOST}${ENDPOINT}\""
    elif [[ "$PAYLOAD" == "" ]]; then
        CMD="curl -s -o response.json -w \"%{http_code}\" -X ${METHOD} ${AUTH_HEADER} \"${API_HOST}${ENDPOINT}\""
    else
        CMD="curl -s -o response.json -w \"%{http_code}\" -X ${METHOD} ${AUTH_HEADER} -H \"Content-Type: application/json\" -d '${PAYLOAD}' \"${API_HOST}${ENDPOINT}\""
    fi
    
    # 执行测试
    STATUS_CODE=$(eval $CMD)
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # 检查状态码
    if [[ "$STATUS_CODE" -eq "$EXPECTED_CODE" ]]; then
        echo -e "  ${GREEN}[通过]${NC} 状态码: $STATUS_CODE (期望: $EXPECTED_CODE)"
        STATUS_PASS=true
    else
        echo -e "  ${RED}[失败]${NC} 状态码: $STATUS_CODE (期望: $EXPECTED_CODE)"
        STATUS_PASS=false
    fi
    
    # 检查响应内容（如果指定）
    CONTENT_PASS=true
    if [[ -n "$EXPECTED_CONTENT" ]]; then
        RESPONSE=$(cat response.json)
        if grep -q "$EXPECTED_CONTENT" response.json; then
            echo -e "  ${GREEN}[通过]${NC} 响应包含预期内容: \"$EXPECTED_CONTENT\""
        else
            echo -e "  ${RED}[失败]${NC} 响应不包含预期内容: \"$EXPECTED_CONTENT\""
            echo -e "  实际响应: $RESPONSE"
            CONTENT_PASS=false
        fi
    fi
    
    # 总体测试结果
    if [[ "$STATUS_PASS" == "true" && "$CONTENT_PASS" == "true" ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
}

# 获取认证令牌
function authenticate {
    echo -e "${YELLOW}[认证]${NC} 获取认证令牌..."
    
    LOGIN_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"admin123"}' \
        ${API_HOST}/api/auth/login)
    
    # 从响应中提取令牌
    AUTH_TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)
    
    if [[ -n "$AUTH_TOKEN" ]]; then
        echo -e "${GREEN}[成功]${NC} 已获取认证令牌"
    else
        echo -e "${RED}[失败]${NC} 获取认证令牌失败，响应: $LOGIN_RESPONSE"
        echo -e "${YELLOW}[警告]${NC} 继续测试，但认证相关测试可能会失败"
    fi
    
    echo ""
}

# 开始测试
echo -e "${GREEN}===== HTTP API 测试 =====${NC}"
echo "API 终端: $API_HOST"
echo "认证状态: ${AUTH_ENABLED}"
echo ""

# 如果启用认证，获取令牌
if [[ "$AUTH_ENABLED" == "true" ]]; then
    authenticate
fi

# 1. 系统状态测试
test_endpoint "系统状态" "GET" "/api/system/status" "" 200 "status"

# 2. 创建扫描任务
SCAN_TASK_PAYLOAD='{"target":"example.com","ports":"1-100","scan_type":"tcp","timeout":5,"workers":10,"output_format":"json"}'
test_endpoint "创建扫描任务" "POST" "/api/tasks" "$SCAN_TASK_PAYLOAD" 202 "task_id"

# 提取任务ID用于后续测试
TASK_ID=$(grep -o '"task_id":"[^"]*' response.json | cut -d'"' -f4)
if [[ -n "$TASK_ID" ]]; then
    echo -e "${GREEN}[信息]${NC} 已创建任务ID: $TASK_ID"
else
    echo -e "${RED}[错误]${NC} 无法获取任务ID，后续任务相关测试可能会失败"
fi

# 3. 任务列表测试
test_endpoint "获取任务列表" "GET" "/api/tasks" "" 200 "tasks"

# 4. 获取特定任务
if [[ -n "$TASK_ID" ]]; then
    test_endpoint "获取特定任务" "GET" "/api/tasks/$TASK_ID" "" 200 "status"
fi

# 5. 错误测试 - 无效的任务ID
test_endpoint "获取无效任务ID" "GET" "/api/tasks/invalid-id" "" 404 "找不到任务"

# 6. 无效请求测试
INVALID_PAYLOAD='{"ports":"1-100","scan_type":"tcp"}'  # 缺少target字段
test_endpoint "无效请求参数" "POST" "/api/tasks" "$INVALID_PAYLOAD" 400 "目标不能为空"

# 7. 取消任务
if [[ -n "$TASK_ID" ]]; then
    test_endpoint "取消任务" "DELETE" "/api/tasks/$TASK_ID" "" 200 "cancelled"
fi

# 8. 获取系统指标
test_endpoint "系统指标" "GET" "/api/system/metrics" "" 200 ""

# 打印测试摘要
echo ""
echo -e "${GREEN}===== 测试摘要 =====${NC}"
echo -e "总测试数: $TOTAL_TESTS"
echo -e "通过: ${GREEN}$PASSED_TESTS${NC}"
echo -e "失败: ${RED}$FAILED_TESTS${NC}"

# 设置退出代码
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！${NC}"
    exit 0
else
    echo -e "${RED}有测试失败！${NC}"
    exit 1
fi 