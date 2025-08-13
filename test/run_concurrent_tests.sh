#!/bin/bash

# 并发测试运行脚本
# 用于测试 go-port-rocket 的并发扫描稳定性

set -e

echo "🚀 Go Port Rocket 并发测试套件"
echo "================================"

# 检查是否在正确的目录
if [ ! -f "go.mod" ]; then
    echo "❌ 错误: 请在项目根目录运行此脚本"
    exit 1
fi

# 创建测试结果目录
TEST_RESULTS_DIR="test_results"
mkdir -p "$TEST_RESULTS_DIR"

# 获取当前时间戳
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$TEST_RESULTS_DIR/concurrent_test_$TIMESTAMP.log"

echo "📝 测试日志将保存到: $LOG_FILE"
echo ""

# 函数：运行测试并记录结果
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo "🧪 运行测试: $test_name"
    echo "命令: $test_command"
    echo "开始时间: $(date)"
    echo "----------------------------------------"
    
    # 运行测试并同时输出到控制台和日志文件
    if eval "$test_command" 2>&1 | tee -a "$LOG_FILE"; then
        echo "✅ $test_name 通过"
    else
        echo "❌ $test_name 失败"
        return 1
    fi
    
    echo "结束时间: $(date)"
    echo ""
}

# 函数：检查系统资源
check_system_resources() {
    echo "🔍 检查系统资源"
    echo "----------------------------------------"
    
    # 检查可用内存
    if command -v free >/dev/null 2>&1; then
        echo "内存使用情况:"
        free -h
    elif command -v vm_stat >/dev/null 2>&1; then
        echo "内存使用情况 (macOS):"
        vm_stat
    fi
    
    # 检查文件描述符限制
    echo ""
    echo "文件描述符限制:"
    ulimit -n
    
    # 检查CPU核心数
    echo ""
    echo "CPU核心数:"
    if command -v nproc >/dev/null 2>&1; then
        nproc
    elif command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.ncpu
    fi
    
    echo ""
}

# 函数：监控资源使用
monitor_resources() {
    local duration="$1"
    local output_file="$2"
    
    echo "📊 开始监控资源使用 (持续 $duration 秒)"
    
    for i in $(seq 1 "$duration"); do
        {
            echo "时间: $(date)"
            echo "内存使用:"
            if command -v free >/dev/null 2>&1; then
                free -m | grep Mem
            elif command -v vm_stat >/dev/null 2>&1; then
                vm_stat | head -5
            fi
            echo "进程数:"
            ps aux | grep go-port-rocket | wc -l
            echo "文件描述符使用:"
            lsof | grep go-port-rocket | wc -l 2>/dev/null || echo "无法获取"
            echo "----------------------------------------"
        } >> "$output_file"
        sleep 1
    done
}

# 主测试流程
main() {
    echo "开始时间: $(date)" | tee "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # 检查系统资源
    check_system_resources | tee -a "$LOG_FILE"
    
    # 构建项目
    echo "🔨 构建项目"
    echo "----------------------------------------"
    if go build -o go-port-rocket . 2>&1 | tee -a "$LOG_FILE"; then
        echo "✅ 构建成功"
    else
        echo "❌ 构建失败"
        exit 1
    fi
    echo ""
    
    # 运行基础功能测试
    echo "🧪 运行基础功能测试"
    run_test "基础扫描测试" "go test -v ./pkg/scanner -run TestBasicScan -timeout 30s" || true
    
    # 运行并发测试
    echo "🔥 运行并发测试"
    run_test "100个并发扫描测试" "go test -v ./test -run TestConcurrent100Scans -timeout 5m" || true
    
    # 运行资源管理测试
    echo "🛡️ 运行资源管理测试"
    run_test "资源管理测试" "go test -v ./test -run TestResourceManagement -timeout 2m" || true
    
    # 运行内存泄漏测试
    echo "🔍 运行内存泄漏测试"
    run_test "内存泄漏检测" "go test -v ./test -run TestMemoryLeaks -timeout 3m" || true
    
    # 运行压力测试
    echo "💪 运行压力测试"
    MONITOR_FILE="$TEST_RESULTS_DIR/resource_monitor_$TIMESTAMP.log"
    monitor_resources 120 "$MONITOR_FILE" &
    MONITOR_PID=$!
    
    run_test "压力测试" "go test -v ./test -run TestStress100ConcurrentScans -timeout 5m" || true
    
    # 停止资源监控
    kill $MONITOR_PID 2>/dev/null || true
    
    # 运行竞态条件测试
    echo "⚡ 运行竞态条件测试"
    run_test "竞态条件测试" "go test -v ./test -run TestRaceConditions -timeout 3m" || true
    
    # 运行性能基准测试
    echo "📈 运行性能基准测试"
    run_test "性能基准测试" "go test -v ./test -bench=BenchmarkConcurrentScans -benchtime=30s -timeout 2m" || true
    
    # 运行竞态检测
    echo "🔍 运行竞态检测"
    run_test "竞态检测" "go test -race -v ./test -run TestConcurrent100Scans -timeout 10m" || true
    
    echo "结束时间: $(date)" | tee -a "$LOG_FILE"
    echo ""
    
    # 生成测试报告
    generate_report
}

# 生成测试报告
generate_report() {
    local report_file="$TEST_RESULTS_DIR/test_report_$TIMESTAMP.md"
    
    echo "📋 生成测试报告: $report_file"
    
    cat > "$report_file" << EOF
# Go Port Rocket 并发测试报告

**测试时间**: $(date)
**测试环境**: $(uname -a)
**Go版本**: $(go version)

## 测试概述

本次测试主要验证 go-port-rocket 在高并发场景下的稳定性和性能表现。

## 测试项目

1. **100个并发扫描测试** - 验证程序在100个并发扫描时是否会崩溃
2. **资源管理测试** - 验证资源管理器是否正常工作
3. **内存泄漏检测** - 检测是否存在内存泄漏
4. **压力测试** - 长时间高并发测试
5. **竞态条件测试** - 检测并发访问时的竞态条件
6. **性能基准测试** - 测量并发性能
7. **竞态检测** - 使用Go的竞态检测器

## 测试结果

详细测试日志请查看: $LOG_FILE
资源监控日志请查看: $MONITOR_FILE

## 系统资源信息

EOF

    # 添加系统信息到报告
    check_system_resources >> "$report_file"
    
    echo ""
    echo "✅ 测试完成！"
    echo "📋 测试报告: $report_file"
    echo "📝 详细日志: $LOG_FILE"
    
    if [ -f "$MONITOR_FILE" ]; then
        echo "📊 资源监控: $MONITOR_FILE"
    fi
}

# 清理函数
cleanup() {
    echo ""
    echo "🧹 清理测试环境..."
    
    # 杀死可能残留的进程
    pkill -f go-port-rocket 2>/dev/null || true
    
    # 清理临时文件
    rm -f go-port-rocket 2>/dev/null || true
    
    echo "✅ 清理完成"
}

# 设置清理陷阱
trap cleanup EXIT

# 运行主函数
main "$@"
