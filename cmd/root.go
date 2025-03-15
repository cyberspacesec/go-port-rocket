package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// 版本号，在构建时通过ldflags注入
// 例如: go build -ldflags="-X github.com/cyberspacesec/go-port-rocket/cmd.Version=v1.0.0"
var Version = "dev"

// 全局变量，用于存储各个命令
var (
	scanCmd *cobra.Command
	apiCmd  *cobra.Command
	// 已删除 mcpScanCmd 和 mcpAPICmd 的引用
)

// ASCII文本Logo模板，构建时会注入版本号
const asciiLogoTemplate = `
 _____         ______           _     ______            _        _   
|  __ \       |  ____|         | |   |  ____|          | |      | |  
| |  \/ ___   | |__   ___  _ __| |_  | |__   ___   ___ | | _____| |_ 
| | __ / _ \  |  __| / _ \| '__| __| |  __| / _ \ / __|| |/ / _ \ __|
| |_\ \ (_) | | |___| (_) | |  | |_  | |___| (_) | (__ |   <  __/ |_ 
 \____/\___/  |______\___/|_|   \__| |______\___/ \___||_|\_\___|\__|
                                                                      
--------------------------------------------------------
高性能端口扫描器 | Fast Port Scanner
版本: %s
`

// 生成包含实际版本号的ASCII Logo
func getAsciiLogo() string {
	return fmt.Sprintf(asciiLogoTemplate, Version)
}

var RootCmd = &cobra.Command{
	Use:   "go-port-rocket",
	Short: "Go Port Rocket - 高性能端口扫描器",
	Long: getAsciiLogo() + `
Go Port Rocket是一个用Go语言编写的高性能端口扫描工具，
类似于nmap，但更加轻量级和易于使用。

基本用法:
  go-port-rocket scan -t example.com -p 1-1000
  go-port-rocket discover -n 192.168.1.0/24`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果没有提供子命令，则显示帮助信息
		cmd.Help()
	},
}

// Execute 执行根命令
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// 添加所有可用的命令
	if scanCmd != nil {
		RootCmd.AddCommand(scanCmd)
	}
	if apiCmd != nil {
		RootCmd.AddCommand(apiCmd)
	}
	// 已删除添加 mcpScanCmd 和 mcpAPICmd 的代码

	// discover命令在其自己的init函数中添加到RootCmd
	// 所以这里不需要再添加

	// 添加全局标志
	RootCmd.PersistentFlags().BoolP("verbose", "v", false, "输出详细信息")
}
