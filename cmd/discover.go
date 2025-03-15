package cmd

import (
	"fmt"
	"time"

	"github.com/cyberspacesec/go-port-rocket/pkg/scanner"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	discoverNetwork    string
	discoverIcmpPing   bool
	discoverTcpPing    bool
	discoverArpScan    bool
	discoverTcpPorts   []int
	discoverTimeout    time.Duration
	discoverConcurrent int
)

// discoverCmd 网络发现命令
var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "发现网络中的主机",
	Long: `发现网络中的活跃主机，支持多种发现方式。
例如：
  go-port-rocket discover -n 192.168.1.0/24
  go-port-rocket discover -n 10.0.0.0/8 --icmp --tcp`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 验证必要参数
		if discoverNetwork == "" {
			return fmt.Errorf("必须指定网段 (-n)")
		}

		// 创建发现选项
		opts := &scanner.DiscoveryOptions{
			ICMPPing:    discoverIcmpPing,
			TCPPing:     discoverTcpPing,
			ARPScan:     discoverArpScan,
			TCPPorts:    discoverTcpPorts,
			Timeout:     discoverTimeout,
			Concurrency: discoverConcurrent,
		}

		// 执行主机发现
		hosts, err := scanner.DiscoverHosts([]string{discoverNetwork}, opts)
		if err != nil {
			return fmt.Errorf("主机发现失败: %v", err)
		}

		// 输出结果
		scanner.PrintHosts(hosts)
		return nil
	},
}

func init() {
	// 添加命令行参数
	discoverCmd.Flags().StringVarP(&discoverNetwork, "network", "n", "", "要扫描的网段，例如：192.168.1.0/24")
	discoverCmd.Flags().BoolVar(&discoverIcmpPing, "icmp", true, "使用ICMP Ping")
	discoverCmd.Flags().BoolVar(&discoverTcpPing, "tcp", true, "使用TCP Ping")
	discoverCmd.Flags().BoolVar(&discoverArpScan, "arp", false, "使用ARP扫描（仅适用于本地网络）")
	discoverCmd.Flags().IntSliceVar(&discoverTcpPorts, "ports", []int{80, 443, 22, 445}, "TCP Ping使用的端口")
	discoverCmd.Flags().DurationVarP(&discoverTimeout, "timeout", "T", 2*time.Second, "超时时间")
	discoverCmd.Flags().IntVarP(&discoverConcurrent, "concurrent", "c", 100, "并发数")

	// 绑定到viper配置
	viper.BindPFlag("discover.network", discoverCmd.Flags().Lookup("network"))
	viper.BindPFlag("discover.icmp", discoverCmd.Flags().Lookup("icmp"))
	viper.BindPFlag("discover.tcp", discoverCmd.Flags().Lookup("tcp"))
	viper.BindPFlag("discover.arp", discoverCmd.Flags().Lookup("arp"))
	viper.BindPFlag("discover.ports", discoverCmd.Flags().Lookup("ports"))
	viper.BindPFlag("discover.timeout", discoverCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("discover.concurrent", discoverCmd.Flags().Lookup("concurrent"))

	// 设置必填参数
	discoverCmd.MarkFlagRequired("network")

	// 添加到根命令
	RootCmd.AddCommand(discoverCmd)
}
