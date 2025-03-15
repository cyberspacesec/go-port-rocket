package scanner

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// checkLibpcapAvailability 检查libpcap是否可用
func checkLibpcapAvailability() error {
	// 检查是否能加载pcap库
	_, err := pcap.OpenLive("any", 65536, true, pcap.BlockForever)
	if err != nil {
		// 根据操作系统提供安装建议
		var errorMsg, installGuide string
		switch runtime.GOOS {
		case "linux":
			errorMsg = "系统未安装libpcap开发库,无法执行SYN扫描"
			installGuide = "请执行以下命令安装libpcap开发库:\n" +
				"Ubuntu/Debian系统: sudo apt-get install libpcap-dev\n" +
				"CentOS/RHEL系统: sudo yum install libpcap-devel\n" +
				"Fedora系统: sudo dnf install libpcap-devel\n\n" +
				"安装完成后重新运行程序即可"
		case "darwin":
			errorMsg = "系统未安装libpcap,无法执行SYN扫描"
			installGuide = "请使用Homebrew安装libpcap:\n" +
				"1. 如果未安装Homebrew,请先访问 https://brew.sh/ 安装\n" +
				"2. 然后执行: brew install libpcap\n\n" +
				"安装完成后重新运行程序即可"
		case "windows":
			errorMsg = "系统未安装Npcap,无法执行SYN扫描"
			installGuide = "请按以下步骤安装Npcap:\n" +
				"1. 访问 https://npcap.com/#download\n" +
				"2. 下载Npcap安装程序\n" +
				"3. 以管理员身份运行安装程序\n" +
				"4. 安装时请确保选中「Install Npcap in WinPcap API-compatible Mode」选项\n\n" +
				"安装完成后重新运行程序即可"
		default:
			errorMsg = "系统未安装libpcap开发库,无法执行SYN扫描"
			installGuide = "请安装libpcap开发库后重试"
		}
		return fmt.Errorf("%s\n\n%s\n\n原始错误: %v", errorMsg, installGuide, err)
	}
	return nil
}

// RawSYNScan 执行原始 SYN 扫描
func RawSYNScan(target string, ports []int, timeout time.Duration, workers int) ([]int, []int, []int, error) {
	// 首先检查libpcap是否可用
	if err := checkLibpcapAvailability(); err != nil {
		return nil, nil, nil, err
	}

	// 解析目标IP
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return nil, nil, nil, fmt.Errorf("无效的目标IP: %s", target)
	}

	// 获取本地接口
	iface, srcIP, err := getInterface(targetIP)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("获取网络接口失败: %v", err)
	}

	// 创建抓包句柄
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("创建抓包句柄失败: %v", err)
	}
	defer handle.Close()

	// 设置BPF过滤器
	err = handle.SetBPFFilter("tcp")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("设置BPF过滤器失败: %v", err)
	}

	// 创建发送socket
	sendSocket, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("创建发送socket失败: %v", err)
	}
	defer sendSocket.Close()

	var (
		openPorts     []int
		closedPorts   []int
		filteredPorts []int
		wg            sync.WaitGroup
		mu            sync.Mutex
		sourcePortMap = make(map[uint16]int) // 源端口到目标端口的映射
		mapMutex      sync.RWMutex
	)

	// 启动数据包接收goroutine
	packetChan := make(chan gopacket.Packet, 1000)
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packetChan <- packet
		}
	}()

	// 启动响应处理goroutine
	go func() {
		var packetCount int
		for {
			select {
			case packet := <-packetChan:
				packetCount++
				log.Printf("收到数据包 #%d", packetCount)

				// 解析IP层
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					log.Printf("数据包 #%d 无IP层", packetCount)
					continue
				}
				ip, ok := ipLayer.(*layers.IPv4)
				if !ok {
					log.Printf("数据包 #%d IP层类型转换失败", packetCount)
					continue
				}
				log.Printf("数据包 #%d IP层: 源IP=%s, 目标IP=%s, 协议=%d",
					packetCount, ip.SrcIP, ip.DstIP, ip.Protocol)

				// 解析TCP层
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					log.Printf("数据包 #%d 无TCP层", packetCount)
					continue
				}
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					log.Printf("数据包 #%d TCP层类型转换失败", packetCount)
					continue
				}
				log.Printf("数据包 #%d TCP层: 源端口=%d, 目标端口=%d, 标志位: SYN=%v ACK=%v RST=%v",
					packetCount, tcp.SrcPort, tcp.DstPort, tcp.SYN, tcp.ACK, tcp.RST)

				// 检查是否是我们发送的SYN包的响应
				mapMutex.RLock()
				targetPort, exists := sourcePortMap[uint16(tcp.DstPort)]
				mapMutex.RUnlock()

				if exists {
					mu.Lock()
					if tcp.SYN && tcp.ACK {
						// 收到SYN+ACK，说明端口开放
						openPorts = append(openPorts, targetPort)
					} else if tcp.RST {
						// 收到RST，说明端口关闭
						closedPorts = append(closedPorts, targetPort)
					}
					mu.Unlock()

					// 从映射中删除已处理的端口
					mapMutex.Lock()
					delete(sourcePortMap, uint16(tcp.DstPort))
					mapMutex.Unlock()
				}

			case <-time.After(timeout):
				log.Println("接收超时")
				return
			}
		}
	}()

	// 发送SYN包
	for _, port := range ports {
		wg.Add(1)
		go func(targetPort int) {
			defer wg.Done()

			// 生成随机源端口
			srcPort := uint16(rand.Intn(65535-1024) + 1024)

			// 记录源端口到目标端口的映射
			mapMutex.Lock()
			sourcePortMap[srcPort] = targetPort
			mapMutex.Unlock()

			// 构建TCP头
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(srcPort),
				DstPort: layers.TCPPort(targetPort),
				SYN:     true,
			}
			tcp.SetNetworkLayerForChecksum(&layers.IPv4{
				SrcIP:    srcIP,
				DstIP:    targetIP,
				Protocol: layers.IPProtocolTCP,
			})

			// 序列化数据包
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			err := gopacket.SerializeLayers(buf, opts, tcp)
			if err != nil {
				log.Printf("序列化数据包失败: %v", err)
				return
			}

			// 发送数据包
			_, err = sendSocket.WriteTo(buf.Bytes(), &net.IPAddr{IP: targetIP})
			if err != nil {
				log.Printf("发送数据包失败: %v", err)
				return
			}
		}(port)
	}

	// 等待所有发送完成
	wg.Wait()

	// 等待接收完成
	time.Sleep(timeout)

	// 处理未收到响应的端口
	mapMutex.Lock()
	for _, port := range sourcePortMap {
		filteredPorts = append(filteredPorts, port)
	}
	mapMutex.Unlock()

	log.Printf("扫描完成，收到 %d 个响应", len(openPorts)+len(closedPorts))

	return openPorts, closedPorts, filteredPorts, nil
}

// getInterface 获取用于发送数据包的网络接口
func getInterface(targetIP net.IP) (*net.Interface, net.IP, error) {
	// 如果是本地回环地址，返回回环接口
	if targetIP.IsLoopback() {
		iface, err := net.InterfaceByName("lo0")
		if err != nil {
			return nil, nil, err
		}
		return iface, net.ParseIP("127.0.0.1"), nil
	}

	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range interfaces {
		// 跳过down的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 获取接口的地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// 转换为IP网络
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// 跳过IPv6地址
			if ipNet.IP.To4() == nil {
				continue
			}

			// 如果目标IP在这个网络中，返回这个接口
			if ipNet.Contains(targetIP) {
				return &iface, ipNet.IP, nil
			}
		}
	}

	// 如果没有找到匹配的接口，返回默认接口
	iface, err := net.InterfaceByName("en0")
	if err != nil {
		return nil, nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				return iface, ipNet.IP, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("无法获取合适的网络接口和IP地址")
}
