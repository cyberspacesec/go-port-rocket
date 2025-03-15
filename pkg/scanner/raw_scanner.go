package scanner

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// SYNScan 使用SYN扫描
func SYNScan(target string, ports []int, timeout time.Duration, workers int) ([]ScanResult, error) {
	// 检查是否有root权限
	if os.Geteuid() != 0 {
		return nil, ErrRootRequired
	}

	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %v", err)
	}
	defer syscall.Close(fd)

	// 设置套接字选项
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, int(timeout.Milliseconds()))
	if err != nil {
		return nil, fmt.Errorf("设置套接字选项失败: %v", err)
	}

	// 解析目标IP
	addr := net.ParseIP(target)
	if addr == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", target)
	}

	// 创建结果通道
	results := make(chan ScanResult, len(ports))
	errors := make(chan error, len(ports))

	// 创建工作协程
	for _, port := range ports {
		go func(port int) {
			// 构造TCP SYN包
			tcpHeader := make([]byte, 20)
			tcpHeader[0] = 0x50 // 数据偏移
			tcpHeader[1] = 0x00 // 保留
			tcpHeader[2] = 0x00 // 窗口大小
			tcpHeader[3] = 0x00
			tcpHeader[4] = 0x00 // 校验和
			tcpHeader[5] = 0x00
			tcpHeader[6] = 0x02 // SYN标志
			tcpHeader[7] = 0x00
			tcpHeader[8] = 0x00 // 序列号
			tcpHeader[9] = 0x00
			tcpHeader[10] = 0x00
			tcpHeader[11] = 0x00
			tcpHeader[12] = 0x00 // 确认号
			tcpHeader[13] = 0x00
			tcpHeader[14] = 0x00
			tcpHeader[15] = 0x00
			tcpHeader[16] = 0x00 // 紧急指针
			tcpHeader[17] = 0x00
			tcpHeader[18] = 0x00
			tcpHeader[19] = 0x00

			// 构造IP头
			ipHeader := make([]byte, 20)
			ipHeader[0] = 0x45 // 版本和头部长度
			ipHeader[1] = 0x00 // 服务类型
			ipHeader[2] = 0x00 // 总长度
			ipHeader[3] = 0x28
			ipHeader[4] = 0x00 // 标识
			ipHeader[5] = 0x00
			ipHeader[6] = 0x40 // 标志和片偏移
			ipHeader[7] = 0x00
			ipHeader[8] = 0x40  // 生存时间
			ipHeader[9] = 0x06  // 协议(TCP)
			ipHeader[10] = 0x00 // 校验和
			ipHeader[11] = 0x00
			ipHeader[12] = 0x00 // 源IP
			ipHeader[13] = 0x00
			ipHeader[14] = 0x00
			ipHeader[15] = 0x00
			ipHeader[16] = byte(addr[0]) // 目标IP
			ipHeader[17] = byte(addr[1])
			ipHeader[18] = byte(addr[2])
			ipHeader[19] = byte(addr[3])

			// 发送SYN包
			packet := append(ipHeader, tcpHeader...)
			sa := &syscall.SockaddrInet4{
				Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]},
			}
			err := syscall.Sendto(fd, packet, 0, sa)
			if err != nil {
				errors <- fmt.Errorf("发送SYN包失败: %v", err)
				return
			}

			// 接收响应
			buf := make([]byte, 1024)
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN {
					results <- ScanResult{Port: port, State: PortStateFiltered}
					return
				}
				errors <- fmt.Errorf("接收响应失败: %v", err)
				return
			}

			// 解析响应
			if n > 0 {
				// 检查是否是RST包
				if buf[33]&0x04 != 0 {
					results <- ScanResult{Port: port, State: PortStateClosed}
					return
				}
				// 检查是否是SYN-ACK包
				if buf[33]&0x12 != 0 {
					results <- ScanResult{Port: port, State: PortStateOpen}
					return
				}
			}

			results <- ScanResult{Port: port, State: PortStateUnknown}
		}(port)
	}

	// 收集结果
	var scanResults []ScanResult
	for i := 0; i < len(ports); i++ {
		select {
		case result := <-results:
			scanResults = append(scanResults, result)
		case err := <-errors:
			return nil, err
		case <-time.After(timeout):
			return nil, ErrScanTimeout
		}
	}

	return scanResults, nil
}

// FINScan 使用FIN扫描
func FINScan(target string, ports []int, timeout time.Duration, workers int) ([]ScanResult, error) {
	// 检查是否有root权限
	if os.Geteuid() != 0 {
		return nil, ErrRootRequired
	}

	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %v", err)
	}
	defer syscall.Close(fd)

	// 设置套接字选项
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, int(timeout.Milliseconds()))
	if err != nil {
		return nil, fmt.Errorf("设置套接字选项失败: %v", err)
	}

	// 解析目标IP
	addr := net.ParseIP(target)
	if addr == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", target)
	}

	// 创建结果通道
	results := make(chan ScanResult, len(ports))
	errors := make(chan error, len(ports))

	// 创建工作协程
	for _, port := range ports {
		go func(port int) {
			// 构造TCP FIN包
			tcpHeader := make([]byte, 20)
			tcpHeader[0] = 0x50 // 数据偏移
			tcpHeader[1] = 0x00 // 保留
			tcpHeader[2] = 0x00 // 窗口大小
			tcpHeader[3] = 0x00
			tcpHeader[4] = 0x00 // 校验和
			tcpHeader[5] = 0x00
			tcpHeader[6] = 0x01 // FIN标志
			tcpHeader[7] = 0x00
			tcpHeader[8] = 0x00 // 序列号
			tcpHeader[9] = 0x00
			tcpHeader[10] = 0x00
			tcpHeader[11] = 0x00
			tcpHeader[12] = 0x00 // 确认号
			tcpHeader[13] = 0x00
			tcpHeader[14] = 0x00
			tcpHeader[15] = 0x00
			tcpHeader[16] = 0x00 // 紧急指针
			tcpHeader[17] = 0x00
			tcpHeader[18] = 0x00
			tcpHeader[19] = 0x00

			// 构造IP头
			ipHeader := make([]byte, 20)
			ipHeader[0] = 0x45 // 版本和头部长度
			ipHeader[1] = 0x00 // 服务类型
			ipHeader[2] = 0x00 // 总长度
			ipHeader[3] = 0x28
			ipHeader[4] = 0x00 // 标识
			ipHeader[5] = 0x00
			ipHeader[6] = 0x40 // 标志和片偏移
			ipHeader[7] = 0x00
			ipHeader[8] = 0x40  // 生存时间
			ipHeader[9] = 0x06  // 协议(TCP)
			ipHeader[10] = 0x00 // 校验和
			ipHeader[11] = 0x00
			ipHeader[12] = 0x00 // 源IP
			ipHeader[13] = 0x00
			ipHeader[14] = 0x00
			ipHeader[15] = 0x00
			ipHeader[16] = byte(addr[0]) // 目标IP
			ipHeader[17] = byte(addr[1])
			ipHeader[18] = byte(addr[2])
			ipHeader[19] = byte(addr[3])

			// 发送FIN包
			packet := append(ipHeader, tcpHeader...)
			sa := &syscall.SockaddrInet4{
				Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]},
			}
			err := syscall.Sendto(fd, packet, 0, sa)
			if err != nil {
				errors <- fmt.Errorf("发送FIN包失败: %v", err)
				return
			}

			// 接收响应
			buf := make([]byte, 1024)
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN {
					// 如果没有收到响应，可能是开放的端口
					results <- ScanResult{Port: port, State: PortStateOpen}
					return
				}
				errors <- fmt.Errorf("接收响应失败: %v", err)
				return
			}

			// 解析响应
			if n > 0 {
				// 如果收到RST包，端口是关闭的
				if buf[33]&0x04 != 0 {
					results <- ScanResult{Port: port, State: PortStateClosed}
					return
				}
			}

			results <- ScanResult{Port: port, State: PortStateUnknown}
		}(port)
	}

	// 收集结果
	var scanResults []ScanResult
	for i := 0; i < len(ports); i++ {
		select {
		case result := <-results:
			scanResults = append(scanResults, result)
		case err := <-errors:
			return nil, err
		case <-time.After(timeout):
			return nil, ErrScanTimeout
		}
	}

	return scanResults, nil
}

// NULLScan 使用NULL扫描
func NULLScan(target string, ports []int, timeout time.Duration, workers int) ([]ScanResult, error) {
	// 检查是否有root权限
	if os.Geteuid() != 0 {
		return nil, ErrRootRequired
	}

	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %v", err)
	}
	defer syscall.Close(fd)

	// 设置套接字选项
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, int(timeout.Milliseconds()))
	if err != nil {
		return nil, fmt.Errorf("设置套接字选项失败: %v", err)
	}

	// 解析目标IP
	addr := net.ParseIP(target)
	if addr == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", target)
	}

	// 创建结果通道
	results := make(chan ScanResult, len(ports))
	errors := make(chan error, len(ports))

	// 创建工作协程
	for _, port := range ports {
		go func(port int) {
			// 构造TCP NULL包（没有设置任何标志）
			tcpHeader := make([]byte, 20)
			tcpHeader[0] = 0x50 // 数据偏移
			tcpHeader[1] = 0x00 // 保留
			tcpHeader[2] = 0x00 // 窗口大小
			tcpHeader[3] = 0x00
			tcpHeader[4] = 0x00 // 校验和
			tcpHeader[5] = 0x00
			tcpHeader[6] = 0x00 // 没有设置任何标志
			tcpHeader[7] = 0x00
			tcpHeader[8] = 0x00 // 序列号
			tcpHeader[9] = 0x00
			tcpHeader[10] = 0x00
			tcpHeader[11] = 0x00
			tcpHeader[12] = 0x00 // 确认号
			tcpHeader[13] = 0x00
			tcpHeader[14] = 0x00
			tcpHeader[15] = 0x00
			tcpHeader[16] = 0x00 // 紧急指针
			tcpHeader[17] = 0x00
			tcpHeader[18] = 0x00
			tcpHeader[19] = 0x00

			// 构造IP头
			ipHeader := make([]byte, 20)
			ipHeader[0] = 0x45 // 版本和头部长度
			ipHeader[1] = 0x00 // 服务类型
			ipHeader[2] = 0x00 // 总长度
			ipHeader[3] = 0x28
			ipHeader[4] = 0x00 // 标识
			ipHeader[5] = 0x00
			ipHeader[6] = 0x40 // 标志和片偏移
			ipHeader[7] = 0x00
			ipHeader[8] = 0x40  // 生存时间
			ipHeader[9] = 0x06  // 协议(TCP)
			ipHeader[10] = 0x00 // 校验和
			ipHeader[11] = 0x00
			ipHeader[12] = 0x00 // 源IP
			ipHeader[13] = 0x00
			ipHeader[14] = 0x00
			ipHeader[15] = 0x00
			ipHeader[16] = byte(addr[0]) // 目标IP
			ipHeader[17] = byte(addr[1])
			ipHeader[18] = byte(addr[2])
			ipHeader[19] = byte(addr[3])

			// 发送NULL包
			packet := append(ipHeader, tcpHeader...)
			sa := &syscall.SockaddrInet4{
				Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]},
			}
			err := syscall.Sendto(fd, packet, 0, sa)
			if err != nil {
				errors <- fmt.Errorf("发送NULL包失败: %v", err)
				return
			}

			// 接收响应
			buf := make([]byte, 1024)
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN {
					// 如果没有收到响应，可能是开放的端口
					results <- ScanResult{Port: port, State: PortStateOpen}
					return
				}
				errors <- fmt.Errorf("接收响应失败: %v", err)
				return
			}

			// 解析响应
			if n > 0 {
				// 如果收到RST包，端口是关闭的
				if buf[33]&0x04 != 0 {
					results <- ScanResult{Port: port, State: PortStateClosed}
					return
				}
			}

			results <- ScanResult{Port: port, State: PortStateUnknown}
		}(port)
	}

	// 收集结果
	var scanResults []ScanResult
	for i := 0; i < len(ports); i++ {
		select {
		case result := <-results:
			scanResults = append(scanResults, result)
		case err := <-errors:
			return nil, err
		case <-time.After(timeout):
			return nil, ErrScanTimeout
		}
	}

	return scanResults, nil
}

// XMASScan 使用XMAS扫描
func XMASScan(target string, ports []int, timeout time.Duration, workers int) ([]ScanResult, error) {
	// 检查是否有root权限
	if os.Geteuid() != 0 {
		return nil, ErrRootRequired
	}

	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %v", err)
	}
	defer syscall.Close(fd)

	// 设置套接字选项
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, int(timeout.Milliseconds()))
	if err != nil {
		return nil, fmt.Errorf("设置套接字选项失败: %v", err)
	}

	// 解析目标IP
	addr := net.ParseIP(target)
	if addr == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", target)
	}

	// 创建结果通道
	results := make(chan ScanResult, len(ports))
	errors := make(chan error, len(ports))

	// 创建工作协程
	for _, port := range ports {
		go func(port int) {
			// 构造TCP XMAS包（设置FIN、PSH和URG标志）
			tcpHeader := make([]byte, 20)
			tcpHeader[0] = 0x50 // 数据偏移
			tcpHeader[1] = 0x00 // 保留
			tcpHeader[2] = 0x00 // 窗口大小
			tcpHeader[3] = 0x00
			tcpHeader[4] = 0x00 // 校验和
			tcpHeader[5] = 0x00
			tcpHeader[6] = 0x29 // FIN、PSH和URG标志
			tcpHeader[7] = 0x00
			tcpHeader[8] = 0x00 // 序列号
			tcpHeader[9] = 0x00
			tcpHeader[10] = 0x00
			tcpHeader[11] = 0x00
			tcpHeader[12] = 0x00 // 确认号
			tcpHeader[13] = 0x00
			tcpHeader[14] = 0x00
			tcpHeader[15] = 0x00
			tcpHeader[16] = 0x00 // 紧急指针
			tcpHeader[17] = 0x00
			tcpHeader[18] = 0x00
			tcpHeader[19] = 0x00

			// 构造IP头
			ipHeader := make([]byte, 20)
			ipHeader[0] = 0x45 // 版本和头部长度
			ipHeader[1] = 0x00 // 服务类型
			ipHeader[2] = 0x00 // 总长度
			ipHeader[3] = 0x28
			ipHeader[4] = 0x00 // 标识
			ipHeader[5] = 0x00
			ipHeader[6] = 0x40 // 标志和片偏移
			ipHeader[7] = 0x00
			ipHeader[8] = 0x40  // 生存时间
			ipHeader[9] = 0x06  // 协议(TCP)
			ipHeader[10] = 0x00 // 校验和
			ipHeader[11] = 0x00
			ipHeader[12] = 0x00 // 源IP
			ipHeader[13] = 0x00
			ipHeader[14] = 0x00
			ipHeader[15] = 0x00
			ipHeader[16] = byte(addr[0]) // 目标IP
			ipHeader[17] = byte(addr[1])
			ipHeader[18] = byte(addr[2])
			ipHeader[19] = byte(addr[3])

			// 发送XMAS包
			packet := append(ipHeader, tcpHeader...)
			sa := &syscall.SockaddrInet4{
				Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]},
			}
			err := syscall.Sendto(fd, packet, 0, sa)
			if err != nil {
				errors <- fmt.Errorf("发送XMAS包失败: %v", err)
				return
			}

			// 接收响应
			buf := make([]byte, 1024)
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN {
					// 如果没有收到响应，可能是开放的端口
					results <- ScanResult{Port: port, State: PortStateOpen}
					return
				}
				errors <- fmt.Errorf("接收响应失败: %v", err)
				return
			}

			// 解析响应
			if n > 0 {
				// 如果收到RST包，端口是关闭的
				if buf[33]&0x04 != 0 {
					results <- ScanResult{Port: port, State: PortStateClosed}
					return
				}
			}

			results <- ScanResult{Port: port, State: PortStateUnknown}
		}(port)
	}

	// 收集结果
	var scanResults []ScanResult
	for i := 0; i < len(ports); i++ {
		select {
		case result := <-results:
			scanResults = append(scanResults, result)
		case err := <-errors:
			return nil, err
		case <-time.After(timeout):
			return nil, ErrScanTimeout
		}
	}

	return scanResults, nil
}

// ACKScan 使用ACK扫描
func ACKScan(target string, ports []int, timeout time.Duration, workers int) ([]ScanResult, error) {
	// 检查是否有root权限
	if os.Geteuid() != 0 {
		return nil, ErrRootRequired
	}

	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %v", err)
	}
	defer syscall.Close(fd)

	// 设置套接字选项
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, int(timeout.Milliseconds()))
	if err != nil {
		return nil, fmt.Errorf("设置套接字选项失败: %v", err)
	}

	// 解析目标IP
	addr := net.ParseIP(target)
	if addr == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", target)
	}

	// 创建结果通道
	results := make(chan ScanResult, len(ports))
	errors := make(chan error, len(ports))

	// 创建工作协程
	for _, port := range ports {
		go func(port int) {
			// 构造TCP ACK包
			tcpHeader := make([]byte, 20)
			tcpHeader[0] = 0x50 // 数据偏移
			tcpHeader[1] = 0x00 // 保留
			tcpHeader[2] = 0x00 // 窗口大小
			tcpHeader[3] = 0x00
			tcpHeader[4] = 0x00 // 校验和
			tcpHeader[5] = 0x00
			tcpHeader[6] = 0x10 // ACK标志
			tcpHeader[7] = 0x00
			tcpHeader[8] = 0x00 // 序列号
			tcpHeader[9] = 0x00
			tcpHeader[10] = 0x00
			tcpHeader[11] = 0x00
			tcpHeader[12] = 0x00 // 确认号
			tcpHeader[13] = 0x00
			tcpHeader[14] = 0x00
			tcpHeader[15] = 0x00
			tcpHeader[16] = 0x00 // 紧急指针
			tcpHeader[17] = 0x00
			tcpHeader[18] = 0x00
			tcpHeader[19] = 0x00

			// 构造IP头
			ipHeader := make([]byte, 20)
			ipHeader[0] = 0x45 // 版本和头部长度
			ipHeader[1] = 0x00 // 服务类型
			ipHeader[2] = 0x00 // 总长度
			ipHeader[3] = 0x28
			ipHeader[4] = 0x00 // 标识
			ipHeader[5] = 0x00
			ipHeader[6] = 0x40 // 标志和片偏移
			ipHeader[7] = 0x00
			ipHeader[8] = 0x40  // 生存时间
			ipHeader[9] = 0x06  // 协议(TCP)
			ipHeader[10] = 0x00 // 校验和
			ipHeader[11] = 0x00
			ipHeader[12] = 0x00 // 源IP
			ipHeader[13] = 0x00
			ipHeader[14] = 0x00
			ipHeader[15] = 0x00
			ipHeader[16] = byte(addr[0]) // 目标IP
			ipHeader[17] = byte(addr[1])
			ipHeader[18] = byte(addr[2])
			ipHeader[19] = byte(addr[3])

			// 发送ACK包
			packet := append(ipHeader, tcpHeader...)
			sa := &syscall.SockaddrInet4{
				Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]},
			}
			err := syscall.Sendto(fd, packet, 0, sa)
			if err != nil {
				errors <- fmt.Errorf("发送ACK包失败: %v", err)
				return
			}

			// 接收响应
			buf := make([]byte, 1024)
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN {
					// 如果没有收到响应，可能是被过滤的端口
					results <- ScanResult{Port: port, State: PortStateFiltered}
					return
				}
				errors <- fmt.Errorf("接收响应失败: %v", err)
				return
			}

			// 解析响应
			if n > 0 {
				// 如果收到RST包，端口是未过滤的
				if buf[33]&0x04 != 0 {
					results <- ScanResult{Port: port, State: PortStateClosed}
					return
				}
			}

			results <- ScanResult{Port: port, State: PortStateUnknown}
		}(port)
	}

	// 收集结果
	var scanResults []ScanResult
	for i := 0; i < len(ports); i++ {
		select {
		case result := <-results:
			scanResults = append(scanResults, result)
		case err := <-errors:
			return nil, err
		case <-time.After(timeout):
			return nil, ErrScanTimeout
		}
	}

	return scanResults, nil
}
