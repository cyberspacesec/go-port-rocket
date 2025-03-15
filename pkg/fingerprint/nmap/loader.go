package nmap

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// loadProbes 加载Nmap探测规则
func (db *NmapDB) loadProbes(nmapSharePath string) error {
	file, err := os.Open(filepath.Join(nmapSharePath, "nmap-service-probes"))
	if err != nil {
		return fmt.Errorf("打开探测规则文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentProbe *Probe

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "Probe") {
			// 解析探测规则
			parts := strings.SplitN(line, " ", 3)
			if len(parts) != 3 {
				continue
			}

			probeName := strings.TrimSpace(parts[1])
			probeStr := strings.TrimSpace(parts[2])

			currentProbe = &Probe{
				Name:     probeName,
				ProbeStr: probeStr,
			}
			db.Probes[probeName] = currentProbe
		} else if strings.HasPrefix(line, "ports") && currentProbe != nil {
			// 解析端口
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				currentProbe.Ports = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "protocol") && currentProbe != nil {
			// 解析协议
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				currentProbe.Protocol = strings.TrimSpace(parts[1])
			}
		}
	}

	return scanner.Err()
}

// loadOSFingerprints 加载操作系统指纹
func (db *NmapDB) loadOSFingerprints(nmapSharePath string) error {
	file, err := os.Open(filepath.Join(nmapSharePath, "nmap-os-db"))
	if err != nil {
		return fmt.Errorf("打开操作系统指纹文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentFP *NmapFingerprint

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "Fingerprint") {
			// 开始新的指纹
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}

			currentFP = &NmapFingerprint{
				Name:     strings.TrimSpace(parts[1]),
				Class:    "OS",
				Line:     line,
				Features: make(map[string]string),
			}
			db.OSFingerprints[currentFP.Name] = currentFP
		} else if strings.HasPrefix(line, "Class") && currentFP != nil {
			// 解析类别
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				currentFP.Class = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Match") && currentFP != nil {
			// 解析匹配规则
			currentFP.MatchLines = append(currentFP.MatchLines, line)
		} else if strings.HasPrefix(line, "SoftMatch") && currentFP != nil {
			// 解析软匹配规则
			currentFP.SoftMatches = append(currentFP.SoftMatches, line)
		}
	}

	return scanner.Err()
}

// loadServiceFingerprints 加载服务指纹
func (db *NmapDB) loadServiceFingerprints(nmapSharePath string) error {
	file, err := os.Open(filepath.Join(nmapSharePath, "nmap-service-probes"))
	if err != nil {
		return fmt.Errorf("打开服务指纹文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentFP *NmapFingerprint
	var currentProbe *Probe

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "Probe") {
			// 开始新的探测规则
			parts := strings.SplitN(line, " ", 3)
			if len(parts) != 3 {
				continue
			}

			probeName := strings.TrimSpace(parts[1])
			probeStr := strings.TrimSpace(parts[2])

			currentProbe = &Probe{
				Name:     probeName,
				ProbeStr: probeStr,
			}
			db.Probes[probeName] = currentProbe
		} else if strings.HasPrefix(line, "match") && currentProbe != nil {
			// 解析服务匹配规则
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}

			currentFP = &NmapFingerprint{
				Name:     strings.TrimSpace(parts[1]),
				Class:    "Service",
				Line:     line,
				Features: make(map[string]string),
				Probes:   []Probe{*currentProbe},
			}
			db.ServiceFingerprints[currentFP.Name] = currentFP
		} else if strings.HasPrefix(line, "softmatch") && currentProbe != nil {
			// 解析服务软匹配规则
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}

			currentFP = &NmapFingerprint{
				Name:     strings.TrimSpace(parts[1]),
				Class:    "Service",
				Line:     line,
				Features: make(map[string]string),
				Probes:   []Probe{*currentProbe},
			}
			db.ServiceFingerprints[currentFP.Name] = currentFP
		} else if strings.HasPrefix(line, "|") && currentFP != nil {
			// 解析特征值
			parts := strings.SplitN(line[1:], ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentFP.Features[key] = value
			}
		}
	}

	return scanner.Err()
}
