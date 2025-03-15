package nmap

import (
	"fmt"
	"regexp"
	"strings"
)

// matchLine 匹配规则行
func (db *NmapDB) matchLine(line string, features map[string]string) bool {
	// 解析规则行
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return false
	}

	ruleType := strings.TrimSpace(parts[0])
	ruleContent := strings.TrimSpace(parts[1])

	switch ruleType {
	case "Match", "SoftMatch":
		return db.matchRule(ruleContent, features)
	case "MatchPoint":
		return db.matchPoint(ruleContent, features)
	default:
		return false
	}
}

// matchRule 匹配规则
func (db *NmapDB) matchRule(rule string, features map[string]string) bool {
	// 解析规则内容
	parts := strings.SplitN(rule, " ", 2)
	if len(parts) != 2 {
		return false
	}

	// 获取探测规则
	if _, exists := db.Probes[parts[0]]; !exists {
		return false
	}

	// 解析模式
	pattern := strings.TrimSpace(parts[1])
	pattern = strings.Trim(pattern, "/")
	pattern = strings.ReplaceAll(pattern, "\\", "\\\\")
	pattern = strings.ReplaceAll(pattern, "|", "\\|")
	pattern = strings.ReplaceAll(pattern, "(", "\\(")
	pattern = strings.ReplaceAll(pattern, ")", "\\)")
	pattern = strings.ReplaceAll(pattern, "[", "\\[")
	pattern = strings.ReplaceAll(pattern, "]", "\\]")
	pattern = strings.ReplaceAll(pattern, "{", "\\{")
	pattern = strings.ReplaceAll(pattern, "}", "\\}")
	pattern = strings.ReplaceAll(pattern, "+", "\\+")
	pattern = strings.ReplaceAll(pattern, "*", "\\*")
	pattern = strings.ReplaceAll(pattern, "?", "\\?")
	pattern = strings.ReplaceAll(pattern, "^", "\\^")
	pattern = strings.ReplaceAll(pattern, "$", "\\$")

	// 编译正则表达式
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}

	// 匹配特征值
	for _, value := range features {
		if re.MatchString(value) {
			return true
		}
	}

	return false
}

// matchPoint 匹配点
func (db *NmapDB) matchPoint(rule string, features map[string]string) bool {
	// 解析规则内容
	parts := strings.SplitN(rule, " ", 2)
	if len(parts) != 2 {
		return false
	}

	// 获取探测规则
	if _, exists := db.Probes[parts[0]]; !exists {
		return false
	}

	// 解析模式
	pattern := strings.TrimSpace(parts[1])
	pattern = strings.Trim(pattern, "/")
	pattern = strings.ReplaceAll(pattern, "\\", "\\\\")
	pattern = strings.ReplaceAll(pattern, "|", "\\|")
	pattern = strings.ReplaceAll(pattern, "(", "\\(")
	pattern = strings.ReplaceAll(pattern, ")", "\\)")
	pattern = strings.ReplaceAll(pattern, "[", "\\[")
	pattern = strings.ReplaceAll(pattern, "]", "\\]")
	pattern = strings.ReplaceAll(pattern, "{", "\\{")
	pattern = strings.ReplaceAll(pattern, "}", "\\}")
	pattern = strings.ReplaceAll(pattern, "+", "\\+")
	pattern = strings.ReplaceAll(pattern, "*", "\\*")
	pattern = strings.ReplaceAll(pattern, "?", "\\?")
	pattern = strings.ReplaceAll(pattern, "^", "\\^")
	pattern = strings.ReplaceAll(pattern, "$", "\\$")

	// 编译正则表达式
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}

	// 匹配特征值
	for _, value := range features {
		if re.MatchString(value) {
			return true
		}
	}

	return false
}

// ParseVersion 解析版本信息
func ParseVersion(response string) (string, error) {
	// 尝试从响应中提取版本信息
	versionPattern := regexp.MustCompile(`(?i)version[:\s]+([0-9.]+)`)
	matches := versionPattern.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1], nil
	}

	// 尝试从响应中提取产品信息
	productPattern := regexp.MustCompile(`(?i)([a-z]+)[/\s]+([0-9.]+)`)
	matches = productPattern.FindStringSubmatch(response)
	if len(matches) > 2 {
		return fmt.Sprintf("%s %s", matches[1], matches[2]), nil
	}

	return "", fmt.Errorf("无法从响应中提取版本信息")
}

// ParseOS 解析操作系统信息
func ParseOS(response string) (string, error) {
	// 尝试从响应中提取操作系统信息
	osPattern := regexp.MustCompile(`(?i)(windows|linux|macos|bsd|unix)`)
	matches := osPattern.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("无法从响应中提取操作系统信息")
}

// ParseService 解析服务信息
func ParseService(response string) (string, error) {
	// 尝试从响应中提取服务信息
	servicePattern := regexp.MustCompile(`(?i)(http|ftp|ssh|telnet|smtp|pop3|imap|mysql|postgresql|redis|mongodb|elasticsearch)`)
	matches := servicePattern.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("无法从响应中提取服务信息")
}
