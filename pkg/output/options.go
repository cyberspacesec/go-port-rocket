package output

import (
	"io"
	"time"
)

// Options 输出选项
type Options struct {
	Format    string        // 输出格式 (text, json, xml, html)
	Pretty    bool          // 美化输出
	Writer    io.Writer     // 输出目标
	Target    string        // 扫描目标
	ScanType  string        // 扫描类型
	StartTime time.Time     // 开始时间
	EndTime   time.Time     // 结束时间
	Duration  time.Duration // 扫描耗时
}
