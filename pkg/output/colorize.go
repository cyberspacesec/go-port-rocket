package output

// colorize.go 提供终端彩色输出支持

const (
	// 终端颜色代码
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"
	Underlined = "\033[4m"
	Blink      = "\033[5m"
	Reverse    = "\033[7m"
	Hidden     = "\033[8m"

	// 前景色
	Black   = "\033[30m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	// 高亮前景色
	BrightBlack   = "\033[90m"
	BrightRed     = "\033[91m"
	BrightGreen   = "\033[92m"
	BrightYellow  = "\033[93m"
	BrightBlue    = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan    = "\033[96m"
	BrightWhite   = "\033[97m"

	// 背景色
	BgBlack   = "\033[40m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgYellow  = "\033[43m"
	BgBlue    = "\033[44m"
	BgMagenta = "\033[45m"
	BgCyan    = "\033[46m"
	BgWhite   = "\033[47m"

	// 高亮背景色
	BgBrightBlack   = "\033[100m"
	BgBrightRed     = "\033[101m"
	BgBrightGreen   = "\033[102m"
	BgBrightYellow  = "\033[103m"
	BgBrightBlue    = "\033[104m"
	BgBrightMagenta = "\033[105m"
	BgBrightCyan    = "\033[106m"
	BgBrightWhite   = "\033[107m"
)

// Colorize 给文本添加颜色
func Colorize(text string, color string) string {
	return color + text + Reset
}

// ColorizeIf 当条件为真时给文本添加颜色
func ColorizeIf(text string, color string, condition bool) string {
	if condition {
		return Colorize(text, color)
	}
	return text
}

// 针对特定类型的彩色输出函数
var (
	// 状态相关
	ColorizeOpen     = func(text string) string { return Colorize(text, Green+Bold) }
	ColorizeFiltered = func(text string) string { return Colorize(text, Yellow) }
	ColorizeClosed   = func(text string) string { return Colorize(text, Red) }

	// 头部和标题
	ColorizeHeader = func(text string) string { return Colorize(text, Blue+Bold) }
	ColorizeTitle  = func(text string) string { return Colorize(text, Cyan+Bold) }

	// 强调和信息
	ColorizeHighlight = func(text string) string { return Colorize(text, Magenta+Bold) }
	ColorizeInfo      = func(text string) string { return Colorize(text, BrightCyan) }
	ColorizeWarning   = func(text string) string { return Colorize(text, Yellow+Bold) }
	ColorizeError     = func(text string) string { return Colorize(text, Red+Bold) }
	ColorizeSuccess   = func(text string) string { return Colorize(text, Green) }

	// 统计和数字
	ColorizeNumber = func(text string) string { return Colorize(text, BrightYellow) }
)
