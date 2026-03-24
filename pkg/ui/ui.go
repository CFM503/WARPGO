package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ANSI 颜色码
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m\033[01m"
	colorGreen  = "\033[32m\033[01m"
	colorYellow = "\033[33m\033[01m"
	colorBlue   = "\033[34m\033[01m"
	colorCyan   = "\033[36m\033[01m"
	colorWhite  = "\033[37m\033[01m"
)

// ANSI 样式码
const (
	styleBold = "\033[1m"
	styleDim  = "\033[2m"
)

// Info 绿色信息
func Info(msg string) {
	fmt.Printf("%s %s %s\n", colorGreen, msg, colorReset)
}

// Warning 黄色警告
func Warning(msg string) {
	fmt.Printf("%s %s %s\n", colorYellow, msg, colorReset)
}

// Error 红色错误并退出
func Error(msg string) {
	fmt.Printf("%s %s %s\n", colorRed, msg, colorReset)
	os.Exit(1)
}

// ErrorMsg 红色错误（不退出）
func ErrorMsg(msg string) {
	fmt.Printf("%s %s %s\n", colorRed, msg, colorReset)
}

// Hint 黄色提示
func Hint(msg string) {
	fmt.Printf("%s %s %s\n", colorYellow, msg, colorReset)
}

// Header 青色标题
func Header(msg string) {
	fmt.Printf("%s %s %s\n", colorCyan, msg, colorReset)
}

// Separator 分隔线
func Separator() {
	fmt.Println(strings.Repeat("=", 100))
}

// Blank 空行
func Blank() {
	fmt.Println()
}

// ReadInput 读取用户输入（带绿色提示）
func ReadInput(prompt string) string {
	fmt.Printf("%s %s %s", colorGreen, prompt, colorReset)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

// Confirm 确认对话框（y/n）
func Confirm(prompt string) bool {
	ans := ReadInput(prompt + " [y/N]: ")
	return strings.ToLower(ans) == "y"
}

// MenuItem 菜单项
type MenuItem struct {
	Key         string
	Label       string
	Description string
}

// ShowMenu 显示菜单并返回用户选择
func ShowMenu(title string, items []MenuItem) string {
	Blank()
	Separator()
	Header(title)
	Separator()
	Blank()
	for _, item := range items {
		if item.Description != "" {
			Hint(fmt.Sprintf("  %s. %-30s %s", item.Key, item.Label, item.Description))
		} else {
			Hint(fmt.Sprintf("  %s. %s", item.Key, item.Label))
		}
	}
	Blank()
	return ReadInput("请输入选项: ")
}

// PrintKV 格式化打印 key: value
func PrintKV(key, value string) {
	fmt.Printf("%s  %-20s%s %s\n", colorCyan, key+":", colorReset, value)
}

// PrintStatus 打印状态（运行中/已停止）
func PrintStatus(name string, running bool) {
	if running {
		fmt.Printf("%s  %-30s%s %s运行中%s\n", colorCyan, name+":", colorReset, colorGreen, colorReset)
	} else {
		fmt.Printf("%s  %-30s%s %s已停止%s\n", colorCyan, name+":", colorReset, colorRed, colorReset)
	}
}

// Clear 清屏
func Clear() {
	fmt.Print("\033[H\033[2J")
}

// PrintBanner 打印程序横幅
func PrintBanner(version string, sysInfo, wanInfo string) {
	Clear()
	Separator()
	fmt.Printf("%s  WarpGo v%s — Cloudflare WARP & Zero Trust 管理工具%s\n", colorCyan, version, colorReset)
	Separator()
	fmt.Printf("%s  系统信息: %s%s\n", colorGreen, sysInfo, colorReset)
	fmt.Printf("%s  网络信息: %s%s\n", colorGreen, wanInfo, colorReset)
	Separator()
}

// PrintStatusPanel 打印状态面板（新版本）
func PrintStatusPanel(version string, sysInfo string, connectionType string, connectionInfo string, networkInfo string) {
	Clear()
	Separator()
	fmt.Printf("%s  WarpGo v%s — Cloudflare WARP & Zero Trust 管理工具%s\n", colorCyan, version, colorReset)
	Separator()

	// 系统信息
	fmt.Printf("%s  系统信息: %s%s\n", colorGreen, sysInfo, colorReset)

	// 连接类型（用不同颜色区分状态）
	if connectionType != "" {
		if strings.Contains(connectionType, "未安装") {
			fmt.Printf("%s  接入方式: %s%s\n", colorYellow, connectionType, colorReset)
		} else if strings.Contains(connectionType, "已停止") || strings.Contains(connectionType, "已断开") {
			fmt.Printf("%s  接入方式: %s%s\n", colorRed, connectionType, colorReset)
		} else {
			fmt.Printf("%s  接入方式: %s%s\n", colorGreen, connectionType, colorReset)
		}
	}

	// 连接信息（Zero Trust 组织名等）
	if connectionInfo != "" {
		fmt.Printf("%s  接入信息: %s%s\n", colorCyan, connectionInfo, colorReset)
	}

	// 网络信息
	fmt.Printf("%s  网络信息: %s%s\n", colorGreen, networkInfo, colorReset)

	Separator()
}

// PrintStatusLine 打印状态行
func PrintStatusLine(label string, value string, status bool) {
	statusText := ""
	if status {
		statusText = fmt.Sprintf("%s✓ 运行中%s", colorGreen, colorReset)
	} else {
		statusText = fmt.Sprintf("%s✗ 已停止%s", colorRed, colorReset)
	}
	fmt.Printf("%s  %-12s%s %s %s\n", colorCyan, label+":", colorReset, value, statusText)
}

// PrintInfoLine 打印信息行
func PrintInfoLine(label string, value string) {
	fmt.Printf("%s  %-12s%s %s\n", colorCyan, label+":", colorReset, value)
}
