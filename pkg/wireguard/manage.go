package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/network"
)

// IsInstalled 检测 WireGuard 接口是否已安装（配置文件存在）
func IsInstalled() bool {
	_, err := os.Stat(config.WarpConfPath)
	return err == nil
}

// IsRunning 检测 WARP WireGuard 接口是否正在运行
func IsRunning() bool {
	out, err := exec.Command("wg", "show", config.WarpIfName).Output()
	return err == nil && strings.Contains(string(out), "interface:")
}

// Up 启动 WARP WireGuard 接口
func Up() error {
	if IsRunning() {
		return fmt.Errorf("WARP 接口已在运行")
	}
	cmd := exec.Command("wg-quick", "up", config.WarpIfName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Down 停止 WARP WireGuard 接口
func Down() error {
	if !IsRunning() {
		return nil
	}
	cmd := exec.Command("wg-quick", "down", config.WarpIfName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Toggle 切换 WARP 状态
func Toggle() error {
	if IsRunning() {
		return Down()
	}
	return Up()
}

// EnableAutoStart 设置开机自启
func EnableAutoStart() error {
	return exec.Command("systemctl", "enable", "wg-quick@warp").Run()
}

// DisableAutoStart 取消开机自启
func DisableAutoStart() error {
	return exec.Command("systemctl", "disable", "wg-quick@warp").Run()
}

// Restart 重启 WARP 接口
func Restart() error {
	Down()
	time.Sleep(time.Second)
	return Up()
}

// SwitchStack 切换双栈模式（修改 AllowedIPs 注释）
func SwitchStack(newMode config.StackMode) error {
	data, err := os.ReadFile(config.WarpConfPath)
	if err != nil {
		return fmt.Errorf("读取 warp.conf 失败: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch newMode {
		case config.StackIPv4:
			// 启用 0.0.0.0/0，禁用 ::/0
			if strings.HasPrefix(trimmed, "# AllowedIPs") && strings.Contains(trimmed, "0.0.0.0/0") {
				lines[i] = strings.Replace(line, "# AllowedIPs", "AllowedIPs", 1)
			} else if strings.HasPrefix(trimmed, "AllowedIPs") && strings.Contains(trimmed, "::/0") {
				lines[i] = "# " + line
			}
		case config.StackIPv6:
			// 启用 ::/0，禁用 0.0.0.0/0
			if strings.HasPrefix(trimmed, "# AllowedIPs") && strings.Contains(trimmed, "::/0") {
				lines[i] = strings.Replace(line, "# AllowedIPs", "AllowedIPs", 1)
			} else if strings.HasPrefix(trimmed, "AllowedIPs") && strings.Contains(trimmed, "0.0.0.0/0") {
				lines[i] = "# " + line
			}
		case config.StackDual:
			// 启用所有
			if strings.HasPrefix(trimmed, "# AllowedIPs") {
				lines[i] = strings.Replace(line, "# AllowedIPs", "AllowedIPs", 1)
			}
		}
	}

	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(config.WarpConfPath, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("写入 warp.conf 失败: %v", err)
	}
	return Restart()
}

// SwitchGlobalMode 切换全局/非全局模式
func SwitchGlobalMode(global bool) error {
	data, err := os.ReadFile(config.WarpConfPath)
	if err != nil {
		return fmt.Errorf("读取 warp.conf 失败: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string

	// 先移除所有 PostUp/PostDown/PreUp/Table 行
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PostUp") || strings.HasPrefix(trimmed, "PostDown") ||
			strings.HasPrefix(trimmed, "PreUp") || trimmed == "Table = off" {
			continue
		}
		newLines = append(newLines, line)
	}

	// 找 [Peer] 行的位置，在它前面插入新规则
	insertIdx := -1
	for i, line := range newLines {
		if strings.TrimSpace(line) == "[Peer]" {
			insertIdx = i
			break
		}
	}

	var rules []string
	if global {
		// 全局模式：检测 LAN IP 并写入 PostUp（和 menu.sh 一致）
		lan4 := network.DetectLAN4()
		lan6 := network.DetectLAN6()
		if lan4 != "" {
			rules = append(rules, fmt.Sprintf("PostUp = ip -4 rule add from %s lookup main", lan4))
			rules = append(rules, fmt.Sprintf("PostDown = ip -4 rule delete from %s lookup main", lan4))
		}
		if lan6 != "" {
			rules = append(rules, fmt.Sprintf("PostUp = ip -6 rule add from %s lookup main", lan6))
			rules = append(rules, fmt.Sprintf("PostDown = ip -6 rule delete from %s lookup main", lan6))
		}
		rules = append(rules, "PostUp = ip -4 rule add from 172.17.0.0/24 lookup main")
		rules = append(rules, "PostDown = ip -4 rule delete from 172.17.0.0/24 lookup main")
	} else {
		// 非全局模式
		rules = append(rules, "Table = off")
		rules = append(rules, fmt.Sprintf("PostUp = %s/NonGlobalUp.sh", config.ScriptDir))
		rules = append(rules, fmt.Sprintf("PostDown = %s/NonGlobalDown.sh", config.ScriptDir))
	}

	if insertIdx > 0 {
		// 在 [Peer] 前插入
		result := make([]string, 0, len(newLines)+len(rules))
		result = append(result, newLines[:insertIdx]...)
		result = append(result, rules...)
		result = append(result, "") // 空行
		result = append(result, newLines[insertIdx:]...)
		newLines = result
	}

	newContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(config.WarpConfPath, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("写入 warp.conf 失败: %v", err)
	}
	WriteScripts(config.ScriptDir)
	return Restart()
}

// GetCurrentStack 从 warp.conf 读取当前双栈状态
func GetCurrentStack() config.StackMode {
	data, err := os.ReadFile(config.WarpConfPath)
	if err != nil {
		return config.StackDual
	}
	content := string(data)

	hasV4 := strings.Contains(content, "AllowedIPs = 0.0.0.0/0") ||
		(strings.Contains(content, "AllowedIPs") && strings.Contains(content, "0.0.0.0/0"))
	hasV6 := strings.Contains(content, "AllowedIPs = ::/0") ||
		(strings.Contains(content, "AllowedIPs") && strings.Contains(content, "::/0"))
	// 检查被注释掉的
	commentedV4 := strings.Contains(content, "# AllowedIPs") && strings.Contains(content, "0.0.0.0/0")
	commentedV6 := strings.Contains(content, "# AllowedIPs") && strings.Contains(content, "::/0")

	if commentedV4 {
		hasV4 = false
	}
	if commentedV6 {
		hasV6 = false
	}

	switch {
	case hasV4 && hasV6:
		return config.StackDual
	case hasV4:
		return config.StackIPv4
	case hasV6:
		return config.StackIPv6
	}
	return config.StackDual
}

// IsGlobalMode 检测当前是否为全局模式
func IsGlobalMode() bool {
	data, err := os.ReadFile(config.WarpConfPath)
	if err != nil {
		return false
	}
	// 现在全局模式不再依赖不写 Table=off，而是识别是否使用了 GlobalUp.sh
	return strings.Contains(string(data), "GlobalUp.sh")
}

// InstallWireGuardTools 安装 wireguard-tools
func InstallWireGuardTools(pm int) error {
	var cmd *exec.Cmd
	switch pm {
	case 0: // APT
		exec.Command("apt-get", "update", "-qq").Run()
		cmd = exec.Command("apt-get", "install", "-y", "-qq", "wireguard-tools", "openresolv")
	case 1, 2: // YUM/DNF
		cmd = exec.Command("dnf", "install", "-y", "wireguard-tools")
	case 3: // APK
		cmd = exec.Command("apk", "add", "--no-cache", "wireguard-tools")
	case 4: // Pacman
		cmd = exec.Command("pacman", "-S", "--noconfirm", "wireguard-tools")
	default:
		return fmt.Errorf("不支持的包管理器")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
