package zerotrust

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/system"
	"github.com/pzeus/warpgo/pkg/ui"
)

const redsocksConfigTemplate = `base {
    log_debug = off;
    log_info = on;
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = %d;
    ip = 127.0.0.1;
    port = %d;
    type = socks5;
}
`

const redsocksServiceTemplate = `[Unit]
Description=Redsocks - Transparent SOCKS5 Proxy
After=network.target warp-svc.service
Wants=warp-svc.service

[Service]
Type=forking
ExecStart=/usr/sbin/redsocks -c /etc/redsocks.conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

// InstallRedsocks 安装并配置 redsocks
func InstallRedsocks(sysInfo *system.SysInfo, socksPort int) error {
	redsocksPort := config.DefaultRedsocksPort

	// 1. 安装 redsocks
	ui.Info("正在安装 redsocks...")
	if err := system.InstallPackages(sysInfo.PkgManager, "redsocks"); err != nil {
		return fmt.Errorf("安装 redsocks 失败: %v", err)
	}

	// 2. 写入配置文件
	ui.Info("正在配置 redsocks...")
	redsocksConfig := fmt.Sprintf(redsocksConfigTemplate, redsocksPort, socksPort)
	if err := os.WriteFile("/etc/redsocks.conf", []byte(redsocksConfig), 0644); err != nil {
		return fmt.Errorf("写入 redsocks 配置失败: %v", err)
	}

	// 3. 创建 systemd 服务文件（如果不存在）
	if _, err := os.Stat("/lib/systemd/system/redsocks.service"); err != nil {
		if err := os.WriteFile("/lib/systemd/system/redsocks.service", []byte(redsocksServiceTemplate), 0644); err != nil {
			ui.Warning(fmt.Sprintf("创建 systemd 服务失败: %v", err))
		} else {
			exec.Command("systemctl", "daemon-reload").Run()
		}
	}

	// 4. 启动 redsocks
	ui.Info("正在启动 redsocks...")
	exec.Command("systemctl", "enable", "redsocks").Run()
	exec.Command("systemctl", "restart", "redsocks").Run()

	ui.Info(fmt.Sprintf("✓ redsocks 已安装，透明代理端口: %d", redsocksPort))
	return nil
}

// SetupTransparentProxy 设置 iptables 透明代理规则
func SetupTransparentProxy() error {
	redsocksPort := config.DefaultRedsocksPort

	ui.Info("正在配置透明代理规则...")

	// 创建自定义链
	exec.Command("iptables", "-t", "nat", "-N", "WARP_PROXY").Run()

	// 清空链（如果已存在）
	exec.Command("iptables", "-t", "nat", "-F", "WARP_PROXY").Run()

	// 排除本地流量
	localRanges := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range localRanges {
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-d", cidr, "-j", "RETURN").Run()
	}

	// 排除 Cloudflare WARP 服务器
	exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-d", "162.159.192.0/24", "-j", "RETURN").Run()

	// 排除 redsocks 端口（防止循环）
	exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-p", "tcp", "--dport", fmt.Sprintf("%d", redsocksPort), "-j", "RETURN").Run()

	// 排除 SSH 客户端 IP（防止 SSH 断开）
	// 使用网络包中的 network 包来检测 SSH 客户端
	sshClientIP := detectSSHClientIPFromSS()
	if sshClientIP != "" {
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-d", sshClientIP, "-j", "RETURN").Run()
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-s", sshClientIP, "-j", "RETURN").Run()
		ui.Info(fmt.Sprintf("已排除 SSH 客户端: %s", sshClientIP))
	}

	// 其他 TCP 流量重定向到 redsocks
	exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redsocksPort)).Run()

	// 将 OUTPUT 链的 TCP 流量发到 WARP_PROXY 链
	exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "WARP_PROXY").Run()

	ui.Info("✓ 透明代理规则已配置")
	return nil
}

// detectSSHClientIPFromSS 检测 SSH 客户端 IP
func detectSSHClientIPFromSS() string {
	out, err := exec.Command("ss", "-tnp").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "sshd") {
			continue
		}
		if !strings.Contains(line, "ESTAB") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		peer := fields[4]
		idx := strings.LastIndex(peer, ":")
		if idx > 0 {
			ip := peer[:idx]
			if ip != "127.0.0.1" && !strings.HasPrefix(ip, "10.") && !strings.HasPrefix(ip, "172.") && !strings.HasPrefix(ip, "192.168.") {
				return ip
			}
		}
	}
	return ""
}

// RemoveTransparentProxy 清理 iptables 透明代理规则
func RemoveTransparentProxy() {
	ui.Info("正在清理透明代理规则...")

	// 从 OUTPUT 链删除规则
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "WARP_PROXY").Run()

	// 清空自定义链
	exec.Command("iptables", "-t", "nat", "-F", "WARP_PROXY").Run()

	// 删除自定义链
	exec.Command("iptables", "-t", "nat", "-X", "WARP_PROXY").Run()

	ui.Info("✓ 透明代理规则已清理")
}

// StopRedsocks 停止 redsocks 服务
func StopRedsocks() {
	exec.Command("systemctl", "disable", "--now", "redsocks").Run()
}

// UninstallRedsocks 卸载 redsocks
func UninstallRedsocks(sysInfo *system.SysInfo) {
	// 停止服务
	StopRedsocks()

	// 删除配置文件
	os.Remove("/etc/redsocks.conf")
	os.Remove("/lib/systemd/system/redsocks.service")

	// 卸载包
	switch sysInfo.PkgManager {
	case system.PkgAPT:
		exec.Command("apt-get", "remove", "-y", "--purge", "redsocks").Run()
	case system.PkgYUM, system.PkgDNF:
		exec.Command("yum", "remove", "-y", "redsocks").Run()
	}

	exec.Command("systemctl", "daemon-reload").Run()
}

// IsRedsocksInstalled 检查 redsocks 是否已安装
func IsRedsocksInstalled() bool {
	_, err := os.Stat("/etc/redsocks.conf")
	if err == nil {
		return true
	}
	_, err = exec.LookPath("redsocks")
	return err == nil
}

// IsRedsocksRunning 检查 redsocks 是否正在运行
func IsRedsocksRunning() bool {
	out, err := exec.Command("systemctl", "is-active", "redsocks").Output()
	if err == nil {
		return strings.TrimSpace(string(out)) == "active"
	}
	return false
}

// SaveTransparentProxyConfig 保存透明代理配置状态
func SaveTransparentProxyConfig(enabled bool) error {
	var content string
	if enabled {
		content = "enabled=true\n"
	} else {
		content = "enabled=false\n"
	}
	return os.WriteFile(config.TransparentProxyConfigPath, []byte(content), 0644)
}

// LoadTransparentProxyConfig 加载透明代理配置状态
func LoadTransparentProxyConfig() bool {
	data, err := os.ReadFile(config.TransparentProxyConfigPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "enabled=true")
}
