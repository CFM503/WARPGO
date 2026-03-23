package install

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/system"
	"github.com/pzeus/warpgo/pkg/ui"
	"github.com/pzeus/warpgo/pkg/warp"
	"github.com/pzeus/warpgo/pkg/zerotrust"
)

// UninstallResult 卸载结果摘要
type UninstallResult struct {
	WireGuardRemoved bool
	WireProxyRemoved bool
	ZeroTrustRemoved bool
}

// Uninstall 一键完全卸载：清理所有组件、配置、网络规则，让服务器恢复干净原状。
// 无论在主菜单哪个状态下触发，都执行同一套完整流程。
func Uninstall() (UninstallResult, error) {
	result := UninstallResult{}
	sysInfo, _ := system.Detect()

	ui.Separator()
	ui.Header("开始完全卸载 — 将清理所有 WarpGo 相关内容")
	ui.Separator()

	// ── 第一步：停止所有服务 ──────────────────────────────────────────────
	ui.Info("步骤 1/6  停止所有运行中的服务...")
	stopAllServices()

	// ── 第二步：清理透明代理规则 ──────────────────────────────────────────
	ui.Info("步骤 2/6  清除透明代理规则...")
	zerotrust.RemoveTransparentProxy()
	zerotrust.StopRedsocks()

	// ── 第三步：注销 API 账户 ─────────────────────────────────────────────
	ui.Info("步骤 3/6  注销 Cloudflare WARP 账户...")
	cancelWarpAccount()

	// ── 第四步：卸载系统包 ────────────────────────────────────────────────
	ui.Info("步骤 4/6  卸载系统包 (wireguard-tools, cloudflare-warp, redsocks)...")
	result.WireGuardRemoved = removePackages()
	result.ZeroTrustRemoved = removeZeroTrustPackage()
	if sysInfo != nil {
		zerotrust.UninstallRedsocks(sysInfo)
	}

	// ── 第五步：清理网络规则 ──────────────────────────────────────────────
	ui.Info("步骤 5/6  清除路由规则、防火墙规则、DNS 配置...")
	cleanupNetworkRules()
	cleanupProxyEnvVars()

	// ── 第六步：删除所有文件 ──────────────────────────────────────────────
	ui.Info("步骤 6/6  删除所有配置文件和二进制文件...")
	removeAllFiles()
	result.WireProxyRemoved = true

	ui.Separator()
	ui.Info("✓ 完全卸载完成！服务器网络和端口已完全恢复原状。")
	ui.Info("请重新登录或运行 'source ~/.bashrc' 使环境变量更改生效。")
	return result, nil
}

// stopAllServices 停止所有相关服务和网络接口
func stopAllServices() {
	cmds := [][]string{
		// 停止 redsocks 透明代理
		{"systemctl", "disable", "--now", "redsocks"},
		// 停止 WireGuard WARP 接口
		{"wg-quick", "down", config.WarpIfName},
		// 停止 Zero Trust / warp-cli 守护进程
		{"warp-cli", "--accept-tos", "disconnect"},
		{"warp-cli", "--accept-tos", "registration", "delete"},
		{"systemctl", "disable", "--now", "warp-svc"},
	}
	for _, args := range cmds {
		exec.Command(args[0], args[1:]...).Run() // 忽略错误，能停则停
	}
}

// cancelWarpAccount 吊销 WARP API 账户（防止账户泄露）
func cancelWarpAccount() {
	if acc, err := warp.LoadFromFile(config.WarpAccountPath); err == nil {
		acc.Cancel()
	}
}

// removePackages 卸载 wireguard-tools 系统包
func removePackages() bool {
	sysInfo, err := system.Detect()
	if err != nil {
		return false
	}
	var cmds [][]string
	switch sysInfo.PkgManager {
	case system.PkgAPT:
		cmds = [][]string{
			{"apt-get", "remove", "-y", "--purge", "wireguard-tools", "openresolv", "resolvconf"},
			{"apt-get", "autoremove", "-y"},
		}
	case system.PkgYUM, system.PkgDNF:
		cmds = [][]string{
			{"yum", "remove", "-y", "wireguard-tools"},
		}
	case system.PkgAPK:
		cmds = [][]string{
			{"apk", "del", "wireguard-tools"},
		}
	case system.PkgPacman:
		cmds = [][]string{
			{"pacman", "-R", "--noconfirm", "wireguard-tools"},
		}
	}
	ok := false
	for _, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err == nil {
			ok = true
		}
	}
	return ok
}

// removeZeroTrustPackage 卸载 cloudflare-warp (warp-cli) 包
func removeZeroTrustPackage() bool {
	sysInfo, err := system.Detect()
	if err != nil {
		return false
	}
	var cmd *exec.Cmd
	switch sysInfo.PkgManager {
	case system.PkgAPT:
		cmd = exec.Command("apt-get", "remove", "-y", "--purge", "cloudflare-warp")
	case system.PkgYUM, system.PkgDNF:
		cmd = exec.Command("yum", "remove", "-y", "cloudflare-warp")
	default:
		return false
	}
	if err := cmd.Run(); err == nil {
		// 也清理软件源配置
		os.Remove("/etc/apt/sources.list.d/cloudflare-client.list")
		os.Remove("/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg")
		os.Remove("/etc/yum.repos.d/cloudflare-warp.repo")
		exec.Command("apt-get", "autoremove", "-y").Run()
		return true
	}
	return false
}

// cleanupNetworkRules 强制清除所有 WarpGo 创建的网络规则
func cleanupNetworkRules() {
	// 1. 删除 fwmark 51820 策略路由规则（重试多次确保清干净）
	for i := 0; i < 5; i++ {
		out, _ := exec.Command("ip", "rule", "show").Output()
		if !strings.Contains(string(out), "51820") {
			break
		}
		exec.Command("ip", "rule", "del", "fwmark", "51820", "table", "51820").Run()
	}

	// 2. 清空路由表 51820
	exec.Command("ip", "route", "flush", "table", "51820").Run()

	// 3. 删除 warp 接口（如果还残留）
	exec.Command("ip", "link", "delete", "dev", config.WarpIfName).Run()

	// 4. 清理 iptables 规则
	if _, err := exec.LookPath("iptables"); err == nil {
		rules := [][]string{
			{"-t", "mangle", "-D", "PREROUTING", "-d", "162.159.0.0/16", "-j", "MARK", "--set-mark", "51820"},
		}
		for _, r := range rules {
			exec.Command("iptables", r...).Run()
		}
	}
	if _, err := exec.LookPath("ip6tables"); err == nil {
		exec.Command("ip6tables", "-t", "mangle", "-D", "PREROUTING",
			"-d", "2606:4700::/32", "-j", "MARK", "--set-mark", "51820").Run()
	}

	// 5. 清理 nftables warpgo 表（Debian 12+/Ubuntu 22+ 现代系统）
	if _, err := exec.LookPath("nft"); err == nil {
		exec.Command("nft", "delete", "table", "ip", "warpgo").Run()
	}

	// 6. 清理 /etc/iproute2/rt_tables 中 warp 相关条目
	rtPath := "/etc/iproute2/rt_tables"
	if data, err := os.ReadFile(rtPath); err == nil {
		var clean []string
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "51820") && !strings.Contains(line, "warp") {
				clean = append(clean, line)
			}
		}
		os.WriteFile(rtPath, []byte(strings.Join(clean, "\n")), 0644)
	}

	// 7. 恢复 resolv.conf（如有备份）
	if _, err := os.Stat("/etc/resolv.conf.origin"); err == nil {
		exec.Command("mv", "-f", "/etc/resolv.conf.origin", "/etc/resolv.conf").Run()
	}

	// 8. 清理 resolvconf 中 warp 的 DNS 条目
	exec.Command("resolvconf", "-d", config.WarpIfName, "-f").Run()

	// 9. 清理 gai.conf 中 warp 添加的 IPv6 优先规则（如有）
	if data, err := os.ReadFile("/etc/gai.conf"); err == nil {
		content := string(data)
		content = strings.ReplaceAll(content, "precedence ::ffff:0:0/96  100\n", "")
		os.WriteFile("/etc/gai.conf", []byte(content), 0644)
	}

	// 10. 重启 DNS 服务确保解析正常
	exec.Command("systemctl", "restart", "systemd-resolved").Run()
	exec.Command("systemctl", "daemon-reload").Run()
}

// removeAllFiles 删除所有配置文件、脚本、二进制、服务单元
func removeAllFiles() {
	// /etc/wireguard/ 下的所有 warp 相关文件
	wireguardFiles := []string{
		config.WarpConfPath,               // warp.conf
		config.WarpAccountPath,            // warp-account.conf
		config.ZeroTrustConfigPath,        // zerotrust.conf
		config.TransparentProxyConfigPath, // transparent-proxy.conf
		config.ScriptDir + "/NonGlobalUp.sh",
		config.ScriptDir + "/NonGlobalDown.sh",
		config.ScriptDir + "/GlobalUp.sh",
		config.ScriptDir + "/GlobalDown.sh",
		config.ScriptDir + "/up",
		config.ScriptDir + "/down",
		config.ScriptDir + "/proxy.conf",
		config.ScriptDir + "/language",
		config.ScriptDir + "/menu.sh",
	}
	for _, f := range wireguardFiles {
		os.Remove(f)
	}
	// 尝试删除 /etc/wireguard 目录（若已空）
	os.Remove(config.ScriptDir)

	// 二进制文件
	binaries := []string{
		config.WireguardGoPath, // /usr/bin/wireguard-go
		config.WarpBinPath,     // /usr/bin/warp
	}
	for _, b := range binaries {
		os.Remove(b)
	}

	// systemd 服务单元
	serviceFiles := []string{
		"/lib/systemd/system/redsocks.service",
		"/etc/redsocks.conf",
	}
	for _, s := range serviceFiles {
		os.Remove(s)
	}

	// WarpGo 相关的运行时缓存文件
	tmpFiles := []string{
		"/tmp/best_mtu",
		"/tmp/wireguard-go-20230223",
		"/tmp/wireguard-go-20201118",
	}
	for _, t := range tmpFiles {
		os.Remove(t)
	}

	// 移除 warp-cli 的本地数据目录
	localWarpDir := os.Getenv("HOME") + "/.local/share/warp"
	os.RemoveAll(localWarpDir)

	// crontab 清理（移除任何 warp/tun.sh 相关条目）
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		var clean []string
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "tun.sh") && !strings.Contains(line, "warp") {
				clean = append(clean, line)
			}
		}
		os.WriteFile("/etc/crontab", []byte(strings.Join(clean, "\n")), 0644)
	}

	fmt.Println() // 视觉间隔
}

// cleanupProxyEnvVars 清理可能由 WarpGo 设置的代理环境变量
// 这些环境变量可能在用户的 shell 配置文件中设置
func cleanupProxyEnvVars() {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return
	}

	// 需要清理的配置文件列表
	configFiles := []string{
		homeDir + "/.bashrc",
		homeDir + "/.bash_profile",
		homeDir + "/.profile",
		homeDir + "/.zshrc",
		homeDir + "/.config/fish/config.fish",
	}

	// 代理环境变量模式
	proxyPatterns := []string{
		"http_proxy",
		"https_proxy",
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"all_proxy",
		"ALL_PROXY",
	}

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err != nil {
			continue
		}

		// 读取文件内容
		data, err := os.ReadFile(configFile)
		if err != nil {
			continue
		}

		content := string(data)
		modified := false

		// 移除包含代理设置的行
		lines := strings.Split(content, "\n")
		var cleanLines []string

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			shouldRemove := false

			// 检查是否包含代理环境变量设置
			for _, pattern := range proxyPatterns {
				if strings.HasPrefix(trimmed, pattern+"=") ||
					strings.HasPrefix(trimmed, "export "+pattern+"=") {
					shouldRemove = true
					modified = true
					break
				}
			}

			if !shouldRemove {
				cleanLines = append(cleanLines, line)
			}
		}

		// 如果有修改，写回文件
		if modified {
			newContent := strings.Join(cleanLines, "\n")
			if err := os.WriteFile(configFile, []byte(newContent), 0644); err == nil {
				ui.Info(fmt.Sprintf("已清理配置文件: %s", configFile))
			}
		}
	}

	// 提醒用户当前 shell 会话可能仍受影响
	ui.Warning("提示：当前 shell 会话中的代理环境变量需要手动清除")
	ui.Info("运行以下命令清除当前会话的代理设置:")
	ui.Info("  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY")
}
