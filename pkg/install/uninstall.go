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
	result.WireGuardRemoved = removePackages(sysInfo)
	result.ZeroTrustRemoved = removeZeroTrustPackage(sysInfo)
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
		{"systemctl", "stop", "wg-quick@warp"},
		{"systemctl", "disable", "wg-quick@warp"},
		// 停止 Zero Trust / warp-cli 守护进程
		{"warp-cli", "--accept-tos", "disconnect"},
		// 不删除注册，只断开连接
		// {"warp-cli", "--accept-tos", "registration", "delete"},
		{"systemctl", "stop", "warp-svc"},
		{"systemctl", "disable", "warp-svc"},
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
func removePackages(sysInfo *system.SysInfo) bool {
	if sysInfo == nil {
		return false
	}
	var cmds [][]string
	switch sysInfo.PkgManager {
	case system.PkgAPT:
		cmds = [][]string{
			// 只卸载 wireguard-tools，不卸载 openresolv/resolvconf（它们可能是系统必需的）
			{"apt-get", "remove", "-y", "--purge", "wireguard-tools"},
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
func removeZeroTrustPackage(sysInfo *system.SysInfo) bool {
	if sysInfo == nil {
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
	// 1. 删除所有 fwmark 51820 策略路由规则（重试多次确保清干净）
	// 包括 IPv4 和 IPv6 的各种规则
	for i := 0; i < 10; i++ {
		out, _ := exec.Command("ip", "rule", "show").Output()
		if !strings.Contains(string(out), "51820") && !strings.Contains(string(out), "warp") {
			break
		}
		// 删除各种可能的规则
		exec.Command("ip", "rule", "del", "fwmark", "51820", "table", "51820").Run()
		exec.Command("ip", "rule", "del", "not", "fwmark", "51820", "table", "51820").Run()
		exec.Command("ip", "rule", "del", "table", "main", "suppress_prefixlength", "0").Run()
	}

	// 1b. 清理 IPv6 规则
	for i := 0; i < 10; i++ {
		out, _ := exec.Command("ip", "-6", "rule", "show").Output()
		if !strings.Contains(string(out), "51820") && !strings.Contains(string(out), "warp") {
			break
		}
		exec.Command("ip", "-6", "rule", "del", "fwmark", "51820", "table", "51820").Run()
		exec.Command("ip", "-6", "rule", "del", "not", "fwmark", "51820", "table", "51820").Run()
		exec.Command("ip", "-6", "rule", "del", "table", "main", "suppress_prefixlength", "0").Run()
	}

	// 1c. 清理 warp 添加的 from/to 规则（仅删除与 warp 相关的规则）
	// 不删除系统原有的路由规则
	out, _ := exec.Command("ip", "rule", "show").Output()
	for _, line := range strings.Split(string(out), "\n") {
		// 只删除明确由 warp 添加的规则（包含 "warp" 关键字）
		if strings.Contains(line, "warp") && !strings.Contains(line, "main") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				priority := fields[0]
				exec.Command("ip", "rule", "del", "priority", priority).Run()
			}
		}
	}

	// 2. 清空路由表 51820（IPv4 和 IPv6）
	exec.Command("ip", "route", "flush", "table", "51820").Run()
	exec.Command("ip", "-6", "route", "flush", "table", "51820").Run()

	// 3. 删除 warp 接口（如果还残留）
	exec.Command("ip", "link", "delete", "dev", config.WarpIfName).Run()

	// 4. 清理 iptables 规则和链
	if _, err := exec.LookPath("iptables"); err == nil {
		// 删除 mangle 表规则
		rules := [][]string{
			{"-t", "mangle", "-D", "PREROUTING", "-d", "162.159.0.0/16", "-j", "MARK", "--set-mark", "51820"},
			{"-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-m", "multiport", "--sports", "22", "-j", "MARK", "--set-mark", "51820"},
		}
		for _, r := range rules {
			exec.Command("iptables", r...).Run()
		}
		// 清理 nat 表的 WARP_PROXY 链（Zero Trust 透明代理）
		exec.Command("iptables", "-t", "nat", "-F", "WARP_PROXY").Run()
		exec.Command("iptables", "-t", "nat", "-X", "WARP_PROXY").Run()
		// 清理 OUTPUT 链的规则
		exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "WARP_PROXY").Run()
	}
	if _, err := exec.LookPath("ip6tables"); err == nil {
		exec.Command("ip6tables", "-t", "mangle", "-D", "PREROUTING",
			"-d", "2606:4700::/32", "-j", "MARK", "--set-mark", "51820").Run()
		// 清理 IPv6 的 nat 表
		exec.Command("ip6tables", "-t", "nat", "-F", "WARP_PROXY").Run()
		exec.Command("ip6tables", "-t", "nat", "-X", "WARP_PROXY").Run()
	}

	// 5. 清理 nftables warpgo 表（IPv4 和 IPv6）
	if _, err := exec.LookPath("nft"); err == nil {
		exec.Command("nft", "delete", "table", "ip", "warpgo").Run()
		exec.Command("nft", "delete", "table", "ip6", "warpgo").Run()
		// 不要删除整个 nat 表，只删除 warpgo 相关的链
		// 如果有 warpgo 链在 nat 表中，删除它
		exec.Command("nft", "delete", "chain", "ip", "nat", "warpgo").Run()
		exec.Command("nft", "delete", "chain", "ip6", "nat", "warpgo").Run()
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

	// 7b. 确保 resolv.conf 存在且有效
	if data, err := os.ReadFile("/etc/resolv.conf"); err != nil || len(data) == 0 {
		// 如果 resolv.conf 为空或不存在，创建一个默认的
		defaultDNS := "nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n"
		os.WriteFile("/etc/resolv.conf", []byte(defaultDNS), 0644)
	}

	// 8. 清理 resolvconf 中 warp 的 DNS 条目（如果命令存在）
	if _, err := exec.LookPath("resolvconf"); err == nil {
		exec.Command("resolvconf", "-d", config.WarpIfName, "-f").Run()
	}

	// 9. 清理 gai.conf 中 warp 添加的 IPv6 优先规则（如有）
	if data, err := os.ReadFile("/etc/gai.conf"); err == nil {
		content := string(data)
		content = strings.ReplaceAll(content, "precedence ::ffff:0:0/96  100\n", "")
		os.WriteFile("/etc/gai.conf", []byte(content), 0644)
	}

	// 10. 不重置 sysctl 参数，避免影响系统网络
	// 11. 不重启网络服务，避免中断当前连接
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
		"/etc/systemd/system/wg-quick@warp.service",
	}
	for _, s := range serviceFiles {
		os.Remove(s)
	}

	// warp-cli 相关文件
	os.RemoveAll("/var/lib/cloudflare-warp")
	os.RemoveAll("/etc/cloudflare-warp")

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
	homeDir := os.Getenv("HOME")
	if homeDir != "" {
		localWarpDirs := []string{
			homeDir + "/.local/share/warp",
			homeDir + "/.config/warp",
			homeDir + "/.cache/warp",
		}
		for _, d := range localWarpDirs {
			os.RemoveAll(d)
		}
	}

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
