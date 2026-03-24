package install

import (
	"fmt"
	"net"
	"time"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/network"
	"github.com/pzeus/warpgo/pkg/system"
	"github.com/pzeus/warpgo/pkg/ui"
	"github.com/pzeus/warpgo/pkg/warp"
	"github.com/pzeus/warpgo/pkg/wireguard"
	"github.com/pzeus/warpgo/pkg/zerotrust"
)

// InstallOptions 安装选项
type InstallOptions struct {
	Mode       config.InstallMode
	StackMode  config.StackMode
	GlobalMode bool
	Port       int
	Endpoint   string
	GHProxy    string
	// Zero Trust
	ZeroTrustOrg          string
	ZeroTrustProxy        bool                       // Zero Trust 使用代理模式
	ZeroTrustEnrollMode   config.ZeroTrustEnrollMode // 接入方式
	ZeroTrustClientID     string                     // Service Token Client ID
	ZeroTrustClientSecret string                     // Service Token Client Secret
}

// Install 主安装函数
func Install(sysInfo *system.SysInfo, opts *InstallOptions) error {
	switch opts.Mode {
	case config.ModeWireGuardV4, config.ModeWireGuardV6, config.ModeWireGuardDual:
		return installWireGuard(sysInfo, opts)
	case config.ModeZeroTrust:
		return installZeroTrust(sysInfo, opts)
	default:
		return fmt.Errorf("不支持的安装模式")
	}
}

// installWireGuard 安装 WireGuard WARP 接口
func installWireGuard(sysInfo *system.SysInfo, opts *InstallOptions) error {
	// 1. 安装 wireguard-tools
	ui.Info("正在安装 wireguard-tools...")
	if err := wireguard.InstallWireGuardTools(int(sysInfo.PkgManager)); err != nil {
		return fmt.Errorf("安装 wireguard-tools 失败: %v", err)
	}

	// 2. 注册 WARP 账户
	ui.Info("正在注册 WARP 账户...")
	acc, err := warp.Register()
	if err != nil {
		return fmt.Errorf("注册 WARP 账户失败: %v", err)
	}
	ui.Info(fmt.Sprintf("账户注册成功: %s (类型: %s)", acc.ID, acc.AccountInfo.AccountType))

	// 3. 保存账户文件
	if err := acc.SaveToFile(config.WarpAccountPath); err != nil {
		return fmt.Errorf("保存账户文件失败: %v", err)
	}

	// 4. 检测最佳 MTU
	ui.Info("正在检测最佳 MTU...")
	mtu := detectMTU(opts.Endpoint)
	ui.Info(fmt.Sprintf("最佳 MTU: %d", mtu))

	// 5. 确定 Endpoint
	if opts.Endpoint == "" {
		opts.Endpoint = acc.GetEndpoint(!sysInfo.HasIPv4)
	}

	// 6. 确定 StackMode
	stackMode := determineStackMode(opts, sysInfo)

	// 7. 生成 WireGuard 配置
	ui.Info("正在生成 WireGuard 配置文件...")
	wgCfg := wireguard.BuildFromAccount(acc, stackMode, opts.GlobalMode, mtu, opts.Endpoint)
	confContent := wireguard.Generate(acc, wgCfg)

	// 8. 写入配置文件
	if err := wireguard.WriteConfig(confContent, config.WarpConfPath); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	// 9. 写入脚本（现在包括 GlobalUp/Down 和 NonGlobalUp/Down）
	if err := wireguard.WriteScripts(config.ScriptDir); err != nil {
		ui.Warning(fmt.Sprintf("写入脚本失败: %v", err))
	}

	// 10. 启动并设置自启
	ui.Info("正在启动 WARP...")
	if err := wireguard.Up(); err != nil {
		return fmt.Errorf("启动 WARP 失败: %v", err)
	}
	wireguard.EnableAutoStart()

	ui.Info("✓ WARP 安装完成！")

	// 等待隧道握手完成后再检测网络
	ui.Info("等待 WARP 隧道建立...")
	time.Sleep(5 * time.Second)
	showNetworkResult()
	return nil
}

// installZeroTrust 安装 Cloudflare Zero Trust
func installZeroTrust(sysInfo *system.SysInfo, opts *InstallOptions) error {
	// 1. 安装 warp-cli
	if !zerotrust.IsWarpCLIInstalled() {
		ui.Info("正在安装 Cloudflare WARP 客户端...")
		if err := zerotrust.InstallWarpCLI(int(sysInfo.PkgManager)); err != nil {
			return fmt.Errorf("安装 warp-cli 失败: %v", err)
		}
	}

	// 2. 确定 SOCKS5 端口
	socksPort := config.DefaultSocks5Port

	// 3. 默认使用代理模式（非全局）
	useProxyMode := true

	// 4. 注册（Service Token 方式，代理模式通过 MDM 配置）
	ui.Info("使用 Service Token 方式加入 Zero Trust...")
	if err := zerotrust.EnrollServiceToken(opts.ZeroTrustOrg, opts.ZeroTrustClientID, opts.ZeroTrustClientSecret, useProxyMode, socksPort); err != nil {
		return fmt.Errorf("Zero Trust 注册失败: %v", err)
	}

	ui.Info(fmt.Sprintf("代理模式已配置，SOCKS5: 127.0.0.1:%d", socksPort))

	// 5. 连接
	ui.Info("正在连接 Zero Trust...")
	if err := zerotrust.Connect(); err != nil {
		return fmt.Errorf("连接 Zero Trust 失败: %v", err)
	}

	// 6. 安装 redsocks 透明代理
	ui.Info("正在配置透明代理，使 VPS 所有出站流量通过 WARP...")
	if err := zerotrust.InstallRedsocks(sysInfo, socksPort); err != nil {
		ui.Warning(fmt.Sprintf("安装 redsocks 失败: %v", err))
		ui.Warning("代理模式仍然可用，但透明代理未配置")
	}

	// 7. 配置 iptables 透明代理规则
	if err := zerotrust.SetupTransparentProxy(); err != nil {
		ui.Warning(fmt.Sprintf("配置透明代理规则失败: %v", err))
	}

	// 8. 保存透明代理配置状态
	zerotrust.SaveTransparentProxyConfig(true)

	// 9. 保存配置
	ztCfg := &zerotrust.ZeroTrustConfig{
		OrgName:      opts.ZeroTrustOrg,
		ClientID:     opts.ZeroTrustClientID,
		ClientSecret: opts.ZeroTrustClientSecret,
	}
	zerotrust.WriteZeroTrustConfig(ztCfg)

	ui.Info("✓ Cloudflare Zero Trust 安装完成！")
	ui.Info("")
	ui.Info("出站流量: VPS → redsocks → SOCKS5(127.0.0.1:40001) → WARP → 互联网")
	ui.Info("入站流量: SSH、Web 等端口正常访问，不受影响")
	ui.Info("")
	showNetworkResult()
	return nil
}

// determineStackMode 根据选项和系统能力确定双栈模式
func determineStackMode(opts *InstallOptions, sysInfo *system.SysInfo) config.StackMode {
	switch opts.Mode {
	case config.ModeWireGuardV4:
		return config.StackIPv4
	case config.ModeWireGuardV6:
		return config.StackIPv6
	case config.ModeWireGuardDual:
		return config.StackDual
	}
	// 根据系统网络能力推断
	if sysInfo.HasIPv4 && sysInfo.HasIPv6 {
		return config.StackDual
	}
	if sysInfo.HasIPv6 {
		return config.StackIPv6
	}
	return config.StackIPv4
}

// detectMTU 检测最佳 MTU
func detectMTU(endpoint string) int {
	if endpoint == "" {
		endpoint = "1.1.1.1"
	}
	mtu := network.FindBestMTU(endpoint)
	if mtu <= 0 || mtu > 1500 {
		return config.DefaultMTU
	}
	// WARP 推荐 MTU 减 80
	if mtu > 80 {
		mtu -= 80
	}
	return mtu
}

// findFreePort 从给定端口开始找一个空闲端口
func findFreePort(startPort int) int {
	// 使用 listen 然后关闭的方式检查端口可用性
	// 限制检查范围避免遍历过多端口
	const maxAttempts = 100
	for port := startPort; port <= startPort+maxAttempts && port <= 65535; port++ {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			l.Close()
			return port
		}
	}
	return startPort
}

// showNetworkResult 显示安装后网络状态（带重试机制，参考 menu.sh net() 函数）
func showNetworkResult() {
	maxRetries := 5
	for i := 1; i <= maxRetries; i++ {
		ui.Info(fmt.Sprintf("正在检测网络状态 (第 %d/%d 次)...", i, maxRetries))
		status := network.GetNetworkStatus()

		if status.HasIPv4 || status.HasIPv6 {
			ui.Info(fmt.Sprintf("网络状态: %s", status.String()))
			if status.WARPTraceV4 == "on" || status.WARPTraceV4 == "plus" {
				ui.Info("✓ IPv4 已通过 WARP 路由")
			}
			if status.WARPTraceV6 == "on" || status.WARPTraceV6 == "plus" {
				ui.Info("✓ IPv6 已通过 WARP 路由")
			}
			return
		}

		if i < maxRetries {
			ui.Warning("网络尚未就绪，正在重启 WARP 并重试...")
			// 参考 menu.sh net(): systemctl restart + wg-quick up
			wireguard.Down()
			time.Sleep(2 * time.Second)
			wireguard.Up()
			time.Sleep(5 * time.Second)
		}
	}
	ui.Warning("网络检测超时，请手动检查:")
	ui.Hint("  curl https://www.cloudflare.com/cdn-cgi/trace")
	ui.Hint("  wg show warp")
}
