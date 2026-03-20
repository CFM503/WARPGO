package install

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/network"
	"github.com/pzeus/warpgo/pkg/system"
	"github.com/pzeus/warpgo/pkg/ui"
	"github.com/pzeus/warpgo/pkg/warp"
	"github.com/pzeus/warpgo/pkg/wireguard"
	"github.com/pzeus/warpgo/pkg/wireproxy"
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
	ZeroTrustProxy        bool                      // Zero Trust 使用代理模式
	ZeroTrustEnrollMode   config.ZeroTrustEnrollMode // 接入方式
	ZeroTrustClientID     string                     // Service Token Client ID
	ZeroTrustClientSecret string                     // Service Token Client Secret
}

// Install 主安装函数
func Install(sysInfo *system.SysInfo, opts *InstallOptions) error {
	switch opts.Mode {
	case config.ModeWireGuardV4, config.ModeWireGuardV6, config.ModeWireGuardDual:
		return installWireGuard(sysInfo, opts)
	case config.ModeWireProxy:
		return installWireProxy(sysInfo, opts)
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

// installWireProxy 安装 WireProxy SOCKS5 方案
func installWireProxy(sysInfo *system.SysInfo, opts *InstallOptions) error {
	// 检查端口
	port := opts.Port
	if port == 0 {
		port = config.DefaultWireproxyPort
	}
	port = findFreePort(port)

	// 1. 注册 WARP 账户
	ui.Info("正在注册 WARP 账户...")
	acc, err := warp.Register()
	if err != nil {
		return fmt.Errorf("注册 WARP 账户失败: %v", err)
	}

	// 2. 保存账户
	acc.SaveToFile(config.WarpAccountPath)

	// 3. 下载 wireproxy
	ui.Info("正在下载 WireProxy...")
	if err := wireproxy.Install(sysInfo.Arch, opts.GHProxy); err != nil {
		return fmt.Errorf("下载 WireProxy 失败: %v", err)
	}

	// 4. 检测 MTU 和 Endpoint
	mtu := detectMTU(opts.Endpoint)
	if opts.Endpoint == "" {
		opts.Endpoint = acc.GetEndpoint(false)
	}

	// 5. 生成配置
	wpCfg := &wireproxy.WireproxyConfig{
		Account:  acc,
		Port:     port,
		MTU:      mtu,
		Endpoint: opts.Endpoint,
	}
	confContent := wireproxy.GenerateConfig(wpCfg)

	// 6. 写入配置
	if err := wireproxy.WriteConfig(confContent); err != nil {
		return fmt.Errorf("写入 wireproxy 配置失败: %v", err)
	}

	// 7. 创建 systemd 服务
	if err := wireproxy.CreateSystemdService(); err != nil {
		return fmt.Errorf("创建 systemd 服务失败: %v", err)
	}

	// 8. 启动
	if err := wireproxy.Start(); err != nil {
		return fmt.Errorf("启动 wireproxy 失败: %v", err)
	}
	wireproxy.Enable()

	ui.Info(fmt.Sprintf("✓ WireProxy 安装完成！SOCKS5 代理: 127.0.0.1:%d", port))
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

	// 2. 注册（Service Token 方式）
	ui.Info("使用 Service Token 方式加入 Zero Trust...")
	if err := zerotrust.EnrollServiceToken(opts.ZeroTrustOrg, opts.ZeroTrustClientID, opts.ZeroTrustClientSecret); err != nil {
		return fmt.Errorf("Zero Trust 注册失败: %v", err)
	}

	// 3. 设置运行模式（代理或标准 WARP）
	port := opts.Port
	if port == 0 {
		port = 40001
	}
	if opts.ZeroTrustProxy {
		if err := zerotrust.SetProxyMode(port); err != nil {
			ui.Warning("设置代理模式失败，将使用标准 WARP 模式")
		} else {
			ui.Info(fmt.Sprintf("已设置代理模式，SOCKS5: 127.0.0.1:%d", port))
		}
	} else {
		zerotrust.SetWarpMode("warp")
	}

	// 4. 连接
	ui.Info("正在连接 Zero Trust...")
	if err := zerotrust.Connect(); err != nil {
		return fmt.Errorf("连接 Zero Trust 失败: %v", err)
	}

	// 5. 保存配置
	ztCfg := &zerotrust.ZeroTrustConfig{
		OrgName:      opts.ZeroTrustOrg,
		ClientID:     opts.ZeroTrustClientID,
		ClientSecret: opts.ZeroTrustClientSecret,
	}
	zerotrust.WriteZeroTrustConfig(ztCfg)

	ui.Info("✓ Cloudflare Zero Trust 安装完成！")
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
	for port := startPort; port <= 65535; port++ {
		addr := fmt.Sprintf(":%d", port)
		l, err := net.Listen("tcp", addr)
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

// CheckDependencies 检查依赖
func CheckDependencies(sysInfo *system.SysInfo) error {
	required := []string{"curl", "wget"}
	missing := []string{}
	for _, dep := range required {
		if !system.CheckBinaryExists(dep) {
			missing = append(missing, dep)
		}
	}
	if len(missing) > 0 {
		ui.Warning(fmt.Sprintf("正在安装缺少的依赖: %s", strings.Join(missing, ", ")))
		if err := system.InstallPackages(sysInfo.PkgManager, missing...); err != nil {
			return fmt.Errorf("安装依赖失败: %v", err)
		}
	}
	return nil
}

// InputPort 交互式输入端口
func InputPort(defaultPort int) int {
	for {
		input := ui.ReadInput(fmt.Sprintf("请输入 SOCKS5 端口 (默认 %d): ", defaultPort))
		if input == "" {
			return findFreePort(defaultPort)
		}
		port, err := strconv.Atoi(input)
		if err != nil || port < 1024 || port > 65535 {
			ui.Warning("请输入 1024-65535 之间的端口号")
			continue
		}
		return findFreePort(port)
	}
}
