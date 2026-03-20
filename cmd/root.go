package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/install"
	"github.com/pzeus/warpgo/pkg/network"
	"github.com/pzeus/warpgo/pkg/system"
	"github.com/pzeus/warpgo/pkg/ui"
	"github.com/pzeus/warpgo/pkg/wireguard"
	"github.com/pzeus/warpgo/pkg/wireproxy"
	"github.com/pzeus/warpgo/pkg/zerotrust"
)

// Execute 也是程序的入口，解析参数或启动交互菜单
func Execute() {
	var (
		optInstallV4  bool
		optInstallV6  bool
		optInstallDual bool
		optInstallProxy bool
		optZeroTrust   bool
		optUninstall   bool
		optVersion     bool
	)

	flag.BoolVar(&optInstallV4, "4", false, "安装 IPv4 WARP")
	flag.BoolVar(&optInstallV6, "6", false, "安装 IPv6 WARP")
	flag.BoolVar(&optInstallDual, "d", false, "安装双栈 WARP")
	flag.BoolVar(&optInstallProxy, "p", false, "安装 WireProxy SOCKS5 代理")
	flag.BoolVar(&optZeroTrust, "z", false, "配置 Zero Trust")
	flag.BoolVar(&optUninstall, "u", false, "卸载所有 WARP 组件")
	flag.BoolVar(&optVersion, "v", false, "显示版本")
	flag.Parse()

	if optVersion {
		fmt.Printf("WarpGo v%s\n", config.Version)
		return
	}

	sysInfo, err := system.Detect()
	if err != nil {
		ui.Error(fmt.Sprintf("系统检测失败: %v", err))
	}

	if err := system.CheckRoot(); err != nil {
		ui.Error(err.Error())
	}

	opts := &install.InstallOptions{
		GlobalMode: true,
	}

	// 命令行快捷方式
	if optInstallV4 {
		opts.Mode = config.ModeWireGuardV4
		install.Install(sysInfo, opts)
		return
	}
	if optInstallV6 {
		opts.Mode = config.ModeWireGuardV6
		install.Install(sysInfo, opts)
		return
	}
	if optInstallDual {
		opts.Mode = config.ModeWireGuardDual
		install.Install(sysInfo, opts)
		return
	}
	if optInstallProxy {
		opts.Mode = config.ModeWireProxy
		install.Install(sysInfo, opts)
		return
	}
	if optZeroTrust {
		opts.Mode = config.ModeZeroTrust
		install.Install(sysInfo, opts)
		return
	}
	if optUninstall {
		install.Uninstall()
		return
	}

	// 如果没有参数，进入交互菜单
	showMainMenu(sysInfo)
}

func showMainMenu(sysInfo *system.SysInfo) {
	status := network.GetNetworkStatus()

	for {
		ui.PrintBanner(config.Version, sysInfo.String(), status.String())

		// 动态菜单
		var items []ui.MenuItem

		wgInstalled := wireguard.IsInstalled()
		wpInstalled := wireproxy.IsInstalled()
		ztInstalled := zerotrust.IsWarpCLIInstalled()

		if ztInstalled {
			ztStatus, _ := zerotrust.GetStatus()
			ui.PrintKV("Zero Trust", fmt.Sprintf("已安装 (状态: %v, 模式: %s)", ztStatus.Connected, ztStatus.Mode))
		} else if wgInstalled {
			ui.PrintStatus("WARP 接口", wireguard.IsRunning())
			mode := "全局"
			if !wireguard.IsGlobalMode() {
				mode = "非全局"
			}
			ui.PrintKV("WARP 模式", mode)
			
			stack := wireguard.GetCurrentStack()
			stackStr := "双栈"
			if stack == config.StackIPv4 {
				stackStr = "IPv4"
			} else if stack == config.StackIPv6 {
				stackStr = "IPv6"
			}
			ui.PrintKV("WARP 协议栈", stackStr)
		} else if wpInstalled {
			ui.PrintStatus("WireProxy 服务", wireproxy.IsRunning())
		}

		if !wgInstalled && !wpInstalled && !ztInstalled {
			items = append(items,
				ui.MenuItem{Key: "1", Label: "安装 WARP", Description: "使用 WireGuard 内核运行，接管全局或部分网络"},
				ui.MenuItem{Key: "2", Label: "安装 WireProxy", Description: "本地 SOCKS5 代理，不修改系统路由表 (推荐)"},
				ui.MenuItem{Key: "3", Label: "配置 Zero Trust", Description: "使用 Cloudflare Teams 组织网络"},
			)
		} else if wgInstalled {
			items = append(items,
				ui.MenuItem{Key: "1", Label: "启停 WARP", Description: "开关 WireGuard 接口"},
				ui.MenuItem{Key: "2", Label: "切换全局/非全局模式", Description: "是否接管所有流量"},
				ui.MenuItem{Key: "3", Label: "切换 IPv4/IPv6/双栈", Description: "修改出口网络类型"},
			)
		} else if wpInstalled {
			items = append(items,
				ui.MenuItem{Key: "1", Label: "启停 WireProxy", Description: "开关 SOCKS5 服务"},
			)
		} else if ztInstalled {
			items = append(items,
				ui.MenuItem{Key: "1", Label: "连接/断开 Zero Trust", Description: "控制 warp-cli 连接状态"},
			)
		}

		if wgInstalled || wpInstalled || ztInstalled {
			items = append(items, ui.MenuItem{Key: "u", Label: "完全卸载", Description: "清理所有已安装的组件和配置"})
		}

		items = append(items, ui.MenuItem{Key: "r", Label: "检查更新", Description: "升级 WarpGo 到最新版本"})
		items = append(items, ui.MenuItem{Key: "0", Label: "退出程序"})

		choice := ui.ShowMenu("请选择你要执行的操作", items)

		switch choice {
		case "1":
			if !wgInstalled && !wpInstalled && !ztInstalled {
				// 安装 WARP 菜单
				installWarpMenu(sysInfo)
			} else if wgInstalled {
				wireguard.Toggle()
			} else if wpInstalled {
				wireproxy.Toggle()
			} else if ztInstalled {
				st, _ := zerotrust.GetStatus()
				if st.Connected {
					zerotrust.Disconnect()
				} else {
					zerotrust.Connect()
				}
			}
		case "2":
			if !wgInstalled && !wpInstalled && !ztInstalled {
				// 安装 WireProxy
				opts := &install.InstallOptions{
					Mode: config.ModeWireProxy,
					Port: install.InputPort(config.DefaultWireproxyPort),
				}
				install.Install(sysInfo, opts)
			} else if wgInstalled {
				global := wireguard.IsGlobalMode()
				wireguard.SwitchGlobalMode(!global)
			}
		case "3":
			if !wgInstalled && !wpInstalled && !ztInstalled {
				// Zero Trust（Service Token 方式）
				ui.Info("Zero Trust 接入需要 Service Token（从 Cloudflare 控制台获取）")
				ui.Hint("获取路径: one.dash.cloudflare.com → Settings → WARP Client → Device enrollment")
				ui.Blank()
				org := ui.ReadInput("请输入 Zero Trust 组织名称 (Team Name): ")
				if org == "" {
					continue
				}
				clientID := ui.ReadInput("请输入 Service Token 的 Client ID: ")
				if clientID == "" {
					continue
				}
				clientSecret := ui.ReadInput("请输入 Service Token 的 Client Secret: ")
				if clientSecret == "" {
					continue
				}
				proxyReq := ui.Confirm("是否使用代理模式 (SOCKS5) 以保护 SSH?")
				opts := &install.InstallOptions{
					Mode:                  config.ModeZeroTrust,
					ZeroTrustOrg:          org,
					ZeroTrustEnrollMode:   config.EnrollServiceToken,
					ZeroTrustClientID:     clientID,
					ZeroTrustClientSecret: clientSecret,
					ZeroTrustProxy:        proxyReq,
				}
				install.Install(sysInfo, opts)

			} else if wgInstalled {
				stackMenu()
			}
		case "u", "U":
			if ui.Confirm("确定要完全卸载所有 WARP 相关组件吗？") {
				install.Uninstall()
			}
		case "r", "R":
			install.Update()
		case "0":
			ui.Info("感谢使用 WarpGo！再见！")
			os.Exit(0)
		default:
			ui.Warning("无效选项，请重新输入")
		}

		// 执行完操作后暂停
		ui.ReadInput("按回车键继续...")
	}
}

func installWarpMenu(sysInfo *system.SysInfo) {
	items := []ui.MenuItem{
		{Key: "1", Label: "安装 WARP IPv4", Description: "仅分配 IPv4 出口"},
		{Key: "2", Label: "安装 WARP IPv6", Description: "仅分配 IPv6 出口"},
		{Key: "3", Label: "安装 WARP 双栈", Description: "同时拥有 IPv4/IPv6 出口"},
		{Key: "0", Label: "返回上级目录"},
	}

	choice := ui.ShowMenu("选择 WARP 网络模式", items)
	opts := &install.InstallOptions{GlobalMode: true}

	switch choice {
	case "1":
		opts.Mode = config.ModeWireGuardV4
	case "2":
		opts.Mode = config.ModeWireGuardV6
	case "3":
		opts.Mode = config.ModeWireGuardDual
	case "0":
		return
	default:
		ui.Warning("无效选项，返回主菜单")
		return
	}

	ui.Blank()
	ui.Hint("【路由模式说明】")
	ui.Hint("  全局模式：所有流量都走 WARP — 服务器出口IP变为 Cloudflare IP")
	ui.Hint("            SSH 依然可用 (Linux conntrack 机制保留已有TCP连接)")
	ui.Hint("            验证：curl https://cloudflare.com/cdn-cgi/trace | grep warp → warp=on")
	ui.Hint("  非全局模式：只有指定流量走 WARP — 适合只需要解锁特定网站的场景")
	ui.Hint("            验证：curl --interface warp https://cloudflare.com/cdn-cgi/trace | grep warp")
	ui.Blank()

	globalReq := ui.Confirm("是否使用全局模式？(推荐选 y，所有流量走 WARP，SSH 不受影响)")
	opts.GlobalMode = globalReq
	install.Install(sysInfo, opts)
}

func stackMenu() {
	items := []ui.MenuItem{
		{Key: "1", Label: "切换为 IPv4 优先"},
		{Key: "2", Label: "切换为 IPv6 优先"},
		{Key: "3", Label: "切换为双栈均使用"},
		{Key: "0", Label: "返回上级"},
	}

	choice := ui.ShowMenu("切换路由协议栈", items)
	switch choice {
	case "1":
		wireguard.SwitchStack(config.StackIPv4)
	case "2":
		wireguard.SwitchStack(config.StackIPv6)
	case "3":
		wireguard.SwitchStack(config.StackDual)
	}
}
