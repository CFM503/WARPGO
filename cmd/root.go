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
	"github.com/pzeus/warpgo/pkg/zerotrust"
)

// Execute 也是程序的入口，解析参数或启动交互菜单
func Execute() {
	var (
		optInstallV4   bool
		optInstallV6   bool
		optInstallDual bool
		optZeroTrust   bool
		optUninstall   bool
		optVersion     bool
	)

	flag.BoolVar(&optInstallV4, "4", false, "安装 IPv4 WARP")
	flag.BoolVar(&optInstallV6, "6", false, "安装 IPv6 WARP")
	flag.BoolVar(&optInstallDual, "d", false, "安装双栈 WARP")
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
		if err := install.Install(sysInfo, opts); err != nil {
			ui.Error(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optInstallV6 {
		opts.Mode = config.ModeWireGuardV6
		if err := install.Install(sysInfo, opts); err != nil {
			ui.Error(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optInstallDual {
		opts.Mode = config.ModeWireGuardDual
		if err := install.Install(sysInfo, opts); err != nil {
			ui.Error(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optZeroTrust {
		opts.Mode = config.ModeZeroTrust
		if err := install.Install(sysInfo, opts); err != nil {
			ui.Error(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optUninstall {
		if _, err := install.Uninstall(); err != nil {
			ui.Error(fmt.Sprintf("卸载失败: %v", err))
		}
		return
	}

	// 如果没有参数，进入交互菜单
	showMainMenu(sysInfo)
}

func showMainMenu(sysInfo *system.SysInfo) {
	status := network.GetNetworkStatus()

	for {
		// 获取当前连接状态
		wgInstalled := wireguard.IsInstalled()
		wgRunning := wireguard.IsRunning()
		ztInstalled := zerotrust.IsWarpCLIInstalled()
		ztStatus, _ := zerotrust.GetStatus()

		// 确定连接类型和信息
		connectionType := ""
		connectionInfo := ""
		isConnected := false

		if ztInstalled && ztStatus.Connected {
			// Zero Trust 已连接
			connectionType = "Zero Trust"
			isConnected = true
			// 获取组织信息
			if ztCfg, err := zerotrust.LoadZeroTrustConfig(); err == nil && ztCfg.OrgName != "" {
				connectionInfo = fmt.Sprintf("组织: %s", ztCfg.OrgName)
			}
		} else if wgInstalled && wgRunning {
			// WARP WireGuard 正在运行
			connectionType = "WARP WireGuard"
			isConnected = true
			mode := "全局模式"
			if !wireguard.IsGlobalMode() {
				mode = "非全局模式"
			}
			connectionInfo = mode
		} else if wgInstalled {
			// WARP 已安装但未运行
			connectionType = "WARP WireGuard (已停止)"
		} else if ztInstalled {
			// Zero Trust 已安装但未连接
			connectionType = "Zero Trust (已断开)"
		} else {
			// 未安装任何组件
			connectionType = "未安装"
		}

		// 显示状态面板
		ui.PrintStatusPanel(
			config.Version,
			sysInfo.String(),
			connectionType,
			connectionInfo,
			status.String(),
		)

		// 动态菜单
		var items []ui.MenuItem

		// 显示详细状态
		if isConnected {
			if ztInstalled && ztStatus.Connected {
				ui.PrintStatusLine("Zero Trust", "已连接", true)
				if ztStatus.Mode != "" {
					ui.PrintInfoLine("运行模式", ztStatus.Mode)
				}
			} else if wgInstalled && wgRunning {
				mode := "全局"
				if !wireguard.IsGlobalMode() {
					mode = "非全局"
				}
				stack := wireguard.GetCurrentStack()
				stackStr := "双栈"
				if stack == config.StackIPv4 {
					stackStr = "IPv4"
				} else if stack == config.StackIPv6 {
					stackStr = "IPv6"
				}
				ui.PrintStatusLine("WARP", fmt.Sprintf("%s %s", mode, stackStr), true)
			}
		} else if wgInstalled {
			ui.PrintStatusLine("WARP", "已停止", false)
		} else if ztInstalled {
			ui.PrintStatusLine("Zero Trust", "已断开", false)
		}

		if !wgInstalled && !ztInstalled {
			items = append(items,
				ui.MenuItem{Key: "1", Label: "安装 WARP", Description: "使用 WireGuard 内核运行，接管全局或部分网络"},
				ui.MenuItem{Key: "2", Label: "配置 Zero Trust", Description: "使用 Cloudflare Teams 组织网络，透明代理"},
			)
		} else if wgInstalled {
			items = append(items,
				ui.MenuItem{Key: "1", Label: "启停 WARP", Description: "开关 WireGuard 接口"},
				ui.MenuItem{Key: "2", Label: "切换全局/非全局模式", Description: "是否接管所有流量"},
				ui.MenuItem{Key: "3", Label: "切换 IPv4/IPv6/双栈", Description: "修改出口网络类型"},
			)
		} else if ztInstalled {
			items = append(items,
				ui.MenuItem{Key: "1", Label: "连接/断开 Zero Trust", Description: "控制 warp-cli 连接状态"},
			)
		}

		if wgInstalled || ztInstalled {
			items = append(items, ui.MenuItem{Key: "u", Label: "完全卸载", Description: "清理所有已安装的组件和配置"})
		}

		items = append(items,
			ui.MenuItem{Key: "i", Label: "刷新状态", Description: "重新获取网络状态和 IP 信息"},
			ui.MenuItem{Key: "h", Label: "帮助", Description: "显示命令行参数和使用说明"},
			ui.MenuItem{Key: "0", Label: "退出程序"},
		)

		choice := ui.ShowMenu("请选择你要执行的操作", items)

		switch choice {
		case "1":
			if !wgInstalled && !ztInstalled {
				// 安装 WARP 菜单
				installWarpMenu(sysInfo)
			} else if wgInstalled {
				if err := wireguard.Toggle(); err != nil {
					ui.Warning(fmt.Sprintf("操作失败: %v", err))
				}
			} else if ztInstalled {
				st, _ := zerotrust.GetStatus()
				if st.Connected {
					if err := zerotrust.Disconnect(); err != nil {
						ui.Warning(fmt.Sprintf("断开连接失败: %v", err))
					}
				} else {
					if err := zerotrust.Connect(); err != nil {
						ui.Warning(fmt.Sprintf("连接失败: %v", err))
					}
				}
			}
		case "2":
			if !wgInstalled && !ztInstalled {
				// Zero Trust 配置菜单
				installZeroTrustMenu(sysInfo)
			} else if wgInstalled {
				global := wireguard.IsGlobalMode()
				if err := wireguard.SwitchGlobalMode(!global); err != nil {
					ui.Warning(fmt.Sprintf("切换模式失败: %v", err))
				}
			}
		case "3":
			if wgInstalled {
				stackMenu()
			}
		case "i", "I":
			// 刷新网络状态
			ui.Info("正在刷新网络状态...")
			status = network.GetNetworkStatus()
			ui.Info("✓ 网络状态已更新")
		case "h", "H":
			showHelp()
		case "u", "U":
			if ui.Confirm("确定要完全卸载所有 WARP 相关组件吗？") {
				if _, err := install.Uninstall(); err != nil {
					ui.Warning(fmt.Sprintf("卸载失败: %v", err))
				}
			}
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
	if err := install.Install(sysInfo, opts); err != nil {
		ui.Warning(fmt.Sprintf("安装失败: %v", err))
	}
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
		if err := wireguard.SwitchStack(config.StackIPv4); err != nil {
			ui.Warning(fmt.Sprintf("切换失败: %v", err))
		}
	case "2":
		if err := wireguard.SwitchStack(config.StackIPv6); err != nil {
			ui.Warning(fmt.Sprintf("切换失败: %v", err))
		}
	case "3":
		if err := wireguard.SwitchStack(config.StackDual); err != nil {
			ui.Warning(fmt.Sprintf("切换失败: %v", err))
		}
	}
}

func installZeroTrustMenu(sysInfo *system.SysInfo) {
	ui.Blank()
	ui.Hint("【Zero Trust 配置说明】")
	ui.Hint("  Zero Trust 需要 Cloudflare 组织（Team）和 Service Token")
	ui.Hint("  获取路径: one.dash.cloudflare.com → Settings → WARP Client → Device enrollment")
	ui.Hint("  创建 Service Token: Access controls → Service credentials → Service Tokens")
	ui.Blank()

	items := []ui.MenuItem{
		{Key: "1", Label: "开始配置", Description: "输入组织名称和 Service Token"},
		{Key: "0", Label: "返回上级菜单"},
	}

	choice := ui.ShowMenu("Zero Trust 配置", items)
	switch choice {
	case "1":
		org := ui.ReadInput("请输入 Zero Trust 组织名称 (Team Name): ")
		if org == "" {
			ui.Warning("组织名称不能为空")
			return
		}
		clientID := ui.ReadInput("请输入 Service Token 的 Client ID: ")
		if clientID == "" {
			ui.Warning("Client ID 不能为空")
			return
		}
		clientSecret := ui.ReadInput("请输入 Service Token 的 Client Secret: ")
		if clientSecret == "" {
			ui.Warning("Client Secret 不能为空")
			return
		}
		opts := &install.InstallOptions{
			Mode:                  config.ModeZeroTrust,
			ZeroTrustOrg:          org,
			ZeroTrustEnrollMode:   config.EnrollServiceToken,
			ZeroTrustClientID:     clientID,
			ZeroTrustClientSecret: clientSecret,
		}
		if err := install.Install(sysInfo, opts); err != nil {
			ui.Warning(fmt.Sprintf("安装失败: %v", err))
		}
	case "0":
		return
	default:
		ui.Warning("无效选项，返回主菜单")
		return
	}
}

func showHelp() {
	ui.Blank()
	ui.Header("WarpGo 命令行参数")
	ui.Separator()
	ui.Hint("  -v    显示版本信息")
	ui.Hint("  -4    安装 IPv4 WARP（WireGuard）")
	ui.Hint("  -6    安装 IPv6 WARP（WireGuard）")
	ui.Hint("  -d    安装双栈 WARP（WireGuard）")
	ui.Hint("  -z    配置 Zero Trust（需要 Service Token）")
	ui.Hint("  -u    完全卸载所有组件")
	ui.Blank()
	ui.Header("使用示例")
	ui.Separator()
	ui.Hint("  ./warpgo -4          # 安装 IPv4 WARP")
	ui.Hint("  ./warpgo -d          # 安装双栈 WARP")
	ui.Hint("  ./warpgo -z          # 配置 Zero Trust")
	ui.Hint("  ./warpgo -u          # 完全卸载")
	ui.Blank()
	ui.Header("交互模式")
	ui.Separator()
	ui.Hint("  直接运行 ./warpgo 进入交互菜单")
	ui.Hint("  支持 WARP 安装/管理、Zero Trust 配置、卸载等功能")
	ui.Blank()
}
