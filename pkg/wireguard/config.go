package wireguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/network"
	"github.com/pzeus/warpgo/pkg/warp"
)

// Config WireGuard 配置参数
type Config struct {
	PrivateKey string
	AddressV4  string
	AddressV6  string
	DNS        string
	MTU        int
	PeerPubKey string
	Endpoint   string
	// 路由模式
	GlobalMode bool       // true=全局路由, false=非全局
	StackMode  config.StackMode // IPv4/IPv6/双栈
	// Reserved 字段（WARP 特有）
	Reserved [3]int
	// LAN IP（安装时检测，写死到 warp.conf PostUp 中）
	LAN4 string
	LAN6 string
}

// GlobalUpScript 全局模式的 PostUp 脚本
// 核心逻辑：
//   1. 保护 SSH —— 为 SSH 端口回包打上 wg-quick 的免路由 fwmark 51820
//   2. 保护 LAN —— 确保服务器自己的 LAN IP 不走 WARP
//   3. 兼容 Docker —— 172.17.0.0/24 保留
const GlobalUpScript = `#!/bin/bash

# 动态获取当前监听的 SSH 端口（支持多端口、22、自定义端口）
SSH_PORTS=$(ss -tlpn | grep -E 'sshd|dropbear' | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u | tr '\n' ',' | sed 's/,$//')
if [ -z "$SSH_PORTS" ]; then
  SSH_PORTS="22"
fi

# 为 SSH 端口流量强制打上 51820 标记（wg-quick 免除接管）
if command -v iptables >/dev/null 2>&1; then
  iptables -t mangle -I OUTPUT -p tcp -m multiport --sports "$SSH_PORTS" -j MARK --set-mark 51820 2>/dev/null || true
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t mangle -I OUTPUT -p tcp -m multiport --sports "$SSH_PORTS" -j MARK --set-mark 51820 2>/dev/null || true
fi

# 保护服务器自己的 LAN IP —— 确保本地流量不走 WARP
LAN4=$(ip route get 192.168.193.10 2>/dev/null | awk '{for (i=0; i<NF; i++) if ($i=="src") {print $(i+1)}}')
[ -n "$LAN4" ] && ip -4 rule add from "$LAN4" lookup main 2>/dev/null || true

LAN6=$(ip route get 2606:4700:d0::a29f:c001 2>/dev/null | awk '{for (i=0; i<NF; i++) if ($i=="src") {print $(i+1)}}')
[ -n "$LAN6" ] && ip -6 rule add from "$LAN6" lookup main 2>/dev/null || true

# 把局域网、链路本地、组播等保留网段加入 main 表
ip -4 rule add from 172.16.0.0/12 lookup main 2>/dev/null || true
ip -4 rule add from 192.168.0.0/16 lookup main 2>/dev/null || true
ip -4 rule add from 10.0.0.0/8 lookup main 2>/dev/null || true
ip -4 rule add from 172.17.0.0/24 lookup main 2>/dev/null || true
ip -6 rule add from fe80::/10 lookup main 2>/dev/null || true

# 兼容各种系统的 sysctl
sysctl -q net.ipv4.conf.all.src_valid_mark=1 2>/dev/null || true

exit 0
`

// GlobalDownScript 全局模式的 PostDown 脚本
const GlobalDownScript = `#!/bin/bash

SSH_PORTS=$(ss -tlpn | grep -E 'sshd|dropbear' | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u | tr '\n' ',' | sed 's/,$//')
if [ -z "$SSH_PORTS" ]; then
  SSH_PORTS="22"
fi

# 清理 SSH 的豁免标记
if command -v iptables >/dev/null 2>&1; then
  iptables -t mangle -D OUTPUT -p tcp -m multiport --sports "$SSH_PORTS" -j MARK --set-mark 51820 2>/dev/null || true
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t mangle -D OUTPUT -p tcp -m multiport --sports "$SSH_PORTS" -j MARK --set-mark 51820 2>/dev/null || true
fi

# 清理 LAN IP 规则
LAN4=$(ip route get 192.168.193.10 2>/dev/null | awk '{for (i=0; i<NF; i++) if ($i=="src") {print $(i+1)}}')
[ -n "$LAN4" ] && ip -4 rule del from "$LAN4" lookup main 2>/dev/null || true

LAN6=$(ip route get 2606:4700:d0::a29f:c001 2>/dev/null | awk '{for (i=0; i<NF; i++) if ($i=="src") {print $(i+1)}}')
[ -n "$LAN6" ] && ip -6 rule del from "$LAN6" lookup main 2>/dev/null || true

# 清理保留网段
ip -4 rule del from 172.16.0.0/12 lookup main 2>/dev/null || true
ip -4 rule del from 192.168.0.0/16 lookup main 2>/dev/null || true
ip -4 rule del from 10.0.0.0/8 lookup main 2>/dev/null || true
ip -4 rule del from 172.17.0.0/24 lookup main 2>/dev/null || true
ip -6 rule del from fe80::/10 lookup main 2>/dev/null || true

exit 0
`

// NonGlobalUpScript 非全局模式的 PostUp 脚本
// 兼容 iptables 和 nftables（Debian 12+ / Ubuntu 22+ 默认 nftables）
const NonGlobalUpScript = `#!/bin/bash
# WarpGo Non-Global Mode - PostUp

# 添加策略路由（先检查是否已存在）
ip rule show | grep -q "fwmark 0xca6c" || ip rule add fwmark 51820 table 51820 priority 100 2>/dev/null
ip route show table 51820 2>/dev/null | grep -q "default" || ip route add default dev warp table 51820 2>/dev/null

# 根据可用工具选择防火墙标记方案
if command -v iptables >/dev/null 2>&1; then
  iptables -t mangle -C PREROUTING -d 162.159.0.0/16 -j MARK --set-mark 51820 2>/dev/null || \
    iptables -t mangle -A PREROUTING -d 162.159.0.0/16 -j MARK --set-mark 51820
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t mangle -C PREROUTING -d 2606:4700::/32 -j MARK --set-mark 51820 2>/dev/null || \
    ip6tables -t mangle -A PREROUTING -d 2606:4700::/32 -j MARK --set-mark 51820
elif command -v nft >/dev/null 2>&1; then
  nft add table ip warpgo 2>/dev/null || true
  nft add chain ip warpgo prerouting '{ type filter hook prerouting priority mangle; }' 2>/dev/null || true
  nft add rule ip warpgo prerouting ip daddr 162.159.0.0/16 meta mark set 51820 2>/dev/null || true
fi

exit 0
`

// NonGlobalDownScript 非全局模式的 PostDown 脚本
const NonGlobalDownScript = `#!/bin/bash
# WarpGo Non-Global Mode - PostDown

ip rule del fwmark 51820 table 51820 2>/dev/null || true
ip route flush table 51820 2>/dev/null || true

if command -v iptables >/dev/null 2>&1; then
  iptables -t mangle -D PREROUTING -d 162.159.0.0/16 -j MARK --set-mark 51820 2>/dev/null || true
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t mangle -D PREROUTING -d 2606:4700::/32 -j MARK --set-mark 51820 2>/dev/null || true
elif command -v nft >/dev/null 2>&1; then
  nft delete table ip warpgo 2>/dev/null || true
fi

exit 0
`

// warpConfTemplate WireGuard 配置文件模板
const warpConfTemplate = `[Interface]
PrivateKey = {{.PrivateKey}}
{{- if .AddressV4}}
Address = {{.AddressV4}}
{{- end}}
{{- if .AddressV6}}
Address = {{.AddressV6}}
{{- end}}
DNS = {{.DNS}}
MTU = {{.MTU}}
{{- if not .GlobalMode}}
Table = off
PostUp = {{.ScriptDir}}/NonGlobalUp.sh
PostDown = {{.ScriptDir}}/NonGlobalDown.sh
{{- end}}

[Peer]
PublicKey = {{.PeerPubKey}}
{{- if .HasReserved}}
# Reserved = {{.Reserved0}}, {{.Reserved1}}, {{.Reserved2}}
{{- end}}
AllowedIPs = {{.AllowedIPs}}
Endpoint = {{.Endpoint}}
`

// templateData 模板渲染数据
type templateData struct {
	PrivateKey  string
	AddressV4   string
	AddressV6   string
	DNS         string
	MTU         int
	PeerPubKey  string
	Endpoint    string
	GlobalMode  bool
	ScriptDir   string
	AllowedIPs  string
	HasReserved bool
	Reserved0   int
	Reserved1   int
	Reserved2   int
	LAN4        string
	LAN6        string
}

// Generate 根据账户和配置生成 WireGuard 配置文件内容
func Generate(acc *warp.Account, cfg *Config) string {
	td := templateData{
		PrivateKey: acc.PrivateKey,
		AddressV4:  cfg.AddressV4,
		AddressV6:  cfg.AddressV6,
		DNS:        cfg.DNS,
		MTU:        cfg.MTU,
		PeerPubKey: acc.GetPeerPublicKey(),
		Endpoint:   cfg.Endpoint,
		GlobalMode: cfg.GlobalMode,
		ScriptDir:  config.ScriptDir,
		LAN4:       cfg.LAN4,
		LAN6:       cfg.LAN6,
	}

	// Reserved 字段
	if len(acc.Config.Reserved) >= 3 {
		td.HasReserved = true
		td.Reserved0 = acc.Config.Reserved[0]
		td.Reserved1 = acc.Config.Reserved[1]
		td.Reserved2 = acc.Config.Reserved[2]
	}

	// AllowedIPs 根据 StackMode 决定。
	// wg setconf 要求必须是单行逗号格式，不能多行、不能带注释。
	switch cfg.StackMode {
	case config.StackIPv4:
		td.AllowedIPs = "0.0.0.0/0"
	case config.StackIPv6:
		td.AllowedIPs = "::/0"
	case config.StackDual:
		td.AllowedIPs = "0.0.0.0/0, ::/0"
	default:
		td.AllowedIPs = "0.0.0.0/0, ::/0"
	}

	// 将构建配置内容
	return buildConfig(td)
}

func buildConfig(td templateData) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", td.PrivateKey))
	if td.AddressV4 != "" {
		sb.WriteString(fmt.Sprintf("Address = %s\n", td.AddressV4))
	}
	if td.AddressV6 != "" {
		sb.WriteString(fmt.Sprintf("Address = %s\n", td.AddressV6))
	}
	sb.WriteString(fmt.Sprintf("DNS = %s\n", td.DNS))
	sb.WriteString(fmt.Sprintf("MTU = %d\n", td.MTU))

	if td.GlobalMode {
		// 全局模式：直接在 warp.conf 写 PostUp/PostDown（和 menu.sh 完全一致）
		// LAN IP 在安装时已检测好，写死在这里，不能运行时动态检测（PostUp时路由已变）
		if td.LAN4 != "" {
			sb.WriteString(fmt.Sprintf("PostUp = ip -4 rule add from %s lookup main\n", td.LAN4))
			sb.WriteString(fmt.Sprintf("PostDown = ip -4 rule delete from %s lookup main\n", td.LAN4))
		}
		if td.LAN6 != "" {
			sb.WriteString(fmt.Sprintf("PostUp = ip -6 rule add from %s lookup main\n", td.LAN6))
			sb.WriteString(fmt.Sprintf("PostDown = ip -6 rule delete from %s lookup main\n", td.LAN6))
		}
		// Docker 兼容
		sb.WriteString("PostUp = ip -4 rule add from 172.17.0.0/24 lookup main\n")
		sb.WriteString("PostDown = ip -4 rule delete from 172.17.0.0/24 lookup main\n")
	} else {
		// 非全局模式：禁用 wg-quick 自动路由
		sb.WriteString("Table = off\n")
		sb.WriteString(fmt.Sprintf("PostUp = %s/NonGlobalUp.sh\n", td.ScriptDir))
		sb.WriteString(fmt.Sprintf("PostDown = %s/NonGlobalDown.sh\n", td.ScriptDir))
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", td.PeerPubKey))
	if td.HasReserved {
		sb.WriteString(fmt.Sprintf("# Reserved = %d, %d, %d\n", td.Reserved0, td.Reserved1, td.Reserved2))
	}
	// AllowedIPs 必须是单行逗号格式，wg setconf 不支持多行、不支持注释内嵌
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", td.AllowedIPs))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", td.Endpoint))
	// WARP 需要保活，否则 Cloudflare 端会断开握手
	sb.WriteString("PersistentKeepalive = 30\n")

	return sb.String()
}

func WriteConfig(content, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	return os.WriteFile(path, []byte(content), 0600)
}

// WriteScripts 写入所有 PostUp/PostDown 脚本（全局 + 非全局）
func WriteScripts(scriptDir string) error {
	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		return fmt.Errorf("创建脚本目录失败: %v", err)
	}

	scripts := map[string]string{
		"GlobalUp.sh":      GlobalUpScript,
		"GlobalDown.sh":    GlobalDownScript,
		"NonGlobalUp.sh":   NonGlobalUpScript,
		"NonGlobalDown.sh": NonGlobalDownScript,
	}

	for name, content := range scripts {
		path := filepath.Join(scriptDir, name)
		content = strings.ReplaceAll(content, "\r\n", "\n")
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			return fmt.Errorf("写入 %s 失败: %v", name, err)
		}
	}
	return nil
}

// BuildFromAccount 从账户信息构建默认 Config
// 注意：LAN IP 必须在此时（wg-quick up 之前）检测！
func BuildFromAccount(acc *warp.Account, stackMode config.StackMode, globalMode bool, mtu int, endpoint string) *Config {
	cfg := &Config{
		PrivateKey: acc.PrivateKey,
		AddressV4:  acc.GetAddressV4(),
		DNS:        config.WarpDNS,
		MTU:        mtu,
		PeerPubKey: acc.GetPeerPublicKey(),
		Endpoint:   endpoint,
		GlobalMode: globalMode,
		StackMode:  stackMode,
	}

	// menu.sh 始终包含 IPv6 地址（只是 AllowedIPs 控制是否启用）
	cfg.AddressV6 = acc.GetAddressV6()

	if len(acc.Config.Reserved) >= 3 {
		cfg.Reserved = [3]int{
			acc.Config.Reserved[0],
			acc.Config.Reserved[1],
			acc.Config.Reserved[2],
		}
	}

	// 全局模式：安装时检测 LAN IP（和 menu.sh 的 $LAN4/$LAN6 一致）
	if globalMode {
		cfg.LAN4 = network.DetectLAN4()
		cfg.LAN6 = network.DetectLAN6()
	}

	return cfg
}

// 确保 template 包被引用（用于后续扩展）
var _ = template.New
