package config

const (
	Version = "1.0.8"

	// Cloudflare WARP API
	WarpAPIBase     = "https://api.cloudflareclient.com/v0a2158"
	WarpRegisterURL = "https://warp.cloudflare.nyc.mn/?run=register"
	WarpPublicKey   = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	WarpEndpointV4  = "162.159.192.1:2408"

	// WireGuard 默认配置
	WarpConfPath    = "/etc/wireguard/warp.conf"
	WarpAccountPath = "/etc/wireguard/warp-account.conf"
	WarpIfName      = "warp"
	WarpDNS         = "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"
	DefaultMTU      = 1280

	// Zero Trust
	ZeroTrustConfigPath        = "/etc/wireguard/zerotrust.conf"
	WarpCLIPath                = "/usr/bin/warp-cli"
	DefaultSocks5Port          = 40001 // Zero Trust SOCKS5 代理端口
	DefaultRedsocksPort        = 12345 // redsocks 透明代理端口
	TransparentProxyConfigPath = "/etc/wireguard/transparent-proxy.conf"

	// 路径
	WireguardGoPath = "/usr/bin/wireguard-go"
	WarpBinPath     = "/usr/bin/warp"
	ScriptDir       = "/etc/wireguard"

	// IP 检测 API
	CloudflareTrace = "https://www.cloudflare.com/cdn-cgi/trace"

	// Cloudflare WARP 客户端 APT 源
	WarpClientRepoDebian = "https://pkg.cloudflareclient.com/pubkey.gpg"
	WarpClientAptList    = "https://pkg.cloudflareclient.com"
)

// 安装模式
type InstallMode int

const (
	ModeWireGuardV4   InstallMode = iota // WireGuard IPv4
	ModeWireGuardV6                      // WireGuard IPv6
	ModeWireGuardDual                    // WireGuard 双栈
	ModeZeroTrust                        // Cloudflare Zero Trust
)

// IP 栈类型
type StackMode int

const (
	StackIPv4 StackMode = iota
	StackIPv6
	StackDual
)

// Zero Trust 接入模式
type ZeroTrustEnrollMode int

const (
	EnrollServiceToken ZeroTrustEnrollMode = iota // 非交互：Service Token
)
