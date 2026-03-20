package config

const (
	Version = "1.0.7"

	// Cloudflare WARP API
	WarpAPIBase      = "https://api.cloudflareclient.com/v0a2158"
	WarpRegisterURL  = "https://warp.cloudflare.nyc.mn/?run=register"
	WarpPublicKey    = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	WarpEndpointV4   = "162.159.192.1:2408"
	WarpEndpointV6   = "[2606:4700:d0::a29f:c001]:2408"
	WarpEndpointHost = "engage.cloudflareclient.com:2408"

	// WireGuard 默认配置
	WarpConfPath    = "/etc/wireguard/warp.conf"
	WarpAccountPath = "/etc/wireguard/warp-account.conf"
	WarpIfName      = "warp"
	WarpAddrV4      = "172.16.0.2/32"
	WarpAddrV6      = "2606:4700:110::/128"
	WarpDNS         = "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"
	DefaultMTU      = 1280

	// WireProxy 默认端口
	DefaultWireproxyPort = 40000

	// Zero Trust
	ZeroTrustConfigPath = "/etc/wireguard/zerotrust.conf"
	WarpCLIPath         = "/usr/bin/warp-cli"

	// 路径
	WireguardGoPath = "/usr/bin/wireguard-go"
	WireproxyPath   = "/usr/bin/wireproxy"
	WarpBinPath     = "/usr/bin/warp"
	ScriptDir       = "/etc/wireguard"
	LanguageFile    = "/etc/wireguard/language"

	// IP 检测 API
	IPAPIv4     = "https://api4.ipify.org"
	IPAPIv6     = "https://api6.ipify.org"
	IPInfoAPI   = "https://ipinfo.io"
	CloudflareTrace = "https://www.cloudflare.com/cdn-cgi/trace"

	// GitHub Proxy（国内加速）
	GHProxy1 = "https://ghproxy.com/"
	GHProxy2 = "https://mirror.ghproxy.com/"

	// WireProxy 下载
	WireproxyRelease = "https://github.com/pufferffish/wireproxy/releases/latest"

	// Cloudflare WARP 客户端 APT 源
	WarpClientRepoDebian = "https://pkg.cloudflareclient.com/pubkey.gpg"
	WarpClientAptList    = "https://pkg.cloudflareclient.com"
)

// AllowedIPs 预设
const (
	AllowedIPsV4Only = "0.0.0.0/0"
	AllowedIPsV6Only = "::/0"
	AllowedIPsDual   = "0.0.0.0/0, ::/0"
)

// 安装模式
type InstallMode int

const (
	ModeWireGuardV4   InstallMode = iota // WireGuard IPv4
	ModeWireGuardV6                      // WireGuard IPv6
	ModeWireGuardDual                    // WireGuard 双栈
	ModeWireProxy                        // WireProxy SOCKS5
	ModeZeroTrust                        // Cloudflare Zero Trust
)

// IP 栈类型
type StackMode int

const (
	StackIPv4   StackMode = iota
	StackIPv6
	StackDual
)

// Zero Trust 接入模式
type ZeroTrustEnrollMode int

const (
	EnrollInteractive  ZeroTrustEnrollMode = iota // 交互式：浏览器认证
	EnrollServiceToken                            // 非交互：Service Token
)
