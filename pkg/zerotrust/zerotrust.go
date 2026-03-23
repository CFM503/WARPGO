package zerotrust

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/network"
	"github.com/pzeus/warpgo/pkg/ui"
)

// ZeroTrustConfig Zero Trust 配置
type ZeroTrustConfig struct {
	OrgName      string
	ClientID     string
	ClientSecret string
}

// ZeroTrustStatus Zero Trust 连接状态
type ZeroTrustStatus struct {
	Connected bool
	OrgName   string
	DeviceID  string
	Mode      string
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// IsWarpCLIInstalled 检测 warp-cli 是否已安装
func IsWarpCLIInstalled() bool {
	// 首先检查指定路径
	_, err := os.Stat(config.WarpCLIPath)
	if err == nil {
		return true
	}

	// 尝试使用 command -v 命令（POSIX标准，比which更可靠）
	out, err := exec.Command("sh", "-c", "command -v warp-cli").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return true
	}

	// 备选方案：使用 which 命令
	out, err = exec.Command("which", "warp-cli").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return true
	}

	// 检查PATH环境变量
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		for _, dir := range strings.Split(pathEnv, string(os.PathListSeparator)) {
			if dir == "" {
				continue
			}
			candidate := filepath.Join(dir, "warp-cli")
			if _, err := os.Stat(candidate); err == nil {
				return true
			}
		}
	}

	return false
}

// InstallWarpCLI 安装官方 cloudflare-warp 客户端
func InstallWarpCLI(pm int) error {
	var cmds [][]string
	switch pm {
	case 0: // APT (Debian/Ubuntu)
		// 首先获取发行版代号
		distroCodename := getDistroCodename()
		if distroCodename == "" {
			return fmt.Errorf("无法获取发行版代号，请手动安装 cloudflare-warp")
		}

		cmds = [][]string{
			{"curl", "-fSsL", config.WarpClientRepoDebian, "--output", "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"},
			{"bash", "-c", fmt.Sprintf(`echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] %s %s main" | tee /etc/apt/sources.list.d/cloudflare-client.list`, config.WarpClientAptList, distroCodename)},
			{"apt-get", "update", "-qq"},
			{"apt-get", "install", "-y", "-qq", "cloudflare-warp"},
		}
	case 1: // YUM (CentOS/RHEL)
		cmds = [][]string{
			{"rpm", "--import", config.WarpClientRepoDebian},
			{"bash", "-c", `curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo > /etc/yum.repos.d/cloudflare-warp.repo`},
			{"yum", "install", "-y", "cloudflare-warp"},
		}
	case 2: // DNF (Fedora/CentOS 8+)
		cmds = [][]string{
			{"rpm", "--import", config.WarpClientRepoDebian},
			{"bash", "-c", `curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo > /etc/yum.repos.d/cloudflare-warp.repo`},
			{"dnf", "install", "-y", "cloudflare-warp"},
		}
	default:
		return fmt.Errorf("当前系统不支持官方 warp-cli 安装，请手动安装")
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("执行 %s 失败: %v", args[0], err)
		}
	}
	return nil
}

// getDistroCodename 获取发行版代号（用于APT源）
func getDistroCodename() string {
	// 尝试使用lsb_release命令
	if out, err := exec.Command("lsb_release", "-cs").Output(); err == nil {
		codename := strings.TrimSpace(string(out))
		if codename != "" {
			return codename
		}
	}

	// 备选方案：读取/etc/os-release文件
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		content := string(data)
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := kv[0]
			val := strings.Trim(kv[1], `"`)

			switch key {
			case "VERSION_CODENAME":
				return val
			case "UBUNTU_CODENAME":
				return val
			}
		}
	}

	// 尝试读取/etc/debian_version
	if data, err := os.ReadFile("/etc/debian_version"); err == nil {
		version := strings.TrimSpace(string(data))
		// Debian版本映射到代号
		debianVersions := map[string]string{
			"11": "bullseye",
			"12": "bookworm",
			"10": "buster",
			"9":  "stretch",
		}
		if major := strings.Split(version, ".")[0]; debianVersions[major] != "" {
			return debianVersions[major]
		}
	}

	return ""
}

// ensureWarpSvc 确保 warp-svc 服务已启动
func ensureWarpSvc() {
	exec.Command("systemctl", "start", "warp-svc").Run()
	time.Sleep(2 * time.Second)
}

// EnrollServiceToken 通过 Service Token + MDM 配置自动注册（不需要浏览器，不受 root 限制）
//
// 流程：
//  1. 写入 MDM 配置文件（组织名 + Client ID + Client Secret + 可选代理模式）
//  2. 重启 warp-svc（自动读取 MDM 并注册）
//  3. 等待自动注册完成
func EnrollServiceToken(orgName, clientID, clientSecret string, proxyMode bool, proxyPort int) error {
	if !IsWarpCLIInstalled() {
		return fmt.Errorf("warp-cli 未安装，请先安装")
	}

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("Service Token 的 Client ID 和 Client Secret 不能为空")
	}

	ensureWarpSvc()

	// 写入 MDM 配置文件 — warp-svc 重启后自动注册，不需要 registration new
	ui.Info("正在配置 Service Token...")

	// 根据是否使用代理模式生成不同的 MDM 配置
	var mdmContent string
	if proxyMode && proxyPort > 0 {
		// 代理模式：service_mode=proxy, proxy_port=指定端口
		mdmContent = fmt.Sprintf(`<dict>
  <key>organization</key>
  <string>%s</string>
  <key>auth_client_id</key>
  <string>%s</string>
  <key>auth_client_secret</key>
  <string>%s</string>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>%d</integer>
</dict>`, orgName, clientID, clientSecret, proxyPort)
		ui.Info(fmt.Sprintf("代理模式已配置，端口: %d", proxyPort))
	} else {
		// 标准 WARP 模式
		mdmContent = fmt.Sprintf(`<dict>
  <key>organization</key>
  <string>%s</string>
  <key>auth_client_id</key>
  <string>%s</string>
  <key>auth_client_secret</key>
  <string>%s</string>
</dict>`, orgName, clientID, clientSecret)
	}

	mdmDir := "/var/lib/cloudflare-warp"
	if err := os.MkdirAll(mdmDir, 0755); err != nil {
		return fmt.Errorf("创建 MDM 目录失败: %v", err)
	}
	mdmPath := mdmDir + "/mdm.xml"
	if err := os.WriteFile(mdmPath, []byte(mdmContent), 0600); err != nil {
		return fmt.Errorf("写入 MDM 配置失败: %v", err)
	}
	ui.Info(fmt.Sprintf("MDM 配置已写入: %s", mdmPath))

	// 重启 warp-svc — 它会自动读取 MDM 并完成注册
	ui.Info("正在重启 warp-svc（自动注册中）...")
	exec.Command("systemctl", "restart", "warp-svc").Run()
	time.Sleep(5 * time.Second)

	// 等待注册完成（最多等 30 秒）
	ui.Info("等待设备注册完成...")
	for i := 0; i < 6; i++ {
		out, _ := exec.Command("warp-cli", "--accept-tos", "registration", "show").Output()
		content := string(out)
		if strings.Contains(content, "Organization:") || strings.Contains(content, orgName) {
			ui.Info("✓ Service Token 自动注册成功！")
			return nil
		}
		if strings.Contains(content, "Registration Missing") {
			// 还没注册完，继续等
			time.Sleep(5 * time.Second)
			continue
		}
		// 有其他输出，可能已成功
		if len(content) > 10 {
			ui.Info("设备已注册！")
			return nil
		}
		time.Sleep(5 * time.Second)
	}

	ui.Warning("自动注册超时，将尝试手动连接...")
	return nil
}

// Connect 连接 WARP（通过 warp-cli），自动保护所有入站连接（与 WireGuard 全局模式同一套思路）
func Connect() error {
	if !IsWarpCLIInstalled() {
		return fmt.Errorf("warp-cli 未安装")
	}

	// 先接受 Terms of Service（Zero Trust 组织需要）
	ui.Info("正在接受服务条款...")
	if err := exec.Command("warp-cli", "--accept-tos").Run(); err != nil {
		// 可能已经接受过，忽略错误
	}

	// 必须在 warp-cli connect 之前检测 LAN：连接后默认路由会走 WARP，DetectLAN4/6 会得到错误 src
	lan4 := network.DetectLAN4()
	lan6 := network.DetectLAN6()

	// split tunnel：私网 + 当前 SSH 会话对端公网 IP（与 WireGuard 路径 AddDefaultExcludedRoutes 一致）
	ui.Info("正在添加排除路由以保护 SSH 连接...")
	network.AddDefaultExcludedRoutes()

	// 额外等待确保排除路由生效
	time.Sleep(1 * time.Second)

	// 连接
	ui.Info("正在连接 Zero Trust...")
	cmd := exec.Command("warp-cli", "--accept-tos", "connect")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// 连接后立即重新添加排除路由，确保 SSH 不会断开
	ui.Info("连接成功，重新确认排除路由...")
	network.AddDefaultExcludedRoutes()

	// 再次等待确保路由生效
	time.Sleep(2 * time.Second)

	ui.Info("正在配置入站策略路由（与 WARP 接入全局模式一致）...")
	network.ApplyWarpCLIInboundProtection(lan4, lan6)
	if lan4 != "" {
		ui.Info(fmt.Sprintf("已保护服务器 IPv4 源地址: %s", lan4))
	}
	if lan6 != "" {
		ui.Info(fmt.Sprintf("已保护服务器 IPv6 源地址: %s", lan6))
	}
	if msg := network.PrintSSHProtectionInfo(); !strings.Contains(msg, "未检测") {
		ui.Info(msg)
	}

	return nil
}

// Disconnect 断开 WARP，并清理 Connect 添加的策略路由
func Disconnect() error {
	lan4Before := network.DetectLAN4()
	lan6Before := network.DetectLAN6()
	err := exec.Command("warp-cli", "--accept-tos", "disconnect").Run()
	// 断开后路由恢复，再测一次 LAN，避免连接态下检测不准导致规则残留
	lan4After := network.DetectLAN4()
	lan6After := network.DetectLAN6()
	network.RemoveWarpCLIInboundProtection(lan4Before, lan6Before)
	network.RemoveWarpCLIInboundProtection(lan4After, lan6After)
	return err
}

// SetWarpMode 设置 WARP 模式
func SetWarpMode(mode string) error {
	// 尝试新命令格式 (2025+)
	if err := exec.Command("warp-cli", "--accept-tos", "mode", mode).Run(); err != nil {
		// 旧版本
		return exec.Command("warp-cli", "--accept-tos", "set-mode", mode).Run()
	}
	return nil
}

// SetProxyMode 设置为代理模式（SOCKS5）
func SetProxyMode(port int) error {
	// 先尝试接受 TOS
	exec.Command("warp-cli", "--accept-tos").Run()

	// 尝试新命令格式 (2025+)：warp-cli mode proxy
	cmd1 := exec.Command("warp-cli", "--accept-tos", "mode", "proxy")
	cmd1.Stdout = os.Stdout
	cmd1.Stderr = os.Stderr
	if err := cmd1.Run(); err != nil {
		// 尝试旧命令格式：warp-cli set-mode proxy
		cmd1Old := exec.Command("warp-cli", "--accept-tos", "set-mode", "proxy")
		cmd1Old.Stdout = os.Stdout
		cmd1Old.Stderr = os.Stderr
		if err := cmd1Old.Run(); err != nil {
			return fmt.Errorf("设置代理模式失败: %v", err)
		}
	}

	// 设置代理端口：先尝试新格式 warp-cli proxy port，再尝试旧格式 warp-cli set-proxy-port
	cmd2 := exec.Command("warp-cli", "--accept-tos", "proxy", "port", fmt.Sprintf("%d", port))
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	if err := cmd2.Run(); err != nil {
		cmd2Old := exec.Command("warp-cli", "--accept-tos", "set-proxy-port", fmt.Sprintf("%d", port))
		cmd2Old.Stdout = os.Stdout
		cmd2Old.Stderr = os.Stderr
		return cmd2Old.Run()
	}
	return nil
}

// GetStatus 获取 Zero Trust 连接状态
func GetStatus() (*ZeroTrustStatus, error) {
	out, err := exec.Command("warp-cli", "--accept-tos", "status").Output()
	if err != nil {
		return &ZeroTrustStatus{Connected: false}, nil
	}

	status := &ZeroTrustStatus{}
	content := string(out)

	if strings.Contains(content, "Connected") {
		status.Connected = true
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "Mode":
			status.Mode = val
		case "Organization":
			status.OrgName = val
		case "Device ID":
			status.DeviceID = val
		}
	}

	return status, nil
}

// WriteZeroTrustConfig 保存配置
func WriteZeroTrustConfig(cfg *ZeroTrustConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config.ZeroTrustConfigPath, data, 0600)
}

// LoadZeroTrustConfig 加载配置
func LoadZeroTrustConfig() (*ZeroTrustConfig, error) {
	data, err := os.ReadFile(config.ZeroTrustConfigPath)
	if err != nil {
		return nil, err
	}
	var cfg ZeroTrustConfig
	return &cfg, json.Unmarshal(data, &cfg)
}

// UnregisterWarpCLI 注销
func UnregisterWarpCLI() error {
	exec.Command("warp-cli", "--accept-tos", "disconnect").Run()
	exec.Command("warp-cli", "--accept-tos", "registration", "delete").Run()
	exec.Command("systemctl", "disable", "--now", "warp-svc").Run()
	os.Remove("/var/lib/cloudflare-warp/mdm.xml")
	return nil
}
