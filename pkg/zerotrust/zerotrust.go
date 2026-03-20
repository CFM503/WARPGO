package zerotrust

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
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
	_, err := os.Stat(config.WarpCLIPath)
	if err == nil {
		return true
	}
	out, err := exec.Command("which", "warp-cli").Output()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// InstallWarpCLI 安装官方 cloudflare-warp 客户端
func InstallWarpCLI(pm int) error {
	var cmds [][]string
	switch pm {
	case 0: // APT (Debian/Ubuntu)
		cmds = [][]string{
			{"curl", "-fSsL", config.WarpClientRepoDebian, "--output", "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"},
			{"bash", "-c", `echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] ` +
				config.WarpClientAptList + ` $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list`},
			{"apt-get", "update", "-qq"},
			{"apt-get", "install", "-y", "-qq", "cloudflare-warp"},
		}
	case 1, 2: // CentOS/Fedora
		cmds = [][]string{
			{"rpm", "--import", config.WarpClientRepoDebian},
			{"bash", "-c", `curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo > /etc/yum.repos.d/cloudflare-warp.repo`},
			{"yum", "install", "-y", "cloudflare-warp"},
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

// ensureWarpSvc 确保 warp-svc 服务已启动
func ensureWarpSvc() {
	exec.Command("systemctl", "start", "warp-svc").Run()
	time.Sleep(2 * time.Second)
}

// EnrollServiceToken 通过 Service Token + MDM 配置自动注册（不需要浏览器，不受 root 限制）
//
// 流程：
//  1. 写入 MDM 配置文件（组织名 + Client ID + Client Secret）
//  2. 重启 warp-svc（自动读取 MDM 并注册）
//  3. 等待自动注册完成
func EnrollServiceToken(orgName, clientID, clientSecret string) error {
	if !IsWarpCLIInstalled() {
		return fmt.Errorf("warp-cli 未安装，请先安装")
	}

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("Service Token 的 Client ID 和 Client Secret 不能为空")
	}

	ensureWarpSvc()

	// 写入 MDM 配置文件 — warp-svc 重启后自动注册，不需要 registration new
	ui.Info("正在配置 Service Token...")
	mdmContent := fmt.Sprintf(`<dict>
  <key>organization</key>
  <string>%s</string>
  <key>auth_client_id</key>
  <string>%s</string>
  <key>auth_client_secret</key>
  <string>%s</string>
</dict>`, orgName, clientID, clientSecret)

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

// Connect 连接 WARP（通过 warp-cli），自动保护所有入站连接
func Connect() error {
	if !IsWarpCLIInstalled() {
		return fmt.Errorf("warp-cli 未安装")
	}

	// 排除私有地址段
	privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, cidr := range privateRanges {
		exec.Command("warp-cli", "--accept-tos", "add-excluded-route", cidr).Run()
	}

	// 连接
	ui.Info("正在连接...")
	cmd := exec.Command("warp-cli", "--accept-tos", "connect")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// 连接后：用 ip rule 保护所有入站连接（和 WireGuard 全局模式一样）
	ui.Info("正在配置入站连接保护...")
	lan4 := network.DetectLAN4()
	lan6 := network.DetectLAN6()
	if lan4 != "" {
		exec.Command("ip", "-4", "rule", "add", "from", lan4, "lookup", "main").Run()
		ui.Info(fmt.Sprintf("已保护服务器 IPv4: %s (所有入站连接均可访问)", lan4))
	}
	if lan6 != "" {
		exec.Command("ip", "-6", "rule", "add", "from", lan6, "lookup", "main").Run()
		ui.Info(fmt.Sprintf("已保护服务器 IPv6: %s", lan6))
	}
	exec.Command("ip", "-4", "rule", "add", "from", "172.17.0.0/24", "lookup", "main").Run()

	return nil
}

// Disconnect 断开 WARP
func Disconnect() error {
	return exec.Command("warp-cli", "--accept-tos", "disconnect").Run()
}

// SetWarpMode 设置 WARP 模式
func SetWarpMode(mode string) error {
	return exec.Command("warp-cli", "--accept-tos", "set-mode", mode).Run()
}

// SetProxyMode 设置为代理模式（SOCKS5）
func SetProxyMode(port int) error {
	exec.Command("warp-cli", "--accept-tos", "set-mode", "proxy").Run()
	return exec.Command("warp-cli", "--accept-tos", "set-proxy-port", fmt.Sprintf("%d", port)).Run()
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
