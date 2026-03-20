package wireproxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/warp"
)

const wireproxyConfTemplate = `[Interface]
PrivateKey = %s
Address = %s
DNS = 1.1.1.1, 1.0.0.1
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s

[Socks5]
BindAddress = 0.0.0.0:%d
`

// WireproxyConfig 配置参数
type WireproxyConfig struct {
	Account  *warp.Account
	Port     int
	MTU      int
	Endpoint string
}

// IsInstalled 检测 wireproxy 是否已安装
func IsInstalled() bool {
	_, err := os.Stat(config.WireproxyPath)
	return err == nil
}

// IsRunning 检测 wireproxy 是否正在运行
func IsRunning() bool {
	out, err := exec.Command("systemctl", "is-active", "wireproxy").Output()
	if err == nil {
		return strings.TrimSpace(string(out)) == "active"
	}
	// 备用：查找进程
	out2, err2 := exec.Command("pgrep", "wireproxy").Output()
	return err2 == nil && len(strings.TrimSpace(string(out2))) > 0
}

// GenerateConfig 生成 wireproxy 配置文件内容
func GenerateConfig(cfg *WireproxyConfig) string {
	addrV4 := cfg.Account.GetAddressV4()
	// wireproxy 使用 /32 地址
	return fmt.Sprintf(wireproxyConfTemplate,
		cfg.Account.PrivateKey,
		addrV4,
		cfg.MTU,
		cfg.Account.GetPeerPublicKey(),
		cfg.Endpoint,
		cfg.Port,
	)
}

// Install 安装 wireproxy 二进制（从 GitHub 下载）
func Install(arch string, ghProxy string) error {
	// 获取最新版本
	version, err := getLatestVersion(ghProxy)
	if err != nil {
		version = "1.0.9"
	}

	downloadURL := fmt.Sprintf("%shttps://github.com/pufferffish/wireproxy/releases/download/v%s/wireproxy_linux_%s.tar.gz",
		ghProxy, version, arch)

	// 下载
	tmpFile := "/tmp/wireproxy.tar.gz"
	if err := download(downloadURL, tmpFile); err != nil {
		// 尝试备用 CDN
		fallbackURL := fmt.Sprintf("https://gitlab.com/fscarmen/warp/-/raw/main/wireproxy/wireproxy_linux_%s.tar.gz", arch)
		if err2 := download(fallbackURL, tmpFile); err2 != nil {
			return fmt.Errorf("下载 wireproxy 失败: %v", err2)
		}
	}
	defer os.Remove(tmpFile)

	// 解压
	if err := exec.Command("tar", "xzf", tmpFile, "-C", "/usr/bin/").Run(); err != nil {
		return fmt.Errorf("解压 wireproxy 失败: %v", err)
	}

	// 设置可执行权限
	if err := os.Chmod(config.WireproxyPath, 0755); err != nil {
		return fmt.Errorf("设置权限失败: %v", err)
	}

	return nil
}

func getLatestVersion(ghProxy string) (string, error) {
	out, err := exec.Command("wget",
		"--no-check-certificate", "-qO-", "-T1", "-t1",
		ghProxy+"https://api.github.com/repos/pufferffish/wireproxy/releases/latest",
	).Output()
	if err != nil {
		return "", err
	}
	// 解析 tag_name
	content := string(out)
	idx := strings.Index(content, `"tag_name"`)
	if idx < 0 {
		return "", fmt.Errorf("未找到版本信息")
	}
	rest := content[idx:]
	start := strings.Index(rest, `"v`) + 2
	end := strings.Index(rest[start:], `"`)
	if start < 2 || end < 0 {
		return "", fmt.Errorf("解析版本失败")
	}
	return rest[start : start+end], nil
}

func download(url, dest string) error {
	return exec.Command("wget", "--no-check-certificate", "-qO", dest, url).Run()
}

// WriteConfig 写入 wireproxy 配置文件
func WriteConfig(content string) error {
	confPath := filepath.Join(config.ScriptDir, "proxy.conf")
	if err := os.MkdirAll(config.ScriptDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(confPath, []byte(content), 0600)
}

// CreateSystemdService 创建 wireproxy systemd 服务
func CreateSystemdService() error {
	svcContent := `[Unit]
Description=WireProxy - WireGuard proxy
After=network.target

[Service]
ExecStart=/usr/bin/wireproxy -c /etc/wireguard/proxy.conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile("/lib/systemd/system/wireproxy.service", []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("创建 systemd 服务失败: %v", err)
	}
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

// Start 启动 wireproxy 服务
func Start() error {
	return exec.Command("systemctl", "start", "wireproxy").Run()
}

// Stop 停止 wireproxy 服务
func Stop() error {
	return exec.Command("systemctl", "stop", "wireproxy").Run()
}

// Enable 开机自启
func Enable() error {
	return exec.Command("systemctl", "enable", "wireproxy").Run()
}

// Toggle 切换 wireproxy 状态
func Toggle() error {
	if IsRunning() {
		return Stop()
	}
	return Start()
}

// Uninstall 卸载 wireproxy
func Uninstall() error {
	exec.Command("systemctl", "disable", "--now", "wireproxy").Run()
	time.Sleep(time.Second)
	files := []string{
		config.WireproxyPath,
		"/lib/systemd/system/wireproxy.service",
		filepath.Join(config.ScriptDir, "proxy.conf"),
	}
	for _, f := range files {
		os.Remove(f)
	}
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

// GetSOCKS5Addr 返回 SOCKS5 监听地址
func GetSOCKS5Addr(port int) string {
	return fmt.Sprintf("socks5://127.0.0.1:%d", port)
}
