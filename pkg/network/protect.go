package network

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// DetectSSHClientIP 检测当前 SSH 客户端的公网 IP
// 通过 ss 命令查看已建立的 SSH 连接，找到对端 IP
func DetectSSHClientIP() string {
	// 方法1: ss -tnp 找 sshd 的 established 连接
	out, err := exec.Command("ss", "-tnp").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, "sshd") && !strings.Contains(line, "dropbear") {
				continue
			}
			if !strings.Contains(line, "ESTAB") {
				continue
			}
			// 格式: ESTAB 0 0 10.0.0.1:22 1.2.3.4:54321
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			peer := fields[4] // 对端 ip:port
			// 去掉端口
			idx := strings.LastIndex(peer, ":")
			if idx > 0 {
				ip := peer[:idx]
				// 过滤掉私有IP，只要公网IP
				if !isPrivateIP(ip) {
					return ip
				}
			}
		}
	}

	// 方法2: 从 who 命令获取
	out2, err2 := exec.Command("who", "-u").Output()
	if err2 == nil {
		for _, line := range strings.Split(string(out2), "\n") {
			// 格式: root pts/0 2024-01-01 12:00 . 1234 (1.2.3.4)
			if strings.Contains(line, "(") {
				start := strings.LastIndex(line, "(")
				end := strings.LastIndex(line, ")")
				if start >= 0 && end > start {
					ip := line[start+1 : end]
					if !isPrivateIP(ip) && ip != "" {
						return ip
					}
				}
			}
		}
	}

	// 方法3: 从 /proc/net/tcp 中获取（适用于没有 ss 或 who 命令的情况）
	if out3, err3 := exec.Command("cat", "/proc/net/tcp").Output(); err3 == nil {
		// 解析 /proc/net/tcp，查找 SSH 端口（22）的连接
		for _, line := range strings.Split(string(out3), "\n") {
			if !strings.Contains(line, ":0016") { // 22 的十六进制是 0x0016
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// 本地地址:端口 远程地址:端口 状态
			remoteAddr := fields[2]
			parts := strings.Split(remoteAddr, ":")
			if len(parts) != 2 {
				continue
			}
			// 转换十六进制 IP 为点分十进制
			ipHex := parts[0]
			if len(ipHex) == 8 {
				// IPv4
				var ipBytes [4]byte
				for i := 0; i < 4; i++ {
					b, _ := strconv.ParseUint(ipHex[i*2:i*2+2], 16, 8)
					ipBytes[i] = byte(b)
				}
				ip := fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
				if !isPrivateIP(ip) && ip != "0.0.0.0" {
					return ip
				}
			}
		}
	}

	return ""
}

// ExcludeSSHClientFromWarp 排除 SSH 客户端 IP 使其不走 WARP/ZT
// 支持 warp-cli 和 ip rule 两种方式
func ExcludeSSHClientFromWarp(useWarpCLI bool) error {
	clientIP := DetectSSHClientIP()
	if clientIP == "" {
		return nil // 无法检测或不需要
	}

	cidr := clientIP + "/32"
	if strings.Contains(clientIP, ":") {
		cidr = clientIP + "/128"
	}

	if useWarpCLI {
		// 尝试新命令 tunnel ip add，如果失败则使用旧命令
		cmd := exec.Command("warp-cli", "--accept-tos", "tunnel", "ip", "add", cidr)
		if err := cmd.Run(); err != nil {
			// 旧版本使用 add-excluded-route
			exec.Command("warp-cli", "--accept-tos", "add-excluded-route", cidr).Run()
		}
		return nil
	}

	// ip rule 方式（WireGuard 全局模式用）
	if strings.Contains(clientIP, ":") {
		exec.Command("ip", "-6", "rule", "add", "to", cidr, "lookup", "main").Run()
	} else {
		exec.Command("ip", "-4", "rule", "add", "to", cidr, "lookup", "main").Run()
	}
	return nil
}

// isPrivateIP 判断是否为私有 IP
func isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "127.", "::1", "fe80:", "fd",
	}
	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// AddDefaultExcludedRoutes 添加默认排除路由（保护 SSH 和 LAN）
// 适用于 warp-cli 模式；应在 warp-cli connect 之前调用（与 split tunnel 一致）
func AddDefaultExcludedRoutes() {
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	}

	// 尝试新命令 tunnel ip add，如果失败则使用旧命令 add-excluded-route
	tryNewCommand := func(cidr string) {
		// 先尝试新命令格式 (2025+ 版本)
		cmd := exec.Command("warp-cli", "--accept-tos", "tunnel", "ip", "add", cidr)
		if err := cmd.Run(); err != nil {
			// 旧版本使用 add-excluded-route
			exec.Command("warp-cli", "--accept-tos", "add-excluded-route", cidr).Run()
		}
	}

	for _, cidr := range privateRanges {
		tryNewCommand(cidr)
	}

	// 排除 SSH 客户端公网 IP
	ExcludeSSHClientFromWarp(true)
}

// ApplyWarpCLIInboundProtection 在 warp-cli connect 之后调用，与 WireGuard 全局模式的
// GlobalUpScript 对齐：用 connect 之前检测到的 LAN 地址做策略路由，避免回包走错隧道导致 SSH 断开。
func ApplyWarpCLIInboundProtection(lan4, lan6 string) {
	if lan4 != "" {
		exec.Command("ip", "-4", "rule", "add", "from", lan4, "lookup", "main").Run()
	}
	if lan6 != "" {
		exec.Command("ip", "-6", "rule", "add", "from", lan6, "lookup", "main").Run()
	}
	// 保留网段与链路本地：从该源发出的流量走主表（与 pkg/wireguard/config.go GlobalUpScript 一致）
	exec.Command("ip", "-4", "rule", "add", "from", "172.16.0.0/12", "lookup", "main").Run()
	exec.Command("ip", "-4", "rule", "add", "from", "192.168.0.0/16", "lookup", "main").Run()
	exec.Command("ip", "-4", "rule", "add", "from", "10.0.0.0/8", "lookup", "main").Run()
	exec.Command("ip", "-4", "rule", "add", "from", "172.17.0.0/24", "lookup", "main").Run()
	exec.Command("ip", "-6", "rule", "add", "from", "fe80::/10", "lookup", "main").Run()
	exec.Command("sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1").Run()
}

// RemoveWarpCLIInboundProtection 删除 ApplyWarpCLIInboundProtection 添加的策略路由。
// lan4/lan6 为可选；若断开前后检测不一致可各调用一次以尽量清理干净。
func RemoveWarpCLIInboundProtection(lan4, lan6 string) {
	if lan4 != "" {
		exec.Command("ip", "-4", "rule", "del", "from", lan4, "lookup", "main").Run()
	}
	if lan6 != "" {
		exec.Command("ip", "-6", "rule", "del", "from", lan6, "lookup", "main").Run()
	}
	exec.Command("ip", "-4", "rule", "del", "from", "172.16.0.0/12", "lookup", "main").Run()
	exec.Command("ip", "-4", "rule", "del", "from", "192.168.0.0/16", "lookup", "main").Run()
	exec.Command("ip", "-4", "rule", "del", "from", "10.0.0.0/8", "lookup", "main").Run()
	exec.Command("ip", "-4", "rule", "del", "from", "172.17.0.0/24", "lookup", "main").Run()
	exec.Command("ip", "-6", "rule", "del", "from", "fe80::/10", "lookup", "main").Run()
}

// PrintSSHProtectionInfo 打印 SSH 保护信息
func PrintSSHProtectionInfo() string {
	clientIP := DetectSSHClientIP()
	if clientIP != "" {
		return fmt.Sprintf("已检测到 SSH 客户端 IP: %s (已自动排除)", clientIP)
	}
	return "未检测到 SSH 客户端公网 IP"
}

// DetectLAN4 检测服务器的 IPv4 出口源地址（等同于 menu.sh 的 $LAN4）
// 必须在 wg-quick up 之前调用！之后路由表会变
func DetectLAN4() string {
	out, err := exec.Command("ip", "route", "get", "192.168.193.10").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "src" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// DetectLAN6 检测服务器的 IPv6 出口源地址（等同于 menu.sh 的 $LAN6）
func DetectLAN6() string {
	out, err := exec.Command("ip", "route", "get", "2606:4700:d0::a29f:c001").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "src" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
