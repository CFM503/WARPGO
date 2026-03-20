package network

import (
	"fmt"
	"os/exec"
	"strings"
)

// DetectSSHClientIP 检测当前 SSH 客户端的公网 IP
// 通过 ss 命令查看已建立的 SSH 连接，找到对端 IP
func DetectSSHClientIP() string {
	// 方法1: ss -tnp 找 sshd 的 established 连接
	out, err := exec.Command("ss", "-tnp").Output()
	if err != nil {
		return ""
	}

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
		// warp-cli 方式排除
		return exec.Command("warp-cli", "--accept-tos", "add-excluded-route", cidr).Run()
	}

	// ip rule 方式（WireGuard 全局模式用）
	if strings.Contains(clientIP, ":") {
		exec.Command("ip", "-6", "rule", "add", "to", cidr, "lookup", "main").Run()
	} else {
		exec.Command("ip", "-4", "rule", "add", "to", cidr, "lookup", "main").Run()
	}
	return nil
}

// GetSSHPorts 获取当前 SSH 监听端口列表
func GetSSHPorts() []string {
	out, err := exec.Command("ss", "-tlpn").Output()
	if err != nil {
		return []string{"22"}
	}

	portSet := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "sshd") && !strings.Contains(line, "dropbear") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		idx := strings.LastIndex(addr, ":")
		if idx >= 0 {
			port := addr[idx+1:]
			portSet[port] = true
		}
	}

	if len(portSet) == 0 {
		return []string{"22"}
	}

	var ports []string
	for p := range portSet {
		ports = append(ports, p)
	}
	return ports
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
// 适用于 warp-cli 模式
func AddDefaultExcludedRoutes() {
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	}
	for _, cidr := range privateRanges {
		exec.Command("warp-cli", "--accept-tos", "add-excluded-route", cidr).Run()
	}
	// 排除 SSH 客户端公网 IP
	ExcludeSSHClientFromWarp(true)
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
