package network

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// IPInfo IP 信息
type IPInfo struct {
	IP      string
	Country string
	City    string
	Org     string // ASN 组织
	IsWARP  bool   // 是否走过 WARP
}

// NetworkStatus 当前网络状态
type NetworkStatus struct {
	IPv4        *IPInfo
	IPv6        *IPInfo
	HasIPv4     bool
	HasIPv6     bool
	WARPTraceV4 string // off / on / plus
	WARPTraceV6 string
	// WARP 接口出口 IP（非全局模式下使用）
	WARPIPv4    *IPInfo
	WARPIPv6    *IPInfo
	HasWARPIPv4 bool
	HasWARPIPv6 bool
}

var httpClient = &http.Client{Timeout: 8 * time.Second}

// GetNetworkStatus 获取完整的网络状态信息
func GetNetworkStatus() *NetworkStatus {
	status := &NetworkStatus{}

	// 并发查询 IPv4 和 IPv6
	ch4 := make(chan *IPInfo, 1)
	ch6 := make(chan *IPInfo, 1)

	go func() { ch4 <- queryIP(false) }()
	go func() { ch6 <- queryIP(true) }()

	status.IPv4 = <-ch4
	status.IPv6 = <-ch6
	status.HasIPv4 = status.IPv4 != nil
	status.HasIPv6 = status.IPv6 != nil

	// 检测 WARP trace
	if status.HasIPv4 {
		status.WARPTraceV4 = checkWARPTrace(false)
	}
	if status.HasIPv6 {
		status.WARPTraceV6 = checkWARPTrace(true)
	}

	// 如果 WARP 接口存在，检测 WARP 接口出口 IP
	if isWARPInterfaceExists() {
		chW4 := make(chan *IPInfo, 1)
		chW6 := make(chan *IPInfo, 1)

		go func() { chW4 <- queryWARPInterfaceIP(false) }()
		go func() { chW6 <- queryWARPInterfaceIP(true) }()

		status.WARPIPv4 = <-chW4
		status.WARPIPv6 = <-chW6
		status.HasWARPIPv4 = status.WARPIPv4 != nil
		status.HasWARPIPv6 = status.WARPIPv6 != nil
	}

	return status
}

func queryIP(useIPv6 bool) *IPInfo {
	// 用 net.Dialer 强制 IPv4 或 IPv6 —— 等价于 curl -4 / curl -6
	var network string
	if useIPv6 {
		network = "tcp6"
	} else {
		network = "tcp4"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}

	// 使用 menu.sh 的同一个 API，一次返回 ip/country/isp/warp trace
	resp, err := client.Get("https://ip.cloudflare.nyc.mn")
	if err != nil {
		// 回退到 ipify
		if ip, err2 := getIPWithStack(client, useIPv6); err2 == nil && ip != "" {
			return &IPInfo{IP: ip}
		}
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		ISP     string `json:"isp"`
		Warp    string `json:"warp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.IP == "" {
		if ip, err2 := getIPWithStack(client, useIPv6); err2 == nil && ip != "" {
			return &IPInfo{IP: ip}
		}
		return nil
	}

	return &IPInfo{
		IP:      data.IP,
		Country: data.Country,
		Org:     data.ISP,
		IsWARP:  data.Warp == "on" || data.Warp == "plus",
	}
}

// getIPWithStack 用指定协议栈获取 IP
func getIPWithStack(client *http.Client, useIPv6 bool) (string, error) {
	var url string
	if useIPv6 {
		url = "https://api6.ipify.org"
	} else {
		url = "https://api4.ipify.org"
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body)), nil
}

// isWARPInterfaceExists 检测 WARP 接口是否存在
func isWARPInterfaceExists() bool {
	out, err := exec.Command("ip", "link", "show", "warp").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "warp")
}

// queryWARPInterfaceIP 通过 WARP 接口获取出口 IP
func queryWARPInterfaceIP(useIPv6 bool) *IPInfo {
	var url string
	if useIPv6 {
		url = "https://api6.ipify.org"
	} else {
		url = "https://api4.ipify.org"
	}

	// 使用 curl 通过 WARP 接口获取 IP
	var cmd *exec.Cmd
	if useIPv6 {
		cmd = exec.Command("curl", "-6", "--interface", "warp", "-s", "--max-time", "5", url)
	} else {
		cmd = exec.Command("curl", "-4", "--interface", "warp", "-s", "--max-time", "5", url)
	}

	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return nil
	}

	return &IPInfo{IP: ip, IsWARP: true}
}

// checkWARPTrace 通过 Cloudflare Trace 检测是否经过 WARP
func checkWARPTrace(useIPv6 bool) string {
	var network string
	if useIPv6 {
		network = "tcp6"
	} else {
		network = "tcp4"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second}

	resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return "off"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	content := string(body)
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "warp=") {
			return strings.TrimPrefix(line, "warp=")
		}
	}
	return "off"
}

// FindBestMTU 寻找最佳 MTU 值（通过 ping 测试）
func FindBestMTU(endpoint string) int {
	host := endpoint
	if idx := strings.LastIndex(endpoint, ":"); idx > 0 {
		host = endpoint[:idx]
	}
	host = strings.Trim(host, "[]")

	// 二分法找最大 MTU
	low, high := 1200, 1500
	best := DefaultMTU

	for low <= high {
		mid := (low + high) / 2
		size := mid - 28 // 去掉 IP(20) + ICMP(8) 头
		if size <= 0 {
			break
		}
		cmd := exec.Command("ping", "-c", "1", "-W", "1", "-M", "do", "-s", strconv.Itoa(size), host)
		if err := cmd.Run(); err != nil {
			high = mid - 1
		} else {
			best = mid
			low = mid + 1
		}
	}
	return best
}

const DefaultMTU = 1280

// String 返回格式化的网络状态信息
func (s *NetworkStatus) String() string {
	var parts []string

	// IPv4 信息 - 固定格式对齐
	if s.HasIPv4 && s.IPv4 != nil {
		warpMark := ""
		if s.WARPTraceV4 == "on" || s.WARPTraceV4 == "plus" {
			warpMark = " [WARP]"
		}
		// 格式: IPv4: <IP> <Country> <Org> [WARP]
		parts = append(parts, fmt.Sprintf("IPv4:      %-15s %-4s %-25s%s",
			s.IPv4.IP, s.IPv4.Country, truncateOrg(s.IPv4.Org), warpMark))
	} else {
		parts = append(parts, "IPv4:      无")
	}

	// IPv6 信息 - 固定格式对齐
	if s.HasIPv6 && s.IPv6 != nil {
		warpMark := ""
		if s.WARPTraceV6 == "on" || s.WARPTraceV6 == "plus" {
			warpMark = " [WARP]"
		}
		// IPv6 地址截断显示
		ip := truncateIPv6(s.IPv6.IP)
		parts = append(parts, fmt.Sprintf("IPv6:      %-15s %-4s %-25s%s",
			ip, s.IPv6.Country, truncateOrg(s.IPv6.Org), warpMark))
	} else {
		parts = append(parts, "IPv6:      无")
	}

	// WARP 接口 IPv4 信息
	if s.HasWARPIPv4 && s.WARPIPv4 != nil {
		parts = append(parts, fmt.Sprintf("WARP IPv4: %-15s %s", s.WARPIPv4.IP, "[WARP接口]"))
	}

	// WARP 接口 IPv6 信息
	if s.HasWARPIPv6 && s.WARPIPv6 != nil {
		ip := truncateIPv6(s.WARPIPv6.IP)
		parts = append(parts, fmt.Sprintf("WARP IPv6: %-15s %s", ip, "[WARP接口]"))
	}

	if len(parts) == 0 {
		return "网络不可用"
	}
	return strings.Join(parts, "\n                    ")
}

// truncateIPv6 截断 IPv6 地址显示
func truncateIPv6(ip string) string {
	if len(ip) > 15 {
		return ip[:15] + ".."
	}
	return ip
}

// truncateOrg 截断组织名称显示
func truncateOrg(org string) string {
	if len(org) > 25 {
		return org[:25] + ".."
	}
	return org
}

// StringSimple 返回简化的网络状态信息（单行）
func (s *NetworkStatus) StringSimple() string {
	var parts []string

	if s.HasIPv4 && s.IPv4 != nil {
		warpMark := ""
		if s.WARPTraceV4 == "on" || s.WARPTraceV4 == "plus" {
			warpMark = " [WARP]"
		}
		parts = append(parts, fmt.Sprintf("v4:%s%s", s.IPv4.IP, warpMark))
	} else {
		parts = append(parts, "v4:无")
	}

	if s.HasIPv6 && s.IPv6 != nil {
		warpMark := ""
		if s.WARPTraceV6 == "on" || s.WARPTraceV6 == "plus" {
			warpMark = " [WARP]"
		}
		parts = append(parts, fmt.Sprintf("v6:%s%s", s.IPv6.IP, warpMark))
	} else {
		parts = append(parts, "v6:无")
	}

	return strings.Join(parts, " | ")
}
