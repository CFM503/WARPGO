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
	if s.HasIPv4 && s.IPv4 != nil {
		warpMark := ""
		if s.WARPTraceV4 == "on" || s.WARPTraceV4 == "plus" {
			warpMark = " [WARP]"
		}
		parts = append(parts, fmt.Sprintf("IPv4: %s %s %s%s",
			s.IPv4.IP, s.IPv4.Country, s.IPv4.Org, warpMark))
	}
	if s.HasIPv6 && s.IPv6 != nil {
		warpMark := ""
		if s.WARPTraceV6 == "on" || s.WARPTraceV6 == "plus" {
			warpMark = " [WARP]"
		}
		parts = append(parts, fmt.Sprintf("IPv6: %s %s %s%s",
			s.IPv6.IP, s.IPv6.Country, s.IPv6.Org, warpMark))
	}
	if len(parts) == 0 {
		return "网络不可用"
	}
	return strings.Join(parts, "\n\t\t    ")
}
