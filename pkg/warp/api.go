package warp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Account WARP 账户信息
type Account struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	PrivateKey string `json:"private_key"`
	Key        string `json:"key"` // 公钥
	Token      string `json:"token"`
	Config     struct {
		ClientID string `json:"client_id"`
		Reserved []int  `json:"reserved"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
	AccountInfo struct {
		AccountType string `json:"account_type"`
		WarpPlus    bool   `json:"warp_plus"`
		License     string `json:"license"`
	} `json:"account"`
	WarpEnabled bool `json:"warp_enabled"`

	// Zero Trust
	IsTeams bool   `json:"-"` // 是否为 Teams 账户
	OrgName string `json:"-"` // 组织名称（Zero Trust）
	TeamURL string `json:"-"` // Zero Trust Team URL
}

const (
	apiBase        = "https://api.cloudflareclient.com/v0a2158"
	registerURL    = "https://warp.cloudflare.nyc.mn/?run=register"
	clientVersion  = "a-6.10-2158"
	userAgent      = "okhttp/3.12.1"
	fallbackAccount = `{
  "id": "b0fe9b24-3396-486e-a12d-c194dbbb7bfb",
  "type": "a",
  "model": "PC",
  "key": "rizJSrjeCO51ck8Rmj9YwstFnf6M9rJKZIXFQo3y8j8=",
  "private_key": "hTk06uwwXhZx3RVqtug3MQ0RSodzdM/U5z/M5NIbh4c=",
  "account": {"id": "5a43e4b3-2e13-46b9-9437-2abe55cd5f4b","account_type": "free","warp_plus": true,"license": "36L7Pg9E-j6Jp2x04-I40UQ39C"},
  "config": {
    "client_id": "lzaY",
    "reserved": [151, 54, 152],
    "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","endpoint": {"v4": "162.159.192.5:0","v6": "[2606:4700:d0::a29f:c005]:0","host": "engage.cloudflareclient.com:2408","ports": [2408,500,1701,4500]}}],
    "interface": {"addresses": {"v4": "172.16.0.2","v6": "2606:4700:110:8a4d:b5e5:4a21:87::1"}}
  },
  "token": "50d988c2-b5fb-c829-42dd-a33a960ea734",
  "warp_enabled": true
}`
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Register 注册 WARP 账户并返回账户信息
func Register() (*Account, error) {
	resp, err := httpClient.Get(registerURL)
	if err != nil {
		return parseFallback()
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return parseFallback()
	}

	var acc Account
	if err := json.Unmarshal(body, &acc); err != nil || acc.ID == "" {
		return parseFallback()
	}

	return &acc, nil
}

// LoadFromFile 从文件加载账户信息
func LoadFromFile(path string) (*Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取账户文件失败: %v", err)
	}

	var acc Account
	if err := json.Unmarshal(data, &acc); err != nil {
		return nil, fmt.Errorf("解析账户文件失败: %v", err)
	}

	// 判断是否为 Teams 账户（ID 以 t. 开头）
	if len(acc.ID) > 2 && acc.ID[:2] == "t." {
		acc.IsTeams = true
	}

	return &acc, nil
}

// SaveToFile 保存账户信息到文件
func (a *Account) SaveToFile(path string) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化账户信息失败: %v", err)
	}
	if err := os.MkdirAll("/etc/wireguard", 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Cancel 注销账户（通过 DELETE API）
func (a *Account) Cancel() error {
	// Teams 账户或预设账户不注销
	if a.IsTeams || a.ID == "b0fe9b24-3396-486e-a12d-c194dbbb7bfb" {
		return nil
	}

	req, err := http.NewRequest("DELETE",
		fmt.Sprintf("%s/reg/%s", apiBase, a.ID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// GetPeerPublicKey 获取 WireGuard Peer 公钥
func (a *Account) GetPeerPublicKey() string {
	if len(a.Config.Peers) > 0 {
		return a.Config.Peers[0].PublicKey
	}
	return "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
}

// GetEndpoint 获取最合适的 Endpoint
// Cloudflare WARP API 返回的 v4/v6 端点端口可能是 :0（无效），
// 必须优先使用 host 字段（含正确端口），或回落到已知可用地址。
func (a *Account) GetEndpoint(useV6 bool) string {
	if len(a.Config.Peers) > 0 {
		ep := a.Config.Peers[0].Endpoint

		// host 字段是 "engage.cloudflareclient.com:2408"，端口最可靠
		if ep.Host != "" {
			return ep.Host
		}

		// v6 地址：过滤掉端口为 0 或空的情况
		if useV6 && ep.V6 != "" && !strings.HasSuffix(ep.V6, ":0") && ep.V6 != "[]:0" {
			return ep.V6
		}

		// v4 地址：过滤掉端口为 0 的情况（如 "162.159.192.5:0"）
		if !useV6 && ep.V4 != "" && !strings.HasSuffix(ep.V4, ":0") {
			return ep.V4
		}
	}

	// 最终回落到已知稳定的 Cloudflare WARP Endpoint
	if useV6 {
		return "[2606:4700:d0::a29f:c001]:2408"
	}
	return "162.159.192.1:2408"
}

// GetAddressV4 获取 WireGuard IPv4 地址
func (a *Account) GetAddressV4() string {
	if a.Config.Interface.Addresses.V4 != "" {
		return a.Config.Interface.Addresses.V4 + "/32"
	}
	return "172.16.0.2/32"
}

// GetAddressV6 获取 WireGuard IPv6 地址（去掉已有的前缀长度）
func (a *Account) GetAddressV6() string {
	v6 := a.Config.Interface.Addresses.V6
	if v6 == "" {
		return ""
	}
	// 有些 API 返回带 /128，有些不带，统一处理
	v6 = strings.Split(v6, "/")[0]
	return v6 + "/128"
}

func parseFallback() (*Account, error) {
	var acc Account
	if err := json.Unmarshal([]byte(fallbackAccount), &acc); err != nil {
		return nil, fmt.Errorf("解析降级账户失败: %v", err)
	}
	return &acc, nil
}

// UpdateLicense 更新 WARP+ License Key
func (a *Account) UpdateLicense(license string) error {
	payload := fmt.Sprintf(`{"license": "%s"}`, license)
	req, err := http.NewRequest("PUT",
		fmt.Sprintf("%s/reg/%s/account", apiBase, a.ID),
		strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("更新 License 失败，状态码: %d", resp.StatusCode)
	}
	return nil
}
