package install

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/pzeus/warpgo/config"
	"github.com/pzeus/warpgo/pkg/ui"
)

// ReleaseInfo GitHub Release 信息
type ReleaseInfo struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"` // changelog
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

const (
	// 发布仓库地址（需根据实际仓库修改）
	releaseAPIURL = "https://api.github.com/repos/pzeus/warpgo/releases/latest"
	// GitHub 代理列表（国内加速）
	ghProxy1 = "https://ghproxy.com/"
	ghProxy2 = "https://mirror.ghproxy.com/"
)

var updateClient = &http.Client{Timeout: 30 * time.Second}

// CheckUpdate 检查是否有新版本可用
func CheckUpdate() (*ReleaseInfo, bool, error) {
	release, err := fetchLatestRelease()
	if err != nil {
		return nil, false, fmt.Errorf("检查更新失败: %v", err)
	}

	remoteVer := strings.TrimPrefix(release.TagName, "v")
	localVer := config.Version

	if compareVersions(remoteVer, localVer) > 0 {
		return release, true, nil
	}
	return release, false, nil
}

// Update 执行自我更新
func Update() error {
	ui.Info("正在检查更新...")

	release, hasUpdate, err := CheckUpdate()
	if err != nil {
		return err
	}

	if !hasUpdate {
		ui.Info(fmt.Sprintf("当前已是最新版本 v%s", config.Version))
		return nil
	}

	remoteVer := strings.TrimPrefix(release.TagName, "v")
	ui.Info(fmt.Sprintf("发现新版本: v%s → v%s", config.Version, remoteVer))

	if release.Body != "" {
		ui.Hint("更新日志:")
		fmt.Println(release.Body)
		ui.Blank()
	}

	if !ui.Confirm(fmt.Sprintf("是否更新到 v%s?", remoteVer)) {
		ui.Info("已取消更新")
		return nil
	}

	// 查找匹配当前平台的 asset
	assetName := getAssetName()
	var downloadURL string
	var assetSize int64

	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			assetSize = asset.Size
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("未找到当前平台 (%s/%s) 的预编译文件 %s", runtime.GOOS, runtime.GOARCH, assetName)
	}

	ui.Info(fmt.Sprintf("正在下载 %s (%.1f MB)...", assetName, float64(assetSize)/1024/1024))

	// 下载新版本到临时文件
	tmpPath, err := downloadBinary(downloadURL)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer os.Remove(tmpPath)

	// 获取当前程序路径
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取当前程序路径失败: %v", err)
	}

	// 备份当前二进制
	backupPath := execPath + ".bak"
	if err := os.Rename(execPath, backupPath); err != nil {
		return fmt.Errorf("备份当前版本失败: %v", err)
	}

	// 将新版本移到原位置
	if err := copyFile(tmpPath, execPath); err != nil {
		// 恢复备份
		os.Rename(backupPath, execPath)
		return fmt.Errorf("替换二进制文件失败: %v", err)
	}

	// 设置可执行权限
	os.Chmod(execPath, 0755)

	// 删除备份
	os.Remove(backupPath)

	ui.Info(fmt.Sprintf("✓ 更新成功！已升级到 v%s", remoteVer))
	ui.Hint("请重新运行程序以使用新版本。")
	return nil
}

// fetchLatestRelease 从 GitHub API 获取最新 release 信息
func fetchLatestRelease() (*ReleaseInfo, error) {
	// 尝试直连
	urls := []string{
		releaseAPIURL,
		ghProxy1 + releaseAPIURL,
		ghProxy2 + releaseAPIURL,
	}

	for _, url := range urls {
		resp, err := updateClient.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		var release ReleaseInfo
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			continue
		}

		if release.TagName != "" {
			return &release, nil
		}
	}

	return nil, fmt.Errorf("无法连接到更新服务器，请检查网络或稍后重试")
}

// getAssetName 根据当前系统生成预期的 asset 文件名
func getAssetName() string {
	os := runtime.GOOS   // linux, darwin, windows
	arch := runtime.GOARCH // amd64, arm64

	name := fmt.Sprintf("warpgo_%s_%s", os, arch)
	if os == "windows" {
		name += ".exe"
	}
	return name
}

// downloadBinary 下载二进制到临时文件
func downloadBinary(url string) (string, error) {
	// 尝试使用代理加速
	urls := []string{url, ghProxy1 + url, ghProxy2 + url}

	for _, u := range urls {
		tmpFile, err := os.CreateTemp("", "warpgo-update-*")
		if err != nil {
			return "", err
		}

		resp, err := updateClient.Get(u)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			continue
		}

		_, err = io.Copy(tmpFile, resp.Body)
		resp.Body.Close()
		tmpFile.Close()

		if err != nil {
			os.Remove(tmpFile.Name())
			continue
		}

		return tmpFile.Name(), nil
	}

	return "", fmt.Errorf("所有下载源均失败")
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// compareVersions 比较版本号，返回: >0 表示 a>b, 0 表示相等, <0 表示 a<b
func compareVersions(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var numA, numB int
		if i < len(partsA) {
			fmt.Sscanf(partsA[i], "%d", &numA)
		}
		if i < len(partsB) {
			fmt.Sscanf(partsB[i], "%d", &numB)
		}
		if numA != numB {
			return numA - numB
		}
	}
	return 0
}
