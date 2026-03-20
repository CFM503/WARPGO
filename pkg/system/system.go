package system

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// OSType 操作系统类型
type OSType string

const (
	OSDebian  OSType = "Debian"
	OSUbuntu  OSType = "Ubuntu"
	OSCentOS  OSType = "CentOS"
	OSFedora  OSType = "Fedora"
	OSAlpine  OSType = "Alpine"
	OSArch    OSType = "Arch"
	OSUnknown OSType = "Unknown"
)

// PackageManager 包管理器类型
type PackageManager int

const (
	PkgAPT PackageManager = iota
	PkgYUM
	PkgDNF
	PkgAPK
	PkgPacman
)

// SysInfo 系统信息
type SysInfo struct {
	OS           OSType
	OSVersion    string
	MajorVersion int
	Arch         string // amd64, arm64, armv7, etc.
	Kernel       string
	Virt         string // kvm, openvz, lxc, none, etc.
	PkgManager   PackageManager
	HasIPv4      bool
	HasIPv6      bool
}

// Detect 检测并返回系统信息
func Detect() (*SysInfo, error) {
	info := &SysInfo{}

	// 架构检测
	switch runtime.GOARCH {
	case "amd64":
		info.Arch = "amd64"
	case "arm64":
		info.Arch = "arm64"
	case "arm":
		info.Arch = "armv7"
	case "386":
		info.Arch = "386"
	default:
		info.Arch = runtime.GOARCH
	}

	// 内核版本
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	// OS 检测
	if err := info.detectOS(); err != nil {
		return nil, err
	}

	// 虚拟化检测
	info.detectVirt()

	// 双栈检测
	info.HasIPv4, info.HasIPv6 = checkNetworkStack()

	return info, nil
}

func (s *SysInfo) detectOS() error {
	// 读取 /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		// 尝试 /etc/alpine-release
		if _, e := os.Stat("/etc/alpine-release"); e == nil {
			s.OS = OSAlpine
			s.PkgManager = PkgAPK
			return nil
		}
		return fmt.Errorf("无法检测操作系统: %v", err)
	}

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
		case "ID":
			switch strings.ToLower(val) {
			case "debian":
				s.OS = OSDebian
				s.PkgManager = PkgAPT
			case "ubuntu":
				s.OS = OSUbuntu
				s.PkgManager = PkgAPT
			case "centos", "rhel", "almalinux", "rocky":
				s.OS = OSCentOS
				s.PkgManager = PkgYUM
			case "fedora":
				s.OS = OSFedora
				s.PkgManager = PkgDNF
			case "alpine":
				s.OS = OSAlpine
				s.PkgManager = PkgAPK
			case "arch", "manjaro":
				s.OS = OSArch
				s.PkgManager = PkgPacman
			default:
				s.OS = OSUnknown
			}
		case "VERSION_ID":
			s.OSVersion = val
			fmt.Sscanf(val, "%d", &s.MajorVersion)
		}
	}

	if s.OS == OSUnknown {
		return fmt.Errorf("不支持的操作系统，请使用 Debian/Ubuntu/CentOS/Alpine/Arch")
	}

	// CentOS 8+ 使用 DNF
	if s.OS == OSCentOS && s.MajorVersion >= 8 {
		s.PkgManager = PkgDNF
	}

	return nil
}

func (s *SysInfo) detectVirt() {
	// 优先 systemd-detect-virt
	if out, err := exec.Command("systemd-detect-virt").Output(); err == nil {
		v := strings.TrimSpace(string(out))
		if v != "none" {
			s.Virt = v
			return
		}
	}
	// 尝试读取 /proc/1/environ 特征
	if data, err := os.ReadFile("/proc/1/environ"); err == nil {
		env := string(data)
		if strings.Contains(env, "container=lxc") {
			s.Virt = "lxc"
			return
		}
	}
	// 读取 /proc/cpuinfo 中的 hypervisor 标志
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(data), "hypervisor") {
			s.Virt = "kvm"
			return
		}
	}
	s.Virt = "none"
}

func checkNetworkStack() (hasV4, hasV6 bool) {
	// 检测 IPv4
	out4, err4 := exec.Command("ip", "-4", "addr").Output()
	if err4 == nil && strings.Contains(string(out4), "inet ") {
		hasV4 = true
	}
	// 检测 IPv6
	out6, err6 := exec.Command("ip", "-6", "addr").Output()
	if err6 == nil {
		lines := string(out6)
		// 排除 loopback (::1)
		for _, line := range strings.Split(lines, "\n") {
			if strings.Contains(line, "inet6") && !strings.Contains(line, "::1") {
				hasV6 = true
				break
			}
		}
	}
	return
}

// CheckRoot 验证 root 权限
func CheckRoot() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("请使用 root 用户运行此程序")
	}
	return nil
}

// InstallPackages 安装系统包
func InstallPackages(pm PackageManager, packages ...string) error {
	if len(packages) == 0 {
		return nil
	}
	pkgStr := strings.Join(packages, " ")
	var cmd *exec.Cmd

	switch pm {
	case PkgAPT:
		exec.Command("apt-get", "update", "-qq").Run() //nolint
		args := append([]string{"install", "-y", "-qq"}, packages...)
		cmd = exec.Command("apt-get", args...)
	case PkgYUM:
		args := append([]string{"install", "-y"}, packages...)
		cmd = exec.Command("yum", args...)
	case PkgDNF:
		args := append([]string{"install", "-y"}, packages...)
		cmd = exec.Command("dnf", args...)
	case PkgAPK:
		args := append([]string{"add", "--no-cache"}, packages...)
		cmd = exec.Command("apk", args...)
	case PkgPacman:
		args := append([]string{"-S", "--noconfirm"}, packages...)
		cmd = exec.Command("pacman", args...)
	default:
		return fmt.Errorf("不支持的包管理器")
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装 %s 失败: %v", pkgStr, err)
	}
	return nil
}

// CheckBinaryExists 检查二进制是否存在
func CheckBinaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RunCommand 运行命令并返回输出
func RunCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// RunCommandSilent 静默运行命令（忽略输出）
func RunCommandSilent(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// String 返回系统信息字符串
func (s *SysInfo) String() string {
	return fmt.Sprintf("%s %s | 内核: %s | 架构: %s | 虚拟化: %s",
		s.OS, s.OSVersion, s.Kernel, s.Arch, s.Virt)
}
