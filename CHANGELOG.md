# Changelog

## [1.2.4] - 2026-03-24

### 错误处理修复
- **18处函数调用添加错误检查**：
  - `install.Install()` - 6处
  - `install.Uninstall()` - 2处
  - `wireguard.Toggle()` - 1处
  - `wireguard.SwitchGlobalMode()` - 1处
  - `wireguard.SwitchStack()` - 3处
  - `zerotrust.Connect()` - 1处
  - `zerotrust.Disconnect()` - 1处

### 改进
- 统一错误处理格式
- 命令行模式使用 `ui.Error()` 终止程序
- 菜单模式使用 `ui.Warning()` 继续运行

---

## [1.2.1] - 2026-03-24

### 网络状态显示优化
- **WARP 接口 IP 检测**：新增 WARP 接口出口 IP 检测功能
- **显示 WARP 接口 IP**：在非全局模式下，显示 WARP 接口的出口 IP
- **检测方式**：使用 `curl --interface warp` 检测 WARP 接口 IP

### 修复
- 修复 WARP 非全局模式下网络状态显示不正确的问题
- 修复 WARP 接口存在但未显示出口 IP 的问题

### 显示效果
- 现在会显示两种 IP：
  - 默认路由 IP（可能走 WARP 也可能不走）
  - WARP 接口 IP（明确走 WARP 的流量）

---

## [1.2.0] - 2026-03-24

### 显示面板重构
- **全新状态面板**：显示接入方式、连接状态、网络信息
- **接入方式显示**：
  - `WARP WireGuard` - WireGuard 连接
  - `Zero Trust` - Zero Trust 连接  
  - `未安装` - 未安装任何组件
- **状态标识**：
  - ✓ 运行中（绿色）
  - ✗ 已停止（红色）
- **连接信息**：
  - WARP：显示模式（全局/非全局）
  - Zero Trust：显示组织名称
- **网络信息**：
  - IPv4 和 IPv6 都显示
  - 无 IPv6 时显示 "IPv6: 无"
  - WARP 流量标识 `[WARP]`

### 修复
- 修复卸载后状态显示不正确的问题
- 修复只显示 IPv6 不显示 IPv4 的问题

### 代码优化
- 删除未使用的 PrintConnectionInfo 函数
- 简化状态检测逻辑
- 统一显示格式

---

## [1.1.0M] - 2026-03-24

### 重大变更
- **Zero Trust 模块恢复到 commit 69db6c2**：包含完整的透明代理功能（redsocks + iptables 规则）
- **WireProxy 功能已移除**：与 commit 69db6c2 保持一致
- **删除检查更新功能**：简化菜单结构

### 新增功能
- **帮助菜单**：按 `h` 显示命令行参数和使用说明
- **Zero Trust 专用配置菜单**：独立的配置流程，提供详细说明和返回选项
- **输入验证**：配置 Zero Trust 时验证必填字段

### 改进优化
- **菜单逻辑优化**：
  - 统一菜单选项功能
  - 新增帮助选项
  - 移除检查更新选项
  
- **卸载模块全面增强**：
  - 停止 wg-quick@warp 服务
  - 清理 not fwmark 规则
  - 清理 from/to 策略路由规则
  - 清理 nat 表的 WARP_PROXY 链
  - 清理 nftables ip6 表
  - 重置 sysctl 参数
  - 删除 MDM 配置文件
  - 删除更多 warp-cli 数据目录
  - 增加重试次数确保清理干净

- **性能优化**：
  - 优化 findFreePort() 函数，限制检查范围
  - 消除重复的 system.Detect() 调用

- **代码清理**：
  - 删除未使用的 wireproxy 包
  - 删除 WireProxyRemoved 字段
  - 删除 update.go 文件

### 修复
- 修复卸载后可能残留的网络规则
- 修复防火墙规则清理不完整的问题
- 修复服务停止不完整的问题

### 命令行参数
```
-v    显示版本信息
-4    安装 IPv4 WARP（WireGuard）
-6    安装 IPv6 WARP（WireGuard）
-d    安装双栈 WARP（WireGuard）
-z    配置 Zero Trust（需要 Service Token）
-u    完全卸载所有组件
```

### 技术细节
- Zero Trust 透明代理：使用 redsocks + iptables 规则
- WARP WireGuard：支持全局/非全局模式
- 卸载清理：6 步骤完整清理，确保系统恢复原状

### 已知限制
- 需要 root 权限运行
- Zero Trust 需要 Cloudflare 组织和 Service Token
- 透明代理仅支持 TCP 流量

---

## [1.0.8] - 2026-03-23 (Commit 69db6c2)

### 功能
- 添加 Zero Trust 透明代理支持
- 集成 redsocks 透明代理
- 自动配置 iptables 规则
- SSH 连接保护
- 支持 Service Token 注册

---

## [1.0.7] - 2026-03-22 (初始版本)

### 功能
- WireGuard WARP 安装
- Zero Trust 基础支持
- 交互式菜单
- 命令行参数支持
