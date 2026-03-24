================================================================================
WarpGo — Cloudflare Zero Trust / WARP 使用说明（备忘）
================================================================================
整理日期参考：2025-03-22
说明：后续若在 warpgo 上改代码，可先对照本文；官方文档以 Cloudflare 为准。

--------------------------------------------------------------------------------
一、这个项目（warpgo）在做什么
--------------------------------------------------------------------------------

warpgo 是在 Linux VPS 上安装、管理 Cloudflare WARP 的工具，主要有两条路径：

  模式 A：WireGuard（命令行 -4 / -6 / -d）
    - 自建 warp 接口
    - 不依赖 Zero Trust 组织，偏「个人 WARP」式用法

  模式 B：Zero Trust（命令行 -z 或交互菜单里选 Zero Trust）
    - 使用官方 cloudflare-warp 与 warp-cli
    - 加入你的 Cloudflare Zero Trust 组织
    - 无图形界面服务器上使用 Service Token 注册（MDM 方式）

Zero Trust 流程（与官方 Headless Linux 教程一致）：
  1. 把组织名 + Service Token 的 Client ID / Client Secret 写入
     /var/lib/cloudflare-warp/mdm.xml
  2. 重启 warp-svc，自动注册
  3. warp-cli connect 连接

代码位置备忘：
  - pkg/zerotrust/zerotrust.go  — EnrollServiceToken、Connect、代理模式等
  - pkg/install/install.go      — installZeroTrust
  - cmd/root.go                 — -z 与菜单、Zero Trust 交互输入
  - config/defaults.go          — 路径与常量

--------------------------------------------------------------------------------
二、官方认可的接入步骤（与网友常见教程一致）
--------------------------------------------------------------------------------

前提：已有 Cloudflare Zero Trust 组织。
教程（推荐收藏）：https://developers.cloudflare.com/cloudflare-one/tutorials/warp-on-headless-linux/

步骤 A — 创建 Service Token
  控制台：https://one.dash.cloudflare.com/
  路径：Access controls → Service credentials → Service Tokens → Create
  保存 Client ID 与 Client Secret（Secret 只显示一次）。

步骤 B — 允许用 Service Token 注册设备
  路径：Team & Resources → Devices → Management
  Device enrollment permissions → Manage
  新建策略：Action = Service Auth
  Selector 可选：Any Access Service Token 或指定某个 Service Token
  保存后，将该策略加入 Device enrollment permissions。

步骤 C — 在 VPS 上安装并接入
  方式 1：使用本仓库 warpgo（需 root）
    - 编译/运行后使用 -z，或菜单选择 Zero Trust
    - 按提示填写 Team Name（组织名）、Client ID、Client Secret
    - 是否使用 SOCKS5 代理模式按需求选择（降低全局接管对 SSH 的影响）

  方式 2：按官方示例脚本
    - 安装 cloudflare-warp，写入 mdm.xml（教程含 organization、
      auth_client_id、auth_client_secret、service_mode 等）

MDM 参数说明（官方）：
  https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/mdm-deployment/parameters/

社区讨论参考（以官方为准）：
  https://community.cloudflare.com/t/hwo-to-connect-zero-trust-on-headless-server/760402

--------------------------------------------------------------------------------
三、「给 VPS 换 IP」在 WARP 语境下通常指什么
--------------------------------------------------------------------------------

  出站 IP（访问外网时远端看到的 IP）
    - 在 WARP / warp 模式下，未排除的流量往往从 Cloudflare 侧 egress 出去，
      curl 等测到的公网 IP 会变成 Cloudflare 相关地址，看起来像「换了出口 IP」。
    - 交互菜单里关于「全局模式出口变为 Cloudflare IP」的说明见 cmd/root.go。

  不能指望的事
    - 普通 Zero Trust + WARP 不保证固定、独享、可随意指定的出口 IP；
      IP 由 Cloudflare 调度，重连后可能变化。
    - 若要固定/专用出口 IP，属于企业级或单独商务产品，不是开源脚本默认能力。

  若只是要换云厂商给的 VPS 公网 IP
    - 在云厂商控制台换弹性 IP / 换实例 / 新购机器，与 WARP 无关。

--------------------------------------------------------------------------------
四、命令行速查（warpgo）
--------------------------------------------------------------------------------

  -v    版本
  -4    安装 IPv4 WARP（WireGuard 路径）
  -6    安装 IPv6 WARP
  -d    双栈
  -z    配置 Zero Trust（cloudflare-warp + Service Token）
  -u    卸载

--------------------------------------------------------------------------------
五、后续改代码时可对照的检查点
--------------------------------------------------------------------------------

  - Service Token 与 mdm.xml 字段是否与官方 MDM 参数一致
  - Device enrollment 是否已配置 Service Auth（否则注册失败）
  - 全局 WARP vs 代理模式对 SSH / 路由的影响（pkg/zerotrust 里 excluded route、
    ip rule 等）
  - 组织名（Team Name）须与控制台一致

================================================================================
结束
================================================================================
