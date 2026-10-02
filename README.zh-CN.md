# vps-sentinel · ChiphaLo fork

面向 Linux VPS 的轻量 Rust 入侵信号监控：提供证据与告警、可选来源 IP 封禁，以及多服务器安全面板。

[English](README.md) · [部署教程](docs/deployment.zh-CN.md) · [实测报告](docs/validation-2026-10-01.md) · [安全增强 / PR #1](https://github.com/ChiphaLo/vps-sentinel/pull/1) · [上游项目](https://github.com/cryptoli/vps-sentinel)

[![Fork CI](https://github.com/ChiphaLo/vps-sentinel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ChiphaLo/vps-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Fork 与分支状态

本仓库 fork 自 [cryptoli/vps-sentinel](https://github.com/cryptoli/vps-sentinel)。原作者提供 agent 和面板，本 fork 着重补充 Linux 安全数据采集、状态漂移检测和隔离实测。

| 分支 | 内容 |
| --- | --- |
| `main` | 上游 v0.3.1 基础代码和本 fork 的说明文档。 |
| [`feat/security-coverage-phase1`](https://github.com/ChiphaLo/vps-sentinel/tree/feat/security-coverage-phase1) | 安全覆盖与可靠性增强，已验证提交为 [`0d9e53f`](https://github.com/ChiphaLo/vps-sentinel/commit/0d9e53ff51de34932fab814fa878d69b7774a5d3)。 |

安全增强仍在 [PR #1](https://github.com/ChiphaLo/vps-sentinel/pull/1) 中，尚未合并到 `main`。要使用这些改动，请明确安装功能分支。下面的命令同时指定 fork 地址和分支；只下载 fork 的安装脚本，不会覆盖脚本内的上游默认地址。

## 能监控什么

| 模块 | 覆盖范围 |
| --- | --- |
| SSH 与账户 | 登录、连续失败、爆破后成功、SSH key 变化、新用户及 UID 0 账户漂移。 |
| 文件与持久化 | 关键文件、Web 内容、cron、systemd、启动项，以及基线复核和白名单。 |
| 进程与网络 | 父进程链、可执行文件身份、已知矿工/扫描器身份、监听端口、外连快照及 Web 探测日志。 |
| Docker 与 audit | 容器配置和 audit 日志；扩展规则位于安全功能分支。 |
| 响应与报告 | 可选 nftables/iptables 来源 IP 封禁、解封与到期维护、攻击指纹和通知渠道。 |
| 多服务器面板 | 可选 Rust 自建或 Cloudflare Worker/D1 面板、签名上报和隐私脱敏。 |

### 安全功能分支新增内容

- 检查 privileged、宿主命名空间、Docker socket、可写宿主根目录挂载，以及包含 `ALL` 的危险 capability。
- 保留 audit 参数的引号与空格、解码十六进制 argv；有执行遥测时识别凭据读取、权限持久化、内核模块操作及禁用日志的命令。
- 检测已监控文件的 SUID/SGID、所有者和 Linux capability 漂移，内容不变也能发现（`FILE-005`、`FILE-006`）。只在原 FIM 路径上读取一个有界 xattr，不增加 Rust 依赖，不做全盘扫描。
- 扩展 FIM 和持久化路径，保留采集期间收到的 SIGINT，并避免把僵尸/已终止进程误报为活动进程。
- 提供小型运行镜像和可复现的隔离攻击响应实验。

## 安装这个 fork

安全分支已经通过源码验证。命令明确使用 `INSTALL_METHOD=source`，避免下载上游或与指定分支无关的 release 二进制。

```bash
curl -fsSL https://raw.githubusercontent.com/ChiphaLo/vps-sentinel/feat/security-coverage-phase1/install.sh | \
  sudo env REPO_URL="https://github.com/ChiphaLo/vps-sentinel.git" \
    BRANCH="feat/security-coverage-phase1" INSTALL_METHOD="source" \
    ACTIVE_RESPONSE_ENABLED="no" \
    ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED="no" sh
```

该示例让新安装的实例先关闭自动 IP 封禁。先运行 `sudo vs doctor`、查看告警及可信管理员白名单，再按实际需要启用响应。重装保留已有配置和本地状态，切换仓库或重装时应检查现有配置。源码构建需要 Rust 和临时构建空间；安装成功后默认删除 target 构建目录。

从同一个 fork、同一个分支升级：

```bash
curl -fsSL https://raw.githubusercontent.com/ChiphaLo/vps-sentinel/feat/security-coverage-phase1/update.sh | \
  sudo env REPO_URL="https://github.com/ChiphaLo/vps-sentinel.git" \
    BRANCH="feat/security-coverage-phase1" INSTALL_METHOD="source" sh
```

通知渠道、可选面板上报、服务操作及完整参数见 [agent 部署教程](docs/deployment.zh-CN.md)，面板见 [面板部署教程](docs/panel-deployment.zh-CN.md)。

## 常用本地操作

| 命令 | 用途 |
| --- | --- |
| `sudo vs doctor` | 检查配置、工具和采集可见性。 |
| `sudo vs check --json` | 查看当前事实，不持久化、不通知、不封禁；不对比已保存基线。 |
| `sudo vs scan --no-notify --json` | 保存扫描并比较基线，不通知、不执行主动响应。 |
| `sudo vs baseline create` | 确认当前状态可信后建立基线。 |
| `sudo vs baseline diff` | 复核相对基线的变化。 |
| `sudo vs blocks list` / `sudo vs blocks why <ip> --json` | 查看封禁及实际到期时间。 |
| `sudo vs blocks unblock <ip>` / `sudo vs blocks cleanup` | 解封或维护过期、失效封禁状态。 |
| `sudo vs config validate` / `sudo vs reload` | 校验配置并重载服务。 |
| `sudo vs menu` | 本地引导式配置与复核。 |

## 已验证的结果

**2026-10-01** 在 hyvps（Debian 13 x86_64）验证安全分支提交 `0d9e53f`：

| 检查 | 结果 |
| --- | --- |
| Debian/bookworm workspace | 546 项通过、0 失败；需要 Docker socket 的 1 项在宿主单独执行。 |
| Alpine/musl workspace | 546 项通过、0 失败；同一项宿主专用测试跳过。 |
| 宿主专项 | 13 项全部通过，包含 Docker socket 测试。 |
| 构建与代码检查 | locked release、格式检查、严格 Clippy 通过。 |
| 隔离运行 | 真实 SSH 失败和 HTTP 探测被识别、封禁；七类惰性入侵后样本被识别。 |
| 资源采样 | 每 5 秒扫描，15 秒采样中 daemon RSS 约 12.4 MiB，进程 CPU 约占单核 0.7%。 |

这是带日期的宿主实测记录，不代表当前 GitHub Actions 已全绿。资源占用取决于监控范围和负载，CPU 不含子进程。方法、边界和复现入口见 [实测报告](docs/validation-2026-10-01.md)。

## 检测与处置边界

主动响应封禁来源 IP，不会自动杀进程、删除后门或恢复账户。实验脚本只清理自己的惰性样本，再独立复扫；不能把这个步骤当成产品自动清除入侵。

audit 规则需要配置真实 audit 遥测。内置运行探针是可选组件，已经结束的瞬时活动可能躲过轮询快照：没有 audit/eBPF 数据源的实验未捕获短暂凭据读取和短暂外连。本 fork 不宣称具备完整 EDR 覆盖、软件包内容完整性验证或 rootkit 清除。权限/capability 比较只覆盖配置的监控文件，且需要包含对应字段的可信基线。

普通隔离容器只观察自身，不会自动监控宿主。运行镜像和实验不是宿主监控部署方案的替代。

## 隐私、贡献与上游

默认使用本地 SQLite；面板上报和通知渠道需要配置。签名遥测对原始证据、路径、命令和服务器标识做脱敏；确认的攻击来源 IP 可以出现在公开黑名单中。面板不提供远程 SSH 或命令控制，特权操作保留在节点本地。

凭据存放在本地配置或部署 secret 中。[贡献说明](CONTRIBUTING.md) 提供开发和规则要求，[安全反馈](SECURITY.md) 说明私下报告方式。保留原作者署名和 [MIT 许可证](LICENSE)，见 [许可证说明](docs/open-source-license.md)。
