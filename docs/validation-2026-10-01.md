# Security branch validation · 2026-10-01

This report records the hyvps run on **2026-10-01**, not a new run triggered by the documentation update. The tested source is [`0d9e53ff51de34932fab814fa878d69b7774a5d3`](https://github.com/ChiphaLo/vps-sentinel/commit/0d9e53ff51de34932fab814fa878d69b7774a5d3) on `feat/security-coverage-phase1`. These changes are proposed in [PR #1](https://github.com/ChiphaLo/vps-sentinel/pull/1), not yet merged into `main`.

本报告记录 2026-10-01 的 hyvps 实测，不是本次文档更新后重新运行的结果。安全代码仍在功能分支；不能将下面的结果归属于 `main` 基础代码。机器可读记录见 [JSON evidence](validation-2026-10-01.json)。

## Build and regression checks

The host was Debian 13 x86_64. Debian/bookworm and Alpine/musl build environments were used separately.

| Environment / check | Result |
| --- | --- |
| Debian/bookworm workspace | 546 passed, 0 failed, 1 ignored |
| Alpine/musl workspace | 546 passed, 0 failed, 1 ignored |
| Explicit host suite | 13 passed, 0 failed, 0 ignored |
| Formatting and strict all-target Clippy | Passed |
| Locked release build | Passed |

The ignored test requires a Docker socket; it passed in the explicit host suite. The suites overlap and should not be added together as a unique test count. Debian used Rust 1.99.0; the musl run used Rust 1.98.1. GitHub workflow/status queries returned no runs/statuses, so cloud CI success was **not confirmed**.

两个 workspace 各有 1 项 Docker socket 测试跳过，该项已在宿主专项中通过。各套件有重叠，不能相加为独立测试总数；GitHub Actions 没有取得运行结果，因此不宣称云端 CI 全绿。

## Runtime isolation and scenarios

The target and attacker were disposable containers on a Docker internal network. No ports were published. Neither host root nor Docker socket was mounted, and host PID/network namespaces and privileged mode were not used. `NET_ADMIN` was limited to the lab containers' own interfaces and firewalls. An isolated veth pair used public-shaped source addresses solely inside the container network namespaces; it did not send traffic to those addresses on the Internet or add host public routes.

| Scenario | Observed result |
| --- | --- |
| Benign HTTP requests | No attack finding |
| Real SSH password failures | `SSH-003`; block applied; blocked source could not connect |
| Real HTTP sensitive-path probes | `WEB-001`; block applied; new connections stopped |
| Manual unblock | Connectivity restored |
| TTL expiry cleanup | Connectivity restored after the recorded `expires_at` |
| SUID/SGID change with unchanged file content | `FILE-005` |
| Capability change with unchanged file content | `FILE-006` |
| Inert cron, SSH key, WebShell text, UID 0 account and miner-identity fixtures | Persistence, SSH, Web, user and process findings |
| Harness cleanup followed by a separate scan | No findings remained |
| SIGINT during daemon collection | Successful exit |

The seven internal-compromise fixture types assume root has already been obtained inside the disposable target. WebShell text was not executed, cron tasks were not started, and the miner identity was an inert `sleep` process. This checks detection of those changes, not prevention of initial compromise or execution of real malware.

外部 SSH/HTTP 流量与防火墙效果均实际验证。内部七类样本假设实验容器已被取得 root；样本是惰性的，不执行 WebShell、cron 或挖矿。主动响应只封禁来源 IP，**产品不自动杀进程、删除后门或恢复账户**。清理由实验脚本针对自己创建的样本执行，之后独立复扫确认。

## Resource sample

| Measurement | Recorded value |
| --- | --- |
| Runtime image | 104,298,834 bytes ≈ 99.5 MiB |
| Fixture image, including SSH/HTTP/test tools | 161,703,296 bytes ≈ 154.2 MiB |
| Release binary | 20,218,448 bytes ≈ 19.3 MiB |
| Daemon RSS, 15 samples | 12,668–12,744 KiB ≈ 12.4 MiB |
| Daemon CPU, 15 seconds, 5-second scan interval | 0.684% of one core, excluding children |
| Individual scenario scans | 0.207–0.363 seconds; RSS 12,344–12,920 KiB |

These are short samples from the configured lab, not production upper bounds. Build tools and fixture services are excluded from the runtime image. FILE-005/006 read one bounded Linux xattr on existing FIM paths; they add neither a new Rust dependency nor a full-disk scan.

以上是指定实验范围内的短时样本，不是生产占用上限。运行镜像不包含构建工具或实验服务；权限/capability 检查只在已有 FIM 路径读取一个有界 xattr。

Release binary SHA-256:

```text
f6855881439f861a7fb6710273e38c76c1f02a00d40ea278e655bbfe188301bf
```

## Coverage limits and host checks

- The lab had no auditd/eBPF execution/connect stream. A brief credential read was not detected and a completed short-lived outbound connection produced no connect event. Snapshot collection does not guarantee coverage of completed activity.
- Audit detection requires configured telemetry. FILE-005/006 apply only to monitored paths and require a trusted metadata baseline. Old baselines remain readable but cannot establish missing historical metadata.
- An ordinary isolated container observes itself; this experiment does not validate host monitoring through a container, package-content integrity, kernel-rootkit detection or destructive remediation.
- Host firewall state matched before and after the lab. Existing SSH, Docker and Caddy services remained active. Temporary lab containers, networks, image tags and build outputs were removed.
- This agent lab does not constitute a fresh end-to-end Cloudflare panel deployment test.

没有 audit/eBPF 时，短暂凭据读取和已结束外连是明确的覆盖缺口。宿主防火墙前后一致，现有服务正常；本次实验不等同于容器监控宿主、内核 rootkit 检测/清除或 Cloudflare 面板端到端部署验证。

## Reproduce on a disposable Linux lab host

Use a disposable Linux host with Docker, Python 3 and a Rust toolchain. Review the [lab design and cleanup scope](https://github.com/ChiphaLo/vps-sentinel/blob/0d9e53ff51de34932fab814fa878d69b7774a5d3/docs/container-lab.zh-CN.md) first. The test files and runtime Dockerfile are on the tested feature commit, not the documentation-only `main` branch.

```bash
git clone --branch feat/security-coverage-phase1 https://github.com/ChiphaLo/vps-sentinel.git
cd vps-sentinel
git checkout --detach 0d9e53ff51de34932fab814fa878d69b7774a5d3
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release
sudo python3 tests/container_lab/run.py \
  --binary target/release/vps-sentinel --output /tmp/sentinel-lab-results
```

The lab writes scan JSON, case outcomes, response evidence, metrics and cleanup results under `--output`. The workspace command can still skip the Docker-socket test; its isolated host verification must be recorded separately before claiming it passed. Environment and image updates can change reproduction results.

请仅在可丢弃的 Linux 实验宿主运行，复现时固定上述提交。保留输出结果，单独记录 Docker socket 专项，不把跳过算作通过。

[English README](../README.md) · [中文首页](../README.zh-CN.md) · [Deployment](deployment.md)
