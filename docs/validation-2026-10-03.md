# Container attack and parasite validation / 容器攻击与寄生程序验证 — 2026-10-03

On hyvps (Debian 13.7, x86_64, Docker 26.1.5, iptables 1.8.11 nf_tables) the fork's `main` at [`26941c29`](https://github.com/ChiphaLo/vps-sentinel/commit/26941c29131feff5957590c52d8137383518268a) was built and then attacked from a separate disposable container. The tested binary was `vps-sentinel 0.3.1`, 20,264,704 bytes, SHA-256 `afdd0ed552d5759985c8bcc333d420fecd0ee3ce1cb65774f34fcb757f37e561`; the `git archive` source used for the build hashes to `be523319691b3ff843601a41a608e5e8f5685d35bac9454398f45e27691fb760`. The work tree was clean before and after the run, and no repository file was changed by the experiments.

本次在 hyvps 上对 `main`（`26941c29`）执行构建检查与容器实测：真实 SSH/HTTP 攻击、宿主发布端口封禁路径、容器内 19 类惰性夹具（15 类寄生样本 + 4 类恶意输入）、恶意文件系统韧性与资源采样。全部攻击只发生在一次性容器和一次性测试地址内；生产容器 `openlist-douyin`、`zephyr-ssh` 未受影响，实验结束后主机防火墙、路由、地址与镜像均恢复到实验前状态。本报告只记录实际运行到的结果；未运行的部分按“证据不足”保留，见文末。

[Machine-readable evidence / JSON 证据](validation-2026-10-03.json) · [2026-10-02 report / 上一次完整验证](validation-2026-10-02.md) · [2026-10-03 security review / 当日代码审查](security-review-2026-10-03.zh-CN.md)

## Checks / 检查结果

| Check | Result |
| --- | --- |
| Debian/bookworm Rust workspace | `cargo test --workspace --locked`: 11 test binaries, 548 passed, 0 failed, 1 ignored host-only test. |
| Formatting and lints | `cargo fmt --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings` passed. |
| Release build | `cargo build --locked --release` passed in a disposable `rust:1-bookworm` container; the container and image were removed afterwards. |
| Isolated container lab | [container lab](container-lab.zh-CN.md) `run.py`: 19/19 cases passed, `result=passed`, host firewall hash unchanged. |
| Extended probes | [`extended_probes.py`](../tests/container_lab/extended_probes.py): host-published-port path, hostile filesystem inputs and 12 further fixture cases (8 malware-shaped, 4 hostile-input) completed with no harness error; host firewall, routes and addresses unchanged. |
| Crash / hang / collector errors | None observed; every scan reported `collector_errors: []` and the daemon exited with code 0 on SIGINT. |

Alpine/musl, installer, panel, dependency-audit and browser checks were **not** rerun in this container-focused run; the [2026-10-02 report](validation-2026-10-02.md) remains the record for those. 本轮只做容器攻防验证，没有重跑 Alpine、安装器、面板、依赖审计和浏览器检查。

## External attacks / 外部真实攻击

Attacks came from a separate container on an internal Docker network. A point-to-point veth pair carrying reserved-range addresses was moved into both container namespaces, so the source address was public-shaped (`11.254.253.3`) while no packet left the isolated network.

| Step | Observed result |
| --- | --- |
| Four real SSH password failures (`sshpass`, `labuser@11.254.253.2`) | `SSH-003`, severity High, subject `11.254.253.3`; `active_response_applied=1`, `failed=0`. |
| HTTP request after the block | `blocked`. |
| `blocks unblock 11.254.253.3` | Connectivity restored (`200`). |
| Six real HTTP probes (`/.env`, `/.git/config`, phpunit `eval-stdin.php`) | `WEB-001`; `active_response_applied=1`. |
| Block record | `backend=iptables`, `firewall_present=true`, `expires_at` set (not permanent), reason includes `request_count=6 layer=high_confidence_web_exploit`. |
| Expiry | `blocks cleanup` reported `expired=1 stale=0` with no failures; the target became reachable again (`200`). |

## Host-published port path / 宿主发布端口封禁路径

The same service was republished with `docker run -p <bridge-gateway>:18480:8080` and attacked from two source shapes. This is the runtime check for review item R6.

| Source shape | Client address seen in the target | Finding | Block | Published port after the scan |
| --- | --- | --- | --- | --- |
| Peer container on the same bridge (hairpin through docker-proxy) | `172.30.0.1` (bridge gateway; the real client is rewritten) | `WEB-001`, subject `172.30.0.1` | none (`no active-response blocks recorded`) | still reachable (`200`) |
| External-shaped source on a veth (source `11.254.253.3` preserved) | `11.254.253.3` | `WEB-001`, subject `11.254.253.3` | applied (`iptables`, TTL 30 s) | `blocked`, restored to `200` after unblock |

结论：对真实外网形态的来源，容器命名空间内的 `INPUT` 封禁**确实能**阻断宿主发布端口流量（DNAT 后报文仍经过容器 `INPUT`，源地址未被改写）；这修正了 R6 中“发布端口必然绕过封禁”的推断。对同网桥/经代理转发的来源，Docker 把真实客户端改写为网桥网关，产品只封禁公网来源（`is_public_remote_ip`），因此该路径不会被封禁——既是盲区，也避免了误封网关。实验中主机 `FORWARD` 策略为 `DROP`、宿主只存在实验期间的 DNAT 规则，清理后消失。

## Post-compromise fixtures / 容器内寄生夹具

The target container was treated as already rooted. Every fixture is inert: miner lookalikes are copies of `/bin/sleep`, webshells and reverse-shell lines are text that is never executed, and persistence files are written but never loaded. Nineteen fixture cases were tested: 7 malware-shaped fixtures in the container lab plus 12 in the extended probes (8 malware-shaped, 4 hostile-input). Fourteen of the 15 malware-shaped cases were detected — the miner lookalike process is probed by both harnesses, and the only miss is the dropped `/tmp` payload that never became a process.

| Fixture | Detection |
| --- | --- |
| SUID/SGID bit, unchanged content | `FILE-005` (High) — `/opt/lab/helper` |
| File capability, unchanged content | `FILE-006` (High) — `/opt/lab/cap-helper` |
| cron entry `/etc/cron.d` | `PERSIST-002` + `PERSIST-001` |
| cron spool `/var/spool/cron/crontabs/root` | `PERSIST-002` + `PERSIST-001` |
| `authorized_keys` appended | `SSH-005` (High) |
| WebShell file in the web root | `FILE-002` (High + Medium) |
| Miner-lookalike process (`/tmp/xmrig`, `/tmp/kinsing`) | `PROC-004` (Critical) |
| Additional UID 0 account | `USER-002` (Critical) |
| `ld.so.preload` entry | `ROOTKIT-003`, `PERSIST-003`, `TIMELINE-001` (High) |
| Reverse-shell line in a shell profile | `PERSIST-002` (High) + `PERSIST-001` |
| systemd unit drop | `PERSIST-002` (High) + `PERSIST-001` |
| `sshd_config` weakened (root login + password auth) | `CONFIG-004` (High), `CONFIG-001`, `FILE-001` |
| Sensitive log truncated in place | `TAMPER-002` (High) |
| Dropped payload and pool config in `/tmp` | **no finding** — `/tmp` is not monitored by default |
| FIFO, symlink loop, 512 MiB file, unreadable file | no finding (expected); no scan hang or collector error |

**主动响应只封禁来源 IP。** 实测扫描后假矿工进程与 WebShell 文件仍然存在（`automatic_payload_cleanup_supported=false`）；清理由实验脚本执行并复扫确认为空，不能算作产品的自动入侵修复能力。

## Hostile filesystem and I/O behaviour / 恶意文件系统与 I/O 抖动

| Probe | Scan wall time | Collectors | Detectors | Peak RSS | Collector errors |
| --- | --- | --- | --- | --- | --- |
| FIFO inside a monitored path | 0.31 s | 50 ms | 132 ms | 12,588 KiB | 0 |
| Self-referential symlink | 0.31 s | 51 ms | 133 ms | 12,468 KiB | 0 |
| 512 MiB file inside a monitored path | 3.58 s | 55 ms | 134 ms | 12,584 KiB | 0 |
| Unreadable file (`chmod 000`) | 10.25 s | 52 ms | 108 ms | 12,456 KiB | 0 |

The FIFO did **not** block the scan, so the review's R3 blocking scenario did not reproduce in this configuration. The two slow scans were reproduced separately:

| Step | Wall time | Collectors | Enrichment | Detectors | Note |
| --- | --- | --- | --- | --- | --- |
| Control scan | 0.39 s | 48 ms | 4 ms | 133 ms | 103 raw events |
| After writing a 512 MiB file | 0.60 s | 52 ms | 265 ms | 132 ms | enrichment already elevated |
| After deleting that file | 10.52 s | 55 ms | 1,983 ms | 8,301 ms | identical 103-event set, 0 diff events |
| 10 s later, after `sync` | 0.42 s | 50 ms | 4 ms | 134 ms | recovered |
| 30 s later | 0.41 s | 50 ms | 5 ms | 133 ms | stable |

The identical event set took 133 ms in the control scan and 8.3 s in the detectors stage right after the deletion, then recovered within 10 s. The delay tracks container overlay write-back of a large file, not FIFO/large-file handling logic, and no collector error was raised.

## Lightweight measurements / 轻量性

| Metric | Observed value |
| --- | --- |
| Runtime image | 104,345,090 bytes, about 99.5 MiB. |
| Lab fixture image | 161,749,548 bytes, about 154.3 MiB; includes SSH/HTTP test services. |
| Daemon RSS | 12,624–12,704 KiB, about 12.3 MiB, 15 samples. |
| Agent process CPU | 0.737% of one core over 15 seconds with 5-second scans; child processes excluded. |
| Individual lab scans | 0.189–0.387 s, 12,348–12,832 KiB RSS. |
| Daemon internal scans | 5 scans in 15 seconds, 0 collector errors, 0 notification failures. |

These numbers are consistent with the 2026-10-02 sample (12,560–12,636 KiB, 0.736%), so this change set shows no obvious runtime growth in the small lab. These are small-lab observations, not resource limits or a load benchmark.

## Visibility and limits / 覆盖边界与证据不足

1. **Default file integrity paths do not include web roots.** `vps-sentinel config print-default` on the tested binary lists `/etc/passwd` … `/home/*/.ssh` under `[file_integrity].paths` while `[web].web_roots` defaults to `/var/www`, `/srv`, `/usr/share/nginx/html`, `/usr/share/httpd/noindex`. WebShell file detection therefore needs an explicit web path in the FIM configuration; this lab added one. This is runtime confirmation of review item R4.
2. **Private sources are never auto-blocked.** Code only creates blocks for public remote IPs (`is_public_remote_ip`); the hairpin source `172.30.0.1` produced a finding but no block. This avoids blocking a gateway, and leaves relayed/proxied attacks unblocked.
3. **No auditd/eBPF source was enabled.** A brief `cat /etc/shadow` and a completed outbound connection produced no `AUDIT-*` event and `outbound_connection` count 0. Those remain negative coverage probes, not proven detections (review R5/R7/R8 untested here).
4. **Landing directories such as `/tmp` are not monitored by default**, so a dropped payload without a matching process or persistence artifact is invisible.
5. **Response layers can multiply the configured TTL** (10 s configured, 30 s recorded). Assert against `blocks why <ip> --json` `expires_at`, not the configured value.
6. **`/tmp/kinsing` was detected by process identity only.** Nothing executed it; a payload that never becomes a process, file change or persistence entry would not be detected by the tested collectors.

## Host safety and cleanup / 宿主检查与清理

- The lab created one internal Docker network, two unprivileged containers with only `NET_ADMIN`, one temporary veth pair and one 512 MiB fixture file; all were removed.
- `docker ps -a` afterwards listed only the pre-existing `openlist-douyin` and `zephyr-ssh`; no lab network, link, address or `11.254.253.*`/`18480` firewall rule remained.
- Normalized `iptables-save` output matched before and after each harness (`host_firewall_unchanged=true` for both the container lab and the extended probes); host routes and addresses were also identical.
- The `rust:1-bookworm` build image, cargo home and build tree were deleted; host disk returned to 18 GiB used / 16 GiB available.
- Raw evidence is archived at `/root/sentinel-lab-20261003/evidence-2026-10-03.tar.gz` (SHA-256 `dec0f978fc48bd91dfa98094decc9565e4af201432176fd8b7e4a8e402bf5fb5`).

## Reproduce / 复现入口

Build and check the workspace in a disposable container:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --locked --release
```

Run the existing container lab, then the extended probes, both only against fixtures you own:

```bash
sudo python3 tests/container_lab/run.py \
  --binary target/release/vps-sentinel --output /tmp/sentinel-lab-results

sudo python3 tests/container_lab/extended_probes.py \
  --binary target/release/vps-sentinel --repo . --output /tmp/sentinel-extended-results
```

The extended probe targets are disposable by construction: it creates its own internal network, publishes only on that network's bridge gateway, and removes every container, image, veth and address it created. It does not target third-party systems.

## Not covered / 未覆盖

- No attack from a real internet source address; the external-shaped source used reserved range `11.254.253.0/24` inside container namespaces.
- Alpine/musl, installer, panel, Worker/SQLite, headless-browser, npm/RustSec audit and host regression suites were not rerun for this report.
- Review items R1 (config backup permissions), R2 (panel cross-node overwrite), R5/R7/R8 (eBPF file events, JSONL partial writes, probe escaping) and R10 (first-baseline trust) are not runtime-verified here.
- The daemon was not run in the host network namespace, so how its rules interact with production host `FORWARD`/`DOCKER-USER` chains is untested; all blocks in this run were inside lab container namespaces.
