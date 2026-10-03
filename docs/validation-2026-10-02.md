# Validation / 合并验证 — 2026-10-02

> Later container-attack validation: the [2026-10-03 report](validation-2026-10-03.md) covers real SSH/HTTP attacks, the host-published-port path and 19 post-compromise fixtures on the same fork `main`; this document remains the record for the merge, dependency and panel checks.

On hyvps (Debian 13, x86_64), the candidate for [PR #1](https://github.com/ChiphaLo/vps-sentinel/pull/1) completed the checks below. The PR was merged into `main` at [`b43a700`](https://github.com/ChiphaLo/vps-sentinel/commit/b43a7006b2eef9e458822d1825fed420b987e034). Its Git tree, `b7d6ebaa5c9c554374a9dee9eb52003bbb8adb94`, exactly matches the tested candidate. Dependency audits then identified additional fixes; the updated lockfiles and frontend dependencies were revalidated and published at [`7051a26`](https://github.com/ChiphaLo/vps-sentinel/commit/7051a267d94b5b8e83a1438962ebaaf795ec771b) as described below. The merged tree identifies the first validation stage, not the final dependency versions.

本次完整执行了仓库测试、两个 Linux 构建环境、安装回归、面板检查和隔离攻击实验，并修复了发现的两个实际问题，并更新存在安全公告的依赖。测试范围内没有失败或尚未修复的已发现 bug；这不能证明所有环境和输入下绝对没有 bug。日期按 Asia/Hong_Kong 记录。

[Machine-readable evidence / JSON 证据](validation-2026-10-02.json) includes source-file hashes, test totals, runtime measurements and individual lab/browser outcomes. [Previous report](validation-2026-10-01.md) is retained as historical evidence.

## Fixed issues / 修复的问题

1. **Command timeout:** a shell descendant retaining stdout made a 100 ms deadline take about 2 seconds, including when the parent exited successfully. The collector now bounds both process completion and stdout receipt with the same deadline and terminates the Unix process group on timeout. Two regression tests passed in Debian and Alpine. No Rust dependency was added.
2. **Cached source selection:** install/update fetched the existing origin instead of honoring a newly selected `REPO_URL`. Both scripts now update origin before fetching; real temporary Git repositories verify switching, repeating, explicit override and fresh checkout. The old implementation failed this test. Defaults and Cargo repository/homepage metadata now point to this fork; both scripts retain executable file modes.

## Dependency audit and follow-up / 依赖审计与后续修复

The first `npm ci` reported 5 affected packages (1 moderate, 3 high, 1 critical). The follow-up pins Next.js 16.3.8 and PostCSS 8.5.28, updates compatible transitive packages including baseline-browser-mapping, nanoid and sharp, and reruns typecheck, static build and the real Rust-panel browser checks. The latest `npm audit` reports 0 vulnerabilities. The application exports static assets, with image optimization disabled; an audit listing is not proof that every listed server-side exploit was reachable in this deployment. Official advisories include [Next.js ImageResponse](https://github.com/vercel/next.js/security/advisories/GHSA-vcvr-r3jv-pc5j), [PostCSS](https://github.com/postcss/postcss/security/advisories/GHSA-fxqj-rqcc-2cmp) and [sharp](https://github.com/lovell/sharp/security/advisories/GHSA-rgj7-g3m4-5g8c).

Cargo audit 0.22.2 identified [rustls TLS 1.3 handling](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc) and unsoundness notices for [anyhow](https://rustsec.org/advisories/RUSTSEC-2026-0190.html) and [event-listener](https://rustsec.org/advisories/RUSTSEC-2026-0221.html). Compatible lockfile updates select rustls 0.23.45, rustls-webpki 0.103.15, anyhow 1.0.103 and event-listener 5.4.2. Debian/Alpine tests, builds, host regressions and the runtime lab were rerun for this binary. There are no new Rust packages; concurrent-queue was removed from the resolved graph.

`cargo audit --deny unsound` reports 0 non-exempt vulnerabilities and no warnings under the repository’s existing policy. **The existing `RUSTSEC-2023-0071` RSA exception remains** for SQLx MySQL’s transitive dependency; [RustSec lists no patched release](https://rustsec.org/advisories/RUSTSEC-2023-0071.html). This exception is explicitly disclosed, not counted as a fixed vulnerability. The panel uses this as a database client; no RSA private-key server operation is implemented by the project. MySQL live deployment was not part of this run.

CI now runs npm and RustSec dependency audits. Cloud execution of the revised workflow remains unverified. A frontend rebuild exceeded its original test-container memory limit; it was rerun with a larger isolated build allowance and serialized with the Rust stages. This was a build-environment failure, not a passing first attempt. Runtime memory figures below come from a fresh post-update lab run. The final build uses a bounded Node heap; build memory allowances are separate from runtime RSS.

## Checks / 检查结果

| Check | Result |
| --- | --- |
| Debian/bookworm Rust workspace | 548 passed, 0 failed, 1 ignored host-only test. |
| Alpine/musl Rust workspace | 548 passed, 0 failed, 1 ignored host-only test. |
| Explicit host regressions | 13 passed, 0 failed, including the Docker-socket-dependent case. |
| Rust code and builds | Formatting, strict Clippy for all targets and locked release builds passed in both environments. |
| Installation | Real local release-package install/config validation passed in a temporary prefix; no systemd service installed. |
| Cached source selection | Both install/update passed all four real Git scenarios. |
| Panel contract / frontend | Generated contract check, Worker syntax, UI typecheck and Next.js static build passed. |
| Worker protocol and SQL | 14 passed using the actual Worker with Node 24 SQLite and a D1-shaped adapter. |
| Real Rust panel / browser | 9 checks passed with isolated SQLite and headless Chromium: public/private API access, 1440 px and 390 px render without horizontal overflow, token gate/login and no uncaught JavaScript errors. |
| Isolated security runtime | All 19 cases passed, detailed below. |
| Dependency audits | npm: 0; RustSec: 0 non-exempt vulnerabilities, no unsound warnings, with the existing RSA exception disclosed above. |
| GitHub Actions | GitHub REST returned no Actions runs or commit statuses for `7051a26`. Cloud CI success is not verified. |

The host regression exercises Docker CLI behavior through the test's existing mock and socket-presence guard; it is not a live Docker escape attempt. Browser checks use an empty fleet and loopback inside the disposable container. PostgreSQL/MySQL, a live Cloudflare/D1 deployment and every browser/input combination were not retested here. Contract generation requires `rustfmt`; the CI panel job now installs it explicitly.

## External and post-compromise lab / 隔离攻击实测

The runtime image was built, started and tested on an internal Docker network. The target was unprivileged, with only `NET_ADMIN` for its own firewall, no host PID/network namespace, no bind mounts or Docker socket, and no published host ports. Attacks came from a separate disposable source container, against services inside the target.

- Benign HTTP traffic produced no attack alert. Real SSH failures raised `SSH-003`; real HTTP exploit probes raised `WEB-001`. Applied IP blocks prevented new HTTP connections. Explicit unblock restored connectivity.
- Inert internal fixtures covered SUID/SGID and capability changes without content changes, cron persistence, unauthorized SSH key changes, webshell content, miner process identity and a second UID 0 account. Each was detected.
- The product performed no unadvertised destructive remediation. The harness removed only its own fixtures; an independent rescan then returned no fixture-related findings.
- A block's recorded `expires_at` was honored; expiry cleanup restored connectivity. SIGINT stopped the daemon successfully.

The web block was recorded at `2026-10-02T11:59:43.381091575Z` and expired at `2026-10-02T12:00:13.381091575Z`. The block existed in the target firewall before cleanup. Scan collector errors and failed active-response counts were zero in the lab.

**主动响应只封禁来源 IP。产品不会自动杀矿工、删除后门或恢复账户；清理样本后复扫通过是实验脚本的能力，不能写成产品自动清除入侵。**

## Lightweight measurements / 轻量性

| Metric | Observed value |
| --- | --- |
| Runtime image | 104,348,730 bytes, about 99.5 MiB. |
| Lab fixture image | 161,753,192 bytes, about 154.3 MiB; includes SSH/HTTP test services. |
| Daemon RSS | 12,560–12,636 KiB, about 12.3 MiB, 15 samples. |
| Agent process CPU | 0.736% of one core over 15 seconds with 5-second scans; child processes excluded. |
| Individual lab scans | 0.233–0.400 seconds, 12,424–12,952 KiB RSS. |

These are small-lab observations, not resource limits or a load benchmark. The fixes use existing Rust dependencies and bounded collection. Temporary builder containers, build targets, frontend caches and formatter tools were removed after verification; host disk use returned to about 17 GiB used / 17 GiB available.

## Visibility and host safety / 覆盖边界与宿主检查

Auditd was not active and no audit/eBPF runtime source was enabled for this experiment. Brief credential reads and short-lived outbound connections were negative coverage probes: the snapshot collector did not reliably capture them. File permission/capability drift comparison requires a trusted baseline containing those fields. Existing installations should review their baseline and establish a fresh trusted baseline when adopting the expanded metadata.

A separate passive `doctor` / `check --json` run on the real host used a temporary configuration with active response, notifications and panel/fleet upload disabled. It collected 937 events, reported 9 findings, and had zero collector errors, response actions or notification attempts. Those findings are host configuration/history for administrator review, not a claim that the host is clean. `check` does not compare a saved baseline.

After the lab and builder cleanup, the original production containers and `ssh`, `docker`, `caddy` service states matched the pre-test snapshot. Normalized IPv4 and IPv6 firewall rules also matched. No production remediation or service replacement was performed.

## Reproduce / 复现入口

From a checkout of this fork's `main`, with the required Rust, Node 24, Git and installer tools available:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --workspace --locked
node scripts/generate-panel-contract.mjs --check
node tests/panel_worker_smoke.mjs
bash tests/install_script_smoke.sh
bash tests/source_checkout_smoke.sh
```

```bash
cd panel/ui
npm ci
npm run typecheck
npm run build
```

Run the host-only suite with appropriate Linux access as described by the existing test, and run the [container lab](container-lab.zh-CN.md) only against disposable fixtures you own. The additional browser smoke in this run was an external verification script against the real built Rust server; the JSON records its scope. It is not a repository-wide browser regression suite.

Install and update examples now select `main`; see [deployment in English](deployment.md) or [中文部署说明](deployment.zh-CN.md).
