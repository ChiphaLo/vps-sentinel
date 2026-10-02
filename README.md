# vps-sentinel · ChiphaLo fork

Lightweight Rust intrusion-signal monitoring for Linux VPS hosts, with evidence-backed alerts, optional source-IP blocking, and a fleet dashboard.

[中文说明](README.zh-CN.md) · [Deployment](docs/deployment.md) · [Validation report](docs/validation-2026-10-02.md) · [Security work / PR #1](https://github.com/ChiphaLo/vps-sentinel/pull/1) · [Upstream](https://github.com/cryptoli/vps-sentinel)

[![Fork CI](https://github.com/ChiphaLo/vps-sentinel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ChiphaLo/vps-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Fork and branch status

This is a fork of [cryptoli/vps-sentinel](https://github.com/cryptoli/vps-sentinel). Upstream provides the original agent and dashboard; this fork extends Linux security collection, state comparison, and isolated validation.

| Branch | Contents |
| --- | --- |
| `main` | Upstream v0.3.1 plus this fork's tested security and reliability improvements. Recommended for installation. |
| [`feat/security-coverage-phase1`](https://github.com/ChiphaLo/vps-sentinel/tree/feat/security-coverage-phase1) | Development history, merged through [PR #1](https://github.com/ChiphaLo/vps-sentinel/pull/1). |

[PR #1](https://github.com/ChiphaLo/vps-sentinel/pull/1) was merged on 2026-10-02 at [`b43a700`](https://github.com/ChiphaLo/vps-sentinel/commit/b43a7006b2eef9e458822d1825fed420b987e034). The merged tree matches the candidate tested on hyvps. Install and update scripts now default to this fork and `main`; an explicit `REPO_URL` also updates the origin in a reused source directory.

## What it monitors

| Area | Coverage |
| --- | --- |
| SSH and accounts | Logins, repeated failures, success after brute force, SSH key changes, new users and UID 0 account drift. |
| Files and persistence | Critical files, web content, cron, systemd and startup entries, plus baseline review and allowlists. |
| Processes and network | Process ancestry, executable identity, known miner/scanner identities, listeners, outbound snapshots and Web probe logs. |
| Docker and audit | Container configuration and audit log facts; expanded rules are included in `main`. |
| Response and reporting | Optional nftables/iptables source-IP blocks, unblock/expiry maintenance, fingerprints and notification channels. |
| Fleet dashboard | Optional self-hosted Rust or Cloudflare Worker/D1 panel, signed telemetry and privacy redaction. |

### Fork improvements

- Inspect container risks: privileged mode, host namespaces, Docker socket and writable host-root mounts, dangerous capabilities including `ALL`.
- Parse quoted and hex-encoded audit arguments; recognize credential-access, privilege-persistence, module-manipulation and logging-disable commands when audit execution telemetry exists.
- Detect monitored-file SUID/SGID, ownership and Linux capability drift without requiring content changes (`FILE-005`, `FILE-006`). Read one bounded xattr on existing FIM paths; add no Rust dependencies or full-disk scan.
- Expand FIM and persistence paths, retain SIGINT during collection, and exclude zombie/dead process snapshots from active process alerts.
- Keep command collection bounded even when descendant processes retain stdout; honor repository overrides when reusing installer/update source caches.
- Provide a small runtime Dockerfile and a reproducible isolated attack-response lab.

## Install this fork

The merged code is validated from source. Use `INSTALL_METHOD=source` to build the selected repository and branch; this fork has not published a release artifact for these changes.

```bash
curl -fsSL https://raw.githubusercontent.com/ChiphaLo/vps-sentinel/main/install.sh | \
  sudo env REPO_URL="https://github.com/ChiphaLo/vps-sentinel.git" \
    BRANCH="main" INSTALL_METHOD="source" \
    ACTIVE_RESPONSE_ENABLED="no" \
    ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED="no" sh
```

New installations in this example start with automatic IP blocking disabled. Run `sudo vs doctor`, inspect findings and trusted-admin allowlists, then enable response if appropriate. Existing configuration and local state are preserved; review them when reinstalling or switching repositories. Source builds need Rust and temporary build space; successful installs remove the build target directory by default.

Update from the same fork and branch:

```bash
curl -fsSL https://raw.githubusercontent.com/ChiphaLo/vps-sentinel/main/update.sh | \
  sudo env REPO_URL="https://github.com/ChiphaLo/vps-sentinel.git" \
    BRANCH="main" INSTALL_METHOD="source" sh
```

For notifications, optional panel upload, service operations and all install options, see [agent deployment](docs/deployment.md). For the optional dashboard, see [panel deployment](docs/panel-deployment.md).

## Local workflow

| Command | Purpose |
| --- | --- |
| `sudo vs doctor` | Check config, tools and collection visibility. |
| `sudo vs check --json` | Inspect current facts without persistence, notifications or firewall response; it does not compare a stored baseline. |
| `sudo vs scan --no-notify --json` | Persist a scan and compare the baseline, without notification or active response. |
| `sudo vs baseline create` | Establish a baseline after reviewing and trusting the current state. |
| `sudo vs baseline diff` | Review host changes against the stored baseline. |
| `sudo vs blocks list` / `sudo vs blocks why <ip> --json` | Inspect recorded blocks and their actual expiry. |
| `sudo vs blocks unblock <ip>` / `sudo vs blocks cleanup` | Remove a block or maintain expired/stale block state. |
| `sudo vs config validate` / `sudo vs reload` | Validate configuration and reload the service. |
| `sudo vs menu` | Guided local configuration and review. |

## Verified results

On **2026-10-02**, the merge candidate was tested on hyvps (Debian 13 x86_64), then its exact tree was verified against merged `main`. Dependency security updates at [`7051a26`](https://github.com/ChiphaLo/vps-sentinel/commit/7051a267d94b5b8e83a1438962ebaaf795ec771b) received a further full validation:

| Check | Result |
| --- | --- |
| Debian/bookworm workspace | 548 passed, 0 failed; one Docker-socket test handled separately on the host. |
| Alpine/musl workspace | 548 passed, 0 failed; the same host-only test skipped. |
| Explicit host suite | 13 passed, including the Docker-socket test. |
| Build and code checks | Locked release build, formatting and strict Clippy passed. |
| Isolated runtime | Real SSH failures and HTTP probes detected and blocked; seven inert post-compromise fixture types detected. |
| Installer and panel | Package install and source switching, contract generation, UI typecheck/build, 14 Worker/SQLite cases and 9 headless Rust-panel browser checks passed. |
| Dependency audits | npm: 0 vulnerabilities; RustSec: 0 non-exempt vulnerabilities and no warnings, retaining the documented RSA exception. |
| Resource sample | Daemon RSS about 12.3 MiB and agent CPU about 0.74% of one core in a 15-second sample at a 5-second scan interval. |

These are dated on-host results, not a claim that current GitHub Actions is green. Resource usage depends on monitored scope and load; CPU excludes child processes. See the [validation report](docs/validation-2026-10-02.md) for methods, limits and reproduction.

## Detection and response limits

Active response blocks source IPs. It does not kill processes, delete backdoors or restore accounts. The lab harness cleans its own inert fixtures and then runs an independent rescan; that is not automatic payload removal by the product.

Audit rules need configured audit telemetry. The built-in runtime probe is optional, and completed short-lived activity can escape snapshots: brief credential reads and outbound connections were not captured in the lab without audit/eBPF data. This fork does not claim complete EDR coverage, package-content integrity verification or rootkit removal. Permission/capability comparison applies only to monitored files and requires a trusted baseline containing those fields.

A normally isolated container observes itself, not the host. The runtime image and lab do not imply host monitoring without an explicit visibility/deployment design.

## Privacy, contributing and upstream

Local SQLite storage is the default; panel upload and notification channels require configuration. Signed panel telemetry redacts raw evidence, paths, commands and server identifiers. Confirmed attacker IPs may appear on the public blocklist. The panel is not a remote SSH/command plane; privileged operations remain local.

Keep secrets in local config or deployment secret stores. [Contributing](CONTRIBUTING.md) covers development and rule expectations; [SECURITY.md](SECURITY.md) covers private reporting. Original attribution is preserved under the [MIT license](LICENSE); see [license notes](docs/open-source-license.md).
