# Contributing

This repository is the ChiphaLo fork of [cryptoli/vps-sentinel](https://github.com/cryptoli/vps-sentinel). See the [README](README.en.md#fork-and-branch-status) before choosing a target branch. Changes target `main`; security improvements from PR #1 are merged.

## Development

```bash
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Documentation should identify the branch and commit behind validation claims, preserve upstream attribution, and set `REPO_URL`, `BRANCH`, and `INSTALL_METHOD` explicitly in fork install examples.

## Rule Contributions

Rules must:

- be defensive;
- have a stable `rule_id`;
- produce a unified `Finding`;
- include evidence and recommendations;
- choose severity conservatively;
- respect allowlists where relevant;
- avoid destructive actions.

## Notifier Contributions

Notifier implementations must:

- implement the shared `Notifier` trait;
- avoid logging tokens, passwords, or secrets;
- return structured errors for missing configuration;
- use the standard finding renderer unless a provider requires a specific format.

## Isolated validation

Use the [container lab](docs/container-lab.zh-CN.md) only against disposable fixtures you own. Keep network, PID and firewall effects inside the lab; do not target third-party systems. Separate actual detection and IP blocking from harness cleanup. The [2026-10-02 report](docs/validation-2026-10-02.md) records the tested scope and telemetry gaps.

## Code Style

- Keep modules focused and cohesive.
- Prefer existing project patterns.
- Avoid hardcoded machine-specific paths.
- Do not add attack, brute-force, stealth, or third-party scanning capabilities.

Panel and installer regressions can also be checked with `node tests/panel_worker_smoke.mjs` (Node 24+) and `bash tests/source_checkout_smoke.sh`. The Worker test uses local SQLite and does not replace a live Cloudflare deployment test. Contract generation requires `rustfmt`; install it before `node scripts/generate-panel-contract.mjs --check`.
