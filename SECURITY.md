# Security Policy

vps-sentinel is a defensive security project. Please do not publish exploitable security issues publicly before maintainers have had time to respond.

## Reporting

Open a private GitHub security advisory if available. If that is not possible, open an issue with minimal sensitive detail and ask for a private contact path.

For this fork, identify the branch and commit from [ChiphaLo/vps-sentinel](https://github.com/ChiphaLo/vps-sentinel). Do not include SSH credentials, notification tokens, panel secrets or unredacted host evidence in a public issue. Do not assume private advisory reporting is enabled on a fork. Coordinate upstream issues with the original project through its own reporting policy.

The [dated validation report](docs/validation-2026-10-01.md) states what was tested. Detection depends on collection visibility and trusted baselines; active response blocks source IPs and does not remove payloads or restore a compromised host.

## Scope

In scope:

- secret leakage in logs or notifications;
- unsafe parsing that can crash the daemon;
- unintended destructive behavior;
- privilege or file-permission mistakes in deployment scripts;
- vulnerabilities in notification or update paths.

Out of scope:

- requests to add exploit code;
- password brute-force features;
- third-party target scanning;
- stealth or evasion features.
