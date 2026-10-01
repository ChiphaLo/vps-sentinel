#!/usr/bin/env python3
"""Run on a disposable Linux Docker host. Attacks stay in isolated network namespaces."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def command(args, *, stdin=None, check=True, timeout=120):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True,
                            check=False, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[:3]} exited {result.returncode}:\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[2]
    suffix = uuid.uuid4().hex[:8]
    prefix = f"sentinel-lab-{suffix}"
    target, attacker = prefix + "-target", prefix + "-attacker"
    network, runtime_image, lab_image = prefix, prefix + ":runtime", prefix + ":fixture"
    summary = {"cases": {}, "limitations": [
        "The product blocks public-source IPs; it does not kill processes, remove payloads, or restore accounts.",
        "Cleanup is performed by the lab harness against its own fixtures, then independently rescanned.",
        "Container-only visibility: no host PID/network, Docker socket, host root mounts, auditd, or eBPF.",
        "Brief credential reads and short-lived outbound connections are negative coverage probes, not guaranteed detections.",
    ]}
    containers = []
    firewall_before = command(["iptables-save"], check=False)

    def firewall_hash(text):
        import re
        text = re.sub(r"\[\d+:\d+\]", "[counters]", text)
        return hashlib.sha256("\n".join(line for line in text.splitlines()
                                        if not line.startswith("#")).encode()).hexdigest()

    def docker(*parts, **kwargs):
        return command(["docker", *parts], **kwargs)

    def execute(container, script):
        return docker("exec", "-i", container, "sh", "-eu", stdin=script)

    def scan(label, response=False):
        started = time.monotonic()
        opts = [] if response else ["--no-notify"]
        raw = docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml",
                     "scan", *opts, "--json")
        report = json.loads(raw)
        (args.output / f"{label}.json").write_text(raw)
        summary.setdefault("scans", {})[label] = {
            "seconds": round(time.monotonic() - started, 3),
            "rss_kb": report.get("memory_rss_after_kb"),
            "collector_errors": report["collector_errors"],
            "rules": sorted({f["rule_id"] for f in report["findings"]}),
            "active_response_applied": report["active_response_applied_count"],
            "active_response_failed": report["active_response_failed_count"],
        }
        assert not report["collector_errors"], report["collector_errors"]
        return report

    def detected(report, rule, subject=None):
        return any(f["rule_id"] == rule and (subject is None or subject in f["subject"])
                   for f in report["findings"])

    def expect(name, condition):
        summary["cases"][name] = bool(condition)
        print(f"{name}: {'PASS' if condition else 'FAIL'}", flush=True)
        assert condition, name

    def request(container, host, path="/"):
        code = """import urllib.request, urllib.error, socket
try:
 r=urllib.request.urlopen(%r, timeout=2); print(r.status)
except urllib.error.HTTPError as e: print(e.code)
except (urllib.error.URLError, socket.timeout): print('blocked')
""" % (f"http://{host}:8080{path}",)
        return docker("exec", "-i", container, "python3", "-", stdin=code).strip()

    try:
        with tempfile.TemporaryDirectory(prefix=prefix) as staging:
            shutil.copy2(args.binary, Path(staging) / "vps-sentinel")
            docker("build", "-t", runtime_image, "-f", str(repo / "packaging/Dockerfile"), staging)
        docker("build", "-t", lab_image, "--build-arg", f"RUNTIME_IMAGE={runtime_image}",
               str(Path(__file__).parent), timeout=600)
        summary["images_bytes"] = {
            "runtime": int(docker("image", "inspect", runtime_image, "--format", "{{.Size}}")),
            "fixture": int(docker("image", "inspect", lab_image, "--format", "{{.Size}}")),
        }
        docker("network", "create", "--internal", network)
        for name in [target, attacker]:
            docker("run", "-d", "--name", name, "--network", network,
                   "--cpus=1", "--memory=192m", "--pids-limit=128",
                   "--cap-add=NET_ADMIN", lab_image)
            containers.append(name)
        # A point-to-point veth pair bypasses the internal bridge's source-subnet
        # guard. Move both unaddressed ends into containers BEFORE adding IPs.
        # The host never receives a public route or address.
        links = [f"sl{suffix}a", f"sl{suffix}b"]
        command(["ip", "link", "add", links[0], "type", "veth", "peer", "name", links[1]])
        for name, link, address in [(target, links[0], "11.254.253.2"), (attacker, links[1], "11.254.253.3")]:
            pid = docker("inspect", name, "--format", "{{.State.Pid}}").strip()
            command(["ip", "link", "set", link, "netns", pid])
            execute(name, f"ip addr add {address}/24 dev {link}\nip link set {link} up\n")
        summary["isolation"] = {
            "internal_network": json.loads(docker("network", "inspect", network))[0]["Internal"],
            "target": {key: json.loads(docker("inspect", target))[0]["HostConfig"][key]
                       for key in ["Privileged", "PidMode", "NetworkMode", "Binds", "PortBindings", "CapAdd"]},
        }
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if request(attacker, "11.254.253.2") == "200":
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("fixture HTTP service did not start")
        config = '''[agent]
data_dir = "/lab/data"
scan_interval_seconds = 5
[storage]
path = "/lab/data/sentinel.db"
[file_integrity]
paths = ["/etc/passwd", "/etc/group", "/etc/cron.d", "/root/.ssh", "/var/www/html", "/opt/lab/helper", "/opt/lab/cap-helper"]
[ssh]
auth_log_paths = ["/var/log/auth.log"]
failed_login_threshold = 3
[web]
web_roots = ["/var/www/html"]
log_paths = ["/var/log/lab-access.log"]
error_burst_threshold = 3
trusted_proxy_cidrs = []
[active_response]
enabled = true
firewall_backend = "iptables"
strategy = "balanced"
cleanup_legacy_port_guards = false
permanent_block_enabled = false
block_ttl_seconds = 10
ssh_failed_login_block_threshold = 3
web_probe_block_threshold = 3
web_exploit_block_threshold = 3
[noise_control]
dedup_window_seconds = 0
state_reminder_interval_seconds = 0
[attack_fingerprints]
active_response_enabled = false
[response_policy]
enabled = false
[fleet]
enabled = false
[panel]
enabled = false
node_location_enabled = false
ip_intel_remote_enabled = false
[reports]
scheduled_enabled = false
[advanced_collectors]
auditd_enabled = false
ebpf_bridge_enabled = false
ebpf_runtime_probe_enabled = false
'''
        docker("exec", "-i", target, "sh", "-c", "cat > /lab/config.toml", stdin=config)
        execute(target, "cp /bin/sleep /opt/lab/helper\ncp /bin/sleep /opt/lab/cap-helper\ncp /etc/passwd /lab/passwd.before\nprintf '# baseline\\n' > /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\n")
        docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml", "baseline", "create")
        clean = scan("clean")
        expect("benign_http_has_no_attack_alert", not any(detected(clean, r) for r in ["SSH-003", "WEB-001", "WEB-002", "FILE-005", "FILE-006"]))

        # Separate real SSH and HTTP attacks; each is scanned and blocked independently.
        for index in range(4):
            docker("exec", attacker, "sshpass", "-p", "deliberately-wrong", "ssh",
                   "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                   "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=3",
                   "labuser@11.254.253.2", "true", check=False)
        time.sleep(0.3)
        ssh = scan("external-ssh", response=True)
        expect("real_ssh_failures_detected", detected(ssh, "SSH-003", "11.254.253.3"))
        expect("ssh_firewall_block_applied", ssh["active_response_applied_count"] >= 1 and ssh["active_response_failed_count"] == 0)
        expect("blocked_source_cannot_reach_http", request(attacker, "11.254.253.2") == "blocked")
        execute(target, "cp /var/log/auth.log /lab/auth.evidence\n: > /var/log/auth.log\n")
        docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml", "blocks", "unblock", "11.254.253.3")
        expect("unblock_restores_connectivity", request(attacker, "11.254.253.2") == "200")
        for path in ["/.env", "/.git/config", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"] * 2:
            expect_status = request(attacker, "11.254.253.2", path)
            assert expect_status == "404", expect_status
        web = scan("external-web", response=True)
        expect("real_http_probes_detected", detected(web, "WEB-001", "11.254.253.3"))
        expect("web_firewall_block_applied", web["active_response_applied_count"] >= 1 and web["active_response_failed_count"] == 0)
        expect("web_block_stops_new_connections", request(attacker, "11.254.253.2") == "blocked")
        block_raw = docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml", "blocks", "why", "11.254.253.3", "--json")
        (args.output / "web-block.json").write_text(block_raw)
        block = json.loads(block_raw)["block"]
        summary["web_block"] = block
        assert block["expires_at"], "lab block unexpectedly became permanent"
        expires = datetime.fromisoformat(block["expires_at"].replace("Z", "+00:00")).timestamp()

        # Assume the attacker already has container root: inert artifacts never execute.
        execute(target, '''
chmod 6755 /opt/lab/helper
setcap cap_setuid+ep /opt/lab/cap-helper
printf '# inert lab persistence\n* * * * * root /tmp/sentinel-lab-payload\n' > /etc/cron.d/sentinel-lab
printf 'sentinel_lab_root:x:0:0:lab:/nonexistent:/usr/sbin/nologin\n' >> /etc/passwd
printf '# inert unauthorized key marker\n' >> /root/.ssh/authorized_keys
printf '<?php eval(base64_decode($_POST["x"])); system($_GET["cmd"]); ?>\n' > /var/www/html/lab-shell.php
cp /bin/sleep /tmp/xmrig
/tmp/xmrig 300 >/lab/payload.log 2>&1 &
echo $! > /lab/payload.pid
''')
        compromised = scan("internal-compromise", response=True)
        for name, rule, subject in [
            ("suid_sgid_without_content_change", "FILE-005", "/opt/lab/helper"),
            ("capability_without_content_change", "FILE-006", "/opt/lab/cap-helper"),
            ("cron_persistence", "PERSIST-001", "sentinel-lab"),
            ("unauthorized_ssh_key_change", "SSH-005", "authorized_keys"),
            ("webshell_content", "FILE-002", "lab-shell.php"),
            ("miner_identity_process", "PROC-004", None),
            ("additional_uid_zero_account", "USER-002", "sentinel_lab_root"),
        ]:
            expect(name, detected(compromised, rule, subject))
        # Explicitly demonstrate the product's remediation boundary.
        product_left_payload = execute(target, "kill -0 $(cat /lab/payload.pid)\ntest -f /var/www/html/lab-shell.php\necho present\n").strip() == "present"
        summary["automatic_payload_cleanup_supported"] = not product_left_payload
        expect("no_unadvertised_destructive_remediation", product_left_payload)

        execute(target, "cat /etc/shadow >/dev/null\npython3 -c 'import socket; s=socket.socket(); s.settimeout(2); s.connect((\"" + json.loads(docker("inspect", attacker))[0]["NetworkSettings"]["Networks"][network]["IPAddress"] + "\",8080)); s.close()'\n")
        negative = scan("telemetry-coverage-probes")
        summary["negative_coverage_probes"] = {
            "brief_shadow_read_detected": any(f["rule_id"].startswith("AUDIT-") for f in negative["findings"]),
            "brief_connect_event_count": negative.get("event_count_by_kind", {}).get("outbound_connection", 0),
            "note": "No audit/eBPF source enabled; snapshots cannot reliably capture already completed activity.",
        }

        # Cleanup is limited to this harness's own files and PID. Keep evidence first.
        execute(target, '''
kill $(cat /lab/payload.pid)
rm /tmp/xmrig /var/www/html/lab-shell.php /etc/cron.d/sentinel-lab
chmod 0755 /opt/lab/helper
setcap -r /opt/lab/cap-helper
cp /lab/passwd.before /etc/passwd
printf '# baseline\n' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
cp /var/log/lab-access.log /lab/web.evidence
: > /var/log/lab-access.log
: > /var/log/auth.log
''')
        after = scan("after-harness-cleanup")
        fixture_subjects = ["/opt/lab/helper", "/opt/lab/cap-helper", "sentinel-lab", "lab-shell.php", "sentinel_lab_root", "authorized_keys", "xmrig"]
        remaining = [f for f in after["findings"] if any(s in f["subject"] for s in fixture_subjects)]
        expect("rescan_confirms_fixture_cleanup", not remaining)
        # Wait for the real TTL and verify both state and packet reachability.
        # Response layers can multiply the configured TTL. Use the recorded expiry.
        assert expires - time.time() < 300, "unexpectedly long lab TTL"
        while time.time() < expires + 2:
            time.sleep(min(5, expires + 2 - time.time()))
        cleanup = docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml", "blocks", "cleanup")
        (args.output / "block-cleanup.txt").write_text(cleanup)
        expect("expired_block_cleanup_restores_connectivity", request(attacker, "11.254.253.2") == "200")
        execute(target, "(vps-sentinel --config /lab/config.toml daemon >/lab/daemon.log 2>&1 & daemon=$!; echo $daemon >/lab/daemon.pid; wait $daemon; echo $? >/lab/daemon.exit) >/lab/controller.log 2>&1 &\n")
        time.sleep(0.2)
        daemon = docker("exec", target, "cat", "/lab/daemon.pid").strip()
        samples = []
        ticks = []
        started = time.monotonic()
        for index in range(15):
            stat = docker("exec", target, "cat", f"/proc/{daemon}/status")
            samples.append(int(next(line.split()[1] for line in stat.splitlines() if line.startswith("VmRSS:"))))
            fields = docker("exec", target, "cat", f"/proc/{daemon}/stat").rsplit(")", 1)[1].split()
            ticks.append(int(fields[11]) + int(fields[12]))
            time.sleep(1)
        execute(target, f"kill -INT {daemon}\n")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = docker("exec", target, "cat", "/lab/daemon.exit", check=False).strip()
            if result:
                expect("daemon_sigint_exits_successfully", result == "0")
                break
            time.sleep(0.2)
        else:
            raise AssertionError("daemon did not exit gracefully")
        summary["daemon_rss_kb"] = {"min": min(samples), "max": max(samples), "samples": len(samples)}
        ticks_per_second = int(docker("exec", target, "getconf", "CLK_TCK").strip())
        summary["daemon_cpu_percent_one_core"] = round((ticks[-1] - ticks[0]) / ticks_per_second / (time.monotonic() - started) * 100, 3)
        (args.output / "daemon.log").write_text(docker("exec", target, "cat", "/lab/daemon.log"))
        summary["result"] = "passed"
    finally:
        for container in containers:
            (args.output / f"{container}.log").write_text(docker("logs", container, check=False))
            if summary.get("result") != "passed":
                (args.output / f"{container}-network.txt").write_text(execute(container, "ip addr\nip route\nss -lntp\n"))
        for container in containers:
            docker("rm", "-f", container, check=False)
        command(["ip", "link", "delete", f"sl{suffix}a"], check=False)
        command(["ip", "link", "delete", f"sl{suffix}b"], check=False)
        docker("network", "rm", network, check=False)
        docker("image", "rm", lab_image, runtime_image, check=False)
        firewall_after = command(["iptables-save"], check=False)
        summary["host_firewall_unchanged"] = firewall_hash(firewall_before) == firewall_hash(firewall_after)
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary, indent=2), flush=True)
    assert summary["host_firewall_unchanged"], "host firewall changed"


if __name__ == "__main__":
    main()
