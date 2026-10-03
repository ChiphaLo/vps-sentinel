#!/usr/bin/env python3
"""Extra isolated probes for vps-sentinel (run as root on a disposable Docker host).

Complements tests/container_lab/run.py with three groups of measurements:

A. Host-published-port attack path. The target service is exposed with
   `docker run -p <bridge-gateway>:18480:8080`, then attacked (a) from a peer
   container on the same Docker bridge (hairpin, normally via the userland
   proxy) and (b) from an external-shaped source address on a dedicated veth
   pair, where the source IP is preserved exactly like a real internet source.

B. Hostile filesystem robustness. FIFO, symlink loop, large file and an
   unreadable file are placed inside `[file_integrity].paths`, then a scan is
   run with a bounded timeout to look for hangs or memory blowups.

C. Common post-compromise parasite fixtures, one scan per fixture, so each
   detection result can be attributed to a single artifact. Nothing here is
   executed: payloads are inert copies of /bin/sleep and text markers only.

The script removes every fixture, veth, container and image it created, and
compares host firewall and address state before/after.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


class CmdError(RuntimeError):
    pass


def run(args, *, stdin=None, check=True, timeout=300):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True,
                            check=False, timeout=timeout)
    if check and result.returncode:
        raise CmdError(f"{args[:4]} exited {result.returncode}:\n{result.stdout[-1500:]}\n{result.stderr[-1500:]}")
    return result


EXT_PROBE_IP = "11.254.253.3"
EXT_PROBE_GATEWAY_IP = "11.254.253.1"
PUBLISHED_PORT = 18480

RUN_SCAN = r'''#!/bin/sh
# usage: run-scan.sh [extra args]
start=$(date +%s.%N)
vps-sentinel --config /lab/config.toml scan $1 --json > /lab/scan.out 2>/lab/scan.err &
p=$!
peak=0
while kill -0 "$p" 2>/dev/null; do
  h=$(awk '/^VmHWM:/{print $2}' "/proc/$p/status" 2>/dev/null)
  if [ -n "$h" ] && [ "$h" -gt "$peak" ]; then peak=$h; fi
  sleep 0.1
done
wait "$p"
code=$?
end=$(date +%s.%N)
secs=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.2f", b-a}')
echo "SCAN_EXIT=$code PEAK_RSS_KB=$peak SECONDS=$secs"
'''

LAB_CONFIG = '''[agent]
data_dir = "/lab/data"
scan_interval_seconds = 5
[storage]
path = "/lab/data/sentinel.db"
[file_integrity]
paths = ["/etc/passwd", "/etc/group", "/etc/cron.d", "/root/.ssh", "/var/www/html", "/opt/lab", "/etc/ld.so.preload", "/etc/systemd/system", "/var/spool/cron/crontabs", "/etc/ssh/sshd_config"]
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


def fixture(name, match, apply_script, cleanup_script, note):
    return {"name": name, "match": match, "apply": apply_script,
            "cleanup": cleanup_script, "note": note}


FIXTURES = [
    fixture("fifo_in_monitored_path", ["parasite.fifo"],
            "mkfifo -m 0644 /opt/lab/parasite.fifo\n",
            "rm -f /opt/lab/parasite.fifo\n",
            "FIFO inside a monitored directory; reading it must never block a scan."),
    fixture("symlink_loop_in_monitored_path", ["parasite.loop"],
            "ln -sf /opt/lab/parasite.loop /opt/lab/parasite.loop\n",
            "rm -f /opt/lab/parasite.loop\n",
            "Self-referential symlink; recursion must terminate."),
    fixture("large_file_in_monitored_path", ["parasite.bin"],
            "dd if=/dev/zero of=/opt/lab/parasite.bin bs=1M count=512 status=none\n",
            "rm -f /opt/lab/parasite.bin\n",
            "512 MiB file under a monitored path: scan time and peak RSS are recorded."),
    fixture("unreadable_file_in_monitored_path", ["parasite.secret"],
            "printf 'inert\n' > /opt/lab/parasite.secret\nchmod 000 /opt/lab/parasite.secret\n",
            "chmod 600 /opt/lab/parasite.secret 2>/dev/null; rm -f /opt/lab/parasite.secret\n",
            "Unreadable file must be reported as a collector condition, not crash the scan."),
    fixture("ld_so_preload_entry", ["ld.so.preload"],
            "printf '/lib/x86_64-linux-gnu/libm.so.6\n' > /etc/ld.so.preload\n",
            "rm -f /etc/ld.so.preload\n",
            "Rootkit-style ld.so.preload entry, expected ROOTKIT-003 / PERSIST-003."),
    fixture("shell_profile_reverse_shell_line", ["bashrc", "dev/tcp"],
            "cp -f /root/.bashrc /lab/bashrc.before 2>/dev/null || printf '' > /lab/bashrc.before\n"
            "printf '\\n# inert lab marker\\nbash -i >& /dev/tcp/127.0.0.1/9 0>&1\\n' >> /root/.bashrc\n",
            "cp -f /lab/bashrc.before /root/.bashrc 2>/dev/null || true\n",
            "Reverse-shell line in a shell profile; inert text, never executed."),
    fixture("systemd_unit_persistence", ["parasite-update"],
            "printf '[Unit]\\nDescription=inert lab fixture\\n[Service]\\nExecStart=/tmp/.parasite/update\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/parasite-update.service\n",
            "rm -f /etc/systemd/system/parasite-update.service\n",
            "Systemd unit drop for a payload that is never started."),
    fixture("cron_spool_root_entry", ["crontabs", "parasite-spool"],
            "mkdir -p /var/spool/cron/crontabs\n"
            "printf '# inert lab marker\\n*/5 * * * * root /tmp/.parasite/update\\n' > /var/spool/cron/crontabs/root\n",
            "rm -f /var/spool/cron/crontabs/root\n",
            "Cron spool persistence, the classic crontab -e backdoor path."),
    fixture("known_miner_process_name", ["kinsing"],
            "cp /bin/sleep /tmp/kinsing\n/tmp/kinsing 240 >/lab/kinsing.log 2>&1 &\necho $! > /lab/kinsing.pid\n",
            "kill $(cat /lab/kinsing.pid) 2>/dev/null || true\nrm -f /tmp/kinsing /lab/kinsing.pid\n",
            "Process named after the Kinsing miner family, running from /tmp; it only sleeps."),
    fixture("dropped_parasite_payload", [".parasite"],
            "mkdir -p /tmp/.parasite\ncp /bin/sleep /tmp/.parasite/update\nchmod 755 /tmp/.parasite/update\n"
            "printf 'stratum+tcp://127.0.0.1:3333 lab-marker\\n' > /tmp/.parasite/config.json\n",
            "rm -rf /tmp/.parasite\n",
            "Dropped payload plus miner config in /tmp, never executed."),
    fixture("sshd_config_weakened", ["sshd_config"],
            "cp -f /etc/ssh/sshd_config /lab/sshd_config.before\n"
            "printf '\\nPermitRootLogin yes\\nPasswordAuthentication yes\\n' >> /etc/ssh/sshd_config\n",
            "cp -f /lab/sshd_config.before /etc/ssh/sshd_config\n",
            "SSH backdoor config: direct root login and password auth enabled."),
    fixture("auth_log_truncated", ["auth.log"],
            ": > /var/log/auth.log\n",
            "cp -f /lab/auth.log.before /var/log/auth.log 2>/dev/null || true\n",
            "Anti-forensics: sensitive log truncated in place, expected TAMPER-002."),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scan-timeout", type=int, default=120)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    suffix = uuid.uuid4().hex[:8]
    prefix = f"sentinel-extra-{suffix}"
    target, attacker = prefix + "-target", prefix + "-attacker"
    network = prefix
    runtime_image, lab_image = prefix + ":runtime", prefix + ":fixture"
    summary = {"cases": {}, "scans": {}, "fixtures": {}, "limitations": [
        "The product blocks public source IPs only; private/loopback sources are never auto-blocked.",
        "Container-side blocking cannot see the real client when Docker rewrites the source address.",
        "Fixtures are inert: no payload is executed, no miner runs, no persistence is activated.",
        "Cleanup is performed by this harness, not by the product under test.",
    ]}
    containers = []
    host_links = []

    def firewall_hash(text):
        text = re.sub(r"\[\d+:\d+\]", "[counters]", text)
        return hashlib.sha256("\n".join(line for line in text.splitlines()
                                        if not line.startswith("#")).encode()).hexdigest()

    def addr_snapshot():
        addr = run(["ip", "-o", "addr", "show"], check=False).stdout
        route = run(["ip", "route", "show"], check=False).stdout
        return addr, route

    firewall_before = run(["iptables-save"], check=False).stdout
    addr_before, route_before = addr_snapshot()

    def docker(*parts, **kwargs):
        return run(["docker", *parts], **kwargs)

    def execute(container, script, **kwargs):
        kwargs.setdefault("timeout", 120)
        return docker("exec", "-i", container, "sh", "-eu", stdin=script, **kwargs)

    def request_from(container, url, timeout=4):
        code = ("import urllib.request, urllib.error, socket\n"
                "try:\n"
                f"  r=urllib.request.urlopen({url!r}, timeout={timeout}); print(r.status)\n"
                "except urllib.error.HTTPError as e: print(e.code)\n"
                "except (urllib.error.URLError, socket.timeout, ConnectionError): print('blocked')\n")
        return docker("exec", "-i", container, "python3", "-", stdin=code).stdout.strip()

    def record_scan(label, *, response=False, timeout=None):
        timeout = timeout or args.scan_timeout
        extra = "" if response else "--no-notify"
        started = time.monotonic()
        try:
            result = execute(target, f"sh /lab/run-scan.sh '{extra}'\n", check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            execute(target, "pkill -f 'vps-sentinel.*scan' 2>/dev/null || true\n", check=False)
            summary["scans"][label] = {"hung": True, "timeout_seconds": timeout}
            (args.output / f"{label}.timeout.txt").write_text(
                docker("exec", target, "cat", "/lab/scan.err", check=False).stdout)
            return None
        elapsed = round(time.monotonic() - started, 3)
        marker = next((line for line in result.stdout.splitlines() if line.startswith("SCAN_EXIT=")), "")
        raw = docker("exec", target, "cat", "/lab/scan.out", check=False).stdout
        (args.output / f"{label}.json").write_text(raw)
        entry = {"marker": marker, "wall_seconds": elapsed}
        try:
            report = json.loads(raw)
        except json.JSONDecodeError:
            entry["parse_error"] = True
            summary["scans"][label] = entry
            return None
        entry.update({
            "rss_kb": report.get("memory_rss_after_kb"),
            "collector_errors": report.get("collector_errors"),
            "rules": sorted({f["rule_id"] for f in report["findings"]}),
            "active_response_applied": report.get("active_response_applied_count"),
            "active_response_failed": report.get("active_response_failed_count"),
        })
        summary["scans"][label] = entry
        return report

    def attributed(report, keys):
        if not report:
            return []
        hits = []
        for finding in report["findings"]:
            blob = json.dumps(finding, ensure_ascii=False)
            if any(key in blob for key in keys):
                hits.append({"rule_id": finding["rule_id"], "subject": finding.get("subject", ""),
                             "severity": finding.get("severity", "")})
        return hits

    def blocks():
        return docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml",
                      "blocks", "list", "--no-verify", check=False).stdout.strip()

    def block_why(ip):
        return docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml",
                      "blocks", "why", ip, "--no-verify", "--json", check=False).stdout.strip()

    try:
        with tempfile.TemporaryDirectory(prefix=prefix) as staging:
            shutil.copy2(args.binary, Path(staging) / "vps-sentinel")
            docker("build", "-t", runtime_image, "-f", str(args.repo / "packaging/Dockerfile"), staging)
        docker("build", "-t", lab_image, "--build-arg", f"RUNTIME_IMAGE={runtime_image}",
               str(args.repo / "tests/container_lab"), timeout=900)
        docker("network", "create", network)
        gateway = docker("network", "inspect", network, "--format",
                         "{{(index .IPAM.Config 0).Gateway}}").stdout.strip()
        docker("run", "-d", "--name", target, "--network", network, "--cpus=1",
               "--memory=192m", "--pids-limit=128", "--cap-add=NET_ADMIN",
               "-p", f"{gateway}:{PUBLISHED_PORT}:8080", lab_image)
        containers.append(target)
        docker("run", "-d", "--name", attacker, "--network", network, "--cpus=1",
               "--memory=192m", "--pids-limit=128", "--cap-add=NET_ADMIN", lab_image)
        containers.append(attacker)
        summary["published_port"] = {"gateway": gateway, "port": PUBLISHED_PORT}
        summary["host_nat_rules"] = [line for line in run(["iptables", "-t", "nat", "-S"], check=False).stdout.splitlines()
                                     if str(PUBLISHED_PORT) in line or "MASQUERADE" in line]
        summary["host_forward_policy"] = run(["iptables", "-S", "FORWARD"], check=False).stdout.splitlines()[:6]

        docker("exec", "-i", target, "sh", "-c", "cat > /lab/config.toml", stdin=LAB_CONFIG, timeout=60)
        docker("exec", "-i", target, "sh", "-c", "cat > /lab/run-scan.sh", stdin=RUN_SCAN, timeout=60)
        execute(target, "chmod 755 /lab/run-scan.sh\n"
                        "cp /bin/sleep /opt/lab/helper\ncp /bin/sleep /opt/lab/cap-helper\n"
                        "printf '# baseline\n' > /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\n"
                        "mkdir -p /lab/data\n")
        docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml", "baseline", "create", timeout=120)
        target_ip = json.loads(docker("inspect", target).stdout)[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if request_from(attacker, f"http://{gateway}:{PUBLISHED_PORT}/") == "200":
                break
            time.sleep(0.25)
        else:
            raise CmdError("published port never became reachable")
        summary["published_port_reachable_from_peer"] = True

        # ---- A1: peer-container (hairpin) attack through the published port ----
        peer_log = docker("exec", target, "tail", "-n", "1", "/var/log/lab-access.log", check=False).stdout.strip()
        summary["cases"]["hairpin_source_address"] = peer_log
        for path in ["/.env", "/.git/config", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"] * 3:
            request_from(attacker, f"http://{gateway}:{PUBLISHED_PORT}{path}")
        hairpin = record_scan("hairpin-published-port", response=True)
        summary["cases"]["hairpin_web_finding"] = attributed(hairpin, [gateway])
        summary["cases"]["hairpin_blocks"] = blocks()
        summary["cases"]["hairpin_peer_still_reachable"] = request_from(attacker, f"http://{gateway}:{PUBLISHED_PORT}/")

        # ---- A2: external-shaped source on a dedicated veth ----
        attacker_pid = docker("inspect", attacker, "--format", "{{.State.Pid}}").stdout.strip()
        link_host, link_guest = f"se{suffix}a", f"se{suffix}b"
        run(["ip", "link", "add", link_host, "type", "veth", "peer", "name", link_guest])
        host_links.append(link_host)
        run(["ip", "addr", "add", f"{EXT_PROBE_GATEWAY_IP}/24", "dev", link_host])
        run(["ip", "link", "set", link_host, "up"])
        run(["ip", "link", "set", link_guest, "netns", attacker_pid])
        execute(attacker, f"ip addr add {EXT_PROBE_IP}/24 dev {link_guest}\n"
                          f"ip link set {link_guest} up\n"
                          f"ip route add {gateway}/32 via {EXT_PROBE_GATEWAY_IP} dev {link_guest}\n")
        summary["cases"]["external_source_published_port"] = request_from(attacker, f"http://{gateway}:{PUBLISHED_PORT}/")
        summary["cases"]["external_source_log_line"] = docker(
            "exec", target, "tail", "-n", "1", "/var/log/lab-access.log", check=False).stdout.strip()
        for path in ["/.env", "/.git/config", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"] * 3:
            request_from(attacker, f"http://{gateway}:{PUBLISHED_PORT}{path}")
        external = record_scan("external-published-port", response=True)
        summary["cases"]["external_web_finding"] = attributed(external, [EXT_PROBE_IP])
        summary["cases"]["external_blocks"] = blocks()
        summary["cases"]["external_block_why"] = block_why(EXT_PROBE_IP)
        summary["cases"]["external_published_port_after_block"] = request_from(attacker, f"http://{gateway}:{PUBLISHED_PORT}/")
        summary["cases"]["external_direct_container_after_block"] = request_from(attacker, f"http://{target_ip}:8080/")
        docker("exec", target, "vps-sentinel", "--config", "/lab/config.toml", "blocks", "unblock", EXT_PROBE_IP, check=False)
        time.sleep(1)
        summary["cases"]["external_published_port_after_unblock"] = request_from(attacker, f"http://{gateway}:{PUBLISHED_PORT}/")

        # ---- B + C: hostile filesystem and parasite fixtures ----
        # Log integrity compares with the previous snapshot, so the auth log has
        # to exceed the documented truncation thresholds (90 percent drop and
        # 262144 bytes) before the truncation fixture is meaningful. The filler
        # is inert text that never passes through a shell here.
        execute(target, "cp -f /var/log/auth.log /lab/auth.log.before 2>/dev/null || true\n"
                        "yes 'lab filler line, inert' | head -n 20000 >> /var/log/auth.log\n"
                        "wc -c /var/log/auth.log\n")
        clean = record_scan("pre-fixture-clean")
        summary["cases"]["clean_scan_rules"] = sorted({f["rule_id"] for f in clean["findings"]}) if clean else None
        for item in FIXTURES:
            entry = {"note": item["note"]}
            try:
                execute(target, item["apply"], timeout=180)
                entry["applied"] = True
            except (CmdError, subprocess.TimeoutExpired) as error:
                entry["applied"] = False
                entry["apply_error"] = str(error)[:500]
                summary["fixtures"][item["name"]] = entry
                continue
            report = record_scan("fixture-" + item["name"], timeout=args.scan_timeout)
            entry["detections"] = attributed(report, item["match"])
            entry["scan"] = summary["scans"].get("fixture-" + item["name"])
            summary["fixtures"][item["name"]] = entry
            try:
                execute(target, item["cleanup"], timeout=120)
                entry["cleaned"] = True
            except (CmdError, subprocess.TimeoutExpired) as error:
                entry["cleaned"] = False
                entry["cleanup_error"] = str(error)[:500]

        after = record_scan("after-fixture-cleanup")
        leftover_keys = [key for item in FIXTURES for key in item["match"]]
        summary["cases"]["fixture_leftovers"] = attributed(after, leftover_keys)
        summary["cases"]["fixture_leftovers_clear"] = not summary["cases"]["fixture_leftovers"]
        summary["cases"]["final_blocks"] = blocks()
        summary["result"] = "completed"
    finally:
        for container in containers:
            log = docker("logs", container, check=False)
            (args.output / f"{container}.log").write_text(log.stdout + log.stderr)
        for container in containers:
            docker("rm", "-f", container, check=False)
        for link in host_links:
            run(["ip", "link", "delete", link], check=False)
        docker("network", "rm", network, check=False)
        docker("image", "rm", lab_image, runtime_image, check=False)
        firewall_after = run(["iptables-save"], check=False).stdout
        addr_after, route_after = addr_snapshot()
        summary["host_firewall_unchanged"] = firewall_hash(firewall_before) == firewall_hash(firewall_after)
        summary["host_routes_unchanged"] = route_before == route_after
        summary["host_addrs_unchanged"] = addr_before == addr_after
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary, indent=2), flush=True)
    if not summary.get("host_firewall_unchanged"):
        raise SystemExit("host firewall changed during the extra probes")


if __name__ == "__main__":
    main()
