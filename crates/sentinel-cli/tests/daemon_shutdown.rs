#![cfg(unix)]

use sentinel_core::SentinelConfig;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn interrupt_during_collection_is_retained_until_scan_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let ready = tmp.path().join("collecting");
    let collector = tmp.path().join("slow-gpu-collector");
    fs::write(
        &collector,
        "#!/bin/sh\n: > \"$VPS_SENTINEL_TEST_READY\"\nsleep 2\n",
    )
    .unwrap();
    fs::set_permissions(&collector, fs::Permissions::from_mode(0o700)).unwrap();

    let mut config = SentinelConfig::default();
    config.agent.data_dir = tmp.path().join("data");
    config.agent.scan_interval_seconds = 60;
    config.storage.path = tmp.path().join("sentinel.db");
    config.active_response.enabled = false;
    config.response_policy.enabled = false;
    config.fleet.enabled = false;
    config.reports.scheduled_enabled = false;
    config.panel.node_location_enabled = false;
    config.panel.ip_intel_remote_enabled = false;
    config.ssh.enabled = false;
    config.file_integrity.enabled = false;
    config.persistence.enabled = false;
    config.process.enabled = false;
    config.network.enabled = false;
    config.docker.enabled = false;
    config.web.enabled = false;
    config.gpu.nvidia_smi_path = collector.display().to_string();
    config.gpu.rocm_smi_path.clear();
    let path = tmp.path().join("config.toml");
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();

    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_vps-sentinel"))
            .arg("--config")
            .arg(path)
            .arg("daemon")
            .env("VPS_SENTINEL_TEST_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "daemon exited before collection"
        );
        assert!(Instant::now() < deadline, "collector did not start");
        sleep(Duration::from_millis(10));
    }
    assert!(Command::new("/bin/sh")
        .args([
            "-c",
            "kill -INT \"$1\"",
            "sentinel-test",
            &child.0.id().to_string()
        ])
        .status()
        .unwrap()
        .success());
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "daemon did not shut down gracefully: {status}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "interrupt was lost during collection"
        );
        sleep(Duration::from_millis(10));
    }
}
