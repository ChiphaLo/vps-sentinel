#![cfg(unix)]

use sentinel_agent::collectors::{
    audit::parse_audit_log, docker::DockerCollector, file_integrity::FileIntegrityCollector,
    persistence::PersistenceCollector, CollectContext, Collector,
};
use sentinel_agent::detectors::{
    audit_rules::AuditDetector, docker_rules::DockerDetector, DetectContext, Detector,
};
use sentinel_core::SentinelConfig;
use std::{fs, sync::Arc};

fn detects_audit(line: &str, rule: &str) -> bool {
    let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
    AuditDetector
        .detect(&parse_audit_log(line, "/test/audit.log"), &ctx)
        .iter()
        .any(|f| f.rule_id == rule)
}

#[test]
fn audit_plain_credential_read() {
    assert!(detects_audit(
        r#"type=EXECVE msg=audit(1710000000.1:1): argc=2 a0="cat" a1="/etc/shadow""#,
        "AUDIT-003"
    ));
}

#[test]
fn audit_absolute_binary_credential_read() {
    assert!(detects_audit(
        r#"type=EXECVE msg=audit(1710000000.1:2): argc=2 a0="/usr/bin/cat" a1="/etc/shadow""#,
        "AUDIT-003"
    ));
}

#[test]
fn audit_hex_encoded_shell_argument() {
    // auditd represents argv values containing spaces as hex strings.
    assert!(detects_audit(
        r#"type=EXECVE msg=audit(1710000000.1:3): argc=3 a0="sh" a1="-c" a2=636174202F6574632F736861646F77"#,
        "AUDIT-003"
    ));
}

#[test]
fn audit_benign_commands_do_not_alert() {
    for line in [
        r#"type=EXECVE msg=audit(1710000000.1:4): argc=3 a0="systemctl" a1="status" a2="auditd""#,
        r#"type=EXECVE msg=audit(1710000000.1:5): argc=3 a0="chmod" a1="0644" a2="/tmp/demo""#,
    ] {
        for rule in ["AUDIT-003", "AUDIT-004", "AUDIT-005", "AUDIT-006"] {
            assert!(!detects_audit(line, rule));
        }
    }
}

#[test]
fn audit_new_rules_positive_log_records() {
    for (line, rule) in [
        (
            r#"type=EXECVE msg=audit(1710000000.1:10): argc=3 a0="setcap" a1="cap_setuid+ep" a2="/tmp/helper""#,
            "AUDIT-004",
        ),
        (
            r#"type=EXECVE msg=audit(1710000000.1:11): argc=2 a0="modprobe" a1="dummy""#,
            "AUDIT-005",
        ),
        (
            r#"type=EXECVE msg=audit(1710000000.1:12): argc=3 a0="systemctl" a1="stop" a2="auditd""#,
            "AUDIT-006",
        ),
    ] {
        assert!(detects_audit(line, rule), "missing {rule}");
    }
}

#[test]
fn audit_public_ssh_key_is_not_private_credential() {
    assert!(!detects_audit(
        r#"type=EXECVE msg=audit(1710000000.1:13): argc=2 a0="cat" a1="/root/.ssh/id_ed25519.pub""#,
        "AUDIT-003"
    ));
}

#[test]
fn audit_absolute_setcap_binary() {
    assert!(detects_audit(
        r#"type=EXECVE msg=audit(1710000000.1:14): argc=3 a0="/usr/sbin/setcap" a1="cap_setuid+ep" a2="/tmp/helper""#,
        "AUDIT-004"
    ));
}

#[test]
fn audit_sgid_numeric_permission() {
    assert!(detects_audit(
        r#"type=EXECVE msg=audit(1710000000.1:15): argc=3 a0="chmod" a1="2755" a2="/tmp/helper""#,
        "AUDIT-004"
    ));
}

#[test]
fn docker_all_capabilities_are_dangerous() {
    let event = sentinel_core::RawEvent::new("docker", "docker_container")
        .with_field("name", "inert-fixture")
        .with_field("cap_add", "ALL");
    let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
    assert!(DockerDetector
        .detect(&[event], &ctx)
        .iter()
        .any(|f| f.rule_id == "DOCKER-006"));
}

#[tokio::test]
async fn expanded_persistence_paths_are_collected() {
    let root = tempfile::tempdir().unwrap();
    let paths = [
        "root/.bashrc",
        "root/.profile",
        "root/.config/systemd/user/example.service",
        "home/test/.zshrc",
        "home/test/.config/systemd/user/example.service",
        "etc/rc.local",
        "etc/init.d/example",
        "etc/udev/rules.d/99-test.rules",
    ];
    for path in paths {
        let full = root.path().join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, "# inert fixture\n").unwrap();
    }
    let ctx =
        CollectContext::new(Arc::new(SentinelConfig::default())).with_scan_root(root.path().into());
    let events = PersistenceCollector.collect(&ctx).await.unwrap();
    for path in paths {
        assert!(
            events
                .iter()
                .any(|e| e.field("path").is_some_and(|p| p.ends_with(path))),
            "missing {path}"
        );
    }
}

#[tokio::test]
async fn expanded_fim_defaults_collect_sensitive_configs() {
    let root = tempfile::tempdir().unwrap();
    let paths = [
        "etc/pam.d/test",
        "etc/security/test",
        "etc/polkit-1/rules.d/test.rules",
        "etc/modprobe.d/test.conf",
        "etc/udev/rules.d/test.rules",
        "etc/apt/sources.list.d/test.list",
    ];
    for path in paths {
        let full = root.path().join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, "# inert fixture\n").unwrap();
    }
    let ctx =
        CollectContext::new(Arc::new(SentinelConfig::default())).with_scan_root(root.path().into());
    let events = FileIntegrityCollector.collect(&ctx).await.unwrap();
    for path in paths {
        assert!(
            events
                .iter()
                .any(|e| e.field("path").is_some_and(|p| p.ends_with(path))),
            "missing {path}"
        );
    }
}

#[test]
fn example_config_keeps_expanded_fim_paths() {
    let cfg: SentinelConfig =
        toml::from_str(include_str!("../../../config/config.example.toml")).unwrap();
    assert_eq!(
        cfg.file_integrity.paths,
        SentinelConfig::default().file_integrity.paths
    );
    for p in [
        "/etc/pam.d",
        "/etc/polkit-1/rules.d",
        "/etc/modprobe.d",
        "/etc/udev/rules.d",
    ] {
        assert!(
            cfg.file_integrity
                .paths
                .iter()
                .any(|path| path == std::path::Path::new(p)),
            "example config missing {p}"
        );
    }
}

#[tokio::test]
#[ignore = "requires a live Docker socket; run explicitly on the Docker host"]
async fn docker_collect_and_detect_all_six_risks_without_starting_container() {
    use std::os::unix::fs::PermissionsExt;
    assert!(
        std::path::Path::new("/var/run/docker.sock").exists(),
        "hyvps docker socket required"
    );
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("docker-fixture");
    let json = r#"[{"Id":"test-high-risk","Name":"/sentinel-fixture","Config":{"Image":"inert-fixture"},"HostConfig":{"Privileged":true,"NetworkMode":"host","PidMode":"host","CapAdd":["SYS_ADMIN"]},"Mounts":[{"Source":"/var/run/docker.sock","Destination":"/socket","RW":false},{"Source":"/","Destination":"/host","RW":true}]}]"#;
    fs::write(&script, format!("#!/bin/sh\nif [ \"$1\" = ps ]; then echo test-high-risk; else printf '%s\\n' '{json}'; fi\n")).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let mut cfg = SentinelConfig::default();
    cfg.docker.docker_command = script.display().to_string();
    let cfg = Arc::new(cfg);
    let events = DockerCollector
        .collect(&CollectContext::new(cfg.clone()))
        .await
        .unwrap();
    let findings = DockerDetector.detect(&events, &DetectContext::new(cfg));
    for rule in [
        "DOCKER-002",
        "DOCKER-003",
        "DOCKER-004",
        "DOCKER-005",
        "DOCKER-006",
        "DOCKER-007",
    ] {
        assert!(findings.iter().any(|f| f.rule_id == rule), "missing {rule}");
    }
}
