#![cfg(unix)]

use sentinel_agent::baseline::{approval_items, diff_snapshots, BaselineSnapshot};
use sentinel_agent::collectors::{
    file_integrity::FileIntegrityCollector, CollectContext, Collector,
};
use sentinel_agent::detectors::{file_rules::FileDetector, DetectContext, Detector};
use sentinel_core::{RawEvent, SentinelConfig};
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

fn file(mode: &str, uid: &str, capabilities: &str) -> RawEvent {
    RawEvent::new("file_integrity", "file_snapshot")
        .with_field("path", "/opt/helper")
        .with_field("hash", "unchanged")
        .with_field("mode_octal", mode)
        .with_field("uid", uid)
        .with_field("gid", "0")
        .with_field("file_capabilities", capabilities)
}

fn rules(old: RawEvent, new: RawEvent) -> Vec<String> {
    let events = diff_snapshots(
        &BaselineSnapshot::from_events(&[old]),
        &BaselineSnapshot::from_events(&[new]),
    );
    FileDetector
        .detect(
            &events,
            &DetectContext::new(Arc::new(SentinelConfig::default())),
        )
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

#[tokio::test]
async fn chmod_without_content_change_is_collected_and_detected() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("helper");
    fs::write(&path, "inert fixture\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = SentinelConfig::default();
    config.ssh.enabled = false;
    config.file_integrity.paths = vec![path.clone()];
    let config = Arc::new(config);
    let ctx = CollectContext::new(Arc::clone(&config));
    let old = BaselineSnapshot::from_events(&FileIntegrityCollector.collect(&ctx).await.unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o6755)).unwrap();
    let new = BaselineSnapshot::from_events(&FileIntegrityCollector.collect(&ctx).await.unwrap());
    assert_eq!(
        old.files.values().next().unwrap().hash,
        new.files.values().next().unwrap().hash
    );
    let events = diff_snapshots(&old, &new);
    assert_eq!(events.len(), 1);
    let findings = FileDetector.detect(&events, &DetectContext::new(config));
    assert!(findings.iter().any(|finding| finding.rule_id == "FILE-005"));
}

#[test]
fn ordinary_permissions_do_not_raise_privilege_alerts() {
    assert!(rules(file("0644", "0", "none"), file("0600", "0", "none")).is_empty());
    assert!(rules(file("0755", "0", "none"), file("0755", "0", "none")).is_empty());
}

#[test]
fn privileged_owner_change_and_sgid_are_detected() {
    assert!(
        rules(file("2755", "1000", "none"), file("2755", "0", "none")).contains(&"FILE-005".into())
    );
    assert!(
        rules(file("0755", "0", "none"), file("2755", "0", "none")).contains(&"FILE-005".into())
    );
}

#[test]
fn capability_addition_and_removal_are_detected() {
    for (before, after) in [
        ("none", "0100000200008000000000000000000000000000"),
        ("0100000200008000000000000000000000000000", "none"),
    ] {
        assert!(
            rules(file("0755", "0", before), file("0755", "0", after)).contains(&"FILE-006".into())
        );
    }
}

#[test]
fn unknown_capability_observation_is_not_a_removal() {
    for (before, after) in [("", "none"), ("01000002", "")] {
        assert!(rules(file("0755", "0", before), file("0755", "0", after)).is_empty());
    }
}

#[test]
fn older_baselines_load_without_metadata_and_do_not_invent_drift() {
    let mut old = BaselineSnapshot::from_events(&[file("0755", "0", "none")]);
    let mut value = serde_json::to_value(&old).unwrap();
    let stored = value["files"]["/opt/helper"].as_object_mut().unwrap();
    for key in ["mode_octal", "uid", "gid", "file_capabilities"] {
        stored.remove(key);
    }
    old = serde_json::from_value(value).unwrap();
    let new = BaselineSnapshot::from_events(&[file("0755", "0", "none")]);
    assert!(diff_snapshots(&old, &new).is_empty());
}

#[test]
fn approval_is_bound_to_privilege_metadata() {
    let old = BaselineSnapshot::from_events(&[file("0755", "0", "none")]);
    let suid = BaselineSnapshot::from_events(&[file("4755", "0", "none")]);
    let sgid = BaselineSnapshot::from_events(&[file("2755", "0", "none")]);
    assert_ne!(
        approval_items(&old, &suid)[0].key,
        approval_items(&old, &sgid)[0].key
    );
}
