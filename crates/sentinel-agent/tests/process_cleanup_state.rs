use sentinel_agent::detectors::{process_rules::ProcessDetector, DetectContext, Detector};
use sentinel_agent::utils::procfs::{collect_processes, ProcfsRoot};
use sentinel_core::{RawEvent, SentinelConfig};
use std::{fs, sync::Arc};

#[test]
fn terminated_procfs_miner_is_retained_as_fact_without_active_alert() {
    let temp = tempfile::tempdir().unwrap();
    let pid = temp.path().join("123");
    fs::create_dir(&pid).unwrap();
    fs::write(
        pid.join("status"),
        "Name:\txmrig\nState:\tZ (zombie)\nPPid:\t1\nUid:\t0 0 0 0\n",
    )
    .unwrap();
    fs::write(pid.join("cmdline"), b"").unwrap();
    let events = collect_processes(&ProcfsRoot::new(temp.path().to_path_buf())).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].field("process_state"), Some("Z"));
    let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
    assert!(ProcessDetector.detect(&events, &ctx).is_empty());
}

#[test]
fn only_terminated_snapshots_are_excluded_from_active_process_rules() {
    let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
    for (kind, state, expected) in [
        ("process_snapshot", "Z", false),
        ("process_snapshot", "X", false),
        ("process_snapshot", "x", false),
        ("process_snapshot", "S", true),
        ("process_snapshot", "T", true),
        ("process_snapshot", "", true),
        ("process_exec", "Z", true),
    ] {
        let event = RawEvent::new("test", kind)
            .with_field("name", "xmrig")
            .with_field("process_state", state);
        assert_eq!(
            ProcessDetector
                .detect(&[event], &ctx)
                .iter()
                .any(|f| f.rule_id == "PROC-004"),
            expected,
            "{kind}/{state}"
        );
    }
}
