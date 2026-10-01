use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct DockerDetector;

impl Detector for DockerDetector {
    fn name(&self) -> &'static str {
        "docker_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "DOCKER-001",
                "Docker socket present",
                Category::Docker,
                Severity::Info,
                "Docker is installed and the local Docker socket is present.",
            ),
            RuleMetadata::new(
                "DOCKER-002",
                "Privileged container detected",
                Category::Docker,
                Severity::High,
                "A running container is configured as privileged.",
            ),
            RuleMetadata::new(
                "DOCKER-003",
                "Docker socket mounted into container",
                Category::Docker,
                Severity::Critical,
                "A running container can access the host Docker control socket.",
            ),
            RuleMetadata::new(
                "DOCKER-004",
                "Host network namespace shared",
                Category::Docker,
                Severity::Medium,
                "A running container uses host networking.",
            ),
            RuleMetadata::new(
                "DOCKER-005",
                "Host PID namespace shared",
                Category::Docker,
                Severity::High,
                "A running container uses the host PID namespace.",
            ),
            RuleMetadata::new(
                "DOCKER-006",
                "Dangerous Linux capabilities added",
                Category::Docker,
                Severity::High,
                "A running container was granted capabilities commonly associated with host compromise or deep introspection.",
            ),
            RuleMetadata::new(
                "DOCKER-007",
                "Host root mounted read-write",
                Category::Docker,
                Severity::Critical,
                "A running container has a read-write bind mount of the host root filesystem.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in events {
            match event.kind.as_str() {
                "docker_socket" => findings.push(docker_socket_present(event, ctx)),
                "docker_container" => {
                    if ctx.config.docker.alert_on_privileged_container
                        && event.field("privileged") == Some("true")
                    {
                        findings.push(container_finding(
                            event,
                            ctx,
                            "Privileged container detected",
                            "A running container is configured as privileged and can bypass many namespace and device restrictions.",
                            Severity::High,
                            "DOCKER-002",
                        ));
                    }
                    if ctx.config.docker.alert_on_docker_socket_mount
                        && event.field("docker_socket_mount") == Some("true")
                    {
                        findings.push(container_finding(
                            event,
                            ctx,
                            "Docker socket mounted into container",
                            "A running container can access the Docker control socket, which commonly provides host-level control.",
                            Severity::Critical,
                            "DOCKER-003",
                        ));
                    }
                    if ctx.config.docker.alert_on_host_network
                        && event.field("network_mode") == Some("host")
                    {
                        findings.push(container_finding(
                            event,
                            ctx,
                            "Container uses host networking",
                            "A running container shares the host network namespace.",
                            Severity::Medium,
                            "DOCKER-004",
                        ));
                    }
                    if ctx.config.docker.alert_on_host_pid
                        && event.field("pid_mode") == Some("host")
                    {
                        findings.push(container_finding(
                            event,
                            ctx,
                            "Container uses host PID namespace",
                            "A running container shares the host PID namespace and can observe host processes.",
                            Severity::High,
                            "DOCKER-005",
                        ));
                    }
                    if ctx.config.docker.alert_on_dangerous_capabilities {
                        let caps = dangerous_capabilities(&string_field(event, "cap_add"));
                        if !caps.is_empty() {
                            findings.push(
                                container_finding(
                                    event,
                                    ctx,
                                    "Dangerous Linux capabilities added",
                                    "A running container was granted high-impact Linux capabilities.",
                                    Severity::High,
                                    "DOCKER-006",
                                )
                                .with_evidence(container_evidence(event, Some((
                                    "dangerous_capabilities",
                                    caps.join(","),
                                )))),
                            );
                        }
                    }
                    if ctx.config.docker.alert_on_host_root_mount
                        && event.field("host_root_mount_rw") == Some("true")
                    {
                        findings.push(container_finding(
                            event,
                            ctx,
                            "Host root mounted read-write",
                            "A running container can write directly to the host root filesystem.",
                            Severity::Critical,
                            "DOCKER-007",
                        ));
                    }
                }
                _ => {}
            }
        }
        findings
    }
}

fn docker_socket_present(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Docker socket present",
        "Docker socket was found. Running containers are inspected when the local Docker CLI is available.",
        Severity::Info,
        Category::Docker,
        "DOCKER-001",
        string_field(event, "path"),
    )
    .with_evidence(vec![
        evidence("path", string_field(event, "path")),
        evidence("exists", string_field(event, "exists")),
    ])
}

fn container_finding(
    event: &RawEvent,
    ctx: &DetectContext,
    title: &str,
    description: &str,
    severity: Severity,
    rule_id: &str,
) -> Finding {
    Finding::new(
        &ctx.host_id,
        title,
        description,
        severity,
        Category::Docker,
        rule_id,
        container_subject(event),
    )
    .with_evidence(container_evidence(event, None))
    .with_recommendations(vec![
        "Confirm the container requires this host-level access.".to_string(),
        "Remove unnecessary privilege, namespace sharing, capabilities, or host mounts and recreate the container.".to_string(),
    ])
}

fn container_subject(event: &RawEvent) -> String {
    let name = string_field(event, "name");
    if !name.is_empty() {
        return name;
    }
    string_field(event, "container_id")
}

fn container_evidence(
    event: &RawEvent,
    extra: Option<(&str, String)>,
) -> Vec<sentinel_core::Evidence> {
    let mut items = vec![
        evidence("container_id", string_field(event, "container_id")),
        evidence("name", string_field(event, "name")),
        evidence("image", string_field(event, "image")),
        evidence("privileged", string_field(event, "privileged")),
        evidence("network_mode", string_field(event, "network_mode")),
        evidence("pid_mode", string_field(event, "pid_mode")),
        evidence("cap_add", string_field(event, "cap_add")),
        evidence(
            "docker_socket_mount",
            string_field(event, "docker_socket_mount"),
        ),
        evidence(
            "host_root_mount_rw",
            string_field(event, "host_root_mount_rw"),
        ),
        evidence("mount_samples", string_field(event, "mount_samples")),
    ];
    if let Some((key, value)) = extra {
        items.push(evidence(key, value));
    }
    items
}

fn dangerous_capabilities(value: &str) -> Vec<String> {
    const DANGEROUS: &[&str] = &[
        "SYS_ADMIN",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "DAC_READ_SEARCH",
        "DAC_OVERRIDE",
        "BPF",
        "PERFMON",
    ];
    value
        .split(',')
        .map(str::trim)
        .filter(|cap| {
            cap.eq_ignore_ascii_case("ALL")
                || DANGEROUS
                    .iter()
                    .any(|dangerous| cap.eq_ignore_ascii_case(dangerous))
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{dangerous_capabilities, DockerDetector};
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn identifies_dangerous_capabilities() {
        assert_eq!(
            dangerous_capabilities("NET_BIND_SERVICE,SYS_ADMIN,SYS_PTRACE"),
            vec!["SYS_ADMIN".to_string(), "SYS_PTRACE".to_string()]
        );
    }

    #[test]
    fn detects_multiple_container_escape_risks() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("docker", "docker_container")
            .with_field("container_id", "abc")
            .with_field("name", "worker")
            .with_field("privileged", "true")
            .with_field("network_mode", "host")
            .with_field("pid_mode", "host")
            .with_field("cap_add", "SYS_ADMIN")
            .with_field("docker_socket_mount", "true")
            .with_field("host_root_mount_rw", "true");

        let findings = DockerDetector.detect(&[event], &ctx);

        for id in [
            "DOCKER-002",
            "DOCKER-003",
            "DOCKER-004",
            "DOCKER-005",
            "DOCKER-006",
            "DOCKER-007",
        ] {
            assert!(findings.iter().any(|finding| finding.rule_id == id));
        }
    }
}
