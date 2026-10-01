use crate::collectors::{CollectContext, Collector};
use crate::utils::command::successful_stdout;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

pub struct DockerCollector;

#[async_trait]
impl Collector for DockerCollector {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.docker.enabled {
            return Ok(Vec::new());
        }

        let socket = ctx.resolve(Path::new("/var/run/docker.sock"));
        if !socket.exists() {
            return Ok(Vec::new());
        }

        let mut events = vec![
            RawEvent::new("docker", "docker_socket")
                .with_field("path", socket.to_string_lossy().to_string())
                .with_field("exists", "true"),
        ];

        // Alternate scan roots are used by tests/offline scans. Do not query the
        // host Docker daemon when the collected filesystem is not the live root.
        if ctx.scan_root.as_path() != Path::new("/") {
            return Ok(events);
        }

        let timeout = Duration::from_secs(ctx.config.docker.command_timeout_seconds);
        let Some(ids) = successful_stdout(
            &ctx.config.docker.docker_command,
            &["ps", "-q", "--no-trunc"],
            timeout,
        ) else {
            return Ok(events);
        };

        for id in ids
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .take(ctx.config.docker.inspect_max_containers)
        {
            let Some(output) = successful_stdout(
                &ctx.config.docker.docker_command,
                &["inspect", id],
                timeout,
            ) else {
                continue;
            };
            if let Some(event) = parse_container_inspect(&output) {
                events.push(event);
            }
        }

        Ok(events)
    }
}

fn parse_container_inspect(text: &str) -> Option<RawEvent> {
    let value: Value = serde_json::from_str(text).ok()?;
    let item = value.as_array()?.first()?;
    let null_host = Value::Null;
    let host = item.get("HostConfig").unwrap_or(&null_host);

    let container_id = item.get("Id").and_then(Value::as_str).unwrap_or_default();
    let name = item
        .get("Name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim_start_matches('/');
    let image = item
        .pointer("/Config/Image")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let privileged = host
        .get("Privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let network_mode = host
        .get("NetworkMode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let pid_mode = host
        .get("PidMode")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let cap_add = host
        .get("CapAdd")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

    let mut docker_socket_mount = false;
    let mut host_root_mount_rw = false;
    let mut mount_samples = Vec::new();
    if let Some(mounts) = item.get("Mounts").and_then(Value::as_array) {
        for mount in mounts {
            let source = mount.get("Source").and_then(Value::as_str).unwrap_or_default();
            let destination = mount
                .get("Destination")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let rw = mount.get("RW").and_then(Value::as_bool).unwrap_or(false);

            if source.ends_with("/docker.sock")
                || destination == "/var/run/docker.sock"
                || destination == "/run/docker.sock"
            {
                docker_socket_mount = true;
            }
            if source == "/" && rw {
                host_root_mount_rw = true;
            }
            if !source.is_empty() || !destination.is_empty() {
                mount_samples.push(format!("{source}:{destination}:rw={rw}"));
            }
        }
    }
    mount_samples.truncate(8);

    Some(
        RawEvent::new("docker", "docker_container")
            .with_field("container_id", container_id)
            .with_field("name", name)
            .with_field("image", image)
            .with_field("privileged", privileged.to_string())
            .with_field("network_mode", network_mode)
            .with_field("pid_mode", pid_mode)
            .with_field("cap_add", cap_add)
            .with_field("docker_socket_mount", docker_socket_mount.to_string())
            .with_field("host_root_mount_rw", host_root_mount_rw.to_string())
            .with_field("mount_samples", mount_samples.join("; ")),
    )
}

#[cfg(test)]
mod tests {
    use super::parse_container_inspect;

    #[test]
    fn parses_high_risk_container_settings() {
        let input = r#"[
          {
            "Id":"abc123",
            "Name":"/worker",
            "Config":{"Image":"example/worker:latest"},
            "HostConfig":{
              "Privileged":true,
              "NetworkMode":"host",
              "PidMode":"host",
              "CapAdd":["SYS_ADMIN","SYS_PTRACE"]
            },
            "Mounts":[
              {"Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true},
              {"Source":"/","Destination":"/host","RW":true}
            ]
          }
        ]"#;
        let event = parse_container_inspect(input).expect("container event");

        assert_eq!(event.kind, "docker_container");
        assert_eq!(event.field("name"), Some("worker"));
        assert_eq!(event.field("privileged"), Some("true"));
        assert_eq!(event.field("network_mode"), Some("host"));
        assert_eq!(event.field("pid_mode"), Some("host"));
        assert_eq!(event.field("docker_socket_mount"), Some("true"));
        assert_eq!(event.field("host_root_mount_rw"), Some("true"));
        assert!(event
            .field("cap_add")
            .is_some_and(|value| value.contains("SYS_ADMIN")));
    }
}
