use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::read_tail;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::collections::BTreeMap;

pub struct AuditLogCollector;

#[async_trait]
impl Collector for AuditLogCollector {
    fn name(&self) -> &'static str {
        "auditd"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.advanced_collectors.auditd_enabled {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for path in &ctx.config.advanced_collectors.audit_log_paths {
            let resolved = ctx.resolve(path);
            if !resolved.exists() {
                continue;
            }
            let text = read_tail(
                &resolved,
                ctx.config.advanced_collectors.audit_max_tail_bytes,
            )?;
            events.extend(parse_audit_log(&text, &path.to_string_lossy()));
        }
        Ok(events)
    }
}

pub fn parse_audit_log(text: &str, path: &str) -> Vec<RawEvent> {
    text.lines()
        .filter_map(|line| parse_audit_line(line, path))
        .collect()
}

fn parse_audit_line(line: &str, path: &str) -> Option<RawEvent> {
    let fields = parse_audit_fields(line);
    let record_type = fields.get("type")?.to_string();
    let kind = match record_type.as_str() {
        "EXECVE" => "audit_exec",
        "SYSCALL" => "audit_syscall",
        "PATH" => "audit_path",
        "USER_AUTH" | "USER_LOGIN" | "USER_ACCT" => "audit_auth",
        _ => return None,
    };
    let mut event = RawEvent::new("auditd", kind)
        .with_field("audit_record_type", record_type)
        .with_field("path", path)
        .with_field("raw", line);
    for key in [
        "msg", "pid", "ppid", "uid", "auid", "ses", "comm", "exe", "name", "addr", "terminal",
        "res", "success", "syscall",
    ] {
        if let Some(value) = fields.get(key).filter(|value| !value.is_empty()) {
            event.fields.insert(key.to_string(), value.clone());
        }
    }
    if kind == "audit_exec" {
        let argv = audit_argv(&fields);
        event.fields.insert("argv".to_string(), argv.clone());
        event.fields.insert("cmdline".to_string(), argv);
        event
            .fields
            .insert("ephemeral_event".to_string(), "true".to_string());
        event.fields.insert(
            "event_source_detail".to_string(),
            "audit_execve".to_string(),
        );
        if let Some(value) = fields.get("exe").filter(|value| !value.is_empty()) {
            event.fields.insert("exe_path".to_string(), value.clone());
        }
        if let Some(value) = fields.get("comm").filter(|value| !value.is_empty()) {
            event
                .fields
                .insert("process_name".to_string(), value.clone());
            event.fields.insert("name".to_string(), value.clone());
        }
    }
    Some(event)
}

fn parse_audit_fields(line: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let mut chars = line.chars().peekable();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
            chars.next();
        }
        let mut key = String::new();
        while chars
            .peek()
            .is_some_and(|ch| *ch != '=' && !ch.is_whitespace())
        {
            key.push(chars.next().expect("peeked character"));
        }
        if chars.next_if_eq(&'=').is_none() {
            continue;
        }
        let quote = chars.next_if(|ch| matches!(ch, '"' | '\''));
        let mut value = String::new();
        while let Some(ch) = chars.peek().copied() {
            if quote == Some(ch) {
                chars.next();
                break;
            }
            if quote.is_none() && ch.is_whitespace() {
                break;
            }
            chars.next();
            if quote.is_some() && ch == '\\' {
                if let Some(escaped) = chars.next() {
                    value.push(escaped);
                }
            } else {
                value.push(ch);
            }
        }
        // auditd hex-encodes unquoted string fields. Do not decode quoted
        // arguments (e.g. "dead") or numeric metadata such as uid/argc.
        let string_field = matches!(key.as_str(), "comm" | "exe" | "name")
            || key
                .strip_prefix('a')
                .is_some_and(|index| index.parse::<usize>().is_ok());
        if quote.is_none() && string_field {
            if let Some(decoded) = decode_audit_hex(&value) {
                value = decoded;
            }
        }
        fields.insert(key, value);
    }
    fields
}

fn audit_argv(fields: &BTreeMap<String, String>) -> String {
    let mut argv = fields
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix('a')
                .and_then(|index| index.parse::<usize>().ok())
                .map(|index| (index, value.clone()))
        })
        .collect::<Vec<_>>();
    argv.sort_by_key(|(index, _)| *index);
    argv.into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_audit_hex(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect::<Option<Vec<_>>>()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::parse_audit_log;

    #[test]
    fn parses_execve_record() {
        let text = r#"type=EXECVE msg=audit(1710000000.1:99): argc=3 a0="sh" a1="-c" a2="id" comm="sh" exe="/usr/bin/sh""#;
        let events = parse_audit_log(text, "/var/log/audit/audit.log");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "audit_exec");
        assert_eq!(events[0].field("argv"), Some("sh -c id"));
        assert_eq!(events[0].field("cmdline"), Some("sh -c id"));
        assert_eq!(events[0].field("exe"), Some("/usr/bin/sh"));
        assert_eq!(events[0].field("exe_path"), Some("/usr/bin/sh"));
        assert_eq!(events[0].field("process_name"), Some("sh"));
        assert_eq!(events[0].field("ephemeral_event"), Some("true"));
        assert_eq!(events[0].field("event_source_detail"), Some("audit_execve"));
    }

    #[test]
    fn preserves_quoted_spaces_and_decodes_unquoted_hex_arguments() {
        let text = r#"type=EXECVE msg=audit(1710000000.1:99): argc=4 a0="sh" a1="-c" a2=636174202F6574632F736861646F77 a3="dead" uid=1000 comm="shell with spaces""#;
        let event = &parse_audit_log(text, "/test/audit.log")[0];
        assert_eq!(event.field("argv"), Some("sh -c cat /etc/shadow dead"));
        assert_eq!(event.field("uid"), Some("1000"));
        assert_eq!(event.field("comm"), Some("shell with spaces"));
    }

    #[test]
    fn preserves_escaped_quotes_and_quoted_shell_commands() {
        let text = r#"type=EXECVE argc=3 a0="sh" a1="-c" a2="cat \"/etc/shadow\"""#;
        assert_eq!(
            parse_audit_log(text, "/test/audit.log")[0].field("argv"),
            Some("sh -c cat \"/etc/shadow\"")
        );
    }

    #[test]
    fn decodes_string_fields_without_decoding_numeric_metadata() {
        let text = r#"type=SYSCALL uid=1000 exe=2F7573722F62696E2F636174 comm="cat""#;
        let event = &parse_audit_log(text, "/test/audit.log")[0];
        assert_eq!(event.field("exe"), Some("/usr/bin/cat"));
        assert_eq!(event.field("uid"), Some("1000"));
    }
}
