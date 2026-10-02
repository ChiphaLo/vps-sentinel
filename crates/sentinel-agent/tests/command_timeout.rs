#![cfg(unix)]

use sentinel_agent::utils::command::command_output;
use std::time::{Duration, Instant};

#[test]
fn timeout_includes_descendants_holding_stdout_open() {
    let started = Instant::now();
    let output = command_output("sh", &["-c", "sleep 2 & wait"], Duration::from_millis(100));
    assert!(output.is_none());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn exited_parent_with_inherited_stdout_obeys_deadline() {
    let started = Instant::now();
    let output = command_output(
        "sh",
        &["-c", "sleep 2 & printf done"],
        Duration::from_millis(100),
    );
    assert!(output.is_none());
    assert!(started.elapsed() < Duration::from_secs(1));
}
