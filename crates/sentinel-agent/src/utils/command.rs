use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status_success: bool,
    pub stdout: String,
}

pub fn command_output(program: &str, args: &[&str], timeout: Duration) -> Option<CommandOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Give collectors their own process group so a timeout also terminates
    // descendants that inherit the stdout pipe.
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().ok()?;

    let stdout = child.stdout.take();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut stdout) = stdout {
            let _ = stdout.read_to_end(&mut buffer);
        }
        let _ = sender.send(String::from_utf8_lossy(&buffer).to_string());
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Exiting the parent does not necessarily close stdout: a
                // background descendant can still hold it open. Apply the
                // same deadline to output collection instead of joining it.
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Ok(stdout) = receiver.recv_timeout(remaining) else {
                    terminate_command(&mut child);
                    return None;
                };
                return Some(CommandOutput {
                    status_success: status.success(),
                    stdout,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_command(&mut child);
                    return None;
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                terminate_command(&mut child);
                return None;
            }
        }
    }
}

fn terminate_command(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // SAFETY: process_group(0) created a group whose ID is this child's PID.
        // Signal only that collector group, including inherited-pipe holders.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub fn successful_stdout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    command_output(program, args, timeout)
        .filter(|output| output.status_success)
        .map(|output| output.stdout)
}

#[cfg(test)]
mod tests {
    use super::successful_stdout;
    use std::time::Duration;

    #[test]
    fn missing_command_returns_none() {
        assert!(successful_stdout(
            "vps-sentinel-command-that-does-not-exist",
            &[],
            Duration::from_millis(50),
        )
        .is_none());
    }
}
