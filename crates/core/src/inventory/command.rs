//! Runs a listing command and returns its stdout.
//!
//! Commands run from `/` with stdin closed and a time limit. From `/`, no project file in
//! the caller's folder (`rust-toolchain.toml`, `.nvmrc`, `.python-version`) changes which tool
//! version answers, and rustup cannot decide to install a toolchain a project pins. Closed
//! stdin and the time limit keep a tool that prompts or hangs from stopping the sweep.

use std::env;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::inventory::InventoryError;

/// How much of a failing command's stderr goes into the error, in characters. Arbitrary.
const STDERR_LIMIT: usize = 300;

/// How long one listing command may run. Arbitrary: `brew info --installed` takes a few
/// seconds with a hundred formulae; a minute means the tool is stuck.
const TIMEOUT: Duration = Duration::from_secs(60);

/// How often a running command is checked for having exited. Arbitrary; short enough that
/// fast commands return promptly.
const POLL: Duration = Duration::from_millis(20);

/// A command that ran to completion.
#[derive(Debug)]
pub(crate) struct Output {
    /// Whether it exited with status 0.
    pub(crate) success: bool,
    pub(crate) stdout: String,
    /// The exit status and the start of stderr, for an error message.
    pub(crate) detail: String,
}

/// Runs `program` and returns stdout, or `None` when it is not installed. A non-zero exit is
/// an error.
pub(crate) fn run(program: &str, args: &[&str]) -> Result<Option<String>, InventoryError> {
    let Some(output) = run_any_status(program, args)? else {
        return Ok(None);
    };
    if output.success {
        Ok(Some(output.stdout))
    } else {
        Err(InventoryError::Command {
            command: command_line(program, args),
            detail: output.detail,
        })
    }
}

/// Runs `program` and returns its output whatever the exit status, or `None` when it is not
/// installed. For tools that print a complete answer and still exit non-zero.
pub(crate) fn run_any_status(
    program: &str,
    args: &[&str],
) -> Result<Option<Output>, InventoryError> {
    run_within(program, args, TIMEOUT)
}

fn run_within(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Option<Output>, InventoryError> {
    let command = command_line(program, args);
    let child = Command::new(program)
        .args(args)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let child = match child {
        Ok(child) => child,
        // A script whose interpreter is gone also fails with NotFound; only a program that is
        // nowhere on PATH is "not installed".
        Err(e) if e.kind() == io::ErrorKind::NotFound && !on_path(program) => return Ok(None),
        Err(source) => return Err(InventoryError::Spawn { command, source }),
    };
    let (status, stdout, stderr) = wait(child, &command, timeout)?;

    let stdout = String::from_utf8(stdout).map_err(|e| InventoryError::parse(&command, &e))?;
    let stderr: String = String::from_utf8_lossy(&stderr)
        .chars()
        .take(STDERR_LIMIT)
        .collect();
    Ok(Some(Output {
        success: status.success(),
        stdout,
        detail: format!("{status}: {}", stderr.trim()),
    }))
}

/// Waits for `child` up to `timeout`, reading stdout and stderr on their own threads so a
/// full pipe cannot stall it, and kills it if it runs too long.
fn wait(
    mut child: Child,
    command: &str,
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), InventoryError> {
    fn reader(pipe: Option<impl io::Read + Send + 'static>) -> thread::JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                // A read error keeps what was read; the exit status still reports a failure.
                drop(pipe.read_to_end(&mut bytes));
            }
            bytes
        })
    }
    let stdout = reader(child.stdout.take());
    let stderr = reader(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let status = loop {
        let polled = child.try_wait().map_err(|source| InventoryError::Spawn {
            command: command.to_owned(),
            source,
        })?;
        if let Some(status) = polled {
            break status;
        }
        if Instant::now() >= deadline {
            // The command is abandoned either way, and a failed kill means it already exited.
            // The reader threads end when the pipes close; nothing waits for them.
            drop(child.kill());
            drop(child.wait());
            return Err(InventoryError::Command {
                command: command.to_owned(),
                detail: format!("still running after {timeout:?}; stopped"),
            });
        }
        thread::sleep(POLL);
    };
    let stdout = stdout.join().expect("the stdout reader does not panic");
    let stderr = stderr.join().expect("the stderr reader does not panic");
    Ok((status, stdout, stderr))
}

/// Returns the file `program` runs: itself if it names a path, else the first match on `PATH`.
pub(crate) fn which(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        return Path::new(program).exists().then(|| PathBuf::from(program));
    }
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.exists())
}

fn on_path(program: &str) -> bool {
    which(program).is_some()
}

fn command_line(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn script(dir: &Path, body: &str) -> String {
        let path = dir.join("tool");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    #[test]
    fn returns_stdout() {
        assert_eq!(run("echo", &["a", "b"]).unwrap().as_deref(), Some("a b\n"));
    }

    #[test]
    fn missing_program_is_none() {
        assert!(
            run("ancient-protector-no-such-tool", &[])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn runs_from_root_with_stdin_closed() {
        assert_eq!(run("pwd", &[]).unwrap().as_deref(), Some("/\n"));
        assert_eq!(run("cat", &[]).unwrap().as_deref(), Some(""));
    }

    #[test]
    fn failure_names_the_command_and_stderr() {
        let err = run("sh", &["-c", "echo boom >&2; exit 3"]).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("`sh -c echo boom >&2; exit 3` failed"),
            "{message}"
        );
        assert!(message.contains("boom"), "{message}");
    }

    #[test]
    fn any_status_keeps_stdout_of_a_failure() {
        let output = run_any_status("sh", &["-c", "echo '{}'; echo bad >&2; exit 1"])
            .unwrap()
            .unwrap();
        assert!(!output.success);
        assert_eq!(output.stdout, "{}\n");
        assert!(output.detail.contains("bad"), "{}", output.detail);
    }

    #[test]
    fn hung_command_is_stopped() {
        let started = Instant::now();
        let err = run_within("sleep", &["30"], Duration::from_millis(200)).unwrap_err();
        assert!(err.to_string().contains("still running"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn non_utf8_output_is_a_parse_error() {
        let err = run("printf", &["\\377"]).unwrap_err();
        assert!(matches!(err, InventoryError::Parse { .. }), "{err:?}");
    }

    /// A program that exists but cannot run is an error, not "not installed".
    #[test]
    fn unrunnable_program_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tool");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        let err = run(path.to_str().unwrap(), &[]).unwrap_err();
        assert!(matches!(err, InventoryError::Spawn { .. }), "{err:?}");
    }

    /// A script whose interpreter was removed fails with `NotFound`, but it is installed.
    #[test]
    fn broken_shebang_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let program = script(tmp.path(), "#!/nonexistent/python3\n");
        let err = run(&program, &[]).unwrap_err();
        assert!(matches!(err, InventoryError::Spawn { .. }), "{err:?}");
    }

    #[test]
    fn on_path_finds_programs() {
        assert!(on_path("sh"));
        assert!(on_path("/bin/sh"));
        assert!(!on_path("ancient-protector-no-such-tool"));
        assert!(!on_path("/nonexistent/tool"));
    }
}
