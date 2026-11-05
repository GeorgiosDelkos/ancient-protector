//! Runs a listing command and returns its stdout.

use std::io;
use std::process::Command;

use crate::inventory::InventoryError;

/// How much of a failing command's stderr goes into the error, in characters. Arbitrary.
const STDERR_LIMIT: usize = 300;

/// Runs `program` with `args` and returns stdout, or `None` when the program is not
/// installed.
pub(crate) fn run(program: &str, args: &[&str]) -> Result<Option<String>, InventoryError> {
    let command = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let output = match Command::new(program).args(args).output() {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(InventoryError::Command {
                command,
                detail: e.to_string(),
            });
        }
    };
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(STDERR_LIMIT)
            .collect();
        return Err(InventoryError::Command {
            command,
            detail: format!("{}: {}", output.status, stderr.trim()),
        });
    }
    String::from_utf8(output.stdout)
        .map(Some)
        .map_err(|e| InventoryError::parse(command, &e))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A program that exists but cannot run is an error, not "not installed".
    #[test]
    fn unrunnable_program_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tool");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        let program = path.to_str().unwrap();
        let err = run(program, &[]).unwrap_err();
        assert!(matches!(err, InventoryError::Command { .. }), "{err:?}");
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
    fn non_utf8_output_is_a_parse_error() {
        let err = run("printf", &["\\377"]).unwrap_err();
        assert!(matches!(err, InventoryError::Parse { .. }), "{err:?}");
    }
}
