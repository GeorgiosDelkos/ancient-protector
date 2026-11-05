//! The coding agents a sweep can run, and how each is started headless with full access.
//!
//! Every agent gets the same one-line prompt, pointing it at `PROMPT.md` in the bundle folder,
//! and runs with that folder as its working directory. The flags are in the spec's "Agent
//! adapters" table, checked against each CLI on 2026-11-05.

use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;

use serde::Deserialize;
use serde::Serialize;

use crate::inventory::command;

/// The one line every agent is given; the real instructions are in the bundle's `PROMPT.md`.
pub(crate) const PROMPT_LINE: &str =
    "Read PROMPT.md in the current directory and follow its instructions exactly.";

/// A coding-agent CLI that Ancient Protector can drive headless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentKind {
    /// Claude Code (`claude`).
    Claude,
    /// Grok CLI (`grok`).
    Grok,
    /// OpenAI Codex CLI (`codex`).
    Codex,
    /// Gemini CLI (`gemini`).
    Gemini,
    /// opencode (`opencode`).
    Opencode,
}

impl AgentKind {
    /// Every agent, in the order they are offered.
    pub const ALL: [Self; 5] = [
        Self::Claude,
        Self::Grok,
        Self::Codex,
        Self::Gemini,
        Self::Opencode,
    ];

    /// Returns the executable name looked up on `PATH`.
    pub fn binary(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Grok => "grok",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Opencode => "opencode",
        }
    }

    /// Finds the agent's executable the way the user's terminal would: through the login
    /// shell, since an app started at login gets a `PATH` without `~/.local/bin`, nvm or
    /// Homebrew. Returns `None` when the shell cannot find it.
    ///
    /// Runs `$SHELL -lc 'command -v <binary>'`, which reads the user's shell startup files.
    ///
    /// # Errors
    ///
    /// Fails when the shell itself cannot be run.
    pub fn locate(self) -> Result<Option<PathBuf>, AgentError> {
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_owned());
        let script = format!("command -v {}", self.binary());
        match command::run_any_status(&shell, &["-lc", &script]) {
            Ok(Some(output)) => Ok(output
                .success
                .then(|| first_absolute_path(&output.stdout))
                .flatten()),
            Ok(None) => Err(AgentError::NoShell { shell }),
            Err(e) => Err(AgentError::Locate {
                agent: self,
                detail: e.to_string(),
            }),
        }
    }

    /// Builds the headless, full-access command for `prompt`, run in `bundle`.
    fn command(self, binary: &Path, bundle: &Path, prompt: &str) -> Command {
        let mut command = Command::new(binary);
        command.current_dir(bundle);
        let bundle = bundle.as_os_str();
        match self {
            Self::Claude => {
                command.args(["-p", prompt, "--dangerously-skip-permissions"]);
            }
            Self::Grok => {
                command.args(["-p", prompt, "--always-approve", "--cwd"]);
                command.arg(bundle);
            }
            Self::Codex => {
                command.args(["exec", "--dangerously-bypass-approvals-and-sandbox"]);
                command.args(["--skip-git-repo-check", "-C"]);
                command.arg(bundle).arg(prompt);
            }
            Self::Gemini => {
                command.args(["-p", prompt, "--yolo"]);
            }
            Self::Opencode => {
                command.args(["run", "--dangerously-skip-permissions", "--dir"]);
                command.arg(bundle).arg(prompt);
            }
        }
        command
    }

    /// Runs the agent in `bundle` with `prompt`, writing its stdout and stderr to `log`, and
    /// waits for it to finish. There is no time limit: an agent sweep can take many minutes,
    /// and the user chose to let it run.
    ///
    /// # Errors
    ///
    /// Fails when the log cannot be created, the agent cannot start, or it exits non-zero.
    pub(crate) fn run(
        self,
        binary: &Path,
        bundle: &Path,
        prompt: &str,
        log: &Path,
    ) -> Result<(), AgentError> {
        let log_err = |source| AgentError::Log {
            path: log.to_owned(),
            source,
        };
        let out = fs::File::create(log).map_err(log_err)?;
        let err = out.try_clone().map_err(log_err)?;
        let status = self
            .command(binary, bundle, prompt)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .status()
            .map_err(|source| AgentError::Start {
                agent: self,
                source,
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(AgentError::Exit {
                agent: self,
                status,
                log: log.to_owned(),
            })
        }
    }
}

/// `command -v` prints the path, but a login shell's startup files may print other lines
/// first, so the last line that is an absolute path wins.
fn first_absolute_path(stdout: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with('/'))
        .map(PathBuf::from)
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.binary())
    }
}

/// Error from finding or running an agent.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The user's login shell could not be found.
    #[error("cannot find the login shell {shell}; set SHELL")]
    NoShell {
        /// The shell tried.
        shell: String,
    },
    /// The login shell failed while looking the agent up.
    #[error("cannot look up {agent}: {detail}")]
    Locate {
        /// The agent.
        agent: AgentKind,
        /// What went wrong.
        detail: String,
    },
    /// The agent's log file could not be created.
    #[error("cannot write the agent log {}", path.display())]
    Log {
        /// The log path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The agent could not be started.
    #[error("cannot start {agent}")]
    Start {
        /// The agent.
        agent: AgentKind,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The agent exited with an error, often because it is not logged in.
    #[error("{agent} exited with {status}; see {} (is it logged in?)", log.display())]
    Exit {
        /// The agent.
        agent: AgentKind,
        /// Its exit status.
        status: ExitStatus,
        /// Its log.
        log: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// The config name, the binary and the display name are the same word, so a user who
    /// writes `agent = "x"` knows the app runs `x`.
    #[test]
    fn config_name_is_binary_name() {
        for kind in AgentKind::ALL {
            let name = kind.binary();
            let parsed: AgentKind = toml::Value::String(name.into()).try_into().unwrap();
            assert_eq!(parsed, kind);
            assert_eq!(kind.to_string(), name);
        }
    }

    #[test]
    fn commands_use_the_documented_flags() {
        let args = |kind: AgentKind| -> Vec<String> {
            kind.command(Path::new("/bin/x"), Path::new("/b"), "P")
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(
            args(AgentKind::Claude),
            ["-p", "P", "--dangerously-skip-permissions"]
        );
        assert_eq!(
            args(AgentKind::Grok),
            ["-p", "P", "--always-approve", "--cwd", "/b"]
        );
        assert_eq!(
            args(AgentKind::Codex),
            [
                "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "--skip-git-repo-check",
                "-C",
                "/b",
                "P"
            ]
        );
        assert_eq!(args(AgentKind::Gemini), ["-p", "P", "--yolo"]);
        assert_eq!(
            args(AgentKind::Opencode),
            ["run", "--dangerously-skip-permissions", "--dir", "/b", "P"]
        );
        for kind in AgentKind::ALL {
            let command = kind.command(Path::new("/bin/x"), Path::new("/b"), "P");
            assert_eq!(command.get_current_dir(), Some(Path::new("/b")), "{kind}");
        }
    }

    #[test]
    fn last_absolute_line_is_the_path() {
        assert_eq!(
            first_absolute_path("Welcome!\n/Users/me/.local/bin/claude\n"),
            Some(PathBuf::from("/Users/me/.local/bin/claude"))
        );
        assert_eq!(first_absolute_path("claude: aliased to x\n"), None);
        assert_eq!(first_absolute_path(""), None);
    }

    #[test]
    fn locates_through_the_login_shell() {
        // `sh` is always on a login shell's PATH; a made-up name never is.
        let found = AgentKind::Claude.locate();
        assert!(found.is_ok(), "{found:?}");
    }

    #[test]
    fn run_logs_output_and_reports_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            let path = tmp.path().join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let ok = script("ok", "pwd; echo \"$@\"; echo oops >&2");
        let log = tmp.path().join("agent.log");
        AgentKind::Gemini.run(&ok, tmp.path(), "P", &log).unwrap();
        let text = fs::read_to_string(&log).unwrap();
        let bundle = tmp.path().canonicalize().unwrap();
        assert!(text.contains(bundle.to_str().unwrap()), "{text}");
        assert!(text.contains("-p P --yolo"), "{text}");
        assert!(text.contains("oops"), "{text}");

        let fail = script("fail", "exit 3");
        let err = AgentKind::Gemini
            .run(&fail, tmp.path(), "P", &log)
            .unwrap_err();
        assert!(matches!(err, AgentError::Exit { .. }), "{err:?}");
        assert!(err.to_string().contains("logged in"), "{err}");

        let missing = tmp.path().join("missing");
        let err = AgentKind::Gemini
            .run(&missing, tmp.path(), "P", &log)
            .unwrap_err();
        assert!(matches!(err, AgentError::Start { .. }), "{err:?}");
    }
}
