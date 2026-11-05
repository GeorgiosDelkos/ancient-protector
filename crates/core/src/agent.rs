//! The coding agents a sweep can run, and how each is started headless.
//!
//! Every agent gets the same one-line prompt, pointing it at `PROMPT.md` in the bundle folder,
//! and runs with that folder as its working directory and the login shell's `PATH`.
//!
//! Sweeps run restricted (decided 2026-11-05), because untrusted text (advisory descriptions,
//! package names from cloned repositories) reaches the agent: they read the Mac, and write only
//! `findings.json` where the CLI can limit writes to one file (claude, grok, opencode). Codex and
//! gemini can write anywhere in the bundle, which is the app's own copy, and codex may run any
//! command its sandbox allows; the app trusts nothing in the bundle but its own files and
//! `findings.json`, which it validates. Fixes, which change the Mac after the user confirms them,
//! are a separate run with full access. The flags per CLI are in the spec's "Agent adapters"
//! table, with what was verified on this Mac.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;

use serde::Deserialize;
use serde::Serialize;

use crate::inventory::InventoryError;
use crate::inventory::command;

/// The one line every agent is given; the real instructions are in the bundle's `PROMPT.md`.
pub(crate) const PROMPT_LINE: &str =
    "Read PROMPT.md in the current directory and follow its instructions exactly.";

/// The shell commands a restricted sweep may run, where the CLI allows commands one by one
/// (Claude Code and opencode): listing commands that only read. Each names its command, never a
/// leading wildcard, since `* --version` would also match `rm -rf ~ --version`. `cargo tree` is
/// left out: it can write `Cargo.lock`, and it runs the `rustc` (or wrapper) a project's
/// `.cargo/config.toml` names, which in a cloned repository is that repository's code.
const READ_ONLY_COMMANDS: &[&str] = &["brew info *", "brew list *", "npm ls *", "npm view *"];

/// opencode's permissions for a sweep, passed in `OPENCODE_CONFIG_CONTENT`: everything denied
/// except reading, searching, editing `findings.json` and [`READ_ONLY_COMMANDS`]. Format:
/// <https://opencode.ai/docs/permissions/> (checked 2026-11-05). The last matching rule wins, so
/// each `"*": "deny"` comes first; the text is built in order rather than with a JSON map, which
/// would sort the keys.
fn opencode_sweep_config() -> String {
    let commands: Vec<String> = READ_ONLY_COMMANDS
        .iter()
        .map(|c| format!(r#", "{c}": "allow""#))
        .collect();
    format!(
        concat!(
            r#"{{"permission": {{"*": "deny", "read": "allow", "glob": "allow", "grep": "allow", "#,
            r#""list": "allow", "external_directory": "allow", "#,
            r#""edit": {{"*": "deny", "findings.json": "allow"}}, "bash": {{"*": "deny"{}}}, "#,
            r#""webfetch": "deny", "websearch": "deny"}}}}"#,
        ),
        commands.concat()
    )
}

/// Marks the lines of the login shell's answer, so nothing its startup files print is mistaken
/// for the answer.
const PATH_MARK: &str = "__ancient_protector_path__";
const BINARY_MARK: &str = "__ancient_protector_binary__";
const END_MARK: &str = "__ancient_protector_end__";

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

    /// Finds the agent's executable the way a login shell would (zsh reads `.zprofile`, not
    /// `.zshrc`), since an app started at login gets a `PATH` without `~/.local/bin`, nvm or
    /// Homebrew. Returns `None` when the shell cannot find it as a file (an alias or a shell
    /// function does not count).
    ///
    /// Runs `$SHELL -lc`, which reads the user's shell startup files.
    ///
    /// # Errors
    ///
    /// Fails when the shell itself cannot be run.
    pub(crate) fn locate(self) -> Result<Option<Located>, AgentError> {
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_owned());
        let script = format!(
            "printf '%s\\n' {PATH_MARK} \"$PATH\" {BINARY_MARK}; command -v {}; \
             printf '%s\\n' {END_MARK}",
            self.binary()
        );
        match command::run_any_status(&shell, &["-lc", &script]) {
            Ok(Some(output)) => Ok(parse_located(&output.stdout)),
            Ok(None) => Err(AgentError::NoShell { shell }),
            Err(source) => Err(AgentError::Locate {
                agent: self,
                source,
            }),
        }
    }

    /// Builds the restricted sweep command for `prompt`, run in `bundle`.
    fn sweep_command(self, located: &Located, bundle: &Path, prompt: &str) -> Command {
        let mut command = Command::new(&located.binary);
        command.current_dir(bundle).env("PATH", &located.path);
        let bundle = bundle.as_os_str();
        match self {
            Self::Claude => {
                command.args([
                    "-p",
                    prompt,
                    "--permission-mode",
                    "dontAsk",
                    "--allowedTools",
                ]);
                command.args(["Read(//**)", "Edit(./findings.json)"]);
                command.args(READ_ONLY_COMMANDS.iter().map(|c| format!("Bash({c})")));
            }
            Self::Grok => {
                // Grok's `dontAsk` mode allowed a shell command in a test on 2026-11-05, so
                // the shell is denied outright and Grok judges from the files.
                command.args(["-p", prompt, "--permission-mode", "default"]);
                command.args(["--allow", "Read(//**)", "--allow", "Edit(./findings.json)"]);
                command.args(["--deny", "Bash", "--cwd"]).arg(bundle);
            }
            Self::Codex => {
                command.args([
                    "exec",
                    "--sandbox",
                    "workspace-write",
                    "--skip-git-repo-check",
                ]);
                command.arg("-C").arg(bundle).arg(prompt);
            }
            Self::Gemini => {
                command.args(["-p", prompt, "--approval-mode", "auto_edit", "--skip-trust"]);
            }
            Self::Opencode => {
                command.env("OPENCODE_CONFIG_CONTENT", opencode_sweep_config());
                command.args(["run", "--dir"]).arg(bundle).arg(prompt);
            }
        }
        command
    }

    /// Runs a restricted sweep in `bundle` with `prompt`, writing the agent's stdout and stderr
    /// to `log`, and waits for it. Returns its exit status: what a failure means depends on
    /// whether it wrote `findings.json`, which is the caller's to check. There is no time limit:
    /// an agent sweep can take many minutes, and the user chose to let it run.
    ///
    /// # Errors
    ///
    /// Fails when the log cannot be created or the agent cannot start.
    pub(crate) fn run_sweep(
        self,
        located: &Located,
        bundle: &Path,
        prompt: &str,
        log: &Path,
    ) -> Result<ExitStatus, AgentError> {
        let log_err = |source| AgentError::Log {
            path: log.to_owned(),
            source,
        };
        let out = fs::File::create(log).map_err(log_err)?;
        let err = out.try_clone().map_err(log_err)?;
        self.sweep_command(located, bundle, prompt)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .status()
            .map_err(|source| AgentError::Start {
                agent: self,
                source,
            })
    }
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.binary())
    }
}

/// An agent found by the login shell, with the `PATH` it runs under.
#[derive(Debug)]
pub(crate) struct Located {
    /// The executable.
    binary: PathBuf,
    /// The login shell's `PATH`, so the agent (an npm script, say) and the tools it calls
    /// start as they do in the user's terminal.
    path: OsString,
}

/// Reads the marked lines of the login shell's answer: the `PATH`, then exactly one absolute
/// path to an executable regular file.
fn parse_located(stdout: &str) -> Option<Located> {
    let lines: Vec<&str> = stdout.lines().collect();
    let at = |mark: &str| lines.iter().position(|l| l.trim() == mark);
    let (path_at, binary_at, end_at) = (at(PATH_MARK)?, at(BINARY_MARK)?, at(END_MARK)?);
    if binary_at != path_at + 2 || end_at != binary_at + 2 {
        return None;
    }
    let binary = PathBuf::from(lines[binary_at + 1].trim());
    let executable =
        fs::metadata(&binary).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
    (binary.is_absolute() && executable).then(|| Located {
        binary,
        path: OsString::from(lines[path_at + 1]),
    })
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
    #[error("cannot look up {agent}")]
    Locate {
        /// The agent.
        agent: AgentKind,
        /// What went wrong.
        #[source]
        source: InventoryError,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [AgentKind; 5] = [
        AgentKind::Claude,
        AgentKind::Grok,
        AgentKind::Codex,
        AgentKind::Gemini,
        AgentKind::Opencode,
    ];

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn located(binary: &Path) -> Located {
        Located {
            binary: binary.to_owned(),
            path: OsString::from("/usr/bin:/bin"),
        }
    }

    /// The config name, the binary and the display name are the same word, so a user who
    /// writes `agent = "x"` knows the app runs `x`.
    #[test]
    fn config_name_is_binary_name() {
        for kind in ALL {
            let name = kind.binary();
            let parsed: AgentKind = toml::Value::String(name.into()).try_into().unwrap();
            assert_eq!(parsed, kind);
            assert_eq!(kind.to_string(), name);
        }
    }

    #[test]
    fn sweeps_use_the_restricted_flags() {
        let at = located(Path::new("/bin/x"));
        let args = |kind: AgentKind| -> Vec<String> {
            kind.sweep_command(&at, Path::new("/b"), "P")
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let mut claude: Vec<String> = [
            "-p",
            "P",
            "--permission-mode",
            "dontAsk",
            "--allowedTools",
            "Read(//**)",
            "Edit(./findings.json)",
        ]
        .map(str::to_owned)
        .into();
        claude.extend(
            ["brew info *", "brew list *", "npm ls *", "npm view *"].map(|c| format!("Bash({c})")),
        );
        assert_eq!(args(AgentKind::Claude), claude);
        assert_eq!(
            args(AgentKind::Grok),
            [
                "-p",
                "P",
                "--permission-mode",
                "default",
                "--allow",
                "Read(//**)",
                "--allow",
                "Edit(./findings.json)",
                "--deny",
                "Bash",
                "--cwd",
                "/b"
            ]
        );
        assert_eq!(
            args(AgentKind::Codex),
            [
                "exec",
                "--sandbox",
                "workspace-write",
                "--skip-git-repo-check",
                "-C",
                "/b",
                "P"
            ]
        );
        assert_eq!(
            args(AgentKind::Gemini),
            ["-p", "P", "--approval-mode", "auto_edit", "--skip-trust"]
        );
        assert_eq!(args(AgentKind::Opencode), ["run", "--dir", "/b", "P"]);

        for kind in ALL {
            let command = kind.sweep_command(&at, Path::new("/b"), "P");
            assert_eq!(command.get_current_dir(), Some(Path::new("/b")), "{kind}");
            let path = command
                .get_envs()
                .find(|(k, _)| *k == "PATH")
                .and_then(|(_, v)| v);
            assert_eq!(path, Some(std::ffi::OsStr::new("/usr/bin:/bin")), "{kind}");
            for arg in command.get_args() {
                let arg = arg.to_string_lossy();
                assert!(
                    !arg.contains("dangerously") && arg != "--yolo",
                    "{kind}: {arg}"
                );
            }
        }
        let opencode = AgentKind::Opencode.sweep_command(&at, Path::new("/b"), "P");
        let config = opencode
            .get_envs()
            .find(|(k, _)| *k == "OPENCODE_CONFIG_CONTENT")
            .and_then(|(_, v)| v)
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(&config.to_string_lossy()).unwrap();
        assert_eq!(config["permission"]["*"], "deny");
        assert_eq!(config["permission"]["edit"]["findings.json"], "allow");
        assert_eq!(config["permission"]["bash"]["*"], "deny");
        assert_eq!(config["permission"]["bash"]["npm ls *"], "allow");
        let text = config.to_string();
        assert!(
            !text.contains("cargo"),
            "cargo tree can run project code: {text}"
        );
        let raw = opencode_sweep_config();
        assert!(
            raw.find(r#""*": "deny""#) < raw.find("brew info"),
            "deny first: {raw}"
        );
    }

    #[test]
    fn reads_only_the_marked_answer() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = script(tmp.path(), "claude", "true");
        let answer = |binary: &str| {
            format!(
                "Welcome! /usr/bin/evil\n{PATH_MARK}\n/a:/b\n{BINARY_MARK}\n{binary}\n{END_MARK}\n\
                 /usr/bin/also-evil\n"
            )
        };
        let found = parse_located(&answer(agent.to_str().unwrap())).unwrap();
        assert_eq!(found.binary, agent);
        assert_eq!(found.path, OsString::from("/a:/b"));

        // An alias, a function, a missing file and a file that cannot run are not agents.
        assert!(parse_located(&answer("alias claude='rm -rf ~'")).is_none());
        assert!(parse_located(&answer("/nonexistent/claude")).is_none());
        let plain = tmp.path().join("plain");
        fs::write(&plain, "").unwrap();
        assert!(parse_located(&answer(plain.to_str().unwrap())).is_none());
        assert!(parse_located(&answer(tmp.path().to_str().unwrap())).is_none());
        // `command -v` printed nothing: the next mark follows at once.
        let none = format!("{PATH_MARK}\n/a\n{BINARY_MARK}\n{END_MARK}\n");
        assert!(parse_located(&none).is_none());
        assert!(parse_located("no marks at all").is_none());
        // Each mark must be exactly where it belongs, even around a real executable.
        let agent = agent.to_str().unwrap();
        let no_path = format!("{PATH_MARK}\n{BINARY_MARK}\n{agent}\n{END_MARK}\n");
        assert!(parse_located(&no_path).is_none());
        let extra = format!("{PATH_MARK}\n/a\n{BINARY_MARK}\n{agent}\nmore\n{END_MARK}\n");
        assert!(parse_located(&extra).is_none());
    }

    #[test]
    fn run_logs_output_and_reports_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let ok = script(
            tmp.path(),
            "ok",
            "pwd; echo \"PATH=$PATH\"; echo \"$@\"; echo oops >&2",
        );
        let log = tmp.path().join("agent.log");
        AgentKind::Gemini
            .run_sweep(&located(&ok), tmp.path(), "P", &log)
            .unwrap();
        let text = fs::read_to_string(&log).unwrap();
        let bundle = tmp.path().canonicalize().unwrap();
        assert!(text.contains(bundle.to_str().unwrap()), "{text}");
        assert!(text.contains("PATH=/usr/bin:/bin"), "{text}");
        assert!(text.contains("-p P --approval-mode auto_edit"), "{text}");
        assert!(text.contains("oops"), "{text}");

        let fail = script(tmp.path(), "fail", "exit 3");
        let status = AgentKind::Gemini
            .run_sweep(&located(&fail), tmp.path(), "P", &log)
            .unwrap();
        assert_eq!(status.code(), Some(3));

        let missing = tmp.path().join("missing");
        let err = AgentKind::Gemini
            .run_sweep(&located(&missing), tmp.path(), "P", &log)
            .unwrap_err();
        assert!(matches!(err, AgentError::Start { .. }), "{err:?}");
    }
}
