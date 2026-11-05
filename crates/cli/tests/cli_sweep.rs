//! End-to-end tests of `sweep` with a fake agent, a fake login shell and no network.
//!
//! Every feed request goes to a dead proxy, so the bundle holds the inventory and no
//! advisories, and the only valid verdict is `{"findings": []}`. The fake agent's behaviour is
//! chosen by `FAKE_AGENT_MODE`; it counts its runs in `FAKE_AGENT_COUNTER`.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

const FAKE_AGENT: &str = r#"#!/bin/sh
echo "path: $PATH"
# The login shell's PATH is made up; this script needs cat.
PATH=/usr/bin:/bin
n=$(cat "$FAKE_AGENT_COUNTER" 2>/dev/null || echo 0)
n=$((n + 1))
echo $n > "$FAKE_AGENT_COUNTER"
test -f PROMPT.md || { echo "no PROMPT.md in $(pwd)" >&2; exit 9; }
echo "args: $*"
case "$FAKE_AGENT_MODE:$n" in
  ok:*) echo '{"findings": []}' > findings.json ;;
  retry:1) echo '{"findings": [], "bogus": 1}' > findings.json ;;
  retry:*) echo '{"findings": []}' > findings.json ;;
  bad:*) echo 'not json' > findings.json ;;
  silent:*) ;;
  crash:*) exit 3 ;;
  late-crash:*) echo '{"findings": []}' > findings.json; exit 3 ;;
esac
"#;

struct Sandbox {
    root: tempfile::TempDir,
}

impl Sandbox {
    /// A home with `bin/sw_vers`, a fake `claude`, and a fake login shell that finds it.
    fn new(config: &str) -> Self {
        let root = tempfile::tempdir().expect("a temp dir can be created");
        let sandbox = Self { root };
        fs::create_dir_all(sandbox.bin()).expect("the temp dir is writable");
        sandbox.script("bin/sw_vers", "#!/bin/sh\necho 27.2\n");
        sandbox.script("agents/claude", FAKE_AGENT);
        let claude = sandbox.path().join("agents/claude");
        sandbox.script(
            "login-shell",
            &format!(
                "#!/bin/sh\n# Called as: login-shell -lc '<script that runs command -v <agent>>'\n\
                 printf '%s\\n' __ancient_protector_path__ /login/bin:/usr/bin \
                 __ancient_protector_binary__\n\
                 case \"$2\" in *'command -v claude;'*) echo {} ;; esac\n\
                 echo __ancient_protector_end__\n",
                claude.display()
            ),
        );
        let data = sandbox.path().join("data");
        fs::create_dir_all(&data).expect("the temp dir is writable");
        fs::write(data.join("config.toml"), config).expect("the temp dir is writable");
        sandbox
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    fn script(&self, rel: &str, body: &str) {
        let path = self.path().join(rel);
        fs::create_dir_all(path.parent().expect("a relative path has a parent"))
            .expect("the temp dir is writable");
        fs::write(&path, body).expect("the temp dir is writable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("the script exists");
    }

    fn sweep(&self, mode: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ancient-protector"))
            .arg("--data-dir")
            .arg(self.path().join("data"))
            .arg("sweep")
            .env("HOME", self.path())
            .env("PATH", self.bin())
            .env("SHELL", self.path().join("login-shell"))
            .env("FAKE_AGENT_MODE", mode)
            .env("FAKE_AGENT_COUNTER", self.path().join("counter"))
            // Port 1 on loopback refuses connections, so every feed request fails at once.
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .expect("the test binary was built by cargo")
    }

    fn runs(&self) -> String {
        fs::read_to_string(self.path().join("counter")).unwrap_or_default()
    }

    /// The single sweep folder's `mac` target.
    fn sweep_dir(&self) -> PathBuf {
        let sweeps = self.path().join("data/sweeps");
        let mut dirs: Vec<_> = fs::read_dir(&sweeps)
            .expect("a sweep wrote its folder")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        assert_eq!(dirs.len(), 1, "{dirs:?}");
        dirs.remove(0).join("mac")
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn clean_sweep_writes_bundle_and_report() {
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("ok");
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("listing what is installed"), "{stderr}");
    assert!(
        stderr.contains("claude is judging the advisories"),
        "{stderr}"
    );
    assert!(stderr.contains("NVD 1/1: apple:macos"), "{stderr}");
    // The feeds are unreachable, so the verdict says it covers only what was checked.
    assert!(
        stdout.contains("No affected component among what was checked"),
        "{stdout}"
    );
    assert!(stdout.contains("## Not checked"), "{stdout}");
    assert!(stdout.contains("NVD product apple:macos"), "{stdout}");
    assert!(stdout.contains("CISA KEV catalog"), "{stdout}");
    assert!(
        stdout.contains("not installed, so not checked: brew"),
        "{stdout}"
    );
    assert_eq!(sandbox.runs().trim(), "1");

    let dir = sandbox.sweep_dir();
    for file in [
        "bundle/PROMPT.md",
        "bundle/inventory.jsonl",
        "bundle/advisories.jsonl",
        "bundle/findings.schema.json",
        "bundle/findings.json",
        "agent-1.log",
        "report.json",
        "report.md",
    ] {
        assert!(dir.join(file).exists(), "{file}");
    }
    let prompt = fs::read_to_string(dir.join("bundle/PROMPT.md")).unwrap();
    assert!(
        prompt.starts_with("# Vulnerability sweep: this Mac (macOS 27.2)"),
        "{prompt}"
    );
    let log = fs::read_to_string(dir.join("agent-1.log")).unwrap();
    assert!(
        log.contains("--permission-mode dontAsk"),
        "restricted: {log}"
    );
    assert!(!log.contains("dangerously"), "{log}");
    assert!(
        log.contains("path: /login/bin:/usr/bin"),
        "the login shell's PATH: {log}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["agent"], "claude");
    assert_eq!(report["components"], 1);
    assert!(report["failure"].is_null());

    // The prompt template is now the user's to edit.
    let template = sandbox.path().join("data/prompts/sweep.md");
    assert!(fs::read_to_string(template).unwrap().contains("{{target}}"));
}

#[test]
fn agent_exit_codes_decide_only_without_a_valid_file() {
    // Valid findings count even when the agent exits non-zero after writing them.
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("late-crash");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(sandbox.runs().trim(), "1");

    // Without a file, a failing agent would fail again, so it is not retried.
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("crash");
    let stderr = text(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("claude exited with"), "{stderr}");
    assert!(stderr.contains("agent-1.log"), "{stderr}");
    assert_eq!(sandbox.runs().trim(), "1");
}

#[test]
fn rejected_findings_are_retried_once_with_the_problems() {
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("retry");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("fixing its rejected findings"));
    assert_eq!(sandbox.runs().trim(), "2");
    let dir = sandbox.sweep_dir();
    let log = fs::read_to_string(dir.join("agent-2.log")).unwrap();
    assert!(log.contains("was rejected"), "{log}");
    assert!(log.contains("unknown field"), "{log}");
    let rejected = fs::read_to_string(dir.join("bundle/findings.rejected.json")).unwrap();
    assert!(
        rejected.contains("bogus"),
        "the first answer is kept: {rejected}"
    );
}

#[test]
fn twice_rejected_findings_fail_the_sweep_but_keep_the_report() {
    for mode in ["bad", "silent"] {
        let sandbox = Sandbox::new("agent = \"claude\"\n");
        let out = sandbox.sweep(mode);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert!(!out.status.success(), "{mode}: {stderr}");
        assert!(stderr.contains("sweep incomplete"), "{mode}: {stderr}");
        assert!(stdout.contains("**No verdict:**"), "{mode}: {stdout}");
        assert!(
            !stdout.contains("No installed component is affected"),
            "{mode}: {stdout}"
        );
        assert_eq!(sandbox.runs().trim(), "2", "{mode}");
        assert!(sandbox.sweep_dir().join("report.json").exists(), "{mode}");
    }
}

#[test]
fn missing_or_unset_agent_stops_before_sweeping() {
    let sandbox = Sandbox::new("");
    let out = sandbox.sweep("ok");
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("no agent chosen"),
        "{}",
        text(&out.stderr)
    );

    let sandbox = Sandbox::new("agent = \"gemini\"\n");
    let out = sandbox.sweep("ok");
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("gemini is not installed"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        !sandbox.path().join("data/sweeps").exists(),
        "nothing was swept"
    );
}
