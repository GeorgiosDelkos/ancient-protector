//! End-to-end test of `inventory` with fake listing tools on `PATH`.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

/// Writes an executable shell script `name` into `dir`.
fn tool(dir: &Path, name: &str, script: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("the temp dir is writable");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("the script exists");
}

#[test]
fn collects_every_source() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    let project = tmp.path().join("src/app");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&project).unwrap();

    tool(&bin, "sw_vers", "echo 27.2");
    tool(
        &bin,
        "brew",
        r#"echo '{"formulae": [{"name": "openssl@3", "installed": [{"version": "3.4.0"}]}],
                 "casks": [{"token": "codex", "installed": "0.128.0"}]}'"#,
    );
    tool(
        &bin,
        "rustup",
        r#"if [ "$1" = toolchain ]; then echo "stable-aarch64-apple-darwin (default)";
           else echo "rustc 1.99.1 (abc 2026-10-13)"; fi"#,
    );
    tool(&bin, "cargo", r"printf 'ripgrep v14.1.0:\n    rg\n'");
    tool(&bin, "node", "echo v22.1.0");
    tool(
        &bin,
        "npm",
        r#"echo '{"dependencies": {"npm": {"version": "10.9.7"}}}'"#,
    );
    tool(&bin, "python3", "echo 'Python 3.13.1'");
    tool(&bin, "uv", r"printf 'ruff v0.6.9\n- ruff\n'");
    // `pipx` is deliberately missing: a tool that is not installed is skipped quietly.

    fs::write(
        project.join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    let data = tmp.path().join("data");
    fs::create_dir_all(&data).unwrap();
    let src = tmp.path().join("src");
    fs::write(
        data.join("config.toml"),
        format!("mac.project_dirs = [{:?}]\n", src.to_str().unwrap()),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_ancient-protector"))
        .arg("--data-dir")
        .arg(&data)
        .arg("inventory")
        .env("HOME", tmp.path())
        .env("PATH", &bin)
        .output()
        .expect("the test binary was built by cargo");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(stderr, "warning: not installed, so not checked: pipx\n");
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let summary: Vec<String> = lines
        .iter()
        .map(|c| {
            let lookup = c["lookup"]["product"].as_str().map_or_else(
                || {
                    let p = &c["lookup"]["package"];
                    format!(
                        "{}:{}",
                        p["ecosystem"].as_str().unwrap(),
                        p["name"].as_str().unwrap()
                    )
                },
                str::to_owned,
            );
            format!(
                "{} {lookup} {}",
                c["found_in"]["kind"].as_str().unwrap(),
                c["version"]
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            r#"mac_os apple:macos "27.2""#,
            r#"homebrew_formula openssl "3.4.0""#,
            r#"homebrew_cask codex "0.128.0""#,
            r#"rustup rust "1.99.1""#,
            r#"cargo_install crates.io:ripgrep "14.1.0""#,
            r#"node node.js "22.1.0""#,
            r#"npm_global npm:npm "10.9.7""#,
            r#"python python "3.13.1""#,
            r#"uv_tool PyPI:ruff "0.6.9""#,
            r#"lockfile crates.io:serde "1.0.229""#,
        ]
    );
    assert_eq!(
        lines[9]["found_in"]["path"],
        project.join("Cargo.lock").to_str().unwrap()
    );
}

#[test]
fn failing_tool_is_reported_and_the_rest_still_count() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    tool(&bin, "sw_vers", "echo 27.2");
    tool(&bin, "brew", "echo 'brew is broken' >&2; exit 1");
    let data = tmp.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("config.toml"), "").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_ancient-protector"))
        .arg("--data-dir")
        .arg(&data)
        .arg("inventory")
        .env("HOME", tmp.path())
        .env("PATH", &bin)
        .output()
        .expect("the test binary was built by cargo");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a failed source makes the list incomplete: {stderr}"
    );
    assert!(stderr.contains("1 inventory problem(s)"), "{stderr}");
    assert!(
        stderr.contains("not installed, so not checked: rustup, cargo"),
        "{stderr}"
    );
    assert!(
        stderr.contains("warning: `brew info --json=v2 --installed` failed"),
        "{stderr}"
    );
    assert!(stderr.contains("brew is broken"), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("apple:macos"), "{stdout}");
}

/// npm lists the whole global tree even when it exits 1 over a problem in it; the packages
/// count, the problem is noted, and it does not fail the command.
#[test]
fn npm_tree_problem_keeps_its_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    tool(
        &bin,
        "npm",
        r#"echo '{"dependencies": {"npm": {"version": "10.9.7"}}}'
           echo 'npm error code ELSPROBLEMS' >&2; exit 1"#,
    );
    let data = tmp.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("config.toml"), "").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_ancient-protector"))
        .arg("--data-dir")
        .arg(&data)
        .arg("inventory")
        .env("HOME", tmp.path())
        .env("PATH", &bin)
        .output()
        .expect("the test binary was built by cargo");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("reports a problem in the global packages"),
        "{stderr}"
    );
    assert!(stderr.contains("ELSPROBLEMS"), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#""name":"npm""#), "{stdout}");
}

/// Output npm cannot have meant as a tree is a parse error when npm succeeded, and npm's own
/// failure (with its stderr) when it did not.
#[test]
fn unreadable_npm_output_names_the_right_cause() {
    for (exit, expected) in [
        ("exit 0", "cannot parse npm ls -g --json"),
        ("exit 1", "`npm ls -g --json --depth=0` failed"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        tool(
            &bin,
            "npm",
            &format!("echo 'not json'; echo 'npm broke' >&2; {exit}"),
        );
        let data = tmp.path().join("data");
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("config.toml"), "").unwrap();

        let out = Command::new(env!("CARGO_BIN_EXE_ancient-protector"))
            .arg("--data-dir")
            .arg(&data)
            .arg("inventory")
            .env("HOME", tmp.path())
            .env("PATH", &bin)
            .output()
            .expect("the test binary was built by cargo");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{exit}: {stderr}");
        assert!(stderr.contains(expected), "{exit}: {stderr}");
    }
}
