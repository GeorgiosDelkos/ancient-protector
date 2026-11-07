//! End-to-end tests of `advisories` that need no network: every request goes to a dead proxy.

use std::fs;
use std::process::Command;

/// With every source unreachable, nothing is printed, each failure is reported, and the exit
/// status says the output is incomplete.
#[test]
fn reports_every_failed_source() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("config.toml"), "").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .arg("--data-dir")
        .arg(tmp.path())
        .args(["advisories", "--package", "npm:lodash", "--product", "zlib"])
        .env("HOME", tmp.path())
        // Port 1 on loopback refuses connections, so every request fails at once.
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("the test binary was built by cargo");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(stderr.contains("warning: CISA KEV catalog"), "{stderr}");
    assert!(stderr.contains("warning: OSV:"), "{stderr}");
    assert!(stderr.contains("warning: NVD product zlib"), "{stderr}");
    assert!(stderr.contains("3 feed request(s) failed"), "{stderr}");
}
