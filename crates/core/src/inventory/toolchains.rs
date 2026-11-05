//! macOS itself and globally installed toolchains: rustup, `cargo install`, Node.js and
//! global npm packages, Python, and uv and pipx tools.
//!
//! Each parser is a plain function over the command's output, so the formats are tested
//! without the tools installed.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::inventory::command;
use crate::package::Ecosystem;
use crate::package::Package;

pub(super) fn macos(inventory: &mut Inventory) {
    let Some(output) = run(inventory, "sw_vers", &["-productVersion"]) else {
        return;
    };
    let version = output.trim();
    if version.is_empty() {
        inventory.problems.push(InventoryError::parse(
            "sw_vers -productVersion",
            &"empty output",
        ));
    } else {
        inventory.add(product("apple:macos"), version, FoundIn::MacOs);
    }
}

pub(super) fn collect(inventory: &mut Inventory) {
    rustup(inventory);
    if let Some(output) = run(inventory, "cargo", &["install", "--list"]) {
        let found = parse_cargo_install(&output);
        inventory.components.extend(found);
    }
    if let Some(output) = run(inventory, "node", &["--version"]) {
        let version = output.trim().trim_start_matches('v').to_owned();
        inventory.add(product("node.js"), version, FoundIn::Node);
    }
    if let Some(output) = run(inventory, "npm", &["ls", "-g", "--json", "--depth=0"]) {
        let found = parse_npm_global(&output);
        inventory.absorb(found);
    }
    if let Some(output) = run(inventory, "python3", &["--version"]) {
        let found = parse_python_version(&output);
        inventory.absorb(found);
    }
    if let Some(output) = run(inventory, "uv", &["tool", "list"]) {
        let found = parse_uv_tools(&output);
        inventory.components.extend(found);
    }
    if let Some(output) = run(inventory, "pipx", &["list", "--json"]) {
        let found = parse_pipx(&output);
        inventory.absorb(found);
    }
}

/// Runs a listing command, recording a failure as a problem. `None` when the tool is not
/// installed or failed.
fn run(inventory: &mut Inventory, program: &str, args: &[&str]) -> Option<String> {
    match command::run(program, args) {
        Ok(output) => output,
        Err(e) => {
            inventory.problems.push(e);
            None
        }
    }
}

fn product(name: &str) -> Lookup {
    Lookup::Product(name.parse().expect("built-in product names are valid"))
}

fn package(ecosystem: Ecosystem, name: &str) -> Lookup {
    Lookup::Package(Package {
        ecosystem,
        name: name.to_owned(),
    })
}

/// Each toolchain's version comes from its `rustc`, since `stable` and `nightly` name no
/// version.
fn rustup(inventory: &mut Inventory) {
    let Some(list) = run(inventory, "rustup", &["toolchain", "list"]) else {
        return;
    };
    for toolchain in parse_rustup_toolchains(&list) {
        let args = ["run", toolchain.as_str(), "rustc", "--version"];
        let Some(output) = run(inventory, "rustup", &args) else {
            continue;
        };
        match parse_rustc_version(&output) {
            Some(version) => {
                inventory.add(product("rust"), version, FoundIn::Rustup { toolchain });
            }
            None => inventory
                .problems
                .push(InventoryError::parse("rustc --version", &output.trim())),
        }
    }
}

/// `rustup toolchain list` prints one name per line, with ` (default)` or ` (active)` after.
fn parse_rustup_toolchains(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "no" && !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `rustc 1.99.1 (58cf8f9c3 2026-10-13)` -> `1.99.1`; nightly prints `1.100.0-nightly`.
fn parse_rustc_version(output: &str) -> Option<String> {
    let mut words = output.split_whitespace();
    (words.next() == Some("rustc")).then(|| words.next().map(str::to_owned))?
}

/// `cargo install --list` prints `name v1.2.3:` (or `name v1.2.3 (/path):` for a local path
/// install, which has no registry advisories) followed by indented binary names.
fn parse_cargo_install(output: &str) -> Vec<crate::inventory::Component> {
    output
        .lines()
        .filter(|line| !line.starts_with(char::is_whitespace))
        .filter_map(|line| {
            let line = line.strip_suffix(':')?;
            let mut words = line.split_whitespace();
            let name = words.next()?;
            let version = words.next()?.strip_prefix('v')?;
            if words.next().is_some() {
                return None;
            }
            Some(crate::inventory::Component {
                lookup: package(Ecosystem::CratesIo, name),
                version: version.to_owned(),
                found_in: FoundIn::CargoInstall,
            })
        })
        .collect()
}

fn parse_npm_global(json: &str) -> Result<Vec<crate::inventory::Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct Tree {
        #[serde(default)]
        dependencies: BTreeMap<String, Dependency>,
    }
    #[derive(Debug, Deserialize)]
    struct Dependency {
        version: Option<String>,
    }

    let tree: Tree =
        serde_json::from_str(json).map_err(|e| InventoryError::parse("npm ls -g --json", &e))?;
    Ok(tree
        .dependencies
        .into_iter()
        .filter_map(|(name, dependency)| {
            Some(crate::inventory::Component {
                lookup: package(Ecosystem::Npm, &name),
                version: dependency.version?,
                found_in: FoundIn::NpmGlobal,
            })
        })
        .collect())
}

/// `Python 3.13.1` -> `3.13.1`.
fn parse_python_version(output: &str) -> Result<Vec<crate::inventory::Component>, InventoryError> {
    let version = output
        .trim()
        .strip_prefix("Python ")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| InventoryError::parse("python3 --version", &output.trim()))?;
    Ok(vec![crate::inventory::Component {
        lookup: product("python"),
        version: version.to_owned(),
        found_in: FoundIn::Python,
    }])
}

/// `uv tool list` prints `name v1.2.3` per tool, then its executables as `- exe` lines.
fn parse_uv_tools(output: &str) -> Vec<crate::inventory::Component> {
    output
        .lines()
        .filter(|line| !line.starts_with('-'))
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let name = words.next()?;
            let version = words.next()?.strip_prefix('v')?;
            Some(crate::inventory::Component {
                lookup: package(Ecosystem::PyPI, name),
                version: version.to_owned(),
                found_in: FoundIn::UvTool,
            })
        })
        .collect()
}

fn parse_pipx(json: &str) -> Result<Vec<crate::inventory::Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct List {
        #[serde(default)]
        venvs: BTreeMap<String, Venv>,
    }
    #[derive(Debug, Deserialize)]
    struct Venv {
        metadata: Metadata,
    }
    #[derive(Debug, Deserialize)]
    struct Metadata {
        main_package: MainPackage,
    }
    #[derive(Debug, Deserialize)]
    struct MainPackage {
        package: String,
        package_version: String,
    }

    let list: List =
        serde_json::from_str(json).map_err(|e| InventoryError::parse("pipx list --json", &e))?;
    Ok(list
        .venvs
        .into_values()
        .map(|venv| {
            let main = venv.metadata.main_package;
            crate::inventory::Component {
                lookup: package(Ecosystem::PyPI, &main.package),
                version: main.package_version,
                found_in: FoundIn::Pipx,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Component;

    fn names(components: &[Component]) -> Vec<String> {
        components
            .iter()
            .map(|c| match &c.lookup {
                Lookup::Package(p) => {
                    format!("{}:{} {}", p.ecosystem.osv_name(), p.name, c.version)
                }
                Lookup::Product(p) => format!("{p} {}", c.version),
            })
            .collect()
    }

    #[test]
    fn rustup_toolchains_and_versions() {
        let list = "stable-aarch64-apple-darwin (default)\nnightly-aarch64-apple-darwin\n\
                    1.99.1-aarch64-apple-darwin (active)\n";
        assert_eq!(
            parse_rustup_toolchains(list),
            [
                "stable-aarch64-apple-darwin",
                "nightly-aarch64-apple-darwin",
                "1.99.1-aarch64-apple-darwin"
            ]
        );
        assert_eq!(
            parse_rustup_toolchains("no installed toolchains\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_rustc_version("rustc 1.99.1 (58cf8f9c3 2026-10-13)\n").as_deref(),
            Some("1.99.1")
        );
        assert_eq!(
            parse_rustc_version("rustc 1.100.0-nightly (abc 2026-11-01)").as_deref(),
            Some("1.100.0-nightly")
        );
        assert_eq!(parse_rustc_version("error: no such toolchain"), None);
        assert_eq!(parse_rustc_version("rustc"), None);
    }

    #[test]
    fn cargo_install_skips_path_installs_and_binaries() {
        let output = "aether-cli v0.1.0 (/Users/me/src/aether):\n    aether\n\
                      cargo-audit v0.22.1:\n    cargo-audit\nripgrep v14.1.0:\n    rg\n";
        assert_eq!(
            names(&parse_cargo_install(output)),
            ["crates.io:cargo-audit 0.22.1", "crates.io:ripgrep 14.1.0"]
        );
    }

    #[test]
    fn npm_global_packages() {
        let json = r#"{"name": "lib", "dependencies": {
            "@google/gemini-cli": {"version": "0.52.0", "overridden": false},
            "npm": {"version": "10.9.7"},
            "broken": {"missing": true}
        }}"#;
        assert_eq!(
            names(&parse_npm_global(json).unwrap()),
            ["npm:@google/gemini-cli 0.52.0", "npm:npm 10.9.7"]
        );
        assert_eq!(
            names(&parse_npm_global("{}").unwrap()),
            Vec::<String>::new()
        );
        assert!(parse_npm_global("[").is_err());
    }

    #[test]
    fn python_version() {
        assert_eq!(
            names(&parse_python_version("Python 3.13.1\n").unwrap()),
            ["python 3.13.1"]
        );
        assert!(parse_python_version("Python \n").is_err());
        assert!(parse_python_version("command not found").is_err());
    }

    #[test]
    fn uv_tools() {
        let output = "ruff v0.6.9\n- ruff\nhttpie v3.2.4\n- http\n- https\n";
        assert_eq!(
            names(&parse_uv_tools(output)),
            ["PyPI:ruff 0.6.9", "PyPI:httpie 3.2.4"]
        );
        assert!(parse_uv_tools("No tools installed\n").is_empty());
    }

    #[test]
    fn pipx_venvs() {
        let json = r#"{"pipx_spec_version": "0.1", "venvs": {
            "black": {"metadata": {"main_package": {"package": "black",
                "package_version": "24.10.0", "apps": ["black"]}}}
        }}"#;
        assert_eq!(names(&parse_pipx(json).unwrap()), ["PyPI:black 24.10.0"]);
        assert!(parse_pipx("{").is_err());
    }
}
