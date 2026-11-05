//! Lockfiles in project folders: `Cargo.lock`, `package-lock.json`, `uv.lock`, `poetry.lock`.
//!
//! The walk never follows symlinks and skips vendored, build and hidden folders, so it reads
//! each project's own lockfile and not the copies dependencies ship. Only packages from a
//! registry are kept: workspace members, local paths and git checkouts have no registry
//! advisories under their name.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::package::Ecosystem;
use crate::package::Package;

/// Folders never entered, besides every hidden one.
const SKIPPED_DIRS: &[&str] = &["node_modules", "target", "vendor", "dist", "build"];

/// Walks `root` and adds every package in every lockfile found.
pub(super) fn collect(root: &Path, inventory: &mut Inventory) {
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                inventory.problems.push(InventoryError::io(&dir, e));
                continue;
            }
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(fs::DirEntry::file_name);

        for entry in entries {
            // `DirEntry::file_type` does not follow symlinks, so a link is neither a dir nor a
            // file here and is skipped.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if file_type.is_dir() {
                if !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_ref()) {
                    pending.push(path);
                }
            } else if file_type.is_file()
                && let Some(parse) = parser(&name)
            {
                let found = fs::read_to_string(&path)
                    .map_err(|e| InventoryError::io(&path, e))
                    .and_then(|text| parse(&path, &text));
                inventory.absorb(found);
            }
        }
    }
}

type Parser = fn(&Path, &str) -> Result<Vec<Component>, InventoryError>;

fn parser(file_name: &str) -> Option<Parser> {
    match file_name {
        "Cargo.lock" => Some(parse_cargo_lock),
        "package-lock.json" => Some(parse_package_lock),
        "uv.lock" => Some(parse_uv_lock),
        "poetry.lock" => Some(parse_poetry_lock),
        _ => None,
    }
}

fn component(path: &Path, ecosystem: Ecosystem, name: String, version: String) -> Component {
    Component {
        lookup: Lookup::Package(Package { ecosystem, name }),
        version,
        found_in: FoundIn::Lockfile {
            path: path.to_owned(),
        },
    }
}

fn parse_error(path: &Path, detail: &impl ToString) -> InventoryError {
    InventoryError::parse(path.display().to_string(), detail)
}

/// Packages with a `registry+` source; workspace members have no source, git ones `git+`.
fn parse_cargo_lock(path: &Path, text: &str) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        name: String,
        version: String,
        source: Option<String>,
    }

    let lock: Lock = toml::from_str(text).map_err(|e| parse_error(path, &e))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| {
            p.source
                .as_deref()
                .is_some_and(|s| s.starts_with("registry+"))
        })
        .map(|p| component(path, Ecosystem::CratesIo, p.name, p.version))
        .collect())
}

/// `lockfileVersion` 2 and 3 list every installed package under `packages`, keyed by its
/// `node_modules/...` path. Version 1 (npm 6 and older) has a different shape and is reported
/// rather than guessed at.
fn parse_package_lock(path: &Path, text: &str) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Lock {
        lockfile_version: u32,
        #[serde(default)]
        packages: BTreeMap<String, Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        /// Set when the installed name differs from the folder (an npm alias).
        name: Option<String>,
        version: Option<String>,
        #[serde(default)]
        link: bool,
    }

    let lock: Lock = serde_json::from_str(text).map_err(|e| parse_error(path, &e))?;
    if lock.lockfile_version < 2 {
        return Err(parse_error(
            path,
            &"lockfileVersion 1 is not supported; upgrade it by running `npm install` with npm 7+",
        ));
    }
    Ok(lock
        .packages
        .into_iter()
        .filter(|(_, entry)| !entry.link)
        .filter_map(|(key, entry)| {
            // The root project is the "" key; nested copies are `node_modules/a/node_modules/b`.
            let folder_name = key.rsplit_once("node_modules/").map(|(_, name)| name)?;
            let name = entry.name.unwrap_or_else(|| folder_name.to_owned());
            Some(component(path, Ecosystem::Npm, name, entry.version?))
        })
        .collect())
}

/// Packages whose `source` is a `registry`; editable, virtual, path and git ones are local.
fn parse_uv_lock(path: &Path, text: &str) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        name: String,
        version: Option<String>,
        #[serde(default)]
        source: BTreeMap<String, toml::Value>,
    }

    let lock: Lock = toml::from_str(text).map_err(|e| parse_error(path, &e))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| p.source.contains_key("registry"))
        .filter_map(|p| Some(component(path, Ecosystem::PyPI, p.name, p.version?)))
        .collect())
}

/// Packages from PyPI (no `source`) or a private index (`source.type = "legacy"`); `git`,
/// `directory`, `file` and `url` sources are not registry packages.
fn parse_poetry_lock(path: &Path, text: &str) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        name: String,
        version: String,
        source: Option<Source>,
    }
    #[derive(Debug, Deserialize)]
    struct Source {
        #[serde(rename = "type")]
        kind: String,
    }

    let lock: Lock = toml::from_str(text).map_err(|e| parse_error(path, &e))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| p.source.as_ref().is_none_or(|s| s.kind == "legacy"))
        .map(|p| component(path, Ecosystem::PyPI, p.name, p.version))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn cargo_lock_keeps_registry_packages() {
        let text = r#"
            version = 4
            [[package]]
            name = "my-app"
            version = "0.1.0"
            [[package]]
            name = "serde"
            version = "1.0.229"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            [[package]]
            name = "forked"
            version = "0.2.0"
            source = "git+https://github.com/x/forked#abc"
        "#;
        let found = parse_cargo_lock(Path::new("/p/Cargo.lock"), text).unwrap();
        assert_eq!(names(&found), ["crates.io:serde 1.0.229"]);
        assert!(matches!(
            &found[0].found_in,
            FoundIn::Lockfile { path } if path == Path::new("/p/Cargo.lock")
        ));
        assert!(parse_cargo_lock(Path::new("x"), "[[package]]\nname = 1").is_err());
    }

    #[test]
    fn package_lock_v3() {
        let text = r#"{"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@scope/pkg": {"version": "2.0.0", "dev": true},
            "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
            "node_modules/my-alias": {"name": "real-name", "version": "1.2.3"},
            "node_modules/local": {"resolved": "../local", "link": true},
            "packages/local": {"version": "0.0.1"}
        }}"#;
        let found = parse_package_lock(Path::new("/p/package-lock.json"), text).unwrap();
        assert_eq!(
            names(&found),
            [
                "npm:@scope/pkg 2.0.0",
                "npm:lodash 3.10.1",
                "npm:lodash 4.17.21",
                "npm:real-name 1.2.3",
            ]
        );
    }

    #[test]
    fn package_lock_v1_is_reported() {
        let text = r#"{"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.0.0"}}}"#;
        let err = parse_package_lock(Path::new("/p/package-lock.json"), text).unwrap_err();
        assert!(err.to_string().contains("lockfileVersion 1"), "{err}");

        let v2 = r#"{"lockfileVersion": 2, "packages": {"node_modules/a": {"version": "1.0.0"}}}"#;
        let found = parse_package_lock(Path::new("/p/package-lock.json"), v2).unwrap();
        assert_eq!(names(&found), ["npm:a 1.0.0"]);
    }

    #[test]
    fn uv_lock_keeps_registry_packages() {
        let text = r#"
            version = 1
            [[package]]
            name = "my-project"
            version = "0.1.0"
            source = { editable = "." }
            [[package]]
            name = "requests"
            version = "2.32.3"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "workspace-member"
            version = "0.1.0"
            source = { virtual = "packages/member" }
        "#;
        let found = parse_uv_lock(Path::new("/p/uv.lock"), text).unwrap();
        assert_eq!(names(&found), ["PyPI:requests 2.32.3"]);
    }

    #[test]
    fn poetry_lock_keeps_pypi_and_private_index() {
        let text = r#"
            [[package]]
            name = "django"
            version = "5.1.2"
            [[package]]
            name = "internal"
            version = "1.0.0"
            [package.source]
            type = "legacy"
            url = "https://pypi.example.com/simple"
            [[package]]
            name = "from-git"
            version = "0.1.0"
            [package.source]
            type = "git"
            url = "https://github.com/x/y"
        "#;
        let found = parse_poetry_lock(Path::new("/p/poetry.lock"), text).unwrap();
        assert_eq!(names(&found), ["PyPI:django 5.1.2", "PyPI:internal 1.0.0"]);
    }

    #[test]
    fn walk_finds_lockfiles_and_skips_vendored_hidden_and_links() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let cargo = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
                     source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let write = |rel: &str, text: &str| {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        write("app/Cargo.lock", cargo);
        write("app/nested/deep/Cargo.lock", cargo);
        write(
            "web/package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1"}}}"#,
        );
        write(
            "py/uv.lock",
            "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"x\" }\n",
        );
        write(
            "poetry/poetry.lock",
            "[[package]]\nname = \"a\"\nversion = \"1\"\n",
        );
        write("app/target/Cargo.lock", cargo);
        write("app/node_modules/x/Cargo.lock", cargo);
        write(".hidden/Cargo.lock", cargo);
        write("broken/Cargo.lock", "not toml [");
        write("other/README.md", "# not a lockfile");
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("Cargo.lock"), cargo).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("linked")).unwrap();

        let mut inventory = Inventory::default();
        collect(root, &mut inventory);
        let mut paths: Vec<_> = inventory
            .components
            .iter()
            .map(|c| match &c.found_in {
                FoundIn::Lockfile { path } => path.strip_prefix(root).unwrap().to_owned(),
                other => panic!("unexpected origin {other:?}"),
            })
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                Path::new("app/Cargo.lock"),
                Path::new("app/nested/deep/Cargo.lock"),
                Path::new("poetry/poetry.lock"),
                Path::new("py/uv.lock"),
                Path::new("web/package-lock.json"),
            ]
        );
        assert!(
            matches!(inventory.problems[..], [InventoryError::Parse { .. }]),
            "{:?}",
            inventory.problems
        );
    }

    #[test]
    fn missing_root_is_reported() {
        let mut inventory = Inventory::default();
        collect(Path::new("/nonexistent/ancient-protector"), &mut inventory);
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::Io { .. }]
        ));
    }
}
