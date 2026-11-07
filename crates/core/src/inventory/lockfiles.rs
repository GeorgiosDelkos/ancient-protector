//! Lockfiles in project folders: `Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`,
//! `uv.lock` and `poetry.lock`.
//!
//! The walk never follows symlinks and skips vendored, build and hidden folders, so it reads
//! each project's own lockfile and not the copies dependencies ship. Only packages from a
//! registry are kept: workspace members, local paths and git checkouts have no registry
//! advisories under their name.
//!
//! Registries other than the public one are treated differently per ecosystem, on purpose.
//! `Cargo.lock` records crates.io even when the index is mirrored, so any other Cargo registry
//! holds different crates, which are noted and left out. npm and Python lockfiles record the
//! mirror's own URL, and corporate mirrors of npmjs and PyPI are common, so their packages are
//! kept and looked up under the public name.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::package::Ecosystem;
use crate::package::Package;

/// Folders never entered, besides every hidden one.
pub(crate) const SKIPPED_DIRS: &[&str] = &["node_modules", "target", "vendor", "dist", "build"];

/// Walks `root` and adds every package in every lockfile found.
pub(super) fn collect(root: &Path, inventory: &mut Inventory) {
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        for (path, kind) in list(&dir, &mut inventory.problems) {
            match kind {
                Entry::Dir => pending.push(path),
                Entry::File => read(&path, inventory),
            }
        }
    }
}

/// What a folder entry is to the walk.
enum Entry {
    /// A folder to enter.
    Dir,
    /// A regular file.
    File,
}

/// Returns `dir`'s entries the walk cares about, sorted by name: folders it enters and regular
/// files. Symlinks, skipped folders and unreadable entries are left out, the last reported.
fn list(dir: &Path, problems: &mut Vec<InventoryError>) -> Vec<(PathBuf, Entry)> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            problems.push(InventoryError::io(dir, e));
            return Vec::new();
        }
    };
    let mut listed = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                problems.push(InventoryError::io(dir, e));
                continue;
            }
        };
        // `DirEntry::file_type` does not follow symlinks, so a link is neither a dir nor a
        // file here and is skipped.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                problems.push(InventoryError::io(&entry.path(), e));
                continue;
            }
        };
        if file_type.is_file() {
            listed.push((entry.path(), Entry::File));
        } else if file_type.is_dir() && entered(&entry.file_name()) {
            listed.push((entry.path(), Entry::Dir));
        }
    }
    listed.sort_by(|a, b| a.0.cmp(&b.0));
    listed
}

/// Returns whether the walk enters a folder named `name`: not hidden, not vendored or built.
fn entered(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_ref())
}

/// Adds the packages of `path` if it is a lockfile this module reads.
fn read(path: &Path, inventory: &mut Inventory) {
    if !is_lockfile(path) {
        return;
    }
    let found = read_lockfile(path).and_then(|text| {
        parse(path, &text, &mut inventory.problems).expect("checked to be a lockfile name")
    });
    inventory.absorb(found);
}

/// The lockfile names this module reads.
pub(crate) const NAMES: [&str; 5] = [
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "uv.lock",
    "poetry.lock",
];

fn is_lockfile(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| NAMES.contains(&name))
}

/// Parses `text`, the lockfile at `path` (which may be on another machine), by its file name.
/// Returns `None` when the name is not one of [`NAMES`].
pub(crate) fn parse(
    path: &Path,
    text: &str,
    problems: &mut Vec<InventoryError>,
) -> Option<Result<Vec<Component>, InventoryError>> {
    let name = path.file_name().and_then(OsStr::to_str)?;
    let found = match name {
        "Cargo.lock" => parse_cargo_lock(path, text, problems),
        // npm-shrinkwrap.json is a package-lock.json that a package publishes with itself.
        "package-lock.json" | "npm-shrinkwrap.json" => parse_package_lock(path, text),
        "uv.lock" => parse_uv_lock(path, text),
        "poetry.lock" => parse_poetry_lock(path, text),
        _ => return None,
    };
    Some(found)
}

/// The largest lockfile read, in bytes. Arbitrary: the biggest real lockfiles are a few MB, and
/// a file far past that is not one, so it is reported instead of read into memory.
const LOCKFILE_LIMIT: u64 = 64 * 1024 * 1024;

fn read_lockfile(path: &Path) -> Result<String, InventoryError> {
    let len = fs::metadata(path)
        .map_err(|e| InventoryError::io(path, e))?
        .len();
    if len > LOCKFILE_LIMIT {
        return Err(parse_error(
            path,
            &format!("{len} bytes, over the {LOCKFILE_LIMIT}-byte limit"),
        ));
    }
    fs::read_to_string(path).map_err(|e| InventoryError::io(path, e))
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

/// Packages from crates.io, by either index protocol; see the module docs for why another
/// Cargo registry is noted and left out. Workspace members have no source and git ones `git+`.
const CRATES_IO_SOURCES: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

fn parse_cargo_lock(
    path: &Path,
    text: &str,
    notes: &mut Vec<InventoryError>,
) -> Result<Vec<Component>, InventoryError> {
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
    let mut components = Vec::new();
    let mut other_registries = BTreeSet::new();
    for p in lock.package {
        match p.source.as_deref() {
            Some(source) if CRATES_IO_SOURCES.contains(&source) => {
                components.push(component(path, Ecosystem::CratesIo, p.name, p.version));
            }
            Some(source) if source.starts_with("registry+") || source.starts_with("sparse+") => {
                other_registries.insert(source.to_owned());
            }
            _ => {}
        }
    }
    notes.extend(
        other_registries
            .into_iter()
            .map(|registry| InventoryError::OtherRegistry {
                path: path.to_owned(),
                registry,
            }),
    );
    Ok(components)
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
        /// Where it came from: a registry tarball (`https://...`), or a `git+`, `github:`,
        /// `file:` or `link:` spec for a dependency that is not a registry package. Only
        /// registry tarballs, or no `resolved` at all (bundled dependencies), are kept.
        resolved: Option<String>,
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
        .filter(|(_, entry)| {
            entry
                .resolved
                .as_deref()
                .is_none_or(|r| r.starts_with("https://") || r.starts_with("http://"))
        })
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
    fn every_lockfile_name_has_a_parser() {
        for name in NAMES {
            let path = Path::new("/p").join(name);
            assert!(parse(&path, "", &mut Vec::new()).is_some(), "{name}");
            assert!(is_lockfile(&path), "{name}");
        }
        assert!(parse(Path::new("/p/Gemfile.lock"), "", &mut Vec::new()).is_none());
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
            [[package]]
            name = "mirrored"
            version = "0.3.0"
            source = "sparse+https://index.crates.io/"
            [[package]]
            name = "internal"
            version = "1.0.0"
            source = "sparse+https://cargo.example.com/index/"
            [[package]]
            name = "internal-two"
            version = "1.0.0"
            source = "sparse+https://cargo.example.com/index/"
        "#;
        let mut notes = Vec::new();
        let found = parse_cargo_lock(Path::new("/p/Cargo.lock"), text, &mut notes).unwrap();
        let registries: Vec<_> = notes
            .iter()
            .map(|n| match n {
                InventoryError::OtherRegistry { registry, .. } => registry.as_str(),
                other => panic!("unexpected note {other:?}"),
            })
            .collect();
        assert_eq!(
            registries,
            ["sparse+https://cargo.example.com/index/"],
            "noted once"
        );
        assert_eq!(
            names(&found),
            ["crates.io:serde 1.0.229", "crates.io:mirrored 0.3.0"]
        );
        assert!(matches!(
            &found[0].found_in,
            FoundIn::Lockfile { path } if path == Path::new("/p/Cargo.lock")
        ));
        assert!(
            parse_cargo_lock(Path::new("x"), "[[package]]\nname = 1", &mut Vec::new()).is_err()
        );
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
            "node_modules/from-git": {"version": "1", "resolved": "git+ssh://git@x.com/y.git"},
            "node_modules/tarball": {"version": "1.0.0", "resolved": "file:../tarball.tgz"},
            "node_modules/shorthand": {"version": "1.0.0", "resolved": "github:x/y#abc"},
            "node_modules/registry": {"version": "2.0.0", "resolved": "https://r.example/r.tgz"},
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
                "npm:registry 2.0.0",
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
        write(
            "published/npm-shrinkwrap.json",
            r#"{"lockfileVersion": 3, "packages": {"node_modules/b": {"version": "1"}}}"#,
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
                Path::new("published/npm-shrinkwrap.json"),
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
    fn oversized_lockfile_is_reported_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Cargo.lock");
        // A sparse file: the length is set without writing 64 MiB.
        fs::File::create(&path)
            .unwrap()
            .set_len(LOCKFILE_LIMIT + 1)
            .unwrap();
        let err = read_lockfile(&path).unwrap_err();
        assert!(err.to_string().contains("over the"), "{err}");

        fs::File::create(&path)
            .unwrap()
            .set_len(LOCKFILE_LIMIT)
            .unwrap();
        assert!(read_lockfile(&path).is_ok());

        // A real lockfile of a few MiB is well under the limit.
        fs::File::create(&path)
            .unwrap()
            .set_len(2 * 1024 * 1024)
            .unwrap();
        assert!(read_lockfile(&path).is_ok());
    }

    #[test]
    fn unreadable_folder_is_reported_and_the_walk_goes_on() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(
            tmp.path().join("Cargo.lock"),
            concat!(
                "[[package]]\nname = \"a\"\nversion = \"1\"\n",
                "source = \"sparse+https://index.crates.io/\"\n",
            ),
        )
        .unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let mut inventory = Inventory::default();
        collect(tmp.path(), &mut inventory);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert!(
            matches!(inventory.problems[..], [InventoryError::Io { .. }]),
            "{:?}",
            inventory.problems
        );
    }

    #[test]
    fn missing_root_is_reported() {
        let mut inventory = Inventory::default();
        collect(Path::new("/nonexistent/vigil"), &mut inventory);
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::Io { .. }]
        ));
    }
}
