//! What is installed: the components a sweep looks up advisories for.
//!
//! Each source (macOS, Homebrew, toolchains, project lockfiles) is collected on its own. A
//! source that fails is reported in [`Inventory::problems`] and the others still count, so one
//! broken tool never hides the rest. A tool that is not installed is listed in
//! [`Inventory::not_installed`], so an inventory taken with a bare `PATH` (an app started by
//! launchd gets `/usr/bin:/bin:/usr/sbin:/sbin`) shows what it did not check.
//!
//! Collecting only reads: it runs listing commands and parses lockfiles, never project code.

mod command;
mod homebrew;
mod lockfiles;
mod toolchains;

use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;

use crate::feeds::Product;
use crate::package::Package;

/// Everything found installed, plus what could not be collected.
#[derive(Debug, Default)]
pub struct Inventory {
    /// Installed components, in collection order. The same component appears once per place it
    /// was found.
    pub components: Vec<Component>,
    /// Sources or files that could not be read, names that cannot be looked up, and notes on
    /// sources that were still read (see [`InventoryError::is_failure`]).
    pub problems: Vec<InventoryError>,
    /// Listing tools that are not on `PATH`, so their part was not checked.
    pub not_installed: Vec<&'static str>,
}

impl Inventory {
    /// Collects this Mac's inventory: macOS, Homebrew, toolchains, and lockfiles under
    /// `project_dirs`.
    ///
    /// Runs read-only listing commands (`sw_vers`, `brew`, `rustup`, `cargo`, `npm`, `node`,
    /// `python3`, `uv`, `pipx`) found on `PATH`, each from `/` with a one-minute limit, and
    /// walks `project_dirs`. Blocks until all of them finish; `brew info` alone can take
    /// several seconds.
    pub fn collect_mac(project_dirs: &[PathBuf]) -> Self {
        let mut inventory = Self::default();
        toolchains::macos(&mut inventory);
        homebrew::collect(&mut inventory);
        toolchains::collect(&mut inventory);
        for dir in project_dirs {
            lockfiles::collect(dir, &mut inventory);
        }
        inventory
    }

    fn add(&mut self, lookup: Lookup, version: impl Into<String>, found_in: FoundIn) {
        self.components.push(Component {
            lookup,
            version: version.into(),
            found_in,
        });
    }

    /// Adds `result`'s components, or records its error.
    fn absorb(&mut self, result: Result<Vec<Component>, InventoryError>) {
        match result {
            Ok(components) => self.components.extend(components),
            Err(e) => self.problems.push(e),
        }
    }

    /// Records that `program` is not installed, once.
    fn missing(&mut self, program: &'static str) {
        if !self.not_installed.contains(&program) {
            self.not_installed.push(program);
        }
    }

    /// Runs a listing command, recording a failure as a problem and a missing tool in
    /// `not_installed`. Returns stdout only when the command succeeded.
    fn run(&mut self, program: &'static str, args: &[&str]) -> Option<String> {
        match command::run(program, args) {
            Ok(Some(output)) => Some(output),
            Ok(None) => {
                self.missing(program);
                None
            }
            Err(e) => {
                self.problems.push(e);
                None
            }
        }
    }
}

/// One installed thing at one version, and where it was found.
#[derive(Debug, Serialize)]
pub struct Component {
    /// How advisories are looked up for it.
    pub lookup: Lookup,
    /// The installed version, as the source reports it.
    pub version: String,
    /// Where it was found.
    pub found_in: FoundIn,
}

/// How a component's advisories are found.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lookup {
    /// An OSV package (ecosystem and name).
    Package(Package),
    /// An NVD CPE product, `name` or `vendor:name`.
    Product(Product),
}

/// Where a component was found, so the agent knows what to check and what to fix.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FoundIn {
    /// The operating system.
    MacOs,
    /// A Homebrew formula, by its Homebrew name (`openssl@3`).
    HomebrewFormula {
        /// The formula name.
        name: String,
    },
    /// A Homebrew cask, by its token.
    HomebrewCask {
        /// The cask token.
        token: String,
    },
    /// A rustup toolchain, by its name (`stable-aarch64-apple-darwin`).
    Rustup {
        /// The toolchain name.
        toolchain: String,
    },
    /// A binary installed with `cargo install`.
    CargoInstall,
    /// The `node` on `PATH`.
    Node,
    /// A package installed with `npm install -g`.
    NpmGlobal,
    /// The `python3` on `PATH`.
    Python,
    /// A tool installed with `uv tool install`.
    UvTool,
    /// A tool installed with `pipx install`.
    Pipx,
    /// A lockfile in a project folder.
    Lockfile {
        /// The lockfile's path.
        path: PathBuf,
    },
}

/// A source or file that could not be collected, or a name that cannot be looked up.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// A listing command exists but could not be started, waited for, or its output read.
    #[error("cannot run `{command}`")]
    Spawn {
        /// The command line.
        command: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A listing command exited with an error or ran too long.
    #[error("`{command}` failed: {detail}")]
    Command {
        /// The command line.
        command: String,
        /// The exit status and the start of its stderr.
        detail: String,
    },
    /// A command's output or a lockfile was not in the expected format.
    #[error("cannot parse {what}: {detail}")]
    Parse {
        /// The command or file.
        what: String,
        /// What did not match.
        detail: String,
    },
    /// A file or folder could not be read.
    #[error("cannot read {}", path.display())]
    Io {
        /// The path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A `Cargo.lock` uses crates from a registry other than crates.io; they are not checked.
    #[error(
        "{} uses crates from {registry}, which are not checked: OSV covers crates.io only",
        path.display()
    )]
    OtherRegistry {
        /// The lockfile.
        path: PathBuf,
        /// The registry source, as Cargo.lock names it.
        registry: String,
    },
    /// `npm ls -g` reported a problem in the global tree but still listed it, so its packages
    /// are in the inventory.
    #[error(
        "`npm ls -g` reports a problem in the global packages (they are still listed): {detail}"
    )]
    NpmTree {
        /// The exit status and the start of npm's stderr.
        detail: String,
    },
    /// A Homebrew formula or cask name cannot be an NVD product name, so it is not checked.
    #[error("no NVD product name for Homebrew {name:?}; it is not checked")]
    NoProduct {
        /// The formula name or cask token.
        name: String,
    },
}

impl InventoryError {
    /// Returns whether a source failed, as opposed to a lasting fact about one item (a
    /// Homebrew name with no NVD product) that the next sweep would report again.
    pub fn is_failure(&self) -> bool {
        match self {
            Self::Spawn { .. } | Self::Command { .. } | Self::Parse { .. } | Self::Io { .. } => {
                true
            }
            Self::NoProduct { .. } | Self::OtherRegistry { .. } | Self::NpmTree { .. } => false,
        }
    }

    fn parse(what: impl Into<String>, detail: &impl ToString) -> Self {
        Self::Parse {
            what: what.into(),
            detail: detail.to_string(),
        }
    }

    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tools_are_listed_once() {
        let mut inventory = Inventory::default();
        assert_eq!(inventory.run("ancient-protector-no-such-tool", &[]), None);
        assert_eq!(
            inventory.run("ancient-protector-no-such-tool", &["x"]),
            None
        );
        assert_eq!(inventory.not_installed, ["ancient-protector-no-such-tool"]);
        assert_eq!(inventory.run("echo", &["hi"]).as_deref(), Some("hi\n"));
        assert_eq!(inventory.run("false", &[]), None);
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::Command { .. }]
        ));
    }

    #[test]
    fn only_source_errors_are_failures() {
        assert!(InventoryError::parse("x", &"y").is_failure());
        assert!(!InventoryError::NoProduct { name: "x".into() }.is_failure());
        let other = InventoryError::OtherRegistry {
            path: PathBuf::from("/p/Cargo.lock"),
            registry: "sparse+https://x/".into(),
        };
        assert!(!other.is_failure());
        assert!(other.to_string().contains("OSV covers crates.io only"));
    }

    #[test]
    fn absorb_keeps_components_and_problems() {
        let mut inventory = Inventory::default();
        inventory.absorb(Ok(vec![Component {
            lookup: Lookup::Product("curl".parse().unwrap()),
            version: "8".into(),
            found_in: FoundIn::MacOs,
        }]));
        inventory.absorb(Err(InventoryError::parse("x", &"y")));
        assert_eq!(inventory.components.len(), 1);
        assert_eq!(inventory.problems.len(), 1);
    }
}
