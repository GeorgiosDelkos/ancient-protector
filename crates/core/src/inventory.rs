//! What is installed: the components a sweep looks up advisories for.
//!
//! Each source (macOS, Homebrew, toolchains, project lockfiles) is collected on its own. A
//! source that fails is reported in [`Inventory::problems`] and the others still count, so one
//! broken tool never hides the rest. A tool that is not installed is skipped silently.
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
    /// Sources or files that could not be read.
    pub problems: Vec<InventoryError>,
}

impl Inventory {
    /// Collects this Mac's inventory: macOS, Homebrew, toolchains, and lockfiles under
    /// `project_dirs`.
    ///
    /// Runs read-only listing commands (`sw_vers`, `brew`, `rustup`, `cargo`, `npm`, `node`,
    /// `python3`, `uv`, `pipx`) found on `PATH`, and walks `project_dirs`. Blocks until all
    /// of them finish; `brew info` alone can take several seconds.
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

    /// Returns each OSV package once, for [`Feeds::osv`](crate::Feeds::osv).
    pub fn packages(&self) -> Vec<Package> {
        let mut packages: Vec<Package> = self
            .components
            .iter()
            .filter_map(|c| match &c.lookup {
                Lookup::Package(p) => Some(p.clone()),
                Lookup::Product(_) => None,
            })
            .collect();
        packages.sort();
        packages.dedup();
        packages
    }

    /// Returns each NVD product once, for [`Feeds::nvd`](crate::Feeds::nvd).
    pub fn products(&self) -> Vec<Product> {
        let mut products: Vec<Product> = self
            .components
            .iter()
            .filter_map(|c| match &c.lookup {
                Lookup::Product(p) => Some(p.clone()),
                Lookup::Package(_) => None,
            })
            .collect();
        products.sort();
        products.dedup();
        products
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
    /// An NVD CPE product name.
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

/// A source or file that could not be collected.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// A listing command failed.
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
    /// A Homebrew formula or cask name cannot be an NVD product name, so it is not checked.
    #[error("no NVD product name for Homebrew {name:?}; it is not checked")]
    NoProduct {
        /// The formula name or cask token.
        name: String,
    },
}

impl InventoryError {
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
    fn packages_and_products_are_unique_and_sorted() {
        let mut inventory = Inventory::default();
        let pkg = |s: &str| Lookup::Package(s.parse().unwrap());
        let product = |s: &str| Lookup::Product(s.parse().unwrap());
        inventory.add(pkg("npm:b"), "1", FoundIn::NpmGlobal);
        inventory.add(pkg("npm:a"), "1", FoundIn::NpmGlobal);
        inventory.add(pkg("npm:b"), "2", FoundIn::CargoInstall);
        inventory.add(product("zlib"), "1", FoundIn::MacOs);
        inventory.add(product("curl"), "1", FoundIn::MacOs);
        inventory.add(product("zlib"), "2", FoundIn::MacOs);

        let names: Vec<_> = inventory.packages().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["a", "b"]);
        let products: Vec<_> = inventory
            .products()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(products, ["curl", "zlib"]);
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
