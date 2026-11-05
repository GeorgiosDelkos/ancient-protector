//! Homebrew formulae and casks, from `brew info --json=v2 --installed`.
//!
//! Homebrew records no CPE names, so each formula or cask is matched to an NVD product by its
//! name: the `@version` suffix is dropped (`openssl@3`), and a short table fixes names known
//! to differ. A wrong guess means NVD returns nothing for that product, so the table errs
//! towards listing every mismatch we know of; the agent still decides what applies.

use serde::Deserialize;

use crate::feeds::Product;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::inventory::command;

/// Homebrew names whose NVD product differs, as (Homebrew name without `@version`, NVD product).
/// Each was checked against NVD's CPE dictionary on 2026-11-05 (`/rest/json/cpes/2.0` with
/// `cpeMatchString`). `gh` names its vendor because other vendors also ship a product `cli`.
/// Extend the table when a formula turns out to be listed under another name.
const ALIASES: &[(&str, &str)] = &[
    ("node", "node.js"),
    ("zstd", "zstandard"),
    ("gh", "github:cli"),
];

pub(super) fn collect(inventory: &mut Inventory) {
    let output = match command::run("brew", &["info", "--json=v2", "--installed"]) {
        Ok(Some(output)) => output,
        Ok(None) => return,
        Err(e) => {
            inventory.problems.push(e);
            return;
        }
    };
    parse(&output, inventory);
}

/// Adds every installed formula version and cask from `brew info --json=v2` output.
fn parse(json: &str, inventory: &mut Inventory) {
    let info: Info = match serde_json::from_str(json) {
        Ok(info) => info,
        Err(e) => {
            inventory
                .problems
                .push(InventoryError::parse("brew info --json=v2", &e));
            return;
        }
    };

    for formula in info.formulae {
        let Some(product) = product(&formula.name) else {
            inventory
                .problems
                .push(InventoryError::NoProduct { name: formula.name });
            continue;
        };
        for installed in formula.installed {
            let found_in = FoundIn::HomebrewFormula {
                name: formula.name.clone(),
            };
            inventory.add(
                Lookup::Product(product.clone()),
                installed.version,
                found_in,
            );
        }
    }
    for cask in info.casks {
        let Some(version) = cask.installed else {
            continue;
        };
        let Some(product) = product(&cask.token) else {
            inventory
                .problems
                .push(InventoryError::NoProduct { name: cask.token });
            continue;
        };
        let found_in = FoundIn::HomebrewCask { token: cask.token };
        inventory.add(Lookup::Product(product), version, found_in);
    }
}

/// Returns the NVD product for a Homebrew name, or `None` when even the cleaned name is not a
/// valid product (such as `gtk+3`).
fn product(name: &str) -> Option<Product> {
    let base = name.split_once('@').map_or(name, |(base, _)| base);
    let base = ALIASES
        .iter()
        .find(|(brew, _)| *brew == base)
        .map_or(base, |(_, nvd)| nvd);
    base.parse().ok()
}

#[derive(Debug, Deserialize)]
struct Info {
    #[serde(default)]
    formulae: Vec<Formula>,
    #[serde(default)]
    casks: Vec<Cask>,
}

#[derive(Debug, Deserialize)]
struct Formula {
    name: String,
    #[serde(default)]
    installed: Vec<Installed>,
}

#[derive(Debug, Deserialize)]
struct Installed {
    version: String,
}

/// `installed` is the installed version, or null for a cask that is listed but not installed.
#[derive(Debug, Deserialize)]
struct Cask {
    token: String,
    installed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(json: &str) -> Inventory {
        let mut inventory = Inventory::default();
        parse(json, &mut inventory);
        inventory
    }

    fn summary(inventory: &Inventory) -> Vec<String> {
        inventory
            .components
            .iter()
            .map(|c| match (&c.lookup, &c.found_in) {
                (Lookup::Product(p), FoundIn::HomebrewFormula { name }) => {
                    format!("{name} -> {p} {}", c.version)
                }
                (Lookup::Product(p), FoundIn::HomebrewCask { token }) => {
                    format!("cask {token} -> {p} {}", c.version)
                }
                other => panic!("unexpected component {other:?}"),
            })
            .collect()
    }

    #[test]
    fn formulae_and_casks_become_products() {
        let inventory = parsed(
            r#"{
              "formulae": [
                {"name": "openssl@3", "installed": [{"version": "3.4.0"}], "versions": {}},
                {"name": "node", "installed": [{"version": "24.1.0"}, {"version": "23.0.0"}]},
                {"name": "zstd", "installed": [{"version": "1.5.6"}]},
                {"name": "uninstalled", "installed": []}
              ],
              "casks": [
                {"token": "codex", "version": "0.165.0", "installed": "0.128.0"},
                {"token": "listed-only", "installed": null}
              ]
            }"#,
        );
        assert_eq!(
            summary(&inventory),
            [
                "openssl@3 -> openssl 3.4.0",
                "node -> node.js 24.1.0",
                "node -> node.js 23.0.0",
                "zstd -> zstandard 1.5.6",
                "cask codex -> codex 0.128.0",
            ]
        );
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
    }

    #[test]
    fn unusable_names_are_reported() {
        let inventory = parsed(
            r#"{"formulae": [{"name": "gtk+3", "installed": [{"version": "3.24"}]}],
                "casks": [{"token": "Weird App", "installed": "1"}]}"#,
        );
        assert!(inventory.components.is_empty());
        let names: Vec<_> = inventory
            .problems
            .iter()
            .map(|p| match p {
                InventoryError::NoProduct { name } => name.as_str(),
                other => panic!("unexpected problem {other:?}"),
            })
            .collect();
        assert_eq!(names, ["gtk+3", "Weird App"]);
    }

    #[test]
    fn bad_json_is_a_parse_problem() {
        let inventory = parsed("not json");
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::Parse { .. }]
        ));
    }

    #[test]
    fn product_names() {
        let name = |s: &str| product(s).map(|p| p.to_string());
        assert_eq!(name("python@3.13").as_deref(), Some("python"));
        assert_eq!(name("gh").as_deref(), Some("github:cli"));
        assert_eq!(name("curl").as_deref(), Some("curl"));
        assert_eq!(name("gtk+3"), None);
    }
}
