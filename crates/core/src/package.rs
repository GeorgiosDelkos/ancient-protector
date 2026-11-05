//! Packages as advisory databases name them.

use std::str::FromStr;

/// A package ecosystem, as OSV names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ecosystem {
    /// Rust crates (`Cargo.lock`).
    CratesIo,
    /// npm packages (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`).
    Npm,
    /// Python packages (`uv.lock`, `poetry.lock`, `requirements.txt`).
    PyPI,
    /// Go modules (`go.sum`).
    Go,
    /// Ruby gems (`Gemfile.lock`).
    RubyGems,
    /// GitHub Actions used by workflows.
    GitHubActions,
}

impl Ecosystem {
    /// Every ecosystem, in declaration order.
    const ALL: [Self; 6] = [
        Self::CratesIo,
        Self::Npm,
        Self::PyPI,
        Self::Go,
        Self::RubyGems,
        Self::GitHubActions,
    ];

    /// Returns OSV's name for the ecosystem, as used in its API and records.
    pub fn osv_name(self) -> &'static str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::Go => "Go",
            Self::RubyGems => "RubyGems",
            Self::GitHubActions => "GitHub Actions",
        }
    }
}

impl FromStr for Ecosystem {
    type Err = ParsePackageError;

    /// Parses OSV's name for the ecosystem, ignoring case.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|e| e.osv_name().eq_ignore_ascii_case(s))
            .ok_or(ParsePackageError::Ecosystem)
    }
}

/// A package in one ecosystem. Versions are deliberately absent: advisories are looked up by
/// name, and the agent decides whether the installed version is affected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    /// The ecosystem the name belongs to.
    pub ecosystem: Ecosystem,
    /// The package name as the ecosystem spells it (`@scope/name`, `golang.org/x/net`).
    pub name: String,
}

impl FromStr for Package {
    type Err = ParsePackageError;

    /// Parses `ecosystem:name`, such as `npm:lodash` or `crates.io:serde`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ecosystem, name) = s.split_once(':').ok_or(ParsePackageError::NoColon)?;
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(ParsePackageError::Name);
        }
        Ok(Self {
            ecosystem: ecosystem.parse()?,
            name: name.to_owned(),
        })
    }
}

/// Why a string is not an `ecosystem:name` package.
#[derive(Debug, thiserror::Error)]
pub enum ParsePackageError {
    /// There is no `:` between ecosystem and name.
    #[error("expected ecosystem:name, such as npm:lodash")]
    NoColon,
    /// The ecosystem is not one Ancient Protector knows.
    #[error("unknown ecosystem; use crates.io, npm, PyPI, Go, RubyGems or GitHub Actions")]
    Ecosystem,
    /// The name is empty or has control characters.
    #[error("package name must be non-empty without control characters")]
    Name,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays_packages() {
        for (text, ecosystem, name) in [
            ("npm:@scope/pkg", Ecosystem::Npm, "@scope/pkg"),
            ("crates.io:serde", Ecosystem::CratesIo, "serde"),
            ("pypi:Django", Ecosystem::PyPI, "Django"),
            ("Go:golang.org/x/net", Ecosystem::Go, "golang.org/x/net"),
            ("RubyGems:rails", Ecosystem::RubyGems, "rails"),
            (
                "GitHub Actions:actions/checkout",
                Ecosystem::GitHubActions,
                "actions/checkout",
            ),
        ] {
            let package: Package = text.parse().unwrap();
            assert_eq!(package.ecosystem, ecosystem, "{text}");
            assert_eq!(package.name, name, "{text}");
        }
    }

    #[test]
    fn rejects_bad_packages() {
        assert!(matches!(
            "lodash".parse::<Package>(),
            Err(ParsePackageError::NoColon)
        ));
        assert!(matches!(
            "cargo:serde".parse::<Package>(),
            Err(ParsePackageError::Ecosystem)
        ));
        assert!(matches!(
            "npm:".parse::<Package>(),
            Err(ParsePackageError::Name)
        ));
        assert!(matches!(
            "npm:a\nb".parse::<Package>(),
            Err(ParsePackageError::Name)
        ));
    }
}
