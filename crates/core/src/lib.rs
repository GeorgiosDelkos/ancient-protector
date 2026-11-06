//! Sweeps a Mac, GitHub repos and servers for known vulnerabilities with a coding agent.
//!
//! The app collects what is installed ([`Inventory`]), fetches advisories ([`Feeds`]:
//! OSV.dev, which includes the GitHub Advisory Database, plus NVD and CISA KEV), and hands
//! both to the user's chosen coding agent, which decides what is affected and, on approval,
//! fixes it. This crate holds all of that logic; the tray app and the CLI are thin front ends
//! over it.
//!
//! State lives in plain files under a [`DataDir`], configured by [`Config`].

mod agent;
mod bundle;
mod config;
mod feeds;
mod findings;
mod github;
mod inventory;
mod package;
mod paths;
mod sweep;

pub use crate::agent::AgentError;
pub use crate::agent::AgentKind;
pub use crate::bundle::BundleError;
pub use crate::config::Config;
pub use crate::config::ConfigProblem;
pub use crate::config::History;
pub use crate::config::LoadConfigError;
pub use crate::config::ParseRepoSlugError;
pub use crate::config::RepoSlug;
pub use crate::config::Schedule;
pub use crate::config::Server;
pub use crate::config::Since;
pub use crate::config::SshConn;
pub use crate::config::SshWord;
pub use crate::feeds::Advisory;
pub use crate::feeds::FeedError;
pub use crate::feeds::Feeds;
pub use crate::feeds::Kev;
pub use crate::feeds::KeychainError;
pub use crate::feeds::NvdAccess;
pub use crate::feeds::OsvAdvisories;
pub use crate::feeds::OsvAdvisory;
pub use crate::feeds::ParseProductError;
pub use crate::feeds::Product;
pub use crate::feeds::Source;
pub use crate::findings::Confidence;
pub use crate::findings::Finding;
pub use crate::findings::Fix;
pub use crate::findings::Issue;
pub use crate::findings::Severity;
pub use crate::findings::Subject;
pub use crate::inventory::Component;
pub use crate::inventory::FoundIn;
pub use crate::inventory::Inventory;
pub use crate::inventory::InventoryError;
pub use crate::inventory::Lookup;
pub use crate::package::Ecosystem;
pub use crate::package::Package;
pub use crate::package::ParsePackageError;
pub use crate::paths::DataDir;
pub use crate::paths::InitError;
pub use crate::sweep::Progress;
pub use crate::sweep::Report;
pub use crate::sweep::ReportFinding;
pub use crate::sweep::SweepError;
pub use crate::sweep::report_markdown;
pub use crate::sweep::sweep;
