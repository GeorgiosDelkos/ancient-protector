//! Sweeps a Mac, GitHub repos and servers for known vulnerabilities with a coding agent.
//!
//! The app downloads advisories (OSV.dev, NVD, CISA KEV, GitHub Advisory Database), collects
//! what is installed, and hands both to the user's chosen coding agent, which decides what is
//! affected and, on approval, fixes it. This crate holds all of that logic; the tray app and
//! the CLI are thin front ends over it.
//!
//! State lives in plain files under a [`DataDir`], configured by [`Config`].

mod agent;
mod config;
mod paths;

pub use crate::agent::AgentKind;
pub use crate::config::Config;
pub use crate::config::ConfigProblem;
pub use crate::config::History;
pub use crate::config::LoadConfigError;
pub use crate::config::ParseRepoSlugError;
pub use crate::config::RepoSlug;
pub use crate::config::Schedule;
pub use crate::config::Server;
pub use crate::config::SshConn;
pub use crate::paths::DataDir;
pub use crate::paths::InitError;
