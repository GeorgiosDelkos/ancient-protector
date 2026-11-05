//! Command-line interface to Ancient Protector.

use std::path::Path;
use std::path::PathBuf;

use ancient_protector_core::Config;
use ancient_protector_core::DataDir;
use ancient_protector_core::Feeds;
use ancient_protector_core::History;
use ancient_protector_core::LoadConfigError;
use ancient_protector_core::NvdAccess;
use ancient_protector_core::Package;
use ancient_protector_core::Product;
use ancient_protector_core::Schedule;
use ancient_protector_core::SshConn;
use anyhow::Context as _;
use clap::Parser;
use clap::Subcommand;

/// Sweep this Mac, GitHub repos and servers for known vulnerabilities.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Data directory [default: ~/Library/Application Support/ancient-protector].
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the data directory and a default config.toml.
    Init,
    /// Validate config.toml and print what a sweep would cover.
    Config,
    /// Fetch advisories for packages and NVD products, one JSON object per line.
    ///
    /// Uses `history.since` from config.toml. An NVD API key stored in the Keychain with
    /// `security add-generic-password -s ancient-protector -a nvd-api-key -w <key>` raises
    /// NVD's rate limit from 5 to 50 requests per 30 seconds.
    Advisories {
        /// A package as ecosystem:name, such as npm:lodash or crates.io:serde. Repeatable.
        #[arg(long = "package", value_name = "ECOSYSTEM:NAME")]
        packages: Vec<Package>,
        /// An NVD product (CPE product name, any vendor), such as openssl. Repeatable.
        #[arg(long = "product", value_name = "NAME")]
        products: Vec<Product>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Looked up only when needed, so `--data-dir X init` works without HOME.
    let home = || std::env::home_dir().context("cannot find the home directory; set HOME");
    let data_dir = match cli.data_dir {
        Some(dir) => DataDir::new(dir),
        None => DataDir::for_home(&home()?),
    };

    match cli.command {
        Command::Init => {
            let path = data_dir.init()?;
            print(&format!("wrote {}", path.display()));
        }
        Command::Config => print(&summary(&load_config(&data_dir, &home()?)?)),
        Command::Advisories { packages, products } => {
            let config = load_config(&data_dir, &home()?)?;
            // Reading the Keychain can prompt the user, so only when NVD will be queried.
            let nvd = if products.is_empty() {
                NvdAccess::Anonymous
            } else {
                NvdAccess::from_keychain()?
            };
            let feeds = Feeds::new(&data_dir, nvd);
            let kev = feeds.kev()?;

            let mut advisories = feeds.osv(&packages, config.history)?;
            for product in &products {
                let found = feeds
                    .nvd(product, config.history)
                    .with_context(|| format!("NVD product {product}"))?;
                advisories.extend(found);
            }
            for advisory in &advisories {
                print(&advisory.to_json_line(&kev));
            }
        }
    }
    Ok(())
}

fn load_config(data_dir: &DataDir, home: &Path) -> anyhow::Result<Config> {
    Config::load(&data_dir.config_file(), home).map_err(|e| match e {
        LoadConfigError::Missing { .. } => {
            anyhow::Error::new(e).context("run `ancient-protector init` first")
        }
        e => e.into(),
    })
}

/// Renders the parts of `config` a sweep acts on, one line each.
fn summary(config: &Config) -> String {
    let agent = config.agent.map_or_else(
        || "none (set `agent` in config.toml)".to_owned(),
        |a| a.to_string(),
    );
    let schedule = match config.schedule {
        Schedule::Manual => "manual".to_owned(),
        Schedule::EveryHours(h) => format!("every {h} h"),
    };
    let history = match config.history {
        History::All => "all".to_owned(),
        History::Since(since) => format!("since {}", since.date()),
    };

    let mut out = format!("agent: {agent}\nschedule: {schedule}\nhistory: {history}\n");
    for dir in &config.project_dirs {
        out.push_str(&format!("mac project dir: {}\n", dir.display()));
    }
    for repo in &config.repos {
        out.push_str(&format!("github repo: {repo}\n"));
    }
    for server in &config.servers {
        let conn = match &server.conn {
            SshConn::Alias(alias) => format!("ssh alias {alias}"),
            SshConn::Direct {
                host,
                user,
                port,
                identity_file,
            } => {
                let mut conn = format!("host {host}");
                if let Some(user) = user {
                    conn.push_str(&format!(", user {user}"));
                }
                if let Some(port) = port {
                    conn.push_str(&format!(", port {port}"));
                }
                if let Some(key) = identity_file {
                    conn.push_str(&format!(", key {}", key.display()));
                }
                conn
            }
        };
        out.push_str(&format!("server: {} ({conn})\n", server.name));
    }
    out
}

#[expect(clippy::print_stdout, reason = "the CLI's one output function")]
fn print(text: &str) {
    println!("{}", text.trim_end());
}
