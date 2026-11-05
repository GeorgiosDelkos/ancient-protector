//! Command-line interface to Ancient Protector.

use std::path::PathBuf;

use ancient_protector_core::Config;
use ancient_protector_core::DataDir;
use ancient_protector_core::History;
use ancient_protector_core::LoadConfigError;
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
        Command::Config => {
            let path = data_dir.config_file();
            let config = Config::load(&path, &home()?).map_err(|e| match e {
                LoadConfigError::Missing { .. } => {
                    anyhow::Error::new(e).context("run `ancient-protector init` first")
                }
                e => e.into(),
            })?;
            print(&summary(&config));
        }
    }
    Ok(())
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
        History::Since(date) => format!("since {date}"),
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
