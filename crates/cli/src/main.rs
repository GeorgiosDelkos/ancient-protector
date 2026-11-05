//! Command-line interface to Ancient Protector.

use std::path::Path;
use std::path::PathBuf;

use ancient_protector_core::Config;
use ancient_protector_core::DataDir;
use ancient_protector_core::Feeds;
use ancient_protector_core::History;
use ancient_protector_core::Inventory;
use ancient_protector_core::LoadConfigError;
use ancient_protector_core::NvdAccess;
use ancient_protector_core::Package;
use ancient_protector_core::Product;
use ancient_protector_core::Progress;
use ancient_protector_core::Schedule;
use ancient_protector_core::SshConn;
use ancient_protector_core::report_markdown;
use ancient_protector_core::sweep_mac;
use anyhow::Context as _;
use clap::ArgGroup;
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
    #[command(group(
        ArgGroup::new("what")
            .required(true)
            .multiple(true)
            .args(["packages", "products"])
    ))]
    Advisories {
        /// A package as ecosystem:name, such as npm:lodash or crates.io:serde. Repeatable.
        #[arg(long = "package", value_name = "ECOSYSTEM:NAME")]
        packages: Vec<Package>,
        /// An NVD product, `name` (any vendor) or `vendor:name`, such as openssl or github:cli.
        /// Repeatable.
        #[arg(long = "product", value_name = "[VENDOR:]NAME")]
        products: Vec<Product>,
    },
    /// List what is installed on this Mac, one JSON object per line.
    ///
    /// Reads macOS, Homebrew, global toolchains, and lockfiles under `mac.project_dirs` from
    /// config.toml. Anything that could not be read is reported on stderr.
    Inventory,
    /// Sweep this Mac: inventory, advisories, the chosen agent's verdict, and a report.
    ///
    /// Prints the report on stdout and progress on stderr. The report and the agent's bundle
    /// are kept under the data directory's `sweeps` folder. Exits non-zero when the agent
    /// gave no valid verdict.
    Sweep,
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
            advisories(&data_dir, config.history, &packages, &products)?;
        }
        Command::Inventory => {
            let config = load_config(&data_dir, &home()?)?;
            inventory(&Inventory::collect_mac(&config.project_dirs))?;
        }
        Command::Sweep => sweep(&data_dir, &load_config(&data_dir, &home()?)?)?,
    }
    Ok(())
}

/// Sweeps this Mac and prints the report; fails when the agent gave no valid verdict.
fn sweep(data_dir: &DataDir, config: &Config) -> anyhow::Result<()> {
    let report = sweep_mac(data_dir, config, &mut |p| show_progress(&p))?;
    print(&report_markdown(&report));
    if let Some(failure) = &report.failure {
        anyhow::bail!("sweep incomplete: {failure}");
    }
    Ok(())
}

/// Prints every advisory each source could fetch, as it arrives, and reports every failure on
/// stderr. One failing source or record never hides the rest; the command still exits
/// non-zero at the end so a script notices the gap.
fn advisories(
    data_dir: &DataDir,
    history: History,
    packages: &[Package],
    products: &[Product],
) -> anyhow::Result<()> {
    // Reading the Keychain can prompt the user, so only when NVD will be queried.
    let nvd = if products.is_empty() {
        NvdAccess::Anonymous
    } else {
        NvdAccess::from_keychain()?
    };
    let feeds = Feeds::new(data_dir, nvd);
    let mut failures = 0;
    let mut fail = |what: &str, error: &dyn std::error::Error| {
        failures += 1;
        warn(&format!("{what}: {}", error_chain(error)));
    };

    let kev = feeds.kev();
    if let Err(e) = &kev {
        fail("CISA KEV catalog, known_exploited is null", e);
    }
    let kev = kev.as_ref().ok();

    if !packages.is_empty() {
        match feeds.osv(packages, history) {
            Ok(osv) => {
                for found in &osv.advisories {
                    print(&found.advisory.to_json_line(kev));
                }
                for e in &osv.failures {
                    fail("OSV record", e);
                }
            }
            Err(e) => fail("OSV", &e),
        }
    }
    for product in products {
        match feeds.nvd(product, history) {
            Ok(found) => {
                for advisory in &found {
                    print(&advisory.to_json_line(kev));
                }
            }
            Err(e) => fail(&format!("NVD product {product}"), &e),
        }
    }

    incomplete(failures)
}

/// Prints each component as a JSON line and reports problems and missing tools on stderr.
///
/// Exits non-zero when anything could not be collected or printed, so a script sees the list is
/// incomplete. Lasting facts about this Mac that the next run would report again do not count:
/// a Homebrew name with no NVD product, crates from a registry other than crates.io, and a
/// problem npm reports in a global tree it still lists.
fn inventory(inventory: &Inventory) -> anyhow::Result<()> {
    let mut failures = 0;
    for component in &inventory.components {
        // A path that is not UTF-8 (possible on network or FAT volumes) cannot be JSON.
        match serde_json::to_string(component) {
            Ok(line) => print(&line),
            Err(e) => {
                failures += 1;
                warn(&format!(
                    "cannot print a component found in {:?}: {e}",
                    component.found_in
                ));
            }
        }
    }
    for problem in &inventory.problems {
        if problem.is_failure() {
            failures += 1;
        }
        warn(&error_chain(problem));
    }
    if !inventory.not_installed.is_empty() {
        warn(&format!(
            "not installed, so not checked: {}",
            inventory.not_installed.join(", ")
        ));
    }
    if failures > 0 {
        anyhow::bail!("{failures} inventory problem(s); the list above is incomplete");
    }
    Ok(())
}

/// Fails when any feed request failed, so a script sees that the printed output has gaps.
fn incomplete(failures: usize) -> anyhow::Result<()> {
    if failures > 0 {
        anyhow::bail!("{failures} feed request(s) failed; the output above is incomplete");
    }
    Ok(())
}

/// Renders an error and its sources as `outer: inner: innermost`.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        text.push_str(&format!(": {e}"));
        source = e.source();
    }
    text
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

#[expect(
    clippy::print_stdout,
    reason = "the CLI's one output function for results"
)]
fn print(text: &str) {
    println!("{}", text.trim_end());
}

/// Prints one progress line of a sweep on stderr.
fn show_progress(progress: &Progress<'_>) {
    let line = match progress {
        Progress::Inventory => "listing what is installed".to_owned(),
        Progress::Advisories { packages, products } => {
            format!("fetching advisories for {packages} packages and {products} NVD products")
        }
        Progress::Product {
            done,
            total,
            product,
        } => format!("NVD {done}/{total}: {product}"),
        Progress::Agent { agent, attempt: 1 } => format!("{agent} is judging the advisories"),
        Progress::Agent { agent, .. } => format!("{agent} is fixing its rejected findings"),
    };
    status(&line);
}

#[expect(
    clippy::print_stderr,
    reason = "the CLI's one output function for progress"
)]
fn status(text: &str) {
    eprintln!("{text}");
}

#[expect(
    clippy::print_stderr,
    reason = "the CLI's one output function for warnings"
)]
fn warn(text: &str) {
    eprintln!("warning: {text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_chain_joins_sources() {
        let inner = std::io::Error::other("disk on fire");
        let outer = anyhow::Error::new(inner).context("reading cache");
        let outer: &dyn std::error::Error = outer.as_ref();
        assert_eq!(error_chain(outer), "reading cache: disk on fire");
    }

    #[test]
    fn any_failure_makes_the_output_incomplete() {
        assert!(incomplete(0).is_ok());
        let err = incomplete(3).unwrap_err();
        assert_eq!(
            err.to_string(),
            "3 feed request(s) failed; the output above is incomplete"
        );
    }

    /// A path that is not UTF-8 cannot be JSON: it is reported and fails the command.
    #[test]
    fn unprintable_component_is_a_failure() {
        use std::os::unix::ffi::OsStringExt as _;

        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/p/\xff/Cargo.lock".to_vec()));
        let inventory = Inventory {
            components: vec![ancient_protector_core::Component {
                lookup: ancient_protector_core::Lookup::Package("npm:a".parse().unwrap()),
                version: "1".into(),
                found_in: ancient_protector_core::FoundIn::Lockfile { path },
            }],
            ..Inventory::default()
        };
        let err = super::inventory(&inventory).unwrap_err();
        assert_eq!(
            err.to_string(),
            "1 inventory problem(s); the list above is incomplete"
        );
        assert!(super::inventory(&Inventory::default()).is_ok());
    }

    #[test]
    fn advisories_needs_a_package_or_product() {
        let err = Cli::try_parse_from(["ancient-protector", "advisories"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let cli = Cli::try_parse_from(["ancient-protector", "advisories", "--product", "zlib"]);
        assert!(cli.is_ok());
    }
}
