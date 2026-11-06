//! One GitHub repository as a sweep target, collected through `gh api` with the user's login.
//!
//! Layout and decisions: spec, "GitHub repositories". Every part is fetched on its own and a
//! part that fails is a problem, so one refused endpoint never hides the rest. GitHub answers a
//! feature that is off (Dependabot alerts disabled, no code scanning, an unprotected branch)
//! with a 403 or 404 and a message; that answer is recorded as the setting's value in
//! `settings.json`, for the agent to judge, not as a failure.
//!
//! Everything here is untrusted: package names come from the repository's manifests and
//! workflow files are the repository's own text. Nothing is run; names that cannot be file
//! names are skipped.

use std::collections::BTreeMap;

use serde_json::Value;
use serde_json::json;

use crate::config::RepoSlug;
use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::inventory::command;
use crate::package::Ecosystem;
use crate::package::Package;

/// The most workflow files fetched from one repository. Arbitrary: real repositories have a
/// handful; a cap keeps a repository with thousands from stalling the sweep.
const WORKFLOW_LIMIT: usize = 100;

/// A collected repository: its components and the files that go into its bundle.
#[derive(Debug, Default)]
pub(crate) struct Repo {
    /// Packages from the dependency graph.
    pub(crate) components: Vec<Component>,
    /// Bundle files, as a path relative to the bundle (`github/settings.json`) and the text.
    pub(crate) files: Vec<(String, String)>,
    /// The keys of `github/settings.json`, which an issue may name.
    pub(crate) settings: Vec<String>,
    /// Parts that could not be collected.
    pub(crate) problems: Vec<String>,
}

/// What `gh api` answered.
#[derive(Debug)]
enum Answer {
    /// The JSON body (`null` for an empty 204 answer).
    Ok(Value),
    /// A 403 or 404 with GitHub's message: the feature is off, or the login may not see it.
    Refused { status: u16, message: String },
}

/// Collects `repo` with `gh`, the program to run.
///
/// # Errors
///
/// Fails when `gh` is not installed or the repository itself cannot be read; every later part
/// that fails is a problem in the result instead.
pub(crate) fn collect(gh: &str, repo: &RepoSlug) -> Result<Repo, GitHubError> {
    let base = format!("repos/{repo}");
    let meta = match api(gh, &base, Paging::Single)? {
        Answer::Ok(meta) => meta,
        Answer::Refused { message, .. } => {
            return Err(GitHubError::Repo {
                repo: repo.to_string(),
                message,
            });
        }
    };
    let mut out = Repo::default();
    let mut settings = BTreeMap::new();
    let branch = meta["default_branch"].as_str().unwrap_or("main").to_owned();
    settings.insert(
        "security_and_analysis".to_owned(),
        meta["security_and_analysis"].clone(),
    );
    out.files.push((
        "github/repository.json".to_owned(),
        pretty(&repository_summary(&meta)),
    ));

    out.sbom(gh, repo, &base);
    for (name, path) in [
        ("dependabot", "dependabot/alerts?state=open&per_page=100"),
        (
            "code-scanning",
            "code-scanning/alerts?state=open&per_page=100",
        ),
        (
            "secret-scanning",
            "secret-scanning/alerts?state=open&per_page=100",
        ),
    ] {
        let value = out.alerts(gh, name, &format!("{base}/{path}"));
        settings.insert(format!("{}_alerts", name.replace('-', "_")), value);
    }
    out.workflows(gh, &base, &branch);

    let parts = [
        (
            "vulnerability_alerts",
            format!("{base}/vulnerability-alerts"),
        ),
        (
            "default_branch_protection",
            format!("{base}/branches/{branch}/protection"),
        ),
        ("rulesets", format!("{base}/rulesets")),
        ("actions_permissions", format!("{base}/actions/permissions")),
        (
            "actions_workflow_permissions",
            format!("{base}/actions/permissions/workflow"),
        ),
    ];
    for (key, path) in parts {
        let value = out.setting(gh, key, &path);
        settings.insert(key.to_owned(), value);
    }
    if meta["owner"]["type"] == "Organization"
        && let Some(login) = meta["owner"]["login"].as_str()
    {
        let org = out.setting(gh, "organization", &format!("orgs/{login}"));
        // The field is there only for the organization's owners; a refusal stays as it is.
        let value = if org.get("message").is_some() {
            org
        } else {
            org.get("two_factor_requirement_enabled")
                .cloned()
                .unwrap_or_else(|| json!("not visible to this login (organization owners only)"))
        };
        settings.insert("organization_two_factor_requirement".to_owned(), value);
    }

    out.settings = settings.keys().cloned().collect();
    out.files.push((
        "github/settings.json".to_owned(),
        pretty(&Value::Object(settings.into_iter().collect())),
    ));
    Ok(out)
}

/// How many pages to ask for.
#[derive(Debug, Clone, Copy)]
enum Paging {
    Single,
    /// Every page, joined into one array.
    All,
}

impl Repo {
    /// Adds the dependency graph's packages as components, or a problem saying why not.
    fn sbom(&mut self, gh: &str, repo: &RepoSlug, base: &str) {
        let path = format!("{base}/dependency-graph/sbom");
        match api(gh, &path, Paging::Single) {
            Ok(Answer::Ok(sbom)) => {
                let (components, skipped) = components_from_sbom(&sbom, &repo.to_string());
                self.components = components;
                if !skipped.is_empty() {
                    let list: Vec<String> = skipped
                        .iter()
                        .map(|(kind, n)| format!("{kind} ({n})"))
                        .collect();
                    self.problems.push(format!(
                        "dependency graph packages in ecosystems that are not checked: {}",
                        list.join(", ")
                    ));
                }
            }
            Ok(Answer::Refused { status, message }) => self.problems.push(format!(
                "dependency graph ({status}: {message}), so the repository's dependencies were \
                 not checked; enable it under Settings, Code security"
            )),
            Err(e) => self.problems.push(format!("dependency graph: {e}")),
        }
    }

    /// Writes `github/<name>-alerts.json` and returns the setting value: the open count, or
    /// GitHub's refusal.
    fn alerts(&mut self, gh: &str, name: &str, path: &str) -> Value {
        match api(gh, path, Paging::All) {
            Ok(Answer::Ok(Value::Array(mut alerts))) => {
                for alert in &mut alerts {
                    // The secret itself never goes into the bundle or the agent's context.
                    if let Some(object) = alert.as_object_mut() {
                        object.remove("secret");
                    }
                }
                let open = alerts.len();
                self.files.push((
                    format!("github/{name}-alerts.json"),
                    pretty(&Value::Array(alerts)),
                ));
                json!({ "open": open })
            }
            Ok(Answer::Ok(other)) => {
                self.problems.push(format!(
                    "{name} alerts: expected a list, got {}",
                    kind_of(&other)
                ));
                Value::Null
            }
            Ok(Answer::Refused { status, message }) => refused(status, &message),
            Err(e) => {
                self.problems.push(format!("{name} alerts: {e}"));
                Value::Null
            }
        }
    }

    /// Adds the default branch's workflow files under `github/workflows/`.
    fn workflows(&mut self, gh: &str, base: &str, branch: &str) {
        let list = format!("{base}/contents/.github/workflows?ref={branch}");
        let entries = match api(gh, &list, Paging::Single) {
            Ok(Answer::Ok(Value::Array(entries))) => entries,
            // No workflows folder.
            Ok(Answer::Refused { status: 404, .. }) => return,
            Ok(Answer::Ok(other)) => {
                let what = kind_of(&other);
                self.problems
                    .push(format!("workflows: expected a folder listing, got {what}"));
                return;
            }
            Ok(Answer::Refused { status, message }) => {
                self.problems
                    .push(format!("workflows: {status}: {message}"));
                return;
            }
            Err(e) => {
                self.problems.push(format!("workflows: {e}"));
                return;
            }
        };
        let names: Vec<&str> = entries
            .iter()
            .filter(|e| e["type"] == "file")
            .filter_map(|e| e["name"].as_str())
            .collect();
        if names.len() > WORKFLOW_LIMIT {
            self.problems.push(format!(
                "workflows: {} files, only the first {WORKFLOW_LIMIT} were read",
                names.len()
            ));
        }
        for name in names.into_iter().take(WORKFLOW_LIMIT) {
            if !safe_file_name(name) {
                self.problems.push(format!(
                    "workflows: {name:?} is not a safe file name; not read"
                ));
                continue;
            }
            let path = format!("{base}/contents/.github/workflows/{name}?ref={branch}");
            match raw(gh, &path) {
                Ok(text) => self.files.push((format!("github/workflows/{name}"), text)),
                Err(e) => self.problems.push(format!("workflow {name}: {e}")),
            }
        }
    }

    /// One setting's value: the answer, GitHub's refusal, or `null` with a problem.
    fn setting(&mut self, gh: &str, key: &str, path: &str) -> Value {
        match api(gh, path, Paging::Single) {
            Ok(Answer::Ok(value)) => value,
            Ok(Answer::Refused { status, message }) => refused(status, &message),
            Err(e) => {
                self.problems.push(format!("setting {key}: {e}"));
                Value::Null
            }
        }
    }
}

/// The parts of `repos/{repo}` that matter to a security review, without the dozens of URLs.
fn repository_summary(meta: &Value) -> Value {
    let mut kept = serde_json::Map::new();
    for key in [
        "full_name",
        "private",
        "visibility",
        "archived",
        "fork",
        "default_branch",
        "pushed_at",
        "allow_forking",
        "has_issues",
        "has_wiki",
        "has_pages",
    ] {
        if let Some(value) = meta.get(key) {
            kept.insert(key.to_owned(), value.clone());
        }
    }
    kept.insert("owner_type".to_owned(), meta["owner"]["type"].clone());
    Value::Object(kept)
}

fn refused(status: u16, message: &str) -> Value {
    json!({ "status": status, "message": message })
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "nothing",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("a JSON value always serializes")
}

/// A workflow file name the bundle can hold: 1 to 128 ASCII letters, digits, `.`, `-` and
/// `_`, not starting with `.`.
fn safe_file_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Runs `gh api` on `path`. A 403 or 404 that GitHub explains is a [`Answer::Refused`]; any
/// other failure is an error.
fn api(gh: &str, path: &str, paging: Paging) -> Result<Answer, GitHubError> {
    let mut args = vec!["api"];
    if matches!(paging, Paging::All) {
        args.extend(["--paginate", "--slurp"]);
    }
    args.push(path);
    let output = command::run_any_status(gh, &args)?.ok_or(GitHubError::NoGh)?;
    let body: Value = if output.stdout.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&output.stdout).map_err(|e| GitHubError::Answer {
            path: path.to_owned(),
            detail: e.to_string(),
        })?
    };
    if output.success {
        return Ok(Answer::Ok(match (paging, body) {
            // `--slurp` wraps each page: `[[...], [...]]`.
            (Paging::All, Value::Array(pages)) => {
                Value::Array(pages.into_iter().flat_map(page_items).collect())
            }
            (_, body) => body,
        }));
    }
    // A failed request prints GitHub's error body, wrapped in a list under `--slurp`.
    let error = match &body {
        Value::Array(list) if list.len() == 1 => &list[0],
        other => other,
    };
    let status = error["status"]
        .as_str()
        .and_then(|s| s.parse::<u16>().ok())
        .or_else(|| error["status"].as_u64().and_then(|s| u16::try_from(s).ok()));
    match (status, error["message"].as_str()) {
        (Some(status @ (403 | 404)), Some(message)) => Ok(Answer::Refused {
            status,
            message: message.to_owned(),
        }),
        _ => Err(GitHubError::Gh(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        })),
    }
}

fn page_items(page: Value) -> Vec<Value> {
    match page {
        Value::Array(items) => items,
        other => vec![other],
    }
}

/// Fetches a file's raw text through the contents API.
fn raw(gh: &str, path: &str) -> Result<String, GitHubError> {
    let args = ["api", "-H", "Accept: application/vnd.github.raw", path];
    match command::run(gh, &args)? {
        Some(text) => Ok(text),
        None => Err(GitHubError::NoGh),
    }
}

/// The packages of an SPDX SBOM as components, and the count of packages per package-URL
/// type that cannot be looked up (ecosystems OSV is not asked about, or no package URL).
fn components_from_sbom(sbom: &Value, repo: &str) -> (Vec<Component>, BTreeMap<String, usize>) {
    let mut components = Vec::new();
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    let packages = sbom["sbom"]["packages"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    for package in packages {
        let purl = package["externalRefs"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["referenceType"] == "purl")
            .and_then(|r| r["referenceLocator"].as_str());
        let Some(purl) = purl else {
            // The repository itself is listed as a package without a package URL.
            continue;
        };
        let listed = package["versionInfo"].as_str().filter(|v| !v.is_empty());
        match parse_purl(purl) {
            Ok((package, version)) => {
                let version = version
                    .or_else(|| listed.map(str::to_owned))
                    .unwrap_or_else(|| "unknown".to_owned());
                components.push(Component {
                    lookup: Lookup::Package(package),
                    version,
                    found_in: FoundIn::DependencyGraph {
                        repo: repo.to_owned(),
                    },
                });
            }
            Err(kind) => *skipped.entry(kind).or_default() += 1,
        }
    }
    (components, skipped)
}

/// Parses a package URL (<https://github.com/package-url/purl-spec>) into a package and its
/// version, or returns its type when that type is not an ecosystem the app looks up.
fn parse_purl(purl: &str) -> Result<(Package, Option<String>), String> {
    let rest = purl
        .strip_prefix("pkg:")
        .ok_or_else(|| "not a package URL".to_owned())?;
    // Qualifiers (`?`) and a subpath (`#`) do not name the package.
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (kind, path) = rest
        .split_once('/')
        .ok_or_else(|| "not a package URL".to_owned())?;
    let ecosystem = match kind.to_ascii_lowercase().as_str() {
        "cargo" => Ecosystem::CratesIo,
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        "golang" => Ecosystem::Go,
        "gem" => Ecosystem::RubyGems,
        "githubactions" => Ecosystem::GitHubActions,
        other => return Err(other.to_owned()),
    };
    let (path, version) = match path.rsplit_once('@') {
        // `@` in npm scopes is percent-encoded, so an unencoded one starts the version.
        Some((path, version)) => (path, Some(percent_decode(version))),
        None => (path, None),
    };
    let name = path
        .split('/')
        .map(percent_decode)
        .collect::<Vec<_>>()
        .join("/");
    let package = format!("{}:{name}", ecosystem.osv_name())
        .parse()
        .map_err(|_| kind.to_owned())?;
    Ok((package, version.filter(|v| !v.is_empty())))
}

/// Decodes `%XX` escapes; a malformed escape is kept as written.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A failure that stops a repository's sweep.
#[derive(Debug, thiserror::Error)]
pub enum GitHubError {
    /// `gh` is not on `PATH`.
    #[error("gh is not installed; install it (brew install gh) and run `gh auth login`")]
    NoGh,
    /// The repository cannot be read.
    #[error(
        "cannot read {repo} on GitHub: {message} (is the name right, and can your gh login see it?)"
    )]
    Repo {
        /// The repository.
        repo: String,
        /// GitHub's message.
        message: String,
    },
    /// `gh` failed for another reason (not logged in, network).
    #[error(transparent)]
    Gh(#[from] InventoryError),
    /// `gh` printed something that is not JSON.
    #[error("unexpected answer from GitHub for {path}: {detail}")]
    Answer {
        /// The API path.
        path: String,
        /// What did not parse.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    /// A fake `gh` that answers by the API path (its last argument), as `gh api` does: JSON on
    /// stdout, exit 1 for an HTTP error, with GitHub's error body.
    const FAKE_GH: &str = r#"#!/bin/sh
for last; do :; done
d=$(dirname "$0")
ok() { cat "$d/$1.json"; }
no() { cat "$d/$1.json"; exit 1; }
refuse() { echo "{\"message\":\"$2\",\"status\":\"$1\"}"; exit 1; }
case "$last" in
  repos/o/r) ok repo ;;
  repos/o/r/dependency-graph/sbom) ok sbom ;;
  repos/o/r/dependabot/alerts*) no dependabot ;;
  repos/o/r/code-scanning/alerts*) no code-scanning ;;
  repos/o/r/secret-scanning/alerts*) ok secret-scanning ;;
  "repos/o/r/contents/.github/workflows?ref=main") ok workflows ;;
  "repos/o/r/contents/.github/workflows/ci.yml?ref=main") echo 'on: push' ;;
  repos/o/r/vulnerability-alerts) refuse 404 "Vulnerability alerts are disabled." ;;
  repos/o/r/branches/main/protection) refuse 404 "Branch not protected" ;;
  repos/o/r/rulesets) echo '[]' ;;
  repos/o/r/actions/permissions) echo '{"enabled":true,"allowed_actions":"all"}' ;;
  repos/o/r/actions/permissions/workflow) echo 'not json' ;;
  orgs/o) echo '{"login":"o","two_factor_requirement_enabled":true}' ;;
  repos/o/missing) refuse 404 "Not Found" ;;
  repos/o/offline) echo 'error connecting to api.github.com' >&2; exit 1 ;;
  *) echo "unexpected $last" >&2; exit 2 ;;
esac
"#;

    fn fake_gh(dir: &Path) -> String {
        let path = dir.join("gh");
        fs::write(&path, FAKE_GH).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let sbom = json!({"sbom": {"packages": [
            {"name": "com.github.o/r", "versionInfo": "main"},
            {"name": "lodash", "versionInfo": "4.17.20", "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}
            ]},
            {"name": "@s/p", "versionInfo": "^1.0.0", "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:npm/%40s/p"}
            ]},
            {"name": "junit", "versionInfo": "4.12", "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:maven/junit/junit@4.12"}
            ]}
        ]}});
        let fixtures = [
            ("sbom", sbom),
            (
                "repo",
                json!({
                    "default_branch": "main",
                    "private": false,
                    "owner": {"type": "Organization", "login": "o"},
                    "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
                    "url": "x"
                }),
            ),
            (
                "dependabot",
                json!([{
                    "message": "Dependabot alerts are disabled for this repository.",
                    "status": "403"
                }]),
            ),
            (
                "code-scanning",
                json!([{"message": "no analysis found", "status": "404"}]),
            ),
            (
                "secret-scanning",
                json!([
                    [{"number": 1, "secret": "hunter2", "secret_type": "t"}],
                    [{"number": 2, "secret": "x"}]
                ]),
            ),
            (
                "workflows",
                json!([
                    {"type": "file", "name": "ci.yml"},
                    {"type": "dir", "name": "sub"},
                    {"type": "file", "name": ".evil"}
                ]),
            ),
        ];
        for (name, value) in fixtures {
            fs::write(dir.join(format!("{name}.json")), value.to_string()).unwrap();
        }
        path.to_str().unwrap().to_owned()
    }

    fn slug(s: &str) -> RepoSlug {
        s.parse().unwrap()
    }

    fn file<'a>(repo: &'a Repo, name: &str) -> &'a str {
        let found = repo.files.iter().find(|(n, _)| n == name);
        &found.unwrap_or_else(|| panic!("no {name}")).1
    }

    #[test]
    fn collects_every_part_and_records_what_is_off() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = fake_gh(tmp.path());
        let repo = collect(&gh, &slug("o/r")).unwrap();

        let names: Vec<String> = repo
            .components
            .iter()
            .map(|c| match &c.lookup {
                Lookup::Package(p) => format!("{p:?} {}", c.version),
                Lookup::Product(p) => p.to_string(),
            })
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(
            names[0].contains("\"lodash\"") && names[0].ends_with(" 4.17.20"),
            "{names:?}"
        );
        assert!(
            names[1].contains("\"@s/p\"") && names[1].ends_with(" ^1.0.0"),
            "{names:?}"
        );
        let found_in = &repo.components[0].found_in;
        assert!(matches!(found_in, FoundIn::DependencyGraph { repo } if repo == "o/r"));

        let settings: Value = serde_json::from_str(file(&repo, "github/settings.json")).unwrap();
        assert_eq!(settings["dependabot_alerts"]["status"], 403);
        assert_eq!(
            settings["code_scanning_alerts"]["message"],
            "no analysis found"
        );
        assert_eq!(settings["secret_scanning_alerts"], json!({"open": 2}));
        assert_eq!(
            settings["default_branch_protection"]["message"],
            "Branch not protected"
        );
        assert_eq!(settings["rulesets"], json!([]));
        assert_eq!(settings["actions_permissions"]["allowed_actions"], "all");
        assert!(
            settings["actions_workflow_permissions"].is_null(),
            "unparsable: a problem"
        );
        assert_eq!(settings["organization_two_factor_requirement"], true);
        assert_eq!(
            settings["security_and_analysis"]["secret_scanning"]["status"],
            "enabled"
        );
        let keys: Vec<&str> = settings
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(repo.settings, keys);

        let secrets = file(&repo, "github/secret-scanning-alerts.json");
        assert!(
            !secrets.contains("hunter2"),
            "the secret is removed: {secrets}"
        );
        assert!(secrets.contains("\"secret_type\""), "{secrets}");
        assert!(
            !repo.files.iter().any(|(n, _)| n.contains("dependabot")),
            "refused: no file"
        );
        assert_eq!(file(&repo, "github/workflows/ci.yml").trim(), "on: push");
        let summary: Value = serde_json::from_str(file(&repo, "github/repository.json")).unwrap();
        assert_eq!(summary["owner_type"], "Organization");
        assert!(summary.get("url").is_none(), "{summary}");

        let problems = repo.problems.join("\n");
        assert!(problems.contains("not checked: maven (1)"), "{problems}");
        assert!(
            problems.contains("\".evil\" is not a safe file name"),
            "{problems}"
        );
        assert!(
            problems.contains("setting actions_workflow_permissions"),
            "{problems}"
        );
        assert_eq!(repo.problems.len(), 3, "{problems}");
    }

    #[test]
    fn a_repository_that_cannot_be_read_stops_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = fake_gh(tmp.path());
        let err = collect(&gh, &slug("o/missing")).unwrap_err();
        assert!(
            matches!(&err, GitHubError::Repo { message, .. } if message == "Not Found"),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("can your gh login see it"),
            "{err}"
        );

        let err = collect(&gh, &slug("o/offline")).unwrap_err();
        assert!(matches!(err, GitHubError::Gh(_)), "{err:?}");
        assert!(err.to_string().contains("error connecting"), "{err}");

        let missing = tmp.path().join("no-gh");
        let err = collect(missing.to_str().unwrap(), &slug("o/r")).unwrap_err();
        assert!(matches!(err, GitHubError::NoGh), "{err:?}");
    }

    #[test]
    fn parses_package_urls() {
        let ok = |purl: &str| {
            let (package, version) = parse_purl(purl).unwrap();
            (
                format!("{}:{}", package.ecosystem.osv_name(), package.name),
                version,
            )
        };
        let v = |s: &str| Some(s.to_owned());
        assert_eq!(
            ok("pkg:npm/%40scope/name@1.2.3"),
            ("npm:@scope/name".into(), v("1.2.3"))
        );
        assert_eq!(
            ok("pkg:cargo/serde@1.0.0"),
            ("crates.io:serde".into(), v("1.0.0"))
        );
        assert_eq!(
            ok("pkg:pypi/django@4.2?extra=x"),
            ("PyPI:django".into(), v("4.2"))
        );
        assert_eq!(
            ok("pkg:golang/github.com/cli/go-gh/v2@v2.13.0"),
            ("Go:github.com/cli/go-gh/v2".into(), v("v2.13.0"))
        );
        assert_eq!(
            ok("pkg:githubactions/actions/checkout@v4#sub"),
            ("GitHub Actions:actions/checkout".into(), v("v4"))
        );
        assert_eq!(ok("pkg:gem/rails"), ("RubyGems:rails".into(), None));
        assert_eq!(ok("pkg:npm/left-pad@"), ("npm:left-pad".into(), None));

        assert_eq!(
            parse_purl("pkg:maven/junit/junit@4.12").unwrap_err(),
            "maven"
        );
        assert_eq!(parse_purl("npm/lodash").unwrap_err(), "not a package URL");
        assert_eq!(parse_purl("pkg:npm").unwrap_err(), "not a package URL");
        assert_eq!(
            parse_purl("pkg:npm/a%0Ab@1").unwrap_err(),
            "npm",
            "control characters"
        );
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
    }

    #[test]
    fn file_names_and_answer_kinds() {
        assert!(safe_file_name("ci.yml"));
        for bad in ["", ".x", "a/b", "a b", &"a".repeat(129)] {
            assert!(!safe_file_name(bad), "{bad:?}");
        }
        assert!(safe_file_name(&"a".repeat(128)));
        assert_eq!(kind_of(&json!(null)), "nothing");
        assert_eq!(kind_of(&json!(true)), "a boolean");
        assert_eq!(kind_of(&json!(1)), "a number");
        assert_eq!(kind_of(&json!("s")), "a string");
        assert_eq!(kind_of(&json!([])), "a list");
        assert_eq!(kind_of(&json!({})), "an object");
    }
}

#[cfg(test)]
mod percent_properties {
    use std::fmt::Write as _;

    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Encoding every byte and decoding gives the text back.
        #[test]
        fn decodes_what_was_encoded(text in any::<String>()) {
            let encoded = text.bytes().fold(String::new(), |mut out, b| {
                write!(out, "%{b:02X}").expect("writing to a String cannot fail");
                out
            });
            prop_assert_eq!(percent_decode(&encoded), text);
        }
    }
}
