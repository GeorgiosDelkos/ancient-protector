//! What carries over from one sweep to the next: finding keys, dismissals, and what changed
//! since the target's last sweep.
//!
//! A [`FindingKey`] names one finding or issue across sweeps, so a dismissal and the
//! comparison with the last sweep can find it again. Dismissals live in
//! `state/dismissals.json`; every write takes `state/.lock`, so two commands cannot lose each
//! other's changes, and replaces the file whole, so a sweep reading it never sees half of it.
//! A dismissal of a finding holds while its advisory's `modified` time is the one it was
//! dismissed at: a changed advisory (a new affected range, a raised score) shows it again.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;

use crate::findings::is_forging;
use crate::paths::DataDir;

/// The stable id of a finding or issue: 16 hex digits, the same in every sweep that finds it.
///
/// A finding's key hashes the target, its primary advisory, the component's lookup and where
/// it was found, but not the version, so the finding keeps its key until it is fixed. An
/// issue's key hashes the target and its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct FindingKey(u64);

impl FindingKey {
    /// The key of the parts, in order. FNV-1a, 64 bits
    /// (<https://datatracker.ietf.org/doc/html/draft-eastlake-fnv-21#section-6.1.2>): unlike
    /// std's hashers it is fixed, so keys stay valid across builds. A zero byte ends each part,
    /// so `["ab", "c"]` and `["a", "bc"]` differ; the parts are text and hold no zero byte.
    pub(crate) fn new(parts: &[&str]) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in parts.iter().flat_map(|p| p.bytes().chain([0])) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        Self(hash)
    }
}

impl fmt::Display for FindingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl FromStr for FindingKey {
    type Err = ParseFindingKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let error = || ParseFindingKeyError {
            input: s.to_owned(),
        };
        hex.then(|| u64::from_str_radix(s, 16).map_err(|_| error()))
            .ok_or_else(error)?
            .map(Self)
    }
}

impl TryFrom<String> for FindingKey {
    type Error = ParseFindingKeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<FindingKey> for String {
    fn from(key: FindingKey) -> Self {
        key.to_string()
    }
}

/// A finding key that is not 16 lowercase hex digits.
#[derive(Debug, thiserror::Error)]
#[error("{input:?} is not a finding key (16 hex digits, as shown in the report)")]
pub struct ParseFindingKeyError {
    input: String,
}

/// Why and when the user dismissed a finding or issue.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dismissal {
    /// The user's reason, one line.
    pub reason: String,
    /// When it was dismissed.
    pub at: Timestamp,
    /// The advisory's `modified` time when it was dismissed; `None` for an issue, or an
    /// advisory without one.
    pub modified: Option<Timestamp>,
}

/// The dismissals in `state/dismissals.json`.
#[derive(Debug, Default)]
pub(crate) struct Dismissals(BTreeMap<FindingKey, Dismissal>);

impl Dismissals {
    /// Reads the dismissals; no file means none.
    pub(crate) fn load(data_dir: &DataDir) -> Result<Self, StateError> {
        read_dismissals(&data_dir.state_dir().join(DISMISSALS)).map(Self)
    }

    /// The dismissal of `key`, when it still holds for an advisory last modified at
    /// `modified`.
    pub(crate) fn get(&self, key: FindingKey, modified: Option<Timestamp>) -> Option<&Dismissal> {
        self.0.get(&key).filter(|d| d.modified == modified)
    }
}

const DISMISSALS: &str = "dismissals.json";

/// Dismisses the finding or issue `key`, as it was in its newest report, for `reason`.
///
/// # Errors
///
/// Returns [`StateError::Reason`] for an empty reason or one with control characters,
/// [`StateError::UnknownKey`] when no report has `key`, and [`StateError::Read`] or
/// [`StateError::Write`] when the state files cannot be used.
pub fn dismiss(data_dir: &DataDir, key: FindingKey, reason: &str) -> Result<Dismissal, StateError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().any(is_forging) {
        return Err(StateError::Reason);
    }
    let newest = newest(&data_dir.sweeps_dir(), key).ok_or(StateError::UnknownKey { key })?;
    let dismissal = Dismissal {
        reason: reason.to_owned(),
        at: Timestamp::now(),
        modified: newest.modified,
    };
    update(data_dir, |all| {
        all.insert(key, dismissal.clone());
        Ok(dismissal)
    })
}

/// Removes the dismissal of `key`, so the finding or issue shows again.
///
/// # Errors
///
/// Returns [`StateError::NotDismissed`] when `key` is not dismissed, and [`StateError::Read`]
/// or [`StateError::Write`] when the state files cannot be used.
pub fn undismiss(data_dir: &DataDir, key: FindingKey) -> Result<Dismissal, StateError> {
    update(data_dir, |all| {
        all.remove(&key).ok_or(StateError::NotDismissed { key })
    })
}

/// Changes the dismissals under `state/.lock` and writes them back whole, unless `change`
/// fails. Returns what `change` returned.
fn update<T>(
    data_dir: &DataDir,
    change: impl FnOnce(&mut BTreeMap<FindingKey, Dismissal>) -> Result<T, StateError>,
) -> Result<T, StateError> {
    let state = data_dir.state_dir();
    let write_err = |path: &Path| {
        let path = path.to_owned();
        move |source| StateError::Write { path, source }
    };
    fs::create_dir_all(&state).map_err(write_err(&state))?;
    let lock_path = state.join(".lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(write_err(&lock_path))?;
    // Blocks: the other holder is a dismiss or undismiss command, which takes milliseconds.
    lock.lock().map_err(write_err(&lock_path))?;

    let path = state.join(DISMISSALS);
    let mut all = read_dismissals(&path)?;
    let changed = change(&mut all)?;
    let json = serde_json::to_string_pretty(&all).expect("dismissals serialize");
    let partial = state.join(format!(".{DISMISSALS}.partial"));
    fs::File::create(&partial)
        .and_then(|mut file| {
            file.write_all(json.as_bytes())?;
            file.sync_data()
        })
        .and_then(|()| fs::rename(&partial, &path))
        .map_err(write_err(&path))?;
    Ok(changed)
}

fn read_dismissals(path: &Path) -> Result<BTreeMap<FindingKey, Dismissal>, StateError> {
    let read_err = |source| StateError::Read {
        path: path.to_owned(),
        source,
    };
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|e| read_err(io::Error::new(io::ErrorKind::InvalidData, e))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(read_err(e)),
    }
}

/// What changed for a target since its last sweep with a verdict.
#[derive(Debug, Serialize)]
pub struct Changes {
    /// When that sweep started.
    pub since: Timestamp,
    /// Findings and issues it did not have.
    pub new: Vec<FindingKey>,
    /// Findings and issues it had that are gone: fixed, or no longer judged affecting.
    pub resolved: Vec<FindingKey>,
}

impl Changes {
    /// Compares `keys`, the current verdict's, with the newest earlier report of `target` in
    /// `sweeps` that has a verdict. `None` when there is none.
    pub(crate) fn since_last(
        sweeps: &Path,
        target: &str,
        keys: &BTreeSet<FindingKey>,
    ) -> Option<Self> {
        let last = saved_reports(sweeps)
            .filter(|r| r.target == target && r.failure.is_none())
            .max_by_key(|r| r.started)?;
        let before: BTreeSet<FindingKey> = last.keys().collect();
        Some(Self {
            since: last.started,
            new: keys.difference(&before).copied().collect(),
            resolved: before.difference(keys).copied().collect(),
        })
    }
}

/// What later sweeps and commands read back from a saved `report.json`.
#[derive(Debug, Deserialize)]
struct Saved {
    started: Timestamp,
    target: String,
    failure: Option<String>,
    findings: Vec<SavedEntry>,
    issues: Vec<SavedEntry>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct SavedEntry {
    key: FindingKey,
    #[serde(default)]
    modified: Option<Timestamp>,
}

impl Saved {
    fn keys(&self) -> impl Iterator<Item = FindingKey> {
        self.findings.iter().chain(&self.issues).map(|e| e.key)
    }
}

/// Every `<sweep>/<target>/report.json` under `sweeps` that parses. Reports written before
/// finding keys existed do not, and are skipped, as are unreadable ones: they hold no key to
/// compare with or dismiss.
fn saved_reports(sweeps: &Path) -> impl Iterator<Item = Saved> {
    let dirs = |dir: &Path| {
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect::<Vec<PathBuf>>()
    };
    dirs(sweeps)
        .into_iter()
        .flat_map(move |sweep| dirs(&sweep))
        .filter_map(|target| fs::read_to_string(target.join("report.json")).ok())
        .filter_map(|text| serde_json::from_str(&text).ok())
}

/// `key` as its newest report has it, when one does.
fn newest(sweeps: &Path, key: FindingKey) -> Option<SavedEntry> {
    saved_reports(sweeps)
        .filter_map(|r| {
            let entry = r.findings.iter().chain(&r.issues).find(|e| e.key == key)?;
            Some((r.started, *entry))
        })
        .max_by_key(|(started, _)| *started)
        .map(|(_, entry)| entry)
}

/// Error from reading or changing the lifecycle state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// The dismissal reason is empty or has control characters.
    #[error("the reason must be one line of text")]
    Reason,
    /// No report has the key.
    #[error("no report has finding {key}; copy the key from the newest report")]
    UnknownKey {
        /// The key.
        key: FindingKey,
    },
    /// The key is not dismissed.
    #[error("finding {key} is not dismissed")]
    NotDismissed {
        /// The key.
        key: FindingKey,
    },
    /// A state file could not be read.
    #[error("cannot read {}; fix or delete it", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A state file could not be written.
    #[error("cannot write {}", path.display())]
    Write {
        /// The file or folder.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[test]
    fn keys_are_fnv1a_of_the_parts_and_parse_back() {
        // No bytes give the offset basis. The others come from a separate implementation that
        // gives the draft's test vector for "a", 0xaf63dc4c8601ec8c.
        assert_eq!(FindingKey::new(&[]).to_string(), "cbf29ce484222325");
        assert_eq!(FindingKey::new(&[""]).to_string(), "af63bd4c8601b7df");
        assert_eq!(FindingKey::new(&["a"]).to_string(), "089be207b544f1e4");
        assert_ne!(FindingKey::new(&["ab", "c"]), FindingKey::new(&["a", "bc"]));

        let key = FindingKey::new(&["mac", "GHSA-1"]);
        assert_eq!(key.to_string().parse::<FindingKey>().unwrap(), key);
        for bad in [
            "",
            "cbf29ce48422232",
            "CBF29CE484222325",
            "cbf29ce4842223255",
            "+bf29ce484222325",
        ] {
            assert!(bad.parse::<FindingKey>().is_err(), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn every_key_round_trips(n: u64) {
            let key = FindingKey(n);
            prop_assert_eq!(key.to_string().parse::<FindingKey>().unwrap(), key);
        }
    }

    fn save(sweeps: &Path, dir: &str, report: &serde_json::Value) {
        let dir = sweeps.join(dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("report.json"), report.to_string()).unwrap();
    }

    fn report(
        started: &str,
        failure: Option<&str>,
        keys: &[FindingKey],
        modified: &str,
    ) -> serde_json::Value {
        let findings: Vec<_> = keys
            .iter()
            .map(|k| json!({"key": k, "severity": "high", "modified": modified}))
            .collect();
        json!({
            "started": started, "target": "mac", "failure": failure,
            "findings": findings, "issues": [],
        })
    }

    #[test]
    fn a_dismissal_holds_until_the_advisory_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let (kept, other) = (FindingKey(1), FindingKey(2));
        let at = "2026-11-01T00:00:00Z";
        save(
            &data_dir.sweeps_dir(),
            "s1/mac",
            &report("2026-11-05T00:00:00Z", None, &[kept], at),
        );

        assert!(matches!(
            dismiss(&data_dir, kept, " \n"),
            Err(StateError::Reason)
        ));
        assert!(matches!(
            dismiss(&data_dir, kept, "a\u{202e}b"),
            Err(StateError::Reason)
        ));
        assert!(matches!(
            dismiss(&data_dir, other, "x"),
            Err(StateError::UnknownKey { key }) if key == other
        ));
        let dismissal = dismiss(&data_dir, kept, " accepted ").unwrap();
        assert_eq!(dismissal.reason, "accepted");

        let dismissals = Dismissals::load(&data_dir).unwrap();
        let modified = Some(at.parse().unwrap());
        assert_eq!(dismissals.get(kept, modified), Some(&dismissal));
        assert_eq!(
            dismissals.get(kept, Some("2026-11-02T00:00:00Z".parse().unwrap())),
            None
        );
        assert_eq!(dismissals.get(kept, None), None);
        assert_eq!(dismissals.get(other, modified), None);

        assert_eq!(undismiss(&data_dir, kept).unwrap(), dismissal);
        assert!(matches!(
            undismiss(&data_dir, kept),
            Err(StateError::NotDismissed { .. })
        ));
        assert!(Dismissals::load(&data_dir).unwrap().0.is_empty());
    }

    #[test]
    fn a_broken_dismissals_file_is_an_error_not_an_empty_list() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        assert!(
            Dismissals::load(&data_dir).unwrap().0.is_empty(),
            "no file is no dismissals"
        );
        fs::create_dir_all(data_dir.state_dir()).unwrap();
        fs::write(data_dir.state_dir().join(DISMISSALS), "{").unwrap();
        assert!(matches!(
            Dismissals::load(&data_dir),
            Err(StateError::Read { .. })
        ));
    }

    #[test]
    fn changes_compare_with_the_newest_report_that_has_a_verdict() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path();
        let [a, b, c] = [FindingKey(1), FindingKey(2), FindingKey(3)];
        let at = "2026-11-01T00:00:00Z";
        assert!(
            Changes::since_last(sweeps, "mac", &[a].into()).is_none(),
            "no sweeps yet"
        );

        save(
            sweeps,
            "old/mac",
            &report("2026-11-03T00:00:00Z", None, &[c], at),
        );
        save(
            sweeps,
            "last/mac",
            &report("2026-11-04T00:00:00Z", None, &[a, b], at),
        );
        save(
            sweeps,
            "failed/mac",
            &report("2026-11-05T00:00:00Z", Some("agent"), &[], at),
        );
        save(
            sweeps,
            "keyless/mac",
            &json!({"started": "2026-11-06T00:00:00Z", "target": "mac"}),
        );
        let mut github = report("2026-11-06T00:00:00Z", None, &[], at);
        github["target"] = json!("github:o/r");
        save(sweeps, "other/github-o--r", &github);

        let changes = Changes::since_last(sweeps, "mac", &[a, c].into()).unwrap();
        assert_eq!(
            changes.since,
            "2026-11-04T00:00:00Z".parse::<Timestamp>().unwrap()
        );
        assert_eq!(changes.new, [c]);
        assert_eq!(changes.resolved, [b]);
    }
}
