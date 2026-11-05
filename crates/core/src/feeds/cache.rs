//! One JSON file per cached record, under `<feeds dir>/<kind>/<key>.json`.
//!
//! Writes go to `<key>.json.tmp`, then rename over the old file, with no fsync: a cache can be
//! rebuilt from the network, so durability is not worth a sync per record. After a crash, or
//! with two overlapping writers of one key (the spec runs one sweep at a time, but nothing here
//! enforces it), a file may be empty or partial. It then fails to parse, reads as absent, and
//! is fetched again, which is the recovery for any damage.

use std::fs;
use std::io;
use std::path::PathBuf;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::feeds::FeedError;
use crate::feeds::cache_key;

#[derive(Debug)]
pub(crate) struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, kind: &str, key: &str) -> Result<PathBuf, FeedError> {
        Ok(self
            .dir
            .join(kind)
            .join(format!("{}.json", cache_key(key)?)))
    }

    /// Returns the cached value, or `None` when there is none or it does not parse.
    ///
    /// Any other read failure (permissions, a failing disk) is an error, so it is not mistaken
    /// for an empty cache.
    pub(crate) fn read<T: DeserializeOwned>(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<T>, FeedError> {
        let path = self.path(kind, key)?;
        match fs::read_to_string(&path) {
            Ok(text) => Ok(serde_json::from_str(&text).ok()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(FeedError::Cache { path, source }),
        }
    }

    pub(crate) fn write(
        &self,
        kind: &str,
        key: &str,
        value: &impl Serialize,
    ) -> Result<(), FeedError> {
        let path = self.path(kind, key)?;
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string(value)
            .expect("cached values are records parsed from JSON, which always serialize");

        let result = path
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|()| fs::write(&tmp, text))
            .and_then(|()| fs::rename(&tmp, &path));
        result.map_err(|source: io::Error| FeedError::Cache { path, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_treats_damage_as_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().to_owned());

        assert_eq!(cache.read::<Vec<u32>>("osv", "A-1").unwrap(), None);
        cache.write("osv", "A-1", &vec![1, 2]).unwrap();
        assert_eq!(
            cache.read::<Vec<u32>>("osv", "A-1").unwrap(),
            Some(vec![1, 2])
        );

        fs::write(tmp.path().join("osv/A-1.json"), "[1, 2").unwrap();
        assert_eq!(cache.read::<Vec<u32>>("osv", "A-1").unwrap(), None);
        assert!(!tmp.path().join("osv/A-1.json.tmp").exists());
    }

    #[test]
    fn refuses_unsafe_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().join("feeds"));
        assert!(matches!(
            cache.write("osv", "../escape", &1),
            Err(FeedError::BadId { .. })
        ));
        assert!(matches!(
            cache.read::<u32>("osv", "a/b"),
            Err(FeedError::BadId { .. })
        ));
        assert!(!tmp.path().join("escape.json").exists());
    }

    #[test]
    fn unreadable_file_is_an_error_not_absent() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().to_owned());
        cache.write("osv", "A-1", &1).unwrap();
        let file = tmp.path().join("osv/A-1.json");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();

        let result = cache.read::<u32>("osv", "A-1");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(result, Err(FeedError::Cache { .. })), "{result:?}");
    }

    #[test]
    fn reports_unwritable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("file");
        fs::write(&blocker, "").unwrap();
        let cache = Cache::new(blocker);
        assert!(matches!(
            cache.write("osv", "A-1", &1),
            Err(FeedError::Cache { .. })
        ));
    }
}
