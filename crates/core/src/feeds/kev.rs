//! The CISA Known Exploited Vulnerabilities catalog: CVEs exploited in the wild.
//!
//! Catalog and schema: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>. It is
//! about 2 MB, so it is downloaded whole each time rather than cached.

use std::collections::HashSet;

use serde::Deserialize;

use crate::feeds::FeedError;
use crate::feeds::Feeds;
use crate::feeds::http::decode;

/// The CVE ids in the KEV catalog.
#[derive(Debug)]
pub struct Kev {
    cves: HashSet<String>,
}

impl Kev {
    /// A catalog of exactly `ids`, for tests elsewhere in the crate.
    #[cfg(test)]
    pub(crate) fn from_ids(ids: &[&str]) -> Self {
        Self {
            cves: ids.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    /// Returns whether `id` is a CVE in the catalog.
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.cves.contains(id)
    }
}

pub(super) fn fetch(feeds: &Feeds) -> Result<Kev, FeedError> {
    let url = &feeds.endpoints.kev;
    let catalog: Catalog = decode(url, &feeds.http.get(url, &[], &[])?)?;
    Ok(Kev {
        cves: catalog
            .vulnerabilities
            .into_iter()
            .map(|v| v.cve_id)
            .collect(),
    })
}

#[derive(Debug, Deserialize)]
struct Catalog {
    vulnerabilities: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::Advisory;
    use crate::feeds::Endpoints;
    use crate::feeds::NvdAccess;
    use crate::feeds::Source;
    use crate::feeds::test_server::TestServer;

    #[test]
    fn marks_known_exploited_ids_and_aliases() {
        let server = TestServer::start(|_| {
            let body = r#"{"catalogVersion":"1","vulnerabilities":[
                {"cveID":"CVE-2024-1","vendorProject":"x"},{"cveID":"CVE-2024-2"}]}"#;
            (200, body.to_owned())
        });
        let tmp = tempfile::tempdir().unwrap();
        let feeds = Feeds::with_endpoints(
            tmp.path().to_owned(),
            NvdAccess::Anonymous,
            Endpoints {
                osv: String::new(),
                nvd: String::new(),
                kev: server.url.clone(),
            },
        );
        let kev = feeds.kev().unwrap();
        assert!(kev.contains("CVE-2024-1"));
        assert!(!kev.contains("CVE-2024-3"));

        let advisory = |id: &str, aliases: &[&str]| Advisory {
            source: Source::Osv,
            id: id.to_owned(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            modified: None,
            record: serde_json::value::RawValue::from_string("{}".to_owned()).unwrap(),
        };
        assert!(advisory("GHSA-x", &["CVE-2024-2"]).is_known_exploited(&kev));
        assert!(advisory("CVE-2024-1", &[]).is_known_exploited(&kev));
        assert!(!advisory("GHSA-y", &["CVE-2024-3"]).is_known_exploited(&kev));

        let line: serde_json::Value =
            serde_json::from_str(&advisory("GHSA-x", &["CVE-2024-2"]).to_json_line(Some(&kev)))
                .unwrap();
        assert_eq!(
            line,
            serde_json::json!({
                "source": "osv",
                "id": "GHSA-x",
                "known_exploited": true,
                "record": {},
            })
        );
        let nvd = Advisory {
            source: Source::Nvd,
            ..advisory("CVE-2024-3", &[])
        };
        let line: serde_json::Value = serde_json::from_str(&nvd.to_json_line(Some(&kev))).unwrap();
        assert_eq!(line["source"], "nvd");
        assert_eq!(line["known_exploited"], false);

        let line: serde_json::Value = serde_json::from_str(&nvd.to_json_line(None)).unwrap();
        assert!(line["known_exploited"].is_null());
    }
}
