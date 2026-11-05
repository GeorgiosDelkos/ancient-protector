//! NVD CVE API 2.0, queried per product with `virtualMatchString=cpe:2.3:*:*:<product>`.
//!
//! API: <https://nvd.nist.gov/developers/vulnerabilities>. Each product's CVEs are cached in
//! one file with the time the last fetch's coverage ended. The next fetch asks only for CVEs
//! modified since then, which NVD allows for windows of at most 120 days; an older cache is
//! fetched in full again.
//!
//! Entries are never removed by a delta: a CVE whose configurations no longer name the
//! product, or that NVD rejected, stays cached until the next full fetch. That errs towards
//! showing the agent too much, which it can dismiss, rather than too little.

use std::collections::BTreeMap;
use std::fmt;
use std::process::Command;
use std::str::FromStr;
use std::sync::PoisonError;
use std::thread;
use std::time::Instant;

use jiff::SignedDuration;
use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;
use serde_json::value::RawValue;

use crate::config::History;
use crate::feeds::Advisory;
use crate::feeds::FeedError;
use crate::feeds::Feeds;
use crate::feeds::Source;
use crate::feeds::cache_key;
use crate::feeds::http::decode;
use crate::feeds::in_window;

/// NVD's maximum `lastModStartDate`..`lastModEndDate` range, in days.
const WINDOW_DAYS: i64 = 120;

/// CVEs per page. NVD allows up to 2000; 500 keeps each response a few MB. Arbitrary.
const PAGE: usize = 500;

/// The Keychain item holding an NVD API key, set with
/// `security add-generic-password -s ancient-protector -a nvd-api-key -w <key>`.
const KEYCHAIN_SERVICE: &str = "ancient-protector";
const KEYCHAIN_ACCOUNT: &str = "nvd-api-key";

/// `security` exits with 44 (`errSecItemNotFound`) when the item does not exist.
const KEYCHAIN_NOT_FOUND: i32 = 44;

/// How requests to NVD authenticate, which sets the rate limit they are paced to.
pub enum NvdAccess {
    /// No key: 5 requests per 30 seconds.
    Anonymous,
    /// An NVD API key, sent in the `apiKey` header: 50 requests per 30 seconds.
    ApiKey(String),
}

impl NvdAccess {
    /// Reads the API key from the login Keychain, falling back to [`NvdAccess::Anonymous`]
    /// when none is stored.
    ///
    /// Runs `/usr/bin/security`, which may prompt the user to allow access.
    ///
    /// # Errors
    ///
    /// Fails when `security` cannot run or exits with an error other than "not found".
    pub fn from_keychain() -> Result<Self, KeychainError> {
        let output = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", KEYCHAIN_SERVICE])
            .args(["-a", KEYCHAIN_ACCOUNT, "-w"])
            .output()
            .map_err(KeychainError::Run)?;
        from_security_output(output.status.code(), &output.stdout)
    }
}

/// The key is a secret: it never appears in `Debug` output or logs.
impl fmt::Debug for NvdAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::ApiKey(_) => f.write_str("ApiKey(..)"),
        }
    }
}

fn from_security_output(code: Option<i32>, stdout: &[u8]) -> Result<NvdAccess, KeychainError> {
    match code {
        Some(0) => {
            let key = String::from_utf8_lossy(stdout).trim().to_owned();
            if key.is_empty() {
                Ok(NvdAccess::Anonymous)
            } else {
                Ok(NvdAccess::ApiKey(key))
            }
        }
        Some(KEYCHAIN_NOT_FOUND) => Ok(NvdAccess::Anonymous),
        Some(code) => Err(KeychainError::Status(code)),
        None => Err(KeychainError::Signal),
    }
}

/// Error from [`NvdAccess::from_keychain`].
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    /// `/usr/bin/security` could not be started.
    #[error("cannot run /usr/bin/security")]
    Run(#[source] std::io::Error),
    /// `security` exited with an error other than "not found", such as access being denied.
    #[error(
        "security find-generic-password exited with {0}; allow access in Keychain Access, \
         or delete the {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} item to run without a key"
    )]
    Status(i32),
    /// `security` was killed by a signal.
    #[error("security find-generic-password was killed by a signal")]
    Signal,
}

/// A CPE product name, such as `openssl` or `node.js`, matched under any vendor.
#[derive(Debug, Clone)]
pub struct Product(String);

impl FromStr for Product {
    type Err = ParseProductError;

    /// Accepts 1 to 64 lowercase ASCII letters, digits, `.`, `-` and `_`, starting with a
    /// letter or digit: the characters CPE product names use without escaping.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ok = (1..=64).contains(&s.len())
            && s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
            });
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(ParseProductError)
        }
    }
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A string that is not a CPE product name.
#[derive(Debug, thiserror::Error)]
#[error("product must be 1-64 lowercase letters, digits, '.', '-' or '_', starting alphanumeric")]
pub struct ParseProductError;

pub(super) fn fetch(
    feeds: &Feeds,
    product: &Product,
    history: History,
) -> Result<Vec<Advisory>, FeedError> {
    let key = cache_key(&product.0)?;
    let cached: Option<ProductCache> = feeds.cache.read("nvd", key)?;
    let now = Timestamp::now();
    let window = cached
        .as_ref()
        .and_then(|c| delta_window(c.fetched_at, now));
    let mut cves = match (cached, window) {
        (Some(c), Some(_)) => c.cves,
        _ => BTreeMap::new(),
    };

    let mut first_page_time = None;
    let mut start = 0;
    loop {
        let page = request_page(feeds, product, window, start)?;
        first_page_time.get_or_insert(page.timestamp);
        let count = page.cves.len();
        cves.extend(page.cves);
        start += count;
        if count == 0 || start >= page.total_results {
            break;
        }
    }

    // The next delta starts where this fetch's coverage ends. A delta covers up to `to` on
    // the local clock, but only up to NVD's present when it answered, so the earlier of the
    // two: CVEs modified after it are picked up next time whichever clock is ahead. A full
    // fetch covers up to NVD's time at the first page; later pages were answered after it,
    // so starting there can only repeat CVEs, never skip them.
    let first_page_time = first_page_time.expect("the loop requests at least one page");
    let fetched_at = window.map_or(first_page_time, |(_, to)| to.min(first_page_time));
    let entry = ProductCache { fetched_at, cves };
    feeds.cache.write("nvd", key, &entry)?;
    Ok(advisories(entry.cves, history))
}

fn window() -> SignedDuration {
    SignedDuration::from_hours(24 * WINDOW_DAYS)
}

/// Returns the `lastModStartDate`..`lastModEndDate` range for a cache fetched at
/// `fetched_at`, or `None` when it is too old for NVD's 120-day limit and must be fetched in
/// full. The range ends at `now`, or at `fetched_at` if the local clock is behind it, since
/// NVD rejects an end before the start. The minute of slack keeps the range under the limit
/// after NVD's millisecond rounding; its size is arbitrary.
fn delta_window(fetched_at: Timestamp, now: Timestamp) -> Option<(Timestamp, Timestamp)> {
    let limit = window() - SignedDuration::from_mins(1);
    (now.duration_since(fetched_at) < limit).then(|| (fetched_at, now.max(fetched_at)))
}

/// One page of results, with each CVE's id read from its record.
struct PageData {
    total_results: usize,
    timestamp: Timestamp,
    cves: Vec<(String, Box<RawValue>)>,
}

fn request_page(
    feeds: &Feeds,
    product: &Product,
    window: Option<(Timestamp, Timestamp)>,
    start: usize,
) -> Result<PageData, FeedError> {
    let url = format!("{}/rest/json/cves/2.0", feeds.endpoints.nvd);
    let matcher = format!("cpe:2.3:*:*:{product}");
    let start = start.to_string();
    let page_size = PAGE.to_string();
    let (from, to) = window.map_or((String::new(), String::new()), |(from, to)| {
        (nvd_time(from), nvd_time(to))
    });

    let mut query = vec![
        ("virtualMatchString", matcher.as_str()),
        ("resultsPerPage", page_size.as_str()),
        ("startIndex", start.as_str()),
    ];
    if window.is_some() {
        query.push(("lastModStartDate", from.as_str()));
        query.push(("lastModEndDate", to.as_str()));
    }
    let headers: Vec<(&str, &str)> = match &feeds.nvd {
        NvdAccess::Anonymous => vec![],
        NvdAccess::ApiKey(key) => vec![("apiKey", key.as_str())],
    };

    pace(feeds);
    let text = feeds.http.get(&url, &query, &headers)?;
    let page: Page = decode(&url, &text)?;
    let cves = page
        .vulnerabilities
        .into_iter()
        .map(|item| {
            let header: CveHeader = decode(&url, item.cve.get())?;
            Ok((header.id, item.cve))
        })
        .collect::<Result<_, FeedError>>()?;
    Ok(PageData {
        total_results: page.total_results,
        timestamp: page.timestamp,
        cves,
    })
}

/// Sleeps until the pacing interval since the previous NVD request has passed. The lock is
/// held while sleeping on purpose: it serializes NVD requests from every thread.
fn pace(feeds: &Feeds) {
    let mut last = feeds
        .nvd_last
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(previous) = *last {
        thread::sleep(feeds.nvd_interval.saturating_sub(previous.elapsed()));
    }
    *last = Some(Instant::now());
}

/// NVD's timestamp format, `2026-11-04T20:18:52.330Z`.
fn nvd_time(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn advisories(cves: BTreeMap<String, Box<RawValue>>, history: History) -> Vec<Advisory> {
    cves.into_iter()
        .filter_map(|(id, record)| {
            let header = serde_json::from_str::<CveHeader>(record.get()).ok();
            let published = header.as_ref().and_then(|h| h.published);
            let modified = header.and_then(|h| h.last_modified);
            in_window(published, modified, history).then_some(Advisory {
                source: Source::Nvd,
                id,
                aliases: Vec::new(),
                published,
                record,
            })
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
struct ProductCache {
    fetched_at: Timestamp,
    cves: BTreeMap<String, Box<RawValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    total_results: usize,
    #[serde(deserialize_with = "de_nvd_time")]
    timestamp: Timestamp,
    vulnerabilities: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    cve: Box<RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveHeader {
    id: String,
    #[serde(default, deserialize_with = "de_nvd_time_opt")]
    published: Option<Timestamp>,
    #[serde(default, deserialize_with = "de_nvd_time_opt")]
    last_modified: Option<Timestamp>,
}

/// NVD writes UTC times without an offset, as `2026-11-04T20:18:52.330`.
fn parse_nvd_time(text: &str) -> Option<Timestamp> {
    let civil: jiff::civil::DateTime = text.parse().ok()?;
    civil
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|z| z.timestamp())
}

fn de_nvd_time<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
    let text = String::deserialize(d)?;
    parse_nvd_time(&text).ok_or_else(|| serde::de::Error::custom("expected an NVD timestamp"))
}

fn de_nvd_time_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.and_then(|t| parse_nvd_time(&t)))
}

#[cfg(test)]
mod tests {
    use crate::config::Since;
    use crate::feeds::cache::Cache;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::feeds::Endpoints;
    use crate::feeds::test_server::Request;
    use crate::feeds::test_server::TestServer;

    fn feeds(server: &TestServer, dir: &std::path::Path, access: NvdAccess) -> Feeds {
        let mut feeds = Feeds::with_endpoints(
            dir.to_owned(),
            access,
            Endpoints {
                osv: String::new(),
                nvd: server.url.clone(),
                kev: String::new(),
            },
        );
        feeds.nvd_interval = Duration::ZERO;
        feeds
    }

    fn cve(id: &str, published: &str) -> serde_json::Value {
        serde_json::json!({"cve": {"id": id, "published": published, "descriptions": []}})
    }

    fn page(total: usize, timestamp: &str, items: &[serde_json::Value]) -> String {
        serde_json::json!({
            "resultsPerPage": items.len(),
            "startIndex": 0,
            "totalResults": total,
            "timestamp": timestamp,
            "vulnerabilities": items,
        })
        .to_string()
    }

    fn product(name: &str) -> Product {
        name.parse().unwrap()
    }

    #[test]
    fn paginates_full_history_then_fetches_modified_window() {
        let round = Arc::new(Mutex::new(0));
        let r = Arc::clone(&round);
        let server = TestServer::start(move |request: &Request| {
            let start = request.query("startIndex").unwrap();
            match (*r.lock().unwrap(), start.as_str()) {
                (0, "0") => (
                    200,
                    page(
                        3,
                        "2026-11-01T10:00:00.000",
                        &[
                            cve("CVE-1", "2020-01-01T00:00:00.000"),
                            cve("CVE-2", "2025-06-01T00:00:00.000"),
                        ],
                    ),
                ),
                (0, "2") => (
                    200,
                    page(
                        3,
                        "2026-11-01T10:00:01.000",
                        &[cve("CVE-3", "2026-01-01T00:00:00.000")],
                    ),
                ),
                (1, "0") => (
                    200,
                    page(
                        1,
                        "2026-11-02T10:00:00.000",
                        &[serde_json::json!({"cve": {
                            "id": "CVE-2",
                            "published": "2025-06-01T00:00:00.000",
                            "v": 2,
                        }})],
                    ),
                ),
                other => panic!("unexpected request {other:?}"),
            }
        });
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path(), NvdAccess::ApiKey("k".into()));

        let ids = |advisories: &[Advisory]| -> Vec<String> {
            advisories.iter().map(|a| a.id.clone()).collect()
        };
        let first = feeds.nvd(&product("openssl"), History::All).unwrap();
        assert_eq!(ids(&first), ["CVE-1", "CVE-2", "CVE-3"]);
        assert!(matches!(first[0].source, Source::Nvd));

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].query("virtualMatchString").as_deref(),
            Some("cpe:2.3:*:*:openssl")
        );
        assert_eq!(requests[0].query("lastModStartDate"), None);
        assert_eq!(requests[0].header("apikey"), Some("k"));

        // Stand in for "the cache was written moments ago"; the window starts at NVD's time.
        let cache_file = tmp.path().join("nvd/openssl.json");
        let text = std::fs::read_to_string(&cache_file).unwrap();
        let mut cache: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(cache["fetched_at"], "2026-11-01T10:00:00Z");
        cache["fetched_at"] = Timestamp::now().to_string().into();
        std::fs::write(&cache_file, cache.to_string()).unwrap();
        let fetched_at: Timestamp = cache["fetched_at"].as_str().unwrap().parse().unwrap();

        *round.lock().unwrap() = 1;
        let since = History::Since(Since::new(jiff::civil::date(2025, 1, 1)).unwrap());
        let second = feeds.nvd(&product("openssl"), since).unwrap();
        assert_eq!(ids(&second), ["CVE-2", "CVE-3"]);
        assert!(second[0].record.get().contains(r#""v":2"#));

        let request = &server.requests()[2];
        assert_eq!(
            request.query("lastModStartDate"),
            Some(nvd_time(fetched_at))
        );
        let end: Timestamp = parse_nvd_time(
            request
                .query("lastModEndDate")
                .unwrap()
                .trim_end_matches('Z'),
        )
        .unwrap();
        // NVD times carry milliseconds, so compare against the start as NVD sees it.
        let start = parse_nvd_time(nvd_time(fetched_at).trim_end_matches('Z')).unwrap();
        assert!(end >= start && end <= Timestamp::now());
    }

    #[test]
    fn stale_cache_is_fetched_in_full() {
        let server = TestServer::start(|_: &Request| {
            (
                200,
                page(
                    1,
                    "2026-11-01T10:00:00.000",
                    &[cve("CVE-9", "2026-01-01T00:00:00.000")],
                ),
            )
        });
        let tmp = tempfile::tempdir().unwrap();
        let old = ProductCache {
            fetched_at: Timestamp::now() - window(),
            cves: BTreeMap::from([(
                "CVE-OLD".to_owned(),
                RawValue::from_string(r#"{"id":"CVE-OLD"}"#.to_owned()).unwrap(),
            )]),
        };
        Cache::new(tmp.path().to_owned())
            .write("nvd", "curl", &old)
            .unwrap();

        let advisories = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("curl"), History::All)
            .unwrap();
        let ids: Vec<_> = advisories.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-9"]);
        let request = &server.requests()[0];
        assert_eq!(request.query("lastModStartDate"), None);
        assert_eq!(request.header("apikey"), None);
    }

    #[test]
    fn month_old_cache_fetches_only_the_window() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let fetched_at = Timestamp::now() - SignedDuration::from_hours(24 * 30);
        let cached = ProductCache {
            fetched_at,
            cves: BTreeMap::from([(
                "CVE-KEPT".to_owned(),
                RawValue::from_string(r#"{"id":"CVE-KEPT"}"#.to_owned()).unwrap(),
            )]),
        };
        Cache::new(tmp.path().to_owned())
            .write("nvd", "curl", &cached)
            .unwrap();

        let advisories = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("curl"), History::All)
            .unwrap();
        let ids: Vec<_> = advisories.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-KEPT"]);
        assert_eq!(
            server.requests()[0].query("lastModStartDate"),
            Some(nvd_time(fetched_at))
        );
    }

    /// With NVD's clock ahead of ours, the delta only covered up to our `now`, so the next one
    /// must start there and not at NVD's later time, or the CVEs in between are never fetched.
    #[test]
    fn delta_coverage_ends_at_the_earlier_clock() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2999-01-01T00:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().to_owned());
        let old = ProductCache {
            fetched_at: Timestamp::now() - SignedDuration::from_hours(1),
            cves: BTreeMap::new(),
        };
        cache.write("nvd", "curl", &old).unwrap();

        let before = Timestamp::now();
        feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("curl"), History::All)
            .unwrap();
        let after: ProductCache = cache.read("nvd", "curl").unwrap().unwrap();
        assert!(after.fetched_at >= before && after.fetched_at <= Timestamp::now());
    }

    #[test]
    fn delta_window_respects_the_limit() {
        let now: Timestamp = "2026-11-05T12:00:00Z".parse().unwrap();
        let limit = window() - SignedDuration::from_mins(1);

        let fresh = now - limit + SignedDuration::from_secs(1);
        assert_eq!(delta_window(fresh, now), Some((fresh, now)));
        assert_eq!(delta_window(now - limit, now), None);
        assert_eq!(delta_window(now - window(), now), None);

        let ahead = now + SignedDuration::from_hours(1);
        assert_eq!(delta_window(ahead, now), Some((ahead, ahead)));
    }

    #[test]
    fn empty_page_ends_pagination() {
        let server =
            TestServer::start(|_: &Request| (200, page(10, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let advisories = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("zlib"), History::All)
            .unwrap();
        assert!(advisories.is_empty());
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn pacing_spaces_requests() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let mut feeds = feeds(&server, tmp.path(), NvdAccess::Anonymous);
        feeds.nvd_interval = Duration::from_millis(200);

        let begin = Instant::now();
        feeds.nvd(&product("a"), History::All).unwrap();
        feeds.nvd(&product("b"), History::All).unwrap();
        assert!(begin.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn products_are_cpe_names() {
        for good in ["openssl", "node.js", "x11", "libxml2", "go-git", "a_b"] {
            assert_eq!(product(good).to_string(), good);
        }
        for bad in [
            "",
            "OpenSSL",
            "-x",
            ".x",
            "a/b",
            "a b",
            "a:b",
            &"a".repeat(65),
        ] {
            assert!(
                matches!(bad.parse::<Product>(), Err(ParseProductError)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn keychain_output() {
        assert!(matches!(
            from_security_output(Some(0), b"abc-123\n"),
            Ok(NvdAccess::ApiKey(k)) if k == "abc-123"
        ));
        assert!(matches!(
            from_security_output(Some(0), b"\n"),
            Ok(NvdAccess::Anonymous)
        ));
        assert!(matches!(
            from_security_output(Some(44), b""),
            Ok(NvdAccess::Anonymous)
        ));
        assert!(matches!(
            from_security_output(Some(51), b""),
            Err(KeychainError::Status(51))
        ));
        assert!(matches!(
            from_security_output(None, b""),
            Err(KeychainError::Signal)
        ));
        assert_eq!(
            format!("{:?}", NvdAccess::ApiKey("secret".into())),
            "ApiKey(..)"
        );
    }

    #[test]
    fn nvd_times() {
        let ts: Timestamp = "2026-11-04T20:18:52.33Z".parse().unwrap();
        assert_eq!(nvd_time(ts), "2026-11-04T20:18:52.330Z");
        assert_eq!(parse_nvd_time("2026-11-04T20:18:52.330"), Some(ts));
        assert_eq!(parse_nvd_time("garbage"), None);
    }
}
