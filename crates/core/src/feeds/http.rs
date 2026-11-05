//! A thin blocking HTTP client shared by every feed.

use std::io::Read as _;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::feeds::FeedError;

/// The largest response body accepted, in bytes, counted after gzip decoding. Arbitrary: well
/// above the biggest response the feeds request (an NVD page of 500 CVEs is a few MB, the KEV
/// catalog about 2 MB), and low enough that a misbehaving server cannot exhaust memory.
const BODY_LIMIT: u64 = 64 * 1024 * 1024;

/// How much of an error response's body goes into the error, in bytes. Arbitrary: enough for
/// NVD's and OSV's one-line explanations.
const DETAIL_LIMIT: u64 = 300;

/// How long one request may take, connect to last byte. Arbitrary, generous for a slow NVD.
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub(crate) struct Http {
    agent: ureq::Agent,
}

impl Http {
    pub(crate) fn new() -> Self {
        // ureq never picks native TLS on its own, and with `native-tls-no-default` the roots
        // must be named: PlatformVerifier means the macOS trust store.
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::NativeTls)
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        // Redirects are not followed: ureq strips only `Authorization` and `Cookie` when it
        // follows one, so NVD's `apiKey` header would go to whatever host a 3xx names. No feed
        // endpoint redirects today; a 3xx becomes a `Status` error naming the URL to update.
        // Statuses are checked in `read`, so the error can carry the body's explanation.
        let config = ureq::Agent::config_builder()
            .user_agent(concat!("ancient-protector/", env!("CARGO_PKG_VERSION")))
            .timeout_global(Some(TIMEOUT))
            .tls_config(tls)
            .max_redirects(0)
            .http_status_as_error(false)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }

    /// GETs `url` with `query` and `headers` and returns the body.
    pub(crate) fn get(
        &self,
        url: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Result<String, FeedError> {
        let mut request = self.agent.get(url).query_pairs(query.iter().copied());
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let shown = with_query(url, query);
        read(&shown, request.call())
    }

    /// POSTs `body` as JSON to `url` and returns the response body.
    pub(crate) fn post_json(&self, url: &str, body: &impl Serialize) -> Result<String, FeedError> {
        let body = serde_json::to_string(body)
            .expect("request bodies are plain structs of strings, which always serialize");
        let response = self
            .agent
            .post(url)
            .header("content-type", "application/json")
            .send(body);
        read(url, response)
    }
}

/// Parses `text`, a response from `url`, as JSON.
pub(crate) fn decode<T: DeserializeOwned>(url: &str, text: &str) -> Result<T, FeedError> {
    serde_json::from_str(text).map_err(|source| FeedError::Decode {
        url: url.to_owned(),
        source,
    })
}

/// Returns the body of a 2xx response. Reads at most `BODY_LIMIT` decoded bytes: ureq's own
/// limit counts bytes before gzip decoding, so a small compressed body could otherwise expand
/// without bound.
fn read(
    url: &str,
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<String, FeedError> {
    let mut response = response.map_err(|source| FeedError::Http {
        url: url.to_owned(),
        source: Box::new(source),
    })?;
    let status = response.status().as_u16();
    let reader = response.body_mut().with_config().reader();
    let body_err = |source| FeedError::Body {
        url: url.to_owned(),
        source,
    };

    if !(200..300).contains(&status) {
        let mut detail = Vec::new();
        // The detail is best effort: the status is the error, an unreadable body adds nothing.
        drop(reader.take(DETAIL_LIMIT).read_to_end(&mut detail));
        let detail = String::from_utf8_lossy(&detail)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>()
            .trim()
            .to_owned();
        return Err(FeedError::Status {
            url: url.to_owned(),
            status,
            detail,
        });
    }

    let mut text = String::new();
    reader
        .take(BODY_LIMIT + 1)
        .read_to_string(&mut text)
        .map_err(body_err)?;
    if text.len() as u64 > BODY_LIMIT {
        return Err(FeedError::TooLarge {
            url: url.to_owned(),
            limit: BODY_LIMIT,
        });
    }
    Ok(text)
}

/// The URL as shown in errors. Query values are ids and dates; API keys go in headers.
fn with_query(url: &str, query: &[(&str, &str)]) -> String {
    let mut shown = url.to_owned();
    for (i, (name, value)) in query.iter().enumerate() {
        shown.push(if i == 0 { '?' } else { '&' });
        shown.push_str(&format!("{name}={value}"));
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::test_server::TestServer;

    #[test]
    fn get_sends_query_and_headers() {
        let server = TestServer::start(|_| (200, "{}".to_owned()));
        let body = Http::new()
            .get(
                &format!("{}/x", server.url),
                &[("a", "1"), ("b", "c:d")],
                &[("apiKey", "secret")],
            )
            .unwrap();
        assert_eq!(body, "{}");

        let request = &server.requests()[0];
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/x?a=1&b=c%3Ad");
        assert_eq!(request.header("apikey"), Some("secret"));
        assert!(
            request
                .header("user-agent")
                .unwrap()
                .starts_with("ancient-protector/")
        );
    }

    #[test]
    fn post_sends_json() {
        let server = TestServer::start(|_| (200, "[]".to_owned()));
        Http::new()
            .post_json(&server.url, &serde_json::json!({"k": "v"}))
            .unwrap();

        let request = &server.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, r#"{"k":"v"}"#);
        assert_eq!(request.header("content-type"), Some("application/json"));
    }

    #[test]
    fn error_status_names_the_url_and_reason() {
        let reason = format!("Request forbidden by rate limit\n{}", "x".repeat(1000));
        let server = TestServer::start(move |_| (403, reason.clone()));
        let err = Http::new()
            .get(&server.url, &[("q", "1")], &[("apiKey", "secret")])
            .unwrap_err();
        let FeedError::Status {
            url,
            status,
            detail,
        } = &err
        else {
            panic!("expected a status error, got {err:?}");
        };
        assert_eq!(*url, format!("{}?q=1", server.url));
        assert_eq!(*status, 403);
        assert!(
            detail.starts_with("Request forbidden by rate limit x"),
            "{detail}"
        );
        assert_eq!(detail.len() as u64, DETAIL_LIMIT);
        assert!(!err.to_string().contains("secret"));
    }

    /// Following a redirect would send NVD's `apiKey` header to the host it names.
    #[test]
    fn redirects_are_errors_and_not_followed() {
        let elsewhere = TestServer::start(|_| (200, "{}".to_owned()));
        let target = elsewhere.url.clone();
        let server = TestServer::start_raw(move |_| {
            (
                302,
                vec![("location".to_owned(), target.clone())],
                Vec::new(),
            )
        });
        let err = Http::new()
            .get(&server.url, &[], &[("apiKey", "secret")])
            .unwrap_err();
        assert!(
            matches!(err, FeedError::Status { status: 302, .. }),
            "{err:?}"
        );
        assert!(elsewhere.requests().is_empty());
    }

    /// ureq's own limit counts compressed bytes; the decoded body must be capped too.
    #[test]
    fn decoded_size_is_capped() {
        use std::io::Write as _;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk = vec![b' '; 1024 * 1024];
        for _ in 0..=BODY_LIMIT / (1024 * 1024) {
            encoder.write_all(&chunk).unwrap();
        }
        let bomb = encoder.finish().unwrap();
        assert!(
            (bomb.len() as u64) < BODY_LIMIT / 100,
            "the test body must be small"
        );

        let server = TestServer::start_raw(move |_| {
            let headers = vec![("content-encoding".to_owned(), "gzip".to_owned())];
            (200, headers, bomb.clone())
        });
        let err = Http::new().get(&server.url, &[], &[]).unwrap_err();
        assert!(matches!(err, FeedError::TooLarge { .. }), "{err:?}");
    }

    /// Responses of a few MB, like the KEV catalog and NVD pages, must fit under the limit.
    #[test]
    fn reads_multi_megabyte_bodies() {
        let big = "x".repeat(2 * 1024 * 1024);
        let expected = big.clone();
        let server = TestServer::start(move |_| (200, big.clone()));
        let body = Http::new().get(&server.url, &[], &[]).unwrap();
        assert_eq!(body.len(), expected.len());
    }

    #[test]
    fn decode_names_the_url() {
        let err = decode::<Vec<u8>>("https://x", "not json").unwrap_err();
        assert!(matches!(err, FeedError::Decode { ref url, .. } if url == "https://x"));
    }
}
