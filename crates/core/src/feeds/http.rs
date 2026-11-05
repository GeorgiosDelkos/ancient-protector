//! A thin blocking HTTP client shared by every feed.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::feeds::FeedError;

/// The largest response body read, in bytes. Arbitrary: well above the biggest response the
/// feeds request (an NVD page of 500 CVEs is a few MB, the KEV catalog about 2 MB), and low
/// enough that a misbehaving server cannot exhaust memory.
const BODY_LIMIT: u64 = 64 * 1024 * 1024;

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
        let config = ureq::Agent::config_builder()
            .user_agent(concat!("ancient-protector/", env!("CARGO_PKG_VERSION")))
            .timeout_global(Some(TIMEOUT))
            .tls_config(tls)
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

fn read(
    url: &str,
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<String, FeedError> {
    let http_err = |source| FeedError::Http {
        url: url.to_owned(),
        source: Box::new(source),
    };
    response
        .map_err(http_err)?
        .body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_string()
        .map_err(http_err)
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
    fn error_status_names_the_url() {
        let server = TestServer::start(|_| (403, String::new()));
        let err = Http::new()
            .get(&server.url, &[("q", "1")], &[("apiKey", "secret")])
            .unwrap_err();
        let FeedError::Http { url, source } = &err else {
            panic!("expected an HTTP error, got {err:?}");
        };
        assert_eq!(*url, format!("{}?q=1", server.url));
        assert!(matches!(**source, ureq::Error::StatusCode(403)), "{source}");
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn decode_names_the_url() {
        let err = decode::<Vec<u8>>("https://x", "not json").unwrap_err();
        assert!(matches!(err, FeedError::Decode { ref url, .. } if url == "https://x"));
    }
}
