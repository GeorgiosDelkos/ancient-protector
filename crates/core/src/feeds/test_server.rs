//! A minimal HTTP/1.1 server for feed tests: the real client talks to scripted responses.

use std::io::BufRead as _;
use std::io::BufReader;
use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::thread;

/// One request the server received.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub(crate) method: String,
    /// Path and query, as sent.
    pub(crate) target: String,
    /// Header names lowercased.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: String,
}

impl Request {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the decoded value of query parameter `name`.
    pub(crate) fn query(&self, name: &str) -> Option<String> {
        let (_, query) = self.target.split_once('?')?;
        query.split('&').find_map(|pair| {
            let (n, v) = pair.split_once('=')?;
            (n == name).then(|| percent_decode(v))
        })
    }

    pub(crate) fn path(&self) -> &str {
        self.target.split_once('?').map_or(&self.target, |(p, _)| p)
    }
}

/// Serves each request with `handler` on a background thread until the test process exits.
/// The thread is never joined: it blocks in `accept`, and the test binary ends it on exit.
#[derive(Debug)]
pub(crate) struct TestServer {
    /// `http://127.0.0.1:<port>`.
    pub(crate) url: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl TestServer {
    pub(crate) fn start(handler: impl Fn(&Request) -> (u16, String) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binding a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("bound socket"));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let log = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.expect("accepting a loopback connection");
                let request = read_request(&stream);
                let (status, body) = handler(&request);
                log.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(request);
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                // The client may have hung up after an error status; that is its business.
                drop(stream.write_all(response.as_bytes()));
            }
        });
        Self { url, requests }
    }

    /// Returns the requests received so far, in order. Responses are written after a request
    /// is logged, so every request whose response the client has read is included.
    pub(crate) fn requests(&self) -> Vec<Request> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn read_request(stream: &TcpStream) -> Request {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("reading the request line");
    let mut parts = line.split_whitespace();
    let method = parts.next().expect("a method").to_owned();
    let target = parts.next().expect("a target").to_owned();

    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).expect("reading a header");
        let Some((name, value)) = line.trim_end().split_once(':') else {
            break;
        };
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }

    let len = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .map_or(0, |(_, v)| v.parse().expect("a numeric content-length"));
    let mut body = vec![0; len];
    reader.read_exact(&mut body).expect("reading the body");
    Request {
        method,
        target,
        headers,
        body: String::from_utf8(body).expect("test bodies are UTF-8"),
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("an ASCII escape");
            out.push(u8::from_str_radix(hex, 16).expect("a hex escape"));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("test queries are UTF-8")
}
