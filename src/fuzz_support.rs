use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use bytes::Bytes;
use chrono::Utc;
use http::{
    HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version, header,
    response::Parts,
};
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, FastCgiAddress, FastCgiBackend},
    handler::ResponseBody,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct FuzzRequest {
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) version: String,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    pub(crate) body: Vec<u8>,
}

impl Default for FuzzRequest {
    fn default() -> Self {
        Self {
            method: "GET".to_owned(),
            uri: "/safe.txt".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

impl FuzzRequest {
    pub(crate) fn build(self) -> Option<Request<Full<Bytes>>> {
        let method = Method::from_bytes(self.method.as_bytes()).ok()?;
        let uri = self.uri.parse::<Uri>().ok()?;
        let version = match self.version.as_str() {
            "HTTP/0.9" => Version::HTTP_09,
            "HTTP/1.0" => Version::HTTP_10,
            "HTTP/1.1" => Version::HTTP_11,
            "HTTP/2.0" => Version::HTTP_2,
            "HTTP/3.0" => Version::HTTP_3,
            _ => return None,
        };
        let mut builder = Request::builder().method(method).uri(uri).version(version);
        let headers = builder.headers_mut()?;
        for (name, value) in self.headers {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).ok()?,
                HeaderValue::from_bytes(&value).ok()?,
            );
        }
        builder.body(Full::new(Bytes::from(self.body))).ok()
    }
}

/// Bump when the fixture layout changes so that stale copies are not reused.
const FIXTURE_VERSION: u32 = 2;

/// Content of the file that lives outside the document root. No response may
/// ever contain it.
const OUTSIDE_SECRET: &[u8] = b"outside secret fixture";

/// Marker that the fuzz ModSecurity rules block in response bodies.
pub(crate) const RESPONSE_SECRET: &[u8] = b"SECRET";

/// Size of `large.txt`. It exceeds the response-body inspection limit used by
/// the WAF target so that the streaming path is reachable.
pub(crate) const LARGE_FILE_LEN: usize = 1024 * 1024 + 8 * 1024;

const WAF_RULES: &str = concat!(
    "SecRuleEngine On\n",
    "SecRequestBodyAccess On\n",
    "SecResponseBodyAccess On\n",
    "SecRule ARGS:block \"@streq yes\" \"id:19871001,phase:1,deny,status:403\"\n",
    "SecRule RESPONSE_BODY \"@contains SECRET\" \"id:19871002,phase:4,deny,status:500\"\n",
);

pub(crate) struct FuzzFixture {
    pub(crate) root: PathBuf,
    pub(crate) outside_secret: &'static [u8],
    pub(crate) rules: PathBuf,
}

static FIXTURE: OnceLock<FuzzFixture> = OnceLock::new();

/// Regular files in the fixture, relative to its base directory.
///
/// The tree deliberately covers the request-handling branches a fuzzer cannot
/// conjure from request bytes alone: directories with and without an index,
/// file names that need escaping in listings, a FastCGI directory index, and a
/// file larger than the WAF response-inspection limit.
fn fixture_files() -> Vec<(&'static str, Vec<u8>)> {
    let large = b"0123456789abcdef"
        .iter()
        .copied()
        .cycle()
        .take(LARGE_FILE_LEN)
        .collect::<Vec<_>>();
    vec![
        ("root/safe.txt", b"safe fixture".to_vec()),
        (
            "root/response-secret.txt",
            b"response contains SECRET".to_vec(),
        ),
        ("root/index.html", b"index fixture".to_vec()),
        ("root/subdir/index.html", b"subdirectory index".to_vec()),
        ("root/app.php", b"<?php echo 'fuzz'; ?>".to_vec()),
        ("root/scripts/index.php", b"<?php echo 'index'; ?>".to_vec()),
        ("root/listing/plain.txt", b"listed file".to_vec()),
        ("root/listing/a&b <c>'d\".txt", b"escaped name".to_vec()),
        ("root/listing/nested/file.txt", b"nested file".to_vec()),
        ("root/large.txt", large),
        ("outside/secret.txt", OUTSIDE_SECRET.to_vec()),
        ("modsecurity.conf", WAF_RULES.as_bytes().to_vec()),
    ]
}

/// Symbolic links in the fixture as `(link, target)`. Targets are relative so
/// that the tree can be built in a staging directory and renamed into place.
const FIXTURE_SYMLINKS: [(&str, &str); 2] = [
    ("root/escape.txt", "../outside/secret.txt"),
    ("root/escape-dir", "../outside"),
];

fn fixture_is_complete(base: &Path, files: &[(&'static str, Vec<u8>)]) -> bool {
    files.iter().all(|(path, content)| {
        std::fs::metadata(base.join(path))
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() == content.len() as u64)
    }) && FIXTURE_SYMLINKS
        .iter()
        .all(|(link, _)| std::fs::symlink_metadata(base.join(link)).is_ok())
}

fn populate_fixture(base: &Path, files: &[(&'static str, Vec<u8>)]) {
    for (path, content) in files {
        let path = base.join(path);
        std::fs::create_dir_all(path.parent().expect("fixture file has a parent"))
            .expect("create fuzz fixture directory");
        std::fs::write(path, content).expect("write fuzz fixture file");
    }
    for (link, target) in FIXTURE_SYMLINKS {
        std::os::unix::fs::symlink(target, base.join(link)).expect("create fuzz fixture symlink");
    }
}

/// Returns the shared on-disk fixture, creating it on first use.
///
/// The fixture lives at a stable per-user path and is reused by every test
/// and fuzz process: AFL forks one process per execution, so building a fresh
/// tree each time would dominate the run and leak a directory per execution.
/// It is built in a staging directory and renamed into place so that
/// concurrent processes only ever observe a complete tree.
pub(crate) fn fixture() -> &'static FuzzFixture {
    FIXTURE.get_or_init(|| {
        let files = fixture_files();
        let temp = std::env::temp_dir();
        let name = format!(
            "project-charlotte-fuzz-fixture-v{FIXTURE_VERSION}-{}",
            nix::unistd::getuid()
        );
        let base = temp.join(&name);
        if !fixture_is_complete(&base, &files) {
            // A partial tree is left behind only by something external, such
            // as a temporary-file cleaner; discard it and rebuild.
            let _ = std::fs::remove_dir_all(&base);
            let staging = temp.join(format!(
                "{name}.staging-{}-{}",
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            populate_fixture(&staging, &files);
            if std::fs::rename(&staging, &base).is_err() {
                // Another process won the race to install the fixture.
                let _ = std::fs::remove_dir_all(&staging);
            }
            assert!(
                fixture_is_complete(&base, &files),
                "fuzz fixture is incomplete: {}",
                base.display()
            );
        }
        // Request handling compares canonical paths against the document
        // root, so the root itself must be canonical.
        let base = std::fs::canonicalize(base).expect("canonicalize fuzz fixture");
        FuzzFixture {
            root: base.join("root"),
            outside_secret: OUTSIDE_SECRET,
            rules: base.join("modsecurity.conf"),
        }
    })
}

pub(crate) fn fuzz_config(root: PathBuf) -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().expect("valid fuzz bind"),
        tls_bind: None,
        http3_bind: "127.0.0.1:8443".parse().expect("valid fuzz HTTP/3 bind"),
        root,
        config_file: None,
        vhost_dir: None,
        index: "index.html".to_owned(),
        listing: true,
        try_files: Vec::new(),
        fastcgi: vec![FastCgiBackend {
            extension: "php".to_owned(),
            address: FastCgiAddress::Tcp("127.0.0.1:9000".to_owned()),
        }],
        fastcgi_timeout: std::time::Duration::from_secs(1),
        threads: None,
        worker_threads: 2,
        modsecurity_rules: Vec::new(),
        modsecurity_body_limit: 16 * 1024 * 1024,
        modsecurity_response_body_limit: 1024 * 1024,
        tls: None,
        acme: None,
        worker: false,
        worker_uid: None,
        worker_gid: None,
    }
}

pub(crate) fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build fuzz runtime")
        .block_on(future)
}

pub(crate) fn addresses() -> (SocketAddr, SocketAddr) {
    (
        "127.0.0.1:12345".parse().expect("valid peer address"),
        "127.0.0.1:8080".parse().expect("valid local address"),
    )
}

/// A response whose body has been read to completion or to its first error.
pub(crate) struct Collected {
    pub(crate) parts: Parts,
    /// Every body byte that was delivered, including those before an error.
    pub(crate) body: Vec<u8>,
    pub(crate) error: Option<io::Error>,
}

/// Drives a response future and its body on a single runtime.
pub(crate) fn collect<F>(future: F) -> Collected
where
    F: Future<Output = Response<ResponseBody>>,
{
    run(async {
        let (parts, mut body) = future.await.into_parts();
        let mut bytes = Vec::new();
        let mut error = None;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        bytes.extend_from_slice(data);
                    }
                }
                Err(frame_error) => {
                    error = Some(frame_error);
                    break;
                }
            }
        }
        Collected {
            parts,
            body: bytes,
            error,
        }
    })
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Asserts the properties every locally generated response must satisfy:
/// nothing from outside the document root is disclosed, and the framing
/// headers describe the body that was actually produced.
pub(crate) fn assert_response_invariants(method: &Method, collected: &Collected) {
    let Collected { parts, body, error } = collected;
    assert!((100..=599).contains(&parts.status.as_u16()));
    assert!(
        !contains(body, fixture().outside_secret),
        "response disclosed a file outside the document root"
    );
    if error.is_some() || method == Method::HEAD {
        return;
    }
    if let Some(length) = parts.headers.get(header::CONTENT_LENGTH) {
        assert_eq!(
            length.to_str().ok().and_then(|value| value.parse().ok()),
            Some(body.len()),
            "Content-Length does not match the response body"
        );
    }
    if parts.status == StatusCode::PARTIAL_CONTENT
        && let Some(range) = parts.headers.get(header::CONTENT_RANGE)
    {
        let parsed = range.to_str().ok().and_then(|value| {
            let (span, total) = value.strip_prefix("bytes ")?.split_once('/')?;
            let (start, end) = span.split_once('-')?;
            Some((
                start.parse::<u64>().ok()?,
                end.parse::<u64>().ok()?,
                total.parse::<u64>().ok()?,
            ))
        });
        let Some((start, end, total)) = parsed else {
            panic!("malformed Content-Range: {range:?}");
        };
        assert!(
            start <= end && end < total,
            "Content-Range is out of bounds"
        );
        assert_eq!(
            end - start + 1,
            body.len() as u64,
            "Content-Range does not match the response body"
        );
    }
}
