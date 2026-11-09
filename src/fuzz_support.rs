use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};
use http_body_util::Full;
use serde::{Deserialize, Serialize};

use crate::config::{Config, FastCgiAddress, FastCgiBackend};

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

pub(crate) struct FuzzFixture {
    pub(crate) root: PathBuf,
    pub(crate) outside_secret: &'static [u8],
    pub(crate) rules: PathBuf,
}

static FIXTURE: OnceLock<FuzzFixture> = OnceLock::new();

pub(crate) fn fixture() -> &'static FuzzFixture {
    FIXTURE.get_or_init(|| {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "project-charlotte-fuzz-{}-{unique}",
            std::process::id()
        ));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("subdir")).expect("create fuzz document root");
        std::fs::create_dir_all(&outside).expect("create fuzz outside directory");
        std::fs::write(root.join("safe.txt"), b"safe fixture").expect("write fuzz file");
        std::fs::write(root.join("response-secret.txt"), b"response contains SECRET")
            .expect("write fuzz response rule fixture");
        std::fs::write(root.join("index.html"), b"index fixture").expect("write fuzz index");
        std::fs::write(root.join("subdir/index.html"), b"subdirectory index")
            .expect("write fuzz subdirectory index");
        std::fs::write(root.join("app.php"), b"<?php echo 'fuzz'; ?>")
            .expect("write fuzz script");
        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, b"outside secret fixture")
            .expect("write outside secret file");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_file, root.join("escape.txt"))
            .expect("create outside symlink");
        let rules = base.join("modsecurity.conf");
        std::fs::write(
            &rules,
            concat!(
                "SecRuleEngine On\n",
                "SecRequestBodyAccess On\n",
                "SecResponseBodyAccess On\n",
                "SecRule ARGS:block \"@streq yes\" \"id:19871001,phase:1,deny,status:403\"\n",
                "SecRule RESPONSE_BODY \"@contains SECRET\" \"id:19871002,phase:4,deny,status:500\"\n",
            ),
        )
        .expect("write fuzz WAF rules");
        FuzzFixture {
            root,
            outside_secret: b"outside secret fixture",
            rules,
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
        index: "index.html".to_owned(),
        listing: true,
        fastcgi: vec![FastCgiBackend {
            extension: "php".to_owned(),
            address: FastCgiAddress::Tcp("127.0.0.1:9000".to_owned()),
        }],
        fastcgi_timeout: std::time::Duration::from_secs(1),
        modsecurity_rules: Vec::new(),
        modsecurity_body_limit: 16 * 1024 * 1024,
        modsecurity_response_body_limit: 1024 * 1024,
        tls: None,
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
