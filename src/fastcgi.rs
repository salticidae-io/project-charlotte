use std::{
    collections::HashSet,
    fmt::Display,
    io,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use fastcgi_client::{Client, Params, Request as FastCgiRequest, response::Content};
use futures_util::{Stream, StreamExt, stream};
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, header, request::Parts};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, BodyStream, Limited, StreamBody};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufWriter},
    net::TcpStream,
    task::spawn_blocking,
};

use crate::{
    config::{Config, FastCgiAddress, FastCgiBackend},
    handler::{self, ResponseBody},
};

const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;
const MAX_CGI_HEADER: usize = 64 * 1024;

pub struct ResolvedScript {
    path: PathBuf,
    script_name: String,
    path_info: String,
    backend: FastCgiBackend,
}

enum ScriptCandidate {
    DirectoryIndex {
        directory: PathBuf,
        index: String,
        script_name: String,
        backend: FastCgiBackend,
    },
    File {
        path: PathBuf,
        script_name: String,
        path_info: String,
        backend: FastCgiBackend,
    },
}

pub async fn resolve_script(
    relative_path: &Path,
    raw_path: &str,
    config: &Config,
) -> Option<ResolvedScript> {
    let segments = relative_path
        .components()
        .map(|component| match component {
            Component::Normal(segment) => segment.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;

    let mut candidates = Vec::new();
    if raw_path.ends_with('/')
        && let Some(backend) = backend_for_name(&config.index, config)
    {
        let mut script_segments = segments.clone();
        script_segments.push(&config.index);
        candidates.push(ScriptCandidate::DirectoryIndex {
            directory: config.root.join(relative_path),
            index: config.index.clone(),
            script_name: uri_path(&script_segments),
            backend: backend.clone(),
        });
    }

    for script_length in 1..=segments.len() {
        let Some(backend) = backend_for_name(segments[script_length - 1], config) else {
            continue;
        };
        let mut path = config.root.clone();
        for segment in &segments[..script_length] {
            path.push(segment);
        }
        let path_info = if segments.len() == script_length {
            String::new()
        } else {
            decoded_path(&segments[script_length..])
        };
        let path_info = if path_info.is_empty() && raw_path.ends_with('/') {
            "/".to_owned()
        } else if path_info.is_empty() {
            String::new()
        } else if raw_path.ends_with('/') {
            format!("{path_info}/")
        } else {
            path_info
        };
        candidates.push(ScriptCandidate::File {
            path,
            script_name: uri_path(&segments[..script_length]),
            path_info,
            backend: backend.clone(),
        });
    }

    if candidates.is_empty() {
        return None;
    }

    let root = config.root.clone();
    spawn_blocking(move || {
        candidates
            .into_iter()
            .find_map(|candidate| match candidate {
                ScriptCandidate::DirectoryIndex {
                    directory,
                    index,
                    script_name,
                    backend,
                } => {
                    let directory = std::fs::canonicalize(directory).ok()?;
                    if !directory.starts_with(&root)
                        || !std::fs::metadata(&directory).is_ok_and(|metadata| metadata.is_dir())
                    {
                        return None;
                    }
                    let path = std::fs::canonicalize(directory.join(index)).ok()?;
                    if !path.starts_with(&root)
                        || !std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
                    {
                        return None;
                    }
                    Some(ResolvedScript {
                        path,
                        script_name,
                        path_info: String::new(),
                        backend,
                    })
                }
                ScriptCandidate::File {
                    path,
                    script_name,
                    path_info,
                    backend,
                } => {
                    let path = std::fs::canonicalize(path).ok()?;
                    if !path.starts_with(&root)
                        || !std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
                    {
                        return None;
                    }
                    Some(ResolvedScript {
                        path,
                        script_name,
                        path_info,
                        backend,
                    })
                }
            })
    })
    .await
    .ok()
    .flatten()
}

fn backend_for_name<'a>(name: &str, config: &'a Config) -> Option<&'a FastCgiBackend> {
    let extension = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    config
        .fastcgi
        .iter()
        .find(|backend| backend.extension == extension)
}

fn uri_path(segments: &[&str]) -> String {
    let mut path = String::new();
    for segment in segments {
        path.push('/');
        for byte in segment.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                path.push(char::from(byte));
            } else {
                path.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    path
}

fn decoded_path(segments: &[&str]) -> String {
    if segments.is_empty() {
        String::new()
    } else {
        format!("/{}", segments.join("/"))
    }
}

pub async fn handle_request<B>(
    request: http::Request<B>,
    config: &Config,
    script: ResolvedScript,
    peer: SocketAddr,
    local: SocketAddr,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, request_body) = request.into_parts();
    // A client that never finishes its body must not hold the request open.
    let collecting = Limited::new(request_body, MAX_REQUEST_BODY).collect();
    let collected = match tokio::time::timeout(config.fastcgi_timeout, collecting).await {
        Err(_) => {
            return handler::error_response(
                StatusCode::REQUEST_TIMEOUT,
                "Request body timed out\n",
            );
        }
        Ok(Ok(body)) => body,
        Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
            return handler::error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body too large\n",
            );
        }
        Ok(Err(_)) => {
            return handler::error_response(StatusCode::BAD_REQUEST, "Invalid request body\n");
        }
    };
    let request_body = collected.to_bytes();
    let params = build_params(&parts, &script, config, peer, local, request_body.len());
    let timeout = config.fastcgi_timeout;
    let operation = async move {
        match script.backend.address {
            FastCgiAddress::Tcp(address) => {
                let stream = TcpStream::connect(address.as_str())
                    .await
                    .map_err(|error| error.to_string())?;
                execute(stream, params, request_body, timeout).await
            }
            FastCgiAddress::Unix(path) => {
                #[cfg(unix)]
                {
                    let stream = tokio::net::UnixStream::connect(path)
                        .await
                        .map_err(|error| error.to_string())?;
                    execute(stream, params, request_body, timeout).await
                }
                #[cfg(not(unix))]
                {
                    let _ = (path, params, request_body);
                    Err("Unix FastCGI sockets are not supported on this platform".to_owned())
                }
            }
            FastCgiAddress::Pool(pool) => {
                let lease = pool.acquire().await.map_err(|error| error.to_string())?;
                let stream = tokio::net::UnixStream::connect(lease.socket_path())
                    .await
                    .map_err(|error| error.to_string())?;
                execute(stream, params, request_body, timeout)
                    .await
                    .map(|response| hold_worker_lease(response, lease))
            }
            FastCgiAddress::Spawn(app) => Err(format!(
                "FastCGI app {} was not started",
                app.program.display()
            )),
        }
    };

    match tokio::time::timeout(timeout, operation).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            eprintln!("FastCGI request failed: {error}");
            handler::error_response(StatusCode::BAD_GATEWAY, "FastCGI backend failed\n")
        }
        Err(_) => {
            handler::error_response(StatusCode::GATEWAY_TIMEOUT, "FastCGI backend timed out\n")
        }
    }
}

fn hold_worker_lease(
    response: Response<ResponseBody>,
    lease: crate::fastcgi_app::WorkerLease,
) -> Response<ResponseBody> {
    let (parts, body) = response.into_parts();
    let stream = stream::unfold(
        (BodyStream::new(body), Some(lease)),
        |(mut body, lease)| async move {
            match body.next().await {
                Some(frame) => Some((frame, (body, lease))),
                None => {
                    drop(lease);
                    None
                }
            }
        },
    );
    Response::from_parts(parts, StreamBody::new(stream).boxed_unsync())
}

fn build_params(
    parts: &Parts,
    script: &ResolvedScript,
    config: &Config,
    peer: SocketAddr,
    local: SocketAddr,
    content_length: usize,
) -> Params<'static> {
    let path = parts.uri.path();
    let request_uri = parts
        .extensions
        .get::<handler::OriginalUri>()
        .map(|uri| uri.0.clone())
        .unwrap_or_else(|| {
            parts
                .uri
                .query()
                .map_or_else(|| path.to_owned(), |query| format!("{path}?{query}"))
        });
    let server_name = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<http::uri::Authority>().ok())
        .map(|authority| authority.host().to_owned())
        .or_else(|| {
            parts
                .uri
                .authority()
                .map(|authority| authority.host().to_owned())
        })
        .unwrap_or_else(|| local.ip().to_string());
    let protocol = match parts.version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut params = Params::default()
        .custom("GATEWAY_INTERFACE", "CGI/1.1")
        .custom("SERVER_SOFTWARE", "project-charlotte")
        .custom("SERVER_PROTOCOL", protocol.to_owned())
        .custom("REQUEST_METHOD", parts.method.as_str().to_owned())
        .custom(
            "SCRIPT_FILENAME",
            script.path.to_string_lossy().into_owned(),
        )
        .custom("SCRIPT_NAME", script.script_name.clone())
        .custom("PATH_INFO", script.path_info.clone())
        .custom(
            "PATH_TRANSLATED",
            if script.path_info.is_empty() {
                String::new()
            } else {
                config
                    .root
                    .join(script.path_info.trim_start_matches('/'))
                    .to_string_lossy()
                    .into_owned()
            },
        )
        .custom(
            "QUERY_STRING",
            parts.uri.query().unwrap_or_default().to_owned(),
        )
        .custom("REQUEST_URI", request_uri)
        .custom("DOCUMENT_ROOT", config.root.to_string_lossy().into_owned())
        .custom("DOCUMENT_URI", path.to_owned())
        .custom("REMOTE_ADDR", peer.ip().to_string())
        .custom("REMOTE_PORT", peer.port().to_string())
        .custom("SERVER_ADDR", local.ip().to_string())
        .custom("SERVER_PORT", local.port().to_string())
        .custom("SERVER_NAME", server_name)
        .custom("CONTENT_TYPE", content_type)
        .custom("CONTENT_LENGTH", content_length.to_string())
        .custom("REDIRECT_STATUS", "200");
    // Applications use these to decide whether to mark cookies secure and
    // which scheme to put in the links and redirects they generate.
    let secure = parts.extensions.get::<crate::vhost::TlsSni>().is_some();
    params = params.custom("REQUEST_SCHEME", if secure { "https" } else { "http" });
    if secure {
        params = params.custom("HTTPS", "on");
    }

    let connection_headers = parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect::<HashSet<_>>();
    for name in parts.headers.keys() {
        // `X_Real-IP` and `X-Real-IP` would both become `HTTP_X_REAL_IP`,
        // letting a client shadow a header the application trusts.
        if is_cgi_excluded_header(name, &connection_headers) || name.as_str().contains('_') {
            continue;
        }
        let key = format!(
            "HTTP_{}",
            name.as_str()
                .bytes()
                .map(|byte| match byte {
                    b'a'..=b'z' => char::from(byte - b'a' + b'A'),
                    b'-' => '_',
                    _ => char::from(byte),
                })
                .collect::<String>()
        );
        let separator = if name == header::COOKIE { "; " } else { ", " };
        let value = parts
            .headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join(separator);
        params = params.custom(key, value);
    }
    params
}

fn is_cgi_excluded_header(name: &HeaderName, connection_headers: &HashSet<String>) -> bool {
    name == header::CONTENT_TYPE
        || name == header::CONTENT_LENGTH
        || name == header::CONNECTION
        || name.as_str() == "keep-alive"
        || name == header::PROXY_AUTHENTICATE
        || name == header::PROXY_AUTHORIZATION
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || name.as_str() == "proxy"
        || connection_headers.contains(name.as_str())
}

async fn execute<S>(
    stream: S,
    params: Params<'static>,
    request_body: Bytes,
    timeout: Duration,
) -> Result<Response<ResponseBody>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client = Client::new_tokio(BufWriter::with_capacity(64 * 1024, stream));
    let stdin = tokio::io::BufReader::new(std::io::Cursor::new(request_body));
    let request = FastCgiRequest::new_tokio(params, stdin);
    let mut output = client
        .execute_once_stream(request)
        .await
        .map_err(|error| error.to_string())?;
    let mut stdout = BytesMut::new();

    loop {
        match output.next().await {
            Some(Ok(Content::Stdout(chunk))) => {
                stdout.extend_from_slice(&chunk);
                if let Some((header_end, delimiter_length)) = find_header_end(&stdout) {
                    if header_end > MAX_CGI_HEADER {
                        return Err("FastCGI response headers exceeded the limit".to_owned());
                    }
                    let parsed = parse_cgi_headers(&stdout[..header_end])?;
                    let body_start = header_end + delimiter_length;
                    let initial_body = Bytes::copy_from_slice(&stdout[body_start..]);
                    let body =
                        handler::coalesce_ready_body(response_body(output, initial_body, timeout));
                    let mut response = handler::response(parsed.status, body);
                    for (name, value) in &parsed.headers {
                        response.headers_mut().append(name.clone(), value.clone());
                    }
                    return Ok(response);
                }
                if stdout.len() > MAX_CGI_HEADER {
                    return Err("FastCGI response headers exceeded the limit".to_owned());
                }
            }
            Some(Ok(Content::Stderr(chunk))) => log_stderr(&chunk),
            Some(Err(error)) => return Err(error.to_string()),
            None => return Err("FastCGI response ended before CGI headers".to_owned()),
        }
    }
}

struct ParsedHeaders {
    status: StatusCode,
    headers: HeaderMap,
}

fn parse_cgi_headers(bytes: &[u8]) -> Result<ParsedHeaders, String> {
    let mut fields = Vec::new();
    let mut connection_headers = HashSet::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| "malformed FastCGI response header".to_owned())?;
        let name = HeaderName::from_bytes(&line[..colon])
            .map_err(|_| "invalid FastCGI response header name".to_owned())?;
        let value = trim_ascii(&line[colon + 1..]);
        if name == header::CONNECTION {
            for token in value.split(|byte| *byte == b',') {
                if let Ok(token) = std::str::from_utf8(trim_ascii(token)) {
                    connection_headers.insert(token.to_ascii_lowercase());
                }
            }
        }
        fields.push((name, value.to_vec()));
    }

    let mut status = None;
    let mut location = false;
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        if name.as_str().eq_ignore_ascii_case("status") {
            let value = std::str::from_utf8(&value)
                .map_err(|_| "invalid FastCGI status header".to_owned())?;
            let code = value
                .split_ascii_whitespace()
                .next()
                .ok_or_else(|| "empty FastCGI status header".to_owned())?
                .parse::<u16>()
                .map_err(|_| "invalid FastCGI status code".to_owned())?;
            if !(100..=599).contains(&code) {
                return Err("invalid FastCGI status code".to_owned());
            }
            status = Some(
                StatusCode::from_u16(code).map_err(|_| "invalid FastCGI status code".to_owned())?,
            );
            continue;
        }
        if name == header::LOCATION {
            location = true;
        }
        if is_hop_by_hop_response_header(&name, &connection_headers)
            || name == header::SERVER
            || name == header::DATE
        {
            continue;
        }
        let value = HeaderValue::from_bytes(&value)
            .map_err(|_| "invalid FastCGI response header value".to_owned())?;
        headers.append(name, value);
    }

    Ok(ParsedHeaders {
        status: status.unwrap_or(if location {
            StatusCode::FOUND
        } else {
            StatusCode::OK
        }),
        headers,
    })
}

fn is_hop_by_hop_response_header(name: &HeaderName, connection_headers: &HashSet<String>) -> bool {
    name == header::CONNECTION
        || name.as_str() == "keep-alive"
        || name == header::PROXY_AUTHENTICATE
        || name == header::PROXY_AUTHORIZATION
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || connection_headers.contains(name.as_str())
}

fn find_header_end(bytes: &[u8]) -> Option<(usize, usize)> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| (offset, 4))
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|offset| (offset, 2))
        })
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn response_body<S, E>(output: S, initial_body: Bytes, timeout: Duration) -> ResponseBody
where
    S: Stream<Item = Result<Content, E>> + Unpin + Send + 'static,
    E: Display + Send + 'static,
{
    let chunks = stream::unfold(
        (Some(initial_body), output),
        move |(initial_body, mut output)| async move {
            if let Some(bytes) = initial_body
                && !bytes.is_empty()
            {
                return Some((Ok(Frame::data(bytes)), (None, output)));
            }
            loop {
                match tokio::time::timeout(timeout, output.next()).await {
                    Err(_) => {
                        return Some((
                            Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "FastCGI response timed out",
                            )),
                            (None, output),
                        ));
                    }
                    Ok(Some(Ok(Content::Stdout(bytes)))) if !bytes.is_empty() => {
                        return Some((Ok(Frame::data(bytes)), (None, output)));
                    }
                    Ok(Some(Ok(Content::Stdout(_)))) => {}
                    Ok(Some(Ok(Content::Stderr(bytes)))) => log_stderr(&bytes),
                    Ok(Some(Err(error))) => {
                        return Some((Err(io::Error::other(error.to_string())), (None, output)));
                    }
                    Ok(None) => return None,
                }
            }
        },
    );
    StreamBody::new(chunks).boxed_unsync()
}

fn log_stderr(bytes: &[u8]) {
    if !bytes.is_empty() {
        eprintln!(
            "FastCGI stderr: {}",
            String::from_utf8_lossy(bytes).trim_end()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{build_params, execute, parse_cgi_headers, resolve_script};
    use crate::{
        config::{Config, FastCgiAddress, FastCgiBackend},
        fuzz_support::{self, FuzzRequest},
        handler::decode_request_path,
    };
    use http::StatusCode;
    use http_body::Body;
    use http_body_util::BodyExt;
    use std::{
        net::SocketAddr,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn test_config(root: PathBuf) -> Config {
        Config {
            bind: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            tls_bind: None,
            http3_bind: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            root,
            config_file: None,
            vhost_dir: None,
            index: "index.php".to_owned(),
            listing: true,
            try_files: Vec::new(),
            fastcgi: vec![FastCgiBackend {
                extension: "php".to_owned(),
                address: FastCgiAddress::Tcp("127.0.0.1:9000".to_owned()),
            }],
            fastcgi_timeout: Duration::from_secs(60),
            threads: None,
            worker_threads: 2,
            modsecurity_rules: Vec::new(),
            modsecurity_block_status: None,
            modsecurity_body_limit: 16 * 1024 * 1024,
            modsecurity_response_body_limit: 1024 * 1024,
            tls: None,
            acme: None,
            worker: false,
            worker_uid: None,
            worker_gid: None,
            master_user: None,
            master_group: None,
        }
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "project-charlotte-fastcgi-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn parses_status_location_and_rejects_malformed_cgi_headers() {
        let status = parse_cgi_headers(b"Status: 201 Created\r\nX-Test: value\r\n\r\n").unwrap();
        assert_eq!(status.status, StatusCode::CREATED);
        assert_eq!(status.headers["x-test"], "value");

        let redirect = parse_cgi_headers(b"Location: /next\r\n\r\n").unwrap();
        assert_eq!(redirect.status, StatusCode::FOUND);

        assert!(parse_cgi_headers(b"Broken header\r\n\r\n").is_err());
        assert!(parse_cgi_headers(b"Status: 999 Nope\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn resolves_script_path_info_index_and_rejects_traversal() {
        let root = temp_root();
        tokio::fs::create_dir_all(root.join("folder"))
            .await
            .unwrap();
        tokio::fs::write(root.join("app.php"), "<?php")
            .await
            .unwrap();
        tokio::fs::write(root.join("folder/index.php"), "<?php")
            .await
            .unwrap();
        let config = test_config(tokio::fs::canonicalize(&root).await.unwrap());

        let relative = decode_request_path("/app.php/extra/path").unwrap();
        let script = resolve_script(&relative, "/app.php/extra/path", &config)
            .await
            .unwrap();
        assert_eq!(script.script_name, "/app.php");
        assert_eq!(script.path_info, "/extra/path");

        let relative = decode_request_path("/folder/").unwrap();
        let script = resolve_script(&relative, "/folder/", &config)
            .await
            .unwrap();
        assert_eq!(script.script_name, "/folder/index.php");
        assert!(script.path_info.is_empty());
        assert!(decode_request_path("/%2e%2e/secret.php").is_none());

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn builds_cgi_parameters_and_omits_http_proxy() {
        use super::ResolvedScript;

        let config = test_config(PathBuf::from("/var/www"));
        let script = ResolvedScript {
            path: PathBuf::from("/var/www/app.php"),
            script_name: "/app.php".to_owned(),
            path_info: "/info".to_owned(),
            backend: config.fastcgi[0].clone(),
        };
        let request = http::Request::builder()
            .method("POST")
            .uri("/app.php/info?item=1")
            .header("Host", "example.test")
            .header("Content-Type", "text/plain")
            .header("X-Test", "present")
            .header("Proxy", "untrusted")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let params = build_params(
            &parts,
            &script,
            &config,
            "192.0.2.1:12345".parse().unwrap(),
            "192.0.2.10:8080".parse().unwrap(),
            7,
        );

        assert_eq!(params["REQUEST_METHOD"], "POST");
        assert_eq!(params["QUERY_STRING"], "item=1");
        assert_eq!(params["PATH_INFO"], "/info");
        assert_eq!(params["PATH_TRANSLATED"], "/var/www/info");
        assert_eq!(params["HTTP_X_TEST"], "present");
        assert!(!params.contains_key("HTTP_PROXY"));
        assert_eq!(params["CONTENT_LENGTH"], "7");

        let mut request = http::Request::builder()
            .uri("/app.php/info?item=1")
            .body(())
            .unwrap();
        request.extensions_mut().insert(crate::handler::OriginalUri(
            "/front.php?original=1".to_owned(),
        ));
        let (parts, ()) = request.into_parts();
        let params = build_params(
            &parts,
            &script,
            &config,
            "192.0.2.1:12345".parse().unwrap(),
            "192.0.2.10:8080".parse().unwrap(),
            0,
        );
        assert_eq!(params["REQUEST_URI"], "/front.php?original=1");
    }

    /// Headers that describe the backend connection, or that the server sets
    /// itself, must never be copied from a CGI response.
    fn assert_backend_headers_filtered(headers: &http::HeaderMap) {
        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "status",
        ] {
            assert!(
                !headers.contains_key(name),
                "CGI response header was forwarded: {name}"
            );
        }
    }

    #[test]
    fn drops_underscore_headers_and_reports_the_client_scheme() {
        let config = test_config(PathBuf::from("/var/www"));
        let script = super::ResolvedScript {
            path: PathBuf::from("/var/www/app.php"),
            script_name: "/app.php".to_owned(),
            path_info: String::new(),
            backend: config.fastcgi[0].clone(),
        };
        let build = |secure: bool| {
            let mut request = http::Request::builder()
                .uri("/app.php")
                .header("X-Real-IP", "198.51.100.7")
                .header("X_Real-IP", "spoofed")
                .body(())
                .unwrap();
            if secure {
                request.extensions_mut().insert(crate::vhost::TlsSni(None));
            }
            let (parts, ()) = request.into_parts();
            build_params(
                &parts,
                &script,
                &config,
                "192.0.2.1:12345".parse().unwrap(),
                "192.0.2.10:8080".parse().unwrap(),
                0,
            )
        };
        let plain = build(false);
        assert_eq!(plain["HTTP_X_REAL_IP"], "198.51.100.7");
        assert_eq!(plain["REQUEST_SCHEME"], "http");
        assert!(!plain.contains_key("HTTPS"));
        let secure = build(true);
        assert_eq!(secure["REQUEST_SCHEME"], "https");
        assert_eq!(secure["HTTPS"], "on");
    }

    #[test_fuzz::test_fuzz]
    fn cgi_headers(stdout: Vec<u8>) {
        if let Ok(parsed) = parse_cgi_headers(&stdout) {
            assert!((100..=599).contains(&parsed.status.as_u16()));
            assert_backend_headers_filtered(&parsed.headers);
            assert!(!parsed.headers.contains_key("server"));
            assert!(!parsed.headers.contains_key("date"));
        }
    }

    #[test]
    fn fuzz_seed_cgi_headers() {
        cgi_headers(b"Status: 201 Created\r\nContent-Type: text/plain\r\n\r\n".to_vec());
        cgi_headers(b"malformed header\r\n".to_vec());
        cgi_headers(
            b"Connection: close, X-Private\r\nX-Private: 1\r\nServer: backend\r\nLocation: /next\r\n"
                .to_vec(),
        );
    }

    #[test_fuzz::test_fuzz]
    fn fastcgi_request(request: FuzzRequest, stdout_chunks: Vec<Vec<u8>>, stderr: Vec<u8>) {
        let Some(request) = request.build() else {
            return;
        };
        let fixture = fuzz_support::fixture();
        let Ok(root) = std::fs::canonicalize(&fixture.root) else {
            return;
        };
        let mut config = fuzz_support::fuzz_config(root.clone());
        // Makes `scripts/index.php` reachable as a directory index.
        config.index = "index.php".to_owned();
        let uri = request.uri().clone();
        let Some(relative) = decode_request_path(uri.path()) else {
            return;
        };
        let Some(script) = fuzz_support::run(resolve_script(&relative, uri.path(), &config)) else {
            return;
        };
        assert!(script.path.starts_with(&root));

        let (peer, local) = fuzz_support::addresses();
        let request_body = request.body().clone();
        let (parts, _) = request.into_parts();
        let params = build_params(
            &parts,
            &script,
            &config,
            peer,
            local,
            request_body.size_hint().exact().unwrap_or_default() as usize,
        );
        assert!(!params.contains_key("HTTP_PROXY"));
        assert_eq!(params["SCRIPT_FILENAME"], script.path.to_string_lossy());

        fuzz_support::run(async move {
            let (client, mut server) = tokio::io::duplex(1024 * 1024);
            let responder = tokio::spawn(async move {
                loop {
                    let mut header = [0; 8];
                    if server.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let content_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
                    let padding_length = usize::from(header[6]);
                    let mut content = vec![0; content_length];
                    if server.read_exact(&mut content).await.is_err() {
                        return;
                    }
                    if padding_length > 0 {
                        let mut padding = vec![0; padding_length];
                        if server.read_exact(&mut padding).await.is_err() {
                            return;
                        }
                    }
                    if header[1] == 5 && content.is_empty() {
                        break;
                    }
                }
                for chunk in stdout_chunks {
                    write_records(&mut server, 6, &chunk).await;
                }
                for chunk in stderr.chunks(60_000) {
                    write_record(&mut server, 7, chunk).await;
                }
                write_record(&mut server, 6, &[]).await;
                write_record(&mut server, 3, &[0; 8]).await;
                let _ = server.flush().await;
            });
            let body = request_body
                .collect()
                .await
                .map(|collected| collected.to_bytes())
                .unwrap_or_default();
            let result = execute(client, params, body, Duration::from_secs(1)).await;
            if let Ok(response) = result {
                assert_backend_headers_filtered(response.headers());
                assert_eq!(response.headers().get_all("server").iter().count(), 1);
                assert_eq!(response.headers().get_all("date").iter().count(), 1);
                let _ = response.into_body().collect().await;
            }
            let _ = responder.await;
        });
    }

    #[test]
    fn fuzz_seed_fastcgi_request() {
        fastcgi_request(
            FuzzRequest {
                uri: "/app.php/extra?x=1".to_owned(),
                headers: vec![
                    ("Host".to_owned(), b"example.test".to_vec()),
                    ("Proxy".to_owned(), b"untrusted".to_vec()),
                ],
                ..FuzzRequest::default()
            },
            vec![b"Content-Type: text/plain\r\n\r\nresponse".to_vec()],
            Vec::new(),
        );
        fastcgi_request(FuzzRequest::default(), Vec::new(), Vec::new());
        fastcgi_request(
            FuzzRequest {
                method: "POST".to_owned(),
                uri: "/scripts/".to_owned(),
                body: b"a=1".to_vec(),
                ..FuzzRequest::default()
            },
            vec![
                b"Status: 404 Not Found\r\nConnection: close\r\n".to_vec(),
                b"\r\nmissing".to_vec(),
            ],
            b"warning".to_vec(),
        );
    }

    /// Feeds the FastCGI client an arbitrary byte stream in place of a
    /// backend, covering record framing that `fastcgi_request` always gets
    /// right: bad versions, lengths, padding, record types, and truncation.
    #[test_fuzz::test_fuzz]
    fn fastcgi_backend_stream(request_body: Vec<u8>, backend: Vec<u8>) {
        fuzz_support::run(async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let (mut reader, mut writer) = tokio::io::split(server);
            let drain = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
            });
            let respond = tokio::spawn(async move {
                let _ = writer.write_all(&backend).await;
                let _ = writer.shutdown().await;
            });
            let params = fastcgi_client::Params::default()
                .custom("REQUEST_METHOD", "POST")
                .custom("SCRIPT_FILENAME", "/app.php");
            let exchange = async {
                let result = execute(
                    client,
                    params,
                    bytes::Bytes::from(request_body),
                    Duration::from_secs(1),
                )
                .await;
                if let Ok(response) = result {
                    assert_backend_headers_filtered(response.headers());
                    let _ = response.into_body().collect().await;
                }
            };
            // The backend closes its end after replying, so the client must
            // finish on its own rather than wait for the request timeout.
            assert!(
                tokio::time::timeout(Duration::from_secs(10), exchange)
                    .await
                    .is_ok(),
                "FastCGI client hung on a backend that closed the connection"
            );
            let _ = respond.await;
            let _ = drain.await;
        });
    }

    #[test]
    fn fuzz_seed_fastcgi_backend_stream() {
        let well_formed = fuzz_support::run(async {
            let mut stream = Vec::new();
            write_record(&mut stream, 7, b"notice").await;
            write_records(&mut stream, 6, b"Content-Type: text/plain\r\n\r\nbody").await;
            write_record(&mut stream, 6, &[]).await;
            write_record(&mut stream, 3, &[0; 8]).await;
            stream
        });
        let mut truncated = well_formed.clone();
        truncated.truncate(well_formed.len() - 11);
        fastcgi_backend_stream(b"a=1".to_vec(), well_formed);
        fastcgi_backend_stream(Vec::new(), truncated);
        fastcgi_backend_stream(Vec::new(), vec![1, 6, 0, 1, 0xff, 0xff, 0xff, 0]);
        fastcgi_backend_stream(Vec::new(), Vec::new());
    }

    async fn write_records<W>(writer: &mut W, record_type: u8, content: &[u8])
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        for chunk in content.chunks(60_000) {
            write_record(writer, record_type, chunk).await;
        }
        if content.is_empty() {
            write_record(writer, record_type, &[]).await;
        }
    }

    async fn write_record<W>(writer: &mut W, record_type: u8, content: &[u8])
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let header = [
            1,
            record_type,
            0,
            1,
            (content.len() >> 8) as u8,
            content.len() as u8,
            0,
            0,
        ];
        let _ = writer.write_all(&header).await;
        let _ = writer.write_all(content).await;
    }
}
