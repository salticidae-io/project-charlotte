use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::stream;
use http::{
    Method, Request, Response, StatusCode,
    header::{self, HeaderValue},
};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
};

use crate::{
    config::Config,
    fastcgi,
    httpdate::{format_http_date, parse_http_date},
    mime,
};

pub(crate) type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;

#[derive(Clone, Debug)]
pub(crate) struct OriginalUri(pub(crate) String);

pub async fn handle_request<B>(
    request: Request<B>,
    config: Arc<Config>,
    peer: SocketAddr,
    local: SocketAddr,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let method = request.method().clone();
    let uri = request.uri().clone();
    let is_head = method == Method::HEAD;
    let mut request = request;
    let mut try_files_response = if config.try_files.is_empty() {
        None
    } else {
        apply_try_files(&mut request, &config).await
    };
    if try_files_response.is_none() {
        let uri = request.uri().clone();
        let script = match decode_request_path(uri.path()) {
            Some(path) => fastcgi::resolve_script(&path, uri.path(), &config).await,
            None => None,
        };
        try_files_response = Some(if let Some(script) = script {
            fastcgi::handle_request(request, &config, script, peer, local).await
        } else if method == Method::OPTIONS {
            let mut response = response(StatusCode::NO_CONTENT, empty_body());
            response.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            response
        } else if method != Method::GET && !is_head {
            let mut response =
                error_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n");
            response.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            response
        } else {
            route_file_request(&request, &config).await
        });
    }
    let mut response =
        try_files_response.expect("try_files or request routing produces a response");

    if is_head {
        *response.body_mut() = empty_body();
    }
    let size = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-");
    eprintln!("{} {} {} {}", method, uri, response.status(), size);
    response
}

async fn apply_try_files<B>(
    request: &mut Request<B>,
    config: &Config,
) -> Option<Response<ResponseBody>> {
    if config.try_files.is_empty() {
        return None;
    }

    let original_uri = request.uri().clone();
    let raw_path = original_uri.path();
    let query = original_uri.query();
    for entry in &config.try_files[..config.try_files.len() - 1] {
        let Some(candidate) = substitute_try_file(entry, raw_path, query) else {
            return Some(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid try_files entry\n",
            ));
        };
        let candidate_path = candidate
            .split_once('?')
            .map_or(candidate.as_str(), |(path, _)| path);
        let Some(relative_path) = decode_request_path(candidate_path) else {
            continue;
        };
        let Ok(canonical) = fs::canonicalize(config.root.join(relative_path)).await else {
            continue;
        };
        if !canonical.starts_with(&config.root) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&canonical).await else {
            continue;
        };
        let matched = if candidate_path.ends_with('/') {
            metadata.is_dir()
        } else {
            metadata.is_file()
        };
        if !matched {
            continue;
        }

        let rewritten = match uri_with_query(candidate_path, query) {
            Some(uri) => uri,
            None => {
                return Some(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid rewritten URI\n",
                ));
            }
        };
        request
            .extensions_mut()
            .insert(OriginalUri(request_uri(&original_uri)));
        *request.uri_mut() = rewritten;
        return None;
    }

    let fallback = config
        .try_files
        .last()
        .expect("non-empty try_files entries");
    if let Some(code) = fallback.strip_prefix('=') {
        let Ok(code) = code.parse::<u16>() else {
            return Some(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid try_files status\n",
            ));
        };
        return Some(match StatusCode::from_u16(code) {
            Ok(status) => response(status, empty_body()),
            Err(_) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid try_files status\n",
            ),
        });
    }

    let Some(fallback) = substitute_try_file(fallback, raw_path, query) else {
        return Some(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid try_files entry\n",
        ));
    };
    let Ok(uri) = fallback.parse::<http::Uri>() else {
        return Some(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid rewritten URI\n",
        ));
    };
    if !uri.path().starts_with('/') || uri.authority().is_some() || uri.scheme().is_some() {
        return Some(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid rewritten URI\n",
        ));
    }
    request
        .extensions_mut()
        .insert(OriginalUri(request_uri(&original_uri)));
    *request.uri_mut() = uri;
    None
}

fn substitute_try_file(entry: &str, path: &str, query: Option<&str>) -> Option<String> {
    let variables = [
        ("$query_string", query.unwrap_or_default()),
        ("$is_args", if query.is_some() { "?" } else { "" }),
        ("$uri", path),
        ("$args", query.unwrap_or_default()),
    ];
    let mut result = String::with_capacity(entry.len());
    let mut index = 0;
    while index < entry.len() {
        if entry.as_bytes()[index] != b'$' {
            let character = entry[index..].chars().next()?;
            result.push(character);
            index += character.len_utf8();
            continue;
        }
        let (variable, value) = variables.iter().find(|(variable, _)| {
            entry[index..].starts_with(variable)
                && entry
                    .as_bytes()
                    .get(index + variable.len())
                    .is_none_or(|next| !next.is_ascii_alphanumeric() && *next != b'_')
        })?;
        result.push_str(value);
        index += variable.len();
    }
    Some(result)
}

fn uri_with_query(path: &str, query: Option<&str>) -> Option<http::Uri> {
    let path_and_query = query.map_or_else(|| path.to_owned(), |query| format!("{path}?{query}"));
    path_and_query.parse().ok()
}

fn request_uri(uri: &http::Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| uri.path().to_owned(), |value| value.as_str().to_owned())
}

async fn route_file_request<B>(request: &Request<B>, config: &Config) -> Response<ResponseBody>
where
    B: Body<Data = Bytes>,
{
    let raw_path = request.uri().path();
    let relative_path = match decode_request_path(raw_path) {
        Some(path) => path,
        None => return error_response(StatusCode::NOT_FOUND, "Not found\n"),
    };
    let candidate = config.root.join(relative_path);
    let canonical = match fs::canonicalize(&candidate).await {
        Ok(path) if path.starts_with(&config.root) => path,
        _ => return error_response(StatusCode::NOT_FOUND, "Not found\n"),
    };
    let metadata = match fs::metadata(&canonical).await {
        Ok(metadata) => metadata,
        Err(_) => return error_response(StatusCode::NOT_FOUND, "Not found\n"),
    };

    if metadata.is_dir() {
        if !raw_path.ends_with('/') {
            let mut location = format!("{raw_path}/");
            if let Some(query) = request.uri().query() {
                location.push('?');
                location.push_str(query);
            }
            let mut response = response(StatusCode::PERMANENT_REDIRECT, empty_body());
            if let Ok(value) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(header::LOCATION, value);
            }
            return response;
        }

        let index = canonical.join(&config.index);
        if let Ok(index_path) = fs::canonicalize(index).await
            && index_path.starts_with(&config.root)
            && fs::metadata(&index_path)
                .await
                .is_ok_and(|metadata| metadata.is_file())
        {
            return serve_file(request, &index_path, &config.root).await;
        }
        if config.listing {
            return directory_listing(request.uri().path(), &canonical).await;
        }
        return error_response(StatusCode::NOT_FOUND, "Not found\n");
    }

    if !metadata.is_file() {
        return error_response(StatusCode::NOT_FOUND, "Not found\n");
    }
    serve_file(request, &canonical, &config.root).await
}

/// Reports whether an open file really lives under the document root.
///
/// The path was checked before it was opened, but a path names a file only
/// for an instant: whoever can write to the document root can replace a
/// component with a symbolic link in between. Asking the kernel where the
/// open descriptor points closes that window.
#[cfg(target_os = "linux")]
async fn opened_within_root(file: &File, root: &Path) -> bool {
    use std::os::fd::AsRawFd;

    fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .await
        .is_ok_and(|path| path.starts_with(root))
}

#[cfg(not(target_os = "linux"))]
async fn opened_within_root(_file: &File, _root: &Path) -> bool {
    true
}

async fn serve_file<B>(request: &Request<B>, path: &Path, root: &Path) -> Response<ResponseBody>
where
    B: Body<Data = Bytes>,
{
    // Everything below describes and reads this one open file, never the
    // path again.
    let not_found = || error_response(StatusCode::NOT_FOUND, "Not found\n");
    let Ok(mut file) = File::open(path).await else {
        return not_found();
    };
    let metadata = match file.metadata().await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return not_found(),
    };
    if !opened_within_root(&file, root).await {
        return not_found();
    }
    let length = metadata.len();
    let modified = metadata
        .modified()
        .map(DateTime::<Utc>::from)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    let modified_secs = modified.timestamp().max(0);
    let etag = format!("\"{:x}-{:x}\"", length, modified_secs);
    let last_modified = format_http_date(modified);

    if not_modified(request, &etag, modified) {
        let mut response = response(StatusCode::NOT_MODIFIED, empty_body());
        add_validators(&mut response, &etag, &last_modified);
        return response;
    }

    let mut range = None;
    if let Some(range_header) = request
        .headers()
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
    {
        let if_range_allows = request
            .headers()
            .get(header::IF_RANGE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| if_range_matches(value, &etag, modified));
        if if_range_allows {
            match parse_byte_range(range_header, length) {
                Ok(parsed) => range = parsed,
                Err(()) => {
                    let mut response = response(StatusCode::RANGE_NOT_SATISFIABLE, empty_body());
                    response.headers_mut().insert(
                        header::CONTENT_RANGE,
                        header_value(&format!("bytes */{length}")),
                    );
                    response
                        .headers_mut()
                        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
                    add_validators(&mut response, &etag, &last_modified);
                    return response;
                }
            }
        }
    }

    let (status, start, end) = match range {
        Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end),
        None => (StatusCode::OK, 0, length.saturating_sub(1)),
    };
    let body_length = if length == 0 { 0 } else { end - start + 1 };
    let body = if request.method() == Method::HEAD || body_length == 0 {
        empty_body()
    } else {
        if file.seek(SeekFrom::Start(start)).await.is_err() {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Unable to read file\n");
        }
        file_body(file, body_length)
    };

    let mut response = response(status, body);
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, header_value(mime::for_path(path)));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        header_value(&body_length.to_string()),
    );
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if status == StatusCode::PARTIAL_CONTENT {
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            header_value(&format!("bytes {start}-{end}/{length}")),
        );
    }
    add_validators(&mut response, &etag, &last_modified);
    response
}

fn not_modified<B>(request: &Request<B>, etag: &str, modified: DateTime<Utc>) -> bool
where
    B: Body<Data = Bytes>,
{
    let if_none_match = request.headers().get_all(header::IF_NONE_MATCH);
    if if_none_match.iter().next().is_some() {
        return if_none_match
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .any(|candidate| {
                candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
            });
    }
    request
        .headers()
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date)
        .is_some_and(|date| modified.timestamp() <= date.timestamp())
}

fn if_range_matches(value: &str, etag: &str, modified: DateTime<Utc>) -> bool {
    if value.starts_with('"') {
        value == etag
    } else {
        parse_http_date(value).is_some_and(|date| modified.timestamp() <= date.timestamp())
    }
}

fn parse_byte_range(value: &str, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let value = value.strip_prefix("bytes=").ok_or(())?;
    if value.contains(',') {
        return Err(());
    }
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ())?;
        if suffix == 0 || size == 0 {
            return Err(());
        }
        return Ok(Some((size.saturating_sub(suffix), size - 1)));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= size {
        return Err(());
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if end < start {
        return Err(());
    }
    Ok(Some((start, end)))
}

async fn directory_listing(path: &str, directory: &Path) -> Response<ResponseBody> {
    let mut entries = Vec::new();
    let mut read_dir = match fs::read_dir(directory).await {
        Ok(read_dir) => read_dir,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to list directory\n",
            );
        }
    };
    loop {
        match read_dir.next_entry().await {
            Ok(Some(entry)) => {
                let name = entry.file_name().to_string_lossy().into_owned();
                if is_hidden(&name) {
                    continue;
                }
                let is_dir = fs::metadata(entry.path())
                    .await
                    .is_ok_and(|metadata| metadata.is_dir());
                entries.push((name, is_dir));
            }
            Ok(None) => break,
            Err(_) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to list directory\n",
                );
            }
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut html =
        String::from("<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of ");
    html.push_str(&escape_html(path));
    html.push_str("</title></head><body><h1>Index of ");
    html.push_str(&escape_html(path));
    html.push_str("</h1><ul>");
    if path != "/" {
        let parent = path
            .trim_end_matches('/')
            .rsplit_once('/')
            .map_or(
                "/",
                |(parent, _)| {
                    if parent.is_empty() { "/" } else { parent }
                },
            );
        html.push_str(&format!(
            "<li><a href=\"{}\">../</a></li>",
            escape_html(parent)
        ));
    }
    for (name, is_dir) in entries {
        let href = format!(
            "{}{}{}",
            path,
            percent_encode(&name),
            if is_dir { "/" } else { "" }
        );
        let label = format!("{}{}", name, if is_dir { "/" } else { "" });
        html.push_str("<li><a href=\"");
        html.push_str(&escape_html(&href));
        html.push_str("\">");
        html.push_str(&escape_html(&label));
        html.push_str("</a></li>");
    }
    html.push_str("</ul></body></html>");
    let bytes = Bytes::from(html);
    let mut response = response(StatusCode::OK, full_body(bytes.clone()));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        header_value(&bytes.len().to_string()),
    );
    response
}

pub(crate) fn decode_request_path(path: &str) -> Option<PathBuf> {
    if !path.starts_with('/') {
        return None;
    }
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(hex_value(high)? * 16 + hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = std::str::from_utf8(&decoded).ok()?;
    if decoded.contains('\0') || decoded.contains('\\') || !decoded.starts_with('/') {
        return None;
    }

    let mut relative = PathBuf::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            // Dotfiles hold what a site never means to publish: version
            // control metadata, credentials, editor backups.
            segment if is_hidden(segment) => return None,
            segment => relative.push(segment),
        }
    }
    Some(relative)
}

/// Reports whether a file name is hidden from clients. `.well-known` is the
/// one dot-directory that exists to be served.
fn is_hidden(name: &str) -> bool {
    name.starts_with('.') && name != ".well-known"
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn file_body(file: File, length: u64) -> ResponseBody {
    let chunks = stream::unfold((file, length), |(mut file, remaining)| async move {
        if remaining == 0 {
            return None;
        }
        let mut buffer = vec![0; remaining.min(16 * 1024) as usize];
        match file.read(&mut buffer).await {
            Ok(0) => Some((
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "file changed while streaming",
                )),
                (file, 0),
            )),
            Ok(count) => {
                buffer.truncate(count);
                Some((
                    Ok(Frame::data(Bytes::from(buffer))),
                    (file, remaining - count as u64),
                ))
            }
            Err(error) => Some((Err(error), (file, 0))),
        }
    });
    StreamBody::new(chunks).boxed_unsync()
}

pub(crate) fn response(status: StatusCode, body: ResponseBody) -> Response<ResponseBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::SERVER,
        HeaderValue::from_static("project-charlotte"),
    );
    response
        .headers_mut()
        .insert(header::DATE, header_value(&format_http_date(Utc::now())));
    response
}

pub(crate) fn error_response(status: StatusCode, message: &'static str) -> Response<ResponseBody> {
    let bytes = Bytes::from_static(message.as_bytes());
    let mut response = response(status, full_body(bytes.clone()));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        header_value(&bytes.len().to_string()),
    );
    response
}

pub(crate) fn text_response(status: StatusCode, text: String) -> Response<ResponseBody> {
    let bytes = Bytes::from(text);
    let mut response = response(status, full_body(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn add_validators(response: &mut Response<ResponseBody>, etag: &str, last_modified: &str) {
    response
        .headers_mut()
        .insert(header::ETAG, header_value(etag));
    response
        .headers_mut()
        .insert(header::LAST_MODIFIED, header_value(last_modified));
}

fn header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("server generated a valid header value")
}

pub(crate) fn empty_body() -> ResponseBody {
    full_body(Bytes::new())
}

fn full_body(bytes: Bytes) -> ResponseBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

#[cfg(test)]
mod tests {
    use super::{OriginalUri, apply_try_files, decode_request_path, escape_html, parse_byte_range};
    use chrono::{DateTime, Utc};
    use std::{
        path::{Component, Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};

    use crate::fuzz_support::{self, FuzzRequest};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    async fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-try-files-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::canonicalize(root).await.unwrap()
    }

    fn try_files_config(root: PathBuf, try_files: &[&str]) -> crate::config::Config {
        let mut config = fuzz_support::fuzz_config(root);
        config.fastcgi.clear();
        config.try_files = try_files.iter().map(|entry| (*entry).to_owned()).collect();
        config
    }

    async fn run_try_files(
        root: PathBuf,
        try_files: &[&str],
        uri: &str,
    ) -> http::Response<super::ResponseBody> {
        let request = http::Request::builder()
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (peer, local) = fuzz_support::addresses();
        super::handle_request(
            request,
            Arc::new(try_files_config(root, try_files)),
            peer,
            local,
        )
        .await
    }

    #[test]
    fn decodes_paths_and_rejects_traversal() {
        assert_eq!(
            decode_request_path("/images/a%20b.png").unwrap().as_path(),
            Path::new("images/a b.png")
        );
        assert!(decode_request_path("/%2e%2e/secret").is_none());
        assert!(decode_request_path("/a/../secret").is_none());
        assert!(decode_request_path("/%00").is_none());
        assert!(decode_request_path("/%GG").is_none());
    }

    #[test]
    fn hides_dotfiles_but_serves_well_known() {
        assert!(decode_request_path("/.git/config").is_none());
        assert!(decode_request_path("/app/.env").is_none());
        assert!(decode_request_path("/%2eenv").is_none());
        assert_eq!(
            decode_request_path("/.well-known/security.txt")
                .unwrap()
                .as_path(),
            Path::new(".well-known/security.txt")
        );
    }

    #[tokio::test]
    async fn try_files_serves_first_existing_file_and_keeps_original_query() {
        let root = temp_root().await;
        tokio::fs::write(root.join("existing.txt"), b"existing file")
            .await
            .unwrap();
        let config = try_files_config(root.clone(), &["$uri", "/fallback.txt", "=404"]);
        let mut request = http::Request::builder()
            .uri("/existing.txt?original=1")
            .body(())
            .unwrap();

        assert!(apply_try_files(&mut request, &config).await.is_none());
        assert_eq!(request.uri().to_string(), "/existing.txt?original=1");
        assert_eq!(
            request.extensions().get::<OriginalUri>().unwrap().0,
            "/existing.txt?original=1"
        );

        let response = run_try_files(
            root.clone(),
            &["$uri", "/fallback.txt", "=404"],
            "/existing.txt",
        )
        .await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "existing file"
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn try_files_directory_candidate_routes_to_index() {
        let root = temp_root().await;
        tokio::fs::create_dir(root.join("folder")).await.unwrap();
        tokio::fs::write(root.join("folder/index.html"), b"directory index")
            .await
            .unwrap();

        let response = run_try_files(root.clone(), &["$uri", "$uri/", "=404"], "/folder?x=1").await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "directory index"
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn try_files_fallback_uri_routes_to_file_with_only_entry_args() {
        let root = temp_root().await;
        tokio::fs::write(root.join("index.html"), b"fallback index")
            .await
            .unwrap();
        for (fallback, expected) in [
            ("/index.html$is_args$args", "/index.html?original=1"),
            ("/index.html$is_args$query_string", "/index.html?original=1"),
            ("/index.html", "/index.html"),
        ] {
            let config = try_files_config(root.clone(), &["$uri", fallback]);
            let mut request = http::Request::builder()
                .uri("/missing?original=1")
                .body(())
                .unwrap();
            assert!(apply_try_files(&mut request, &config).await.is_none());
            assert_eq!(request.uri().to_string(), expected);
            assert_eq!(
                request.extensions().get::<OriginalUri>().unwrap().0,
                "/missing?original=1"
            );
        }

        let response =
            run_try_files(root.clone(), &["$uri", "/index.html", "=404"], "/missing").await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "fallback index"
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn try_files_status_and_traversal_fallback_are_respected() {
        let root = temp_root().await;
        let outside = root.parent().unwrap().join(format!(
            "project-charlotte-try-files-outside-{}",
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::write(&outside, b"outside file").await.unwrap();

        let missing = run_try_files(root.clone(), &["$uri", "=404"], "/missing").await;
        assert_eq!(missing.status(), http::StatusCode::NOT_FOUND);
        let traversal = run_try_files(
            root.clone(),
            &["$uri", "=404"],
            &format!("/../{}", outside.file_name().unwrap().to_string_lossy()),
        )
        .await;
        assert_eq!(traversal.status(), http::StatusCode::NOT_FOUND);
        tokio::fs::remove_file(outside).await.unwrap();
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn parses_single_byte_ranges() {
        assert_eq!(parse_byte_range("bytes=2-5", 10), Ok(Some((2, 5))));
        assert_eq!(parse_byte_range("bytes=7-", 10), Ok(Some((7, 9))));
        assert_eq!(parse_byte_range("bytes=-3", 10), Ok(Some((7, 9))));
        assert!(parse_byte_range("bytes=10-", 10).is_err());
        assert!(parse_byte_range("bytes=0-1,4-5", 10).is_err());
    }

    #[test]
    fn escapes_html_text_and_attributes() {
        assert_eq!(
            escape_html("<a x=\"&'\">"),
            "&lt;a x=&quot;&amp;&#39;&quot;&gt;"
        );
    }

    #[test_fuzz::test_fuzz]
    fn request_path(path: String) {
        if let Some(decoded) = decode_request_path(&path) {
            assert!(
                decoded
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            );
        }
    }

    #[test]
    fn fuzz_seed_request_path() {
        request_path("/subdir/index.html".to_owned());
        request_path("/%2e%2e/secret".to_owned());
    }

    #[test_fuzz::test_fuzz]
    fn byte_range(value: &str, size: u64) {
        if let Ok(Some((start, end))) = parse_byte_range(value, size) {
            assert!(start <= end);
            assert!(end < size);
        }
    }

    #[test]
    fn fuzz_seed_byte_range() {
        byte_range("bytes=2-5", 10);
        byte_range("bytes=-3", 10);
    }

    #[test_fuzz::test_fuzz]
    fn if_range(value: &str, etag: &str) {
        let modified = DateTime::<Utc>::from_timestamp(784_111_777, 0).unwrap();
        let matches = super::if_range_matches(value, etag, modified);
        if matches && value != etag {
            // Anything other than the exact entity tag may only match as a
            // date that is no older than the file.
            let date = crate::httpdate::parse_http_date(value)
                .expect("a non-tag If-Range only matches as an HTTP date");
            assert!(date >= modified);
        }
        if etag.starts_with('"') {
            assert!(super::if_range_matches(etag, etag, modified));
        }
    }

    #[test]
    fn fuzz_seed_if_range() {
        if_range("\"tag\"", "\"tag\"");
        if_range("invalid", "\"tag\"");
        if_range("Sun, 06 Nov 1994 08:49:37 GMT", "\"tag\"");
    }

    #[test_fuzz::test_fuzz]
    fn html_escape(value: &str) {
        let escaped = escape_html(value);
        for character in ['<', '>', '"', '\''] {
            assert!(!escaped.contains(character));
        }
    }

    #[test]
    fn fuzz_seed_html_escape() {
        html_escape("<script>alert('&')</script>");
        html_escape("ordinary text");
    }

    #[test_fuzz::test_fuzz]
    fn static_request(request: FuzzRequest) {
        let Some(request) = request.build() else {
            return;
        };
        let fixture = fuzz_support::fixture();
        let mut config = fuzz_support::fuzz_config(fixture.root.clone());
        config.fastcgi.clear();
        let (peer, local) = fuzz_support::addresses();
        let method = request.method().clone();
        let collected = fuzz_support::collect(super::handle_request(
            request,
            Arc::new(config),
            peer,
            local,
        ));
        assert!(
            collected.error.is_none(),
            "static response body should be readable"
        );
        fuzz_support::assert_response_invariants(&method, &collected);
    }

    #[test]
    fn fuzz_seed_static_request() {
        static_request(FuzzRequest::default());
        for uri in [
            "/escape.txt",
            "/escape-dir/secret.txt",
            "/escape-dir/",
            "/listing/",
            "/listing/nested/",
            "/subdir",
        ] {
            static_request(FuzzRequest {
                uri: uri.to_owned(),
                ..FuzzRequest::default()
            });
        }
        static_request(FuzzRequest {
            uri: "/large.txt".to_owned(),
            headers: vec![("range".to_owned(), b"bytes=1048570-".to_vec())],
            ..FuzzRequest::default()
        });
        static_request(FuzzRequest {
            method: "HEAD".to_owned(),
            headers: vec![("if-none-match".to_owned(), b"*".to_vec())],
            ..FuzzRequest::default()
        });
    }

    #[test_fuzz::test_fuzz]
    fn try_files_request(request: FuzzRequest, entries: Vec<String>) {
        if entries.is_empty() || crate::config::validate_try_files(&entries).is_err() {
            return;
        }
        let Some(request) = request.build() else {
            return;
        };
        // Every entry that configuration validation accepts must expand for
        // any request; a failure here is a 500 an operator cannot foresee.
        for entry in &entries {
            assert!(
                super::substitute_try_file(entry, request.uri().path(), request.uri().query())
                    .is_some(),
                "validated try_files entry failed to expand: {entry}"
            );
        }
        let fixture = fuzz_support::fixture();
        let mut config = fuzz_support::fuzz_config(fixture.root.clone());
        config.fastcgi.clear();
        config.try_files = entries;
        let (peer, local) = fuzz_support::addresses();
        let method = request.method().clone();
        let collected = fuzz_support::collect(super::handle_request(
            request,
            Arc::new(config),
            peer,
            local,
        ));
        assert!(
            collected.error.is_none(),
            "try_files response body should be readable"
        );
        fuzz_support::assert_response_invariants(&method, &collected);
    }

    #[test]
    fn fuzz_seed_try_files_request() {
        let entries = |entries: &[&str]| entries.iter().map(|entry| (*entry).to_owned()).collect();
        try_files_request(
            FuzzRequest {
                uri: "/missing?x=1".to_owned(),
                ..FuzzRequest::default()
            },
            entries(&["$uri", "$uri/", "/index.html?$args"]),
        );
        try_files_request(
            FuzzRequest {
                uri: "/escape.txt".to_owned(),
                ..FuzzRequest::default()
            },
            entries(&["$uri", "/escape-dir/secret.txt", "=404"]),
        );
        try_files_request(
            FuzzRequest::default(),
            entries(&["/subdir$uri", "/safe.txt$is_args$query_string"]),
        );
    }
}
