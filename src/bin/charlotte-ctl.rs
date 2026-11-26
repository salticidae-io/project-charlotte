use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "charlotte-ctl",
    version,
    about = "Configure project-charlotte over its control socket"
)]
struct Cli {
    /// Path to the control socket
    #[arg(
        long,
        global = true,
        env = "CHARLOTTE_CONTROL_SOCKET",
        default_value = "/run/charlotte/control.sock",
        value_name = "PATH"
    )]
    socket: PathBuf,
    /// Socket read and write timeout in seconds
    #[arg(
        long,
        global = true,
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..),
        value_name = "SECS"
    )]
    timeout: u64,
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Show server status
    Status,
    /// Show server-wide configuration options
    Options,
    /// Replace server-wide configuration options from a YAML or JSON file (or stdin)
    SetOptions { file: Option<PathBuf> },
    /// List virtual hosts
    List,
    /// Show a virtual host's configuration
    Get {
        #[arg(allow_hyphen_values = true)]
        name: String,
    },
    /// Create a virtual host from a YAML or JSON file (or stdin)
    Create {
        #[arg(allow_hyphen_values = true)]
        name: String,
        file: Option<PathBuf>,
    },
    /// Create or replace a virtual host from a YAML or JSON file (or stdin)
    #[command(alias = "apply")]
    Put {
        #[arg(allow_hyphen_values = true)]
        name: String,
        file: Option<PathBuf>,
    },
    /// Delete a virtual host
    Delete {
        #[arg(allow_hyphen_values = true)]
        name: String,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("charlotte-ctl: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let (method, path, body) = match cli.action {
        Action::Status => ("GET", "/status".to_owned(), Vec::new()),
        Action::Options => ("GET", "/options".to_owned(), Vec::new()),
        Action::SetOptions { file } => ("PUT", "/options".to_owned(), read_body(file)?),
        Action::List => ("GET", "/vhosts".to_owned(), Vec::new()),
        Action::Get { name } => ("GET", vhost_path(&name), Vec::new()),
        Action::Create { name, file } => ("POST", vhost_path(&name), read_body(file)?),
        Action::Put { name, file } => ("PUT", vhost_path(&name), read_body(file)?),
        Action::Delete { name } => ("DELETE", vhost_path(&name), Vec::new()),
    };

    let mut stream = UnixStream::connect(&cli.socket)?;
    let timeout = Duration::from_secs(cli.timeout);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&build_request(method, &path, &body))?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response = parse_response(&response)?;
    if !(200..300).contains(&response.status) {
        let message = serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("server returned HTTP {}", response.status));
        return Err(io::Error::other(message).into());
    }

    if !response.body.is_empty() {
        let value: serde_json::Value = serde_json::from_slice(&response.body)?;
        writeln!(
            io::stdout().lock(),
            "{}",
            serde_json::to_string_pretty(&value)?
        )?;
    }
    Ok(())
}

fn read_body(file: Option<PathBuf>) -> io::Result<Vec<u8>> {
    match file {
        Some(path) if path != Path::new("-") => fs::read(path),
        _ => {
            let mut body = Vec::new();
            io::stdin().read_to_end(&mut body)?;
            Ok(body)
        }
    }
}

fn vhost_path(name: &str) -> String {
    format!("/vhosts/{}", encode_segment(name))
}

fn encode_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn build_request(method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .into_bytes();
    if !body.is_empty() {
        request.extend_from_slice(b"Content-Type: application/yaml\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);
    request
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn parse_response(response: &[u8]) -> io::Result<HttpResponse> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| invalid_response("missing end of headers"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| invalid_response("headers are not valid UTF-8"))?;
    let mut lines = headers.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| invalid_response("missing or invalid status code"))?;

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_response("malformed header"));
        };
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| invalid_response("invalid content length"))?;
            if content_length.is_some_and(|previous| previous != length) {
                return Err(invalid_response("conflicting content lengths"));
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked |= value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
        }
    }

    let body = &response[header_end + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else if let Some(length) = content_length {
        body.get(..length)
            .ok_or_else(|| invalid_response("response body is shorter than content length"))?
            .to_vec()
    } else {
        body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut body: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| invalid_response("malformed chunk size"))?;
        let size = std::str::from_utf8(&body[..line_end])
            .map_err(|_| invalid_response("malformed chunk size"))?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size =
            usize::from_str_radix(size, 16).map_err(|_| invalid_response("invalid chunk size"))?;
        body = &body[line_end + 2..];

        if size == 0 {
            if body.starts_with(b"\r\n") || body.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(decoded);
            }
            return Err(invalid_response("malformed chunk trailers"));
        }

        let chunk_end = size
            .checked_add(2)
            .ok_or_else(|| invalid_response("chunk size overflow"))?;
        let chunk = body
            .get(..size)
            .ok_or_else(|| invalid_response("truncated chunk"))?;
        if body.get(size..chunk_end) != Some(b"\r\n") {
            return Err(invalid_response("malformed chunk ending"));
        }
        decoded.extend_from_slice(chunk);
        body = &body[chunk_end..];
    }
}

fn invalid_response(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{build_request, encode_segment, parse_response};

    #[test]
    fn formats_http_request_with_content_length() {
        assert_eq!(
            build_request("POST", "/vhosts/site", b"root: /srv/site\n"),
            b"POST /vhosts/site HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 16\r\nContent-Type: application/yaml\r\n\r\nroot: /srv/site\n"
        );
    }

    #[test]
    fn percent_encodes_path_segment_bytes() {
        assert_eq!(encode_segment("bad/name %"), "bad%2Fname%20%25");
        assert_eq!(encode_segment("example-site_1.test"), "example-site_1.test");
    }

    #[test]
    fn parses_content_length_response() {
        let response =
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"a":1}"#);
    }

    #[test]
    fn parses_chunked_response() {
        let response = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;ext=x\r\npedia\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.body, b"Wikipedia");
    }

    #[test]
    fn reads_response_without_explicit_framing_to_eof() {
        let response = parse_response(b"HTTP/1.1 200 OK\r\n\r\nbody").unwrap();
        assert_eq!(response.body, b"body");
    }
}
