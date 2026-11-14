//! Access and error log formatting and output.

use std::{
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::{Instant, SystemTime},
};

use http::{HeaderMap, Method, Version};
use http_body::{Body, Frame};

#[derive(Clone)]
pub(crate) struct LogTarget(Arc<Mutex<Box<dyn Write + Send>>>);

impl LogTarget {
    pub(crate) fn file(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(path)?;
        Ok(Self(Arc::new(Mutex::new(Box::new(file)))))
    }

    pub(crate) fn stdout() -> Self {
        Self(Arc::new(Mutex::new(Box::new(io::stdout()))))
    }

    pub(crate) fn stderr() -> Self {
        Self(Arc::new(Mutex::new(Box::new(io::stderr()))))
    }

    fn write_line(&self, line: &str) {
        let mut writer = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = writer.write_all(line.as_bytes());
        let _ = writer.write_all(b"\n");
        let _ = writer.flush();
    }
}

#[derive(Clone, Debug)]
enum AccessPart {
    Literal(String),
    Directive {
        code: char,
        argument: Option<String>,
        modifier: Option<char>,
        condition: Option<(bool, Vec<u16>)>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct AccessFormat(Vec<AccessPart>);

impl AccessFormat {
    pub(crate) fn parse(format: &str) -> Result<Self, String> {
        match format {
            "common" => return Self::parse("%h %l %u %t \"%r\" %>s %b"),
            "combined" => {
                return Self::parse("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"");
            }
            "vhost_common" => return Self::parse("%v %h %l %u %t \"%r\" %>s %b"),
            "vhost_combined" => {
                return Self::parse(
                    "%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"",
                );
            }
            "referer" => return Self::parse("%{Referer}i -> %U"),
            "agent" => return Self::parse("%{User-agent}i"),
            _ => {}
        }
        let mut parts = Vec::new();
        let bytes = format.as_bytes();
        let mut index = 0;
        let mut literal = String::new();
        while index < bytes.len() {
            if bytes[index] != b'%' {
                let ch = format[index..]
                    .chars()
                    .next()
                    .ok_or_else(|| "invalid format string".to_owned())?;
                literal.push(ch);
                index += ch.len_utf8();
                continue;
            }
            index += 1;
            if bytes.get(index) == Some(&b'%') {
                literal.push('%');
                index += 1;
                continue;
            }
            if !literal.is_empty() {
                parts.push(AccessPart::Literal(std::mem::take(&mut literal)));
            }
            let condition = parse_status_condition(bytes, &mut index)?;
            let modifier = if matches!(bytes.get(index), Some(b'>' | b'<')) {
                let value = bytes[index] as char;
                index += 1;
                Some(value)
            } else {
                None
            };
            let argument = parse_braced_argument(format, bytes, &mut index)?;
            let Some(&code) = bytes.get(index) else {
                return Err("incomplete access log format directive".to_owned());
            };
            index += 1;
            let code = code as char;
            if !"aAbBDhHilmnopPqrstTuvVUC".contains(code) {
                return Err(format!("unsupported access log format directive: %{code}"));
            }
            if code == 'n' && argument.as_deref().is_some_and(|arg| arg != "ja4") {
                return Err(format!(
                    "unsupported access log note: {}",
                    argument.unwrap()
                ));
            }
            parts.push(AccessPart::Directive {
                code,
                argument,
                modifier,
                condition,
            });
        }
        if !literal.is_empty() {
            parts.push(AccessPart::Literal(literal));
        }
        Ok(Self(parts))
    }

    fn render(
        &self,
        request: &AccessRequest,
        response: &AccessResponse,
        elapsed: Instant,
        bytes: u64,
        finished: SystemTime,
    ) -> String {
        let mut output = String::new();
        for part in &self.0 {
            match part {
                AccessPart::Literal(value) => output.push_str(value),
                AccessPart::Directive {
                    code,
                    argument,
                    modifier,
                    condition,
                } => {
                    if condition.as_ref().is_some_and(|(negated, statuses)| {
                        let matches = statuses.contains(&response.status);
                        matches == *negated
                    }) {
                        output.push('-');
                        continue;
                    }
                    let value = access_value(
                        *code,
                        argument.as_deref(),
                        *modifier,
                        request,
                        response,
                        elapsed,
                        bytes,
                        finished,
                    );
                    output.push_str(&escape_access_value(&value));
                }
            }
        }
        output
    }
}

fn parse_status_condition(
    bytes: &[u8],
    index: &mut usize,
) -> Result<Option<(bool, Vec<u16>)>, String> {
    let start = *index;
    let negated = bytes.get(*index) == Some(&b'!');
    if negated {
        *index += 1;
    }
    let digits_start = *index;
    while bytes.get(*index).is_some_and(u8::is_ascii_digit) || bytes.get(*index) == Some(&b',') {
        *index += 1;
    }
    if *index == digits_start {
        *index = start;
        return Ok(None);
    }
    let list = std::str::from_utf8(&bytes[digits_start..*index])
        .map_err(|_| "invalid status condition")?;
    let statuses = list
        .split(',')
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| format!("invalid status condition: {list}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some((negated, statuses)))
}

fn parse_braced_argument(
    format: &str,
    bytes: &[u8],
    index: &mut usize,
) -> Result<Option<String>, String> {
    if bytes.get(*index) != Some(&b'{') {
        return Ok(None);
    }
    let start = *index + 1;
    *index = start;
    while bytes.get(*index).is_some_and(|byte| *byte != b'}') {
        *index += 1;
    }
    if bytes.get(*index) != Some(&b'}') {
        return Err("unclosed access log format argument".to_owned());
    }
    let value = format[start..*index].to_owned();
    *index += 1;
    Ok(Some(value))
}

#[derive(Clone)]
pub(crate) struct AccessLog {
    target: LogTarget,
    format: AccessFormat,
}

impl AccessLog {
    pub(crate) fn new(target: LogTarget, format: AccessFormat) -> Self {
        Self { target, format }
    }

    pub(crate) fn write(
        &self,
        request: AccessRequest,
        response: AccessResponse,
        started: Instant,
        bytes: u64,
    ) {
        self.target.write_line(&self.format.render(
            &request,
            &response,
            started,
            bytes,
            SystemTime::now(),
        ));
    }

    pub(crate) fn target(&self) -> LogTarget {
        self.target.clone()
    }
}

#[derive(Clone)]
pub(crate) struct AccessRequest {
    pub method: Method,
    pub path: String,
    pub version: Version,
    pub client: SocketAddr,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub server_name: String,
    pub ja4: String,
    pub headers: HeaderMap,
    pub started: SystemTime,
}

#[derive(Clone)]
pub(crate) struct AccessResponse {
    pub status: u16,
    pub headers: HeaderMap,
}

fn access_value(
    code: char,
    argument: Option<&str>,
    modifier: Option<char>,
    request: &AccessRequest,
    response: &AccessResponse,
    elapsed: Instant,
    bytes: u64,
    finished: SystemTime,
) -> String {
    let query = request.path.split_once('?').map_or("", |(_, query)| query);
    match code {
        'a' => {
            if argument == Some("c") {
                request.peer.ip().to_string()
            } else {
                request.client.ip().to_string()
            }
        }
        'A' => request.local.ip().to_string(),
        'b' => {
            if bytes == 0 {
                "-".to_owned()
            } else {
                bytes.to_string()
            }
        }
        'B' => bytes.to_string(),
        'D' => elapsed.elapsed().as_micros().to_string(),
        'h' => request.client.ip().to_string(),
        'H' => version_name(request.version).to_owned(),
        'i' => header_value(&request.headers, argument),
        'l' => "-".to_owned(),
        'm' => request.method.to_string(),
        'n' => {
            if argument == Some("ja4") {
                request.ja4.clone()
            } else {
                "-".to_owned()
            }
        }
        'p' => match argument.unwrap_or("canonical") {
            "local" => request.local.port().to_string(),
            "remote" => request.peer.port().to_string(),
            _ => request.local.port().to_string(),
        },
        'P' => std::process::id().to_string(),
        'q' => {
            if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }
        }
        'r' => format!(
            "{} {} {}",
            request.method,
            request.path,
            version_name(request.version)
        ),
        's' => response.status.to_string(),
        't' => access_time(argument, request.started, finished),
        'T' => match argument.unwrap_or("s") {
            "ms" => elapsed.elapsed().as_millis().to_string(),
            "us" => elapsed.elapsed().as_micros().to_string(),
            _ => elapsed.elapsed().as_secs().to_string(),
        },
        'u' => "-".to_owned(),
        'U' => request
            .path
            .split_once('?')
            .map_or(request.path.as_str(), |(path, _)| path)
            .to_owned(),
        'v' | 'V' => request.server_name.clone(),
        'o' => header_value(&response.headers, argument),
        'C' => request
            .headers
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, _)| Some(*name) == argument)
            .map_or_else(|| "-".to_owned(), |(_, value)| value.to_owned()),
        _ => {
            let _ = modifier;
            "-".to_owned()
        }
    }
}

fn header_value(headers: &HeaderMap, name: Option<&str>) -> String {
    name.and_then(|name| headers.get(name))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_owned()
}

fn escape_access_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'"' => escaped.push_str("\\\""),
            b'\\' => escaped.push_str("\\\\"),
            0..=31 | 127 => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\x{byte:02x}");
            }
            _ => escaped.push(char::from(byte)),
        }
    }
    escaped
}

fn version_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

fn access_time(argument: Option<&str>, begin: SystemTime, end: SystemTime) -> String {
    let argument = argument.unwrap_or("[%d/%b/%Y:%H:%M:%S %z]");
    let (format, time) = if let Some(format) = argument.strip_prefix("begin:") {
        (format, begin)
    } else if let Some(format) = argument.strip_prefix("end:") {
        (format, end)
    } else {
        (argument, begin)
    };
    let format = format.strip_prefix("strftime:").unwrap_or(format);
    let format = if format == "strftime" {
        "[%d/%b/%Y:%H:%M:%S %z]"
    } else {
        format
    };
    let now = chrono::DateTime::<chrono::Local>::from(time);
    if matches!(format, "sec" | "msec" | "usec" | "msec_frac" | "usec_frac") {
        let micros = now.timestamp_subsec_micros();
        return match format {
            "sec" => now.timestamp().to_string(),
            "msec" => now.timestamp_millis().to_string(),
            "usec" => now.timestamp_micros().to_string(),
            "msec_frac" => format!("{:03}", micros / 1000),
            _ => format!("{micros:06}"),
        };
    }
    now.format(format).to_string()
}

#[derive(Clone, Debug)]
enum ErrorPart {
    Literal(String),
    Field {
        code: char,
        argument: Option<String>,
        omit_empty: bool,
    },
    OptionalField {
        prefix: String,
        code: char,
        argument: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ErrorFormat(Vec<ErrorPart>);

impl ErrorFormat {
    pub(crate) fn parse(format: &str) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut optional_prefix: Option<String> = None;
        let bytes = format.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b' ') {
                optional_prefix
                    .as_mut()
                    .map_or_else(|| literal.push(' '), |prefix| prefix.push(' '));
                index += 2;
                continue;
            }
            if bytes[index] != b'%' {
                let ch = format[index..]
                    .chars()
                    .next()
                    .ok_or("invalid error format")?;
                optional_prefix
                    .as_mut()
                    .map_or_else(|| literal.push(ch), |prefix| prefix.push(ch));
                index += ch.len_utf8();
                continue;
            }
            index += 1;
            if bytes.get(index) == Some(&b'%') {
                literal.push('%');
                index += 1;
                continue;
            }
            if bytes.get(index) == Some(&b' ') {
                if !literal.is_empty() {
                    parts.push(ErrorPart::Literal(std::mem::take(&mut literal)));
                }
                index += 1;
                optional_prefix = Some(String::new());
                continue;
            }
            if !literal.is_empty() {
                parts.push(ErrorPart::Literal(std::mem::take(&mut literal)));
            }
            let omit_empty = bytes.get(index) == Some(&b'-');
            if omit_empty {
                index += 1;
            }
            let argument = parse_braced_argument(format, bytes, &mut index)?;
            let Some(&code) = bytes.get(index) else {
                return Err("incomplete error log format directive".to_owned());
            };
            index += 1;
            let code = code as char;
            if !"AatlmMPTv".contains(code) {
                return Err(format!("unsupported error log format directive: %{code}"));
            }
            if let Some(prefix) = optional_prefix.take() {
                parts.push(ErrorPart::OptionalField {
                    prefix,
                    code,
                    argument,
                });
            } else {
                parts.push(ErrorPart::Field {
                    code,
                    argument,
                    omit_empty,
                });
            }
        }
        if !literal.is_empty() {
            parts.push(ErrorPart::Literal(literal));
        }
        Ok(Self(parts))
    }

    fn render(&self, event: &ErrorEvent<'_>) -> String {
        let mut output = String::new();
        for part in &self.0 {
            match part {
                ErrorPart::Literal(value) => output.push_str(value),
                ErrorPart::Field {
                    code,
                    argument,
                    omit_empty,
                } => {
                    let value = error_value(*code, argument.as_deref(), event);
                    if let Some(value) = value {
                        if !(*omit_empty && value.is_empty()) {
                            output.push_str(&value);
                        }
                    }
                }
                ErrorPart::OptionalField {
                    prefix,
                    code,
                    argument,
                } => {
                    if let Some(value) = error_value(*code, argument.as_deref(), event)
                        && !value.is_empty()
                    {
                        output.push_str(prefix);
                        output.push_str(&value);
                    }
                }
            }
        }
        output
    }
}

#[derive(Clone)]
pub(crate) struct ErrorLog {
    target: LogTarget,
    format: ErrorFormat,
}

impl ErrorLog {
    pub(crate) fn new(target: LogTarget, format: ErrorFormat) -> Self {
        Self { target, format }
    }
    fn write(&self, level: &str, module: &str, message: &str, context: Option<&RequestContext>) {
        self.target.write_line(&self.format.render(&ErrorEvent {
            level,
            module,
            message,
            context,
        }));
    }
    pub(crate) fn target(&self) -> LogTarget {
        self.target.clone()
    }
}

struct ErrorEvent<'a> {
    level: &'a str,
    module: &'a str,
    message: &'a str,
    context: Option<&'a RequestContext>,
}

fn error_value(code: char, argument: Option<&str>, event: &ErrorEvent<'_>) -> Option<String> {
    let now = chrono::Local::now();
    match code {
        'a' => event
            .context
            .and_then(|context| context.client)
            .map(|address| address.ip().to_string()),
        'A' => event
            .context
            .and_then(|context| context.local)
            .map(|address| address.ip().to_string()),
        't' => Some(match argument.unwrap_or("t") {
            "u" => now.timestamp().to_string(),
            "c" => now.to_rfc3339(),
            "cu" => now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            _ => now.format("%a %b %d %H:%M:%S%.6f %Y").to_string(),
        }),
        'l' => Some(event.level.to_owned()),
        'm' => Some(event.module.to_owned()),
        'M' => Some(event.message.to_owned()),
        'P' => Some(std::process::id().to_string()),
        'T' => Some(format!("{:?}", std::thread::current().id())),
        'v' => event
            .context
            .map(|context| context.server_name.clone())
            .filter(|name| !name.is_empty()),
        _ => None,
    }
}

#[derive(Clone, Default)]
pub(crate) struct RequestContext {
    pub client: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
    pub server_name: String,
    pub error_log: Option<Arc<ErrorLog>>,
}

tokio::task_local! { static REQUEST_CONTEXT: RequestContext; }

pub(crate) async fn with_request_context<F: std::future::Future>(
    context: RequestContext,
    future: F,
) -> F::Output {
    REQUEST_CONTEXT.scope(context, future).await
}

#[cfg(feature = "hosting")]
pub(crate) fn captured_context() -> RequestContext {
    REQUEST_CONTEXT.try_with(Clone::clone).unwrap_or_default()
}

static GLOBAL_ERROR_LOG: OnceLock<Arc<ErrorLog>> = OnceLock::new();
static GLOBAL_ACCESS_LOG: OnceLock<Option<Arc<AccessLog>>> = OnceLock::new();

pub(crate) fn set_global_error_log(log: Arc<ErrorLog>) {
    let _ = GLOBAL_ERROR_LOG.set(log);
}
pub(crate) fn set_global_access_log(log: Option<Arc<AccessLog>>) {
    let _ = GLOBAL_ACCESS_LOG.set(log);
}
pub(crate) fn global_error_log() -> Option<Arc<ErrorLog>> {
    GLOBAL_ERROR_LOG.get().cloned()
}
pub(crate) fn global_access_log() -> Option<Arc<AccessLog>> {
    GLOBAL_ACCESS_LOG.get().and_then(Clone::clone)
}

pub(crate) fn log(level: &str, module: &str, message: &str) {
    let context = REQUEST_CONTEXT.try_with(Clone::clone).ok();
    if let Some(log) = context
        .as_ref()
        .and_then(|context| context.error_log.as_ref())
    {
        log.write(level, module, message, context.as_ref());
    } else if let Some(log) = GLOBAL_ERROR_LOG.get() {
        log.write(level, module, message, context.as_ref());
    } else {
        let _ = writeln!(io::stderr().lock(), "{message}");
    }
}

#[macro_export]
macro_rules! log_error { ($($arg:tt)*) => { $crate::logging::log("error", module_path!(), &format!($($arg)*)) }; }
#[macro_export]
macro_rules! log_warn { ($($arg:tt)*) => { $crate::logging::log("warn", module_path!(), &format!($($arg)*)) }; }
#[macro_export]
macro_rules! log_notice { ($($arg:tt)*) => { $crate::logging::log("notice", module_path!(), &format!($($arg)*)) }; }

pub(crate) struct LoggedBody<B> {
    inner: std::pin::Pin<Box<B>>,
    log: Arc<AccessLog>,
    request: Option<AccessRequest>,
    response: AccessResponse,
    started: Instant,
    bytes: u64,
}

impl<B> LoggedBody<B> {
    pub(crate) fn new(
        inner: B,
        log: Arc<AccessLog>,
        request: AccessRequest,
        response: AccessResponse,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            log,
            request: Some(request),
            response,
            started: Instant::now(),
            bytes: 0,
        }
    }
}

impl<B> Body for LoggedBody<B>
where
    B: Body<Data = bytes::Bytes>,
{
    type Data = bytes::Bytes;
    type Error = B::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.inner.as_mut().poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(frame))) = &result {
            if let Some(data) = frame.data_ref() {
                self.bytes = self.bytes.saturating_add(data.len() as u64);
            }
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for LoggedBody<B> {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            self.log
                .write(request, self.response.clone(), self.started, self.bytes);
        }
    }
}

pub(crate) fn open_log(path: &Path, kind: &str) -> Result<LogTarget, Box<dyn Error + Send + Sync>> {
    LogTarget::file(path)
        .map_err(|error| format!("could not open {kind} log {}: {error}", path.display()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_and_combined_formats() {
        assert!(AccessFormat::parse("common").is_ok());
        assert!(AccessFormat::parse("combined").is_ok());
        assert!(AccessFormat::parse("%h %l %u %t \"%r\" %>s %b").is_ok());
    }

    #[test]
    fn rejects_unknown_directives() {
        assert!(AccessFormat::parse("%z").is_err());
    }

    #[test]
    fn parses_conditional_and_strftime_directives() {
        assert!(
            AccessFormat::parse("%400,501{User-Agent}i %{begin:%d/%b/%Y:%H:%M:%S %z}t").is_ok()
        );
    }

    #[test]
    fn parses_error_format_omission() {
        assert!(ErrorFormat::parse("[%t] [%l] %-M").is_ok());
    }

    fn sample_request() -> AccessRequest {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "agent \"x\"\t".parse().unwrap());
        AccessRequest {
            method: Method::GET,
            path: "/a?b=1".to_owned(),
            version: Version::HTTP_11,
            client: "203.0.113.9:1234".parse().unwrap(),
            peer: "127.0.0.1:5555".parse().unwrap(),
            local: "127.0.0.1:8080".parse().unwrap(),
            server_name: "example.test".to_owned(),
            ja4: "-".to_owned(),
            headers,
            started: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(17_280_000),
        }
    }

    fn render(format: &str, status: u16, bytes: u64) -> String {
        let response = AccessResponse {
            status,
            headers: HeaderMap::new(),
        };
        AccessFormat::parse(format).unwrap().render(
            &sample_request(),
            &response,
            Instant::now(),
            bytes,
            SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn renders_common_fields_and_escapes_values() {
        assert_eq!(
            render("%h %a %{c}a %v \"%r\" %>s %b %B %U%q", 200, 0),
            "203.0.113.9 203.0.113.9 127.0.0.1 example.test \"GET /a?b=1 HTTP/1.1\" 200 - 0 /a?b=1"
        );
        assert_eq!(render("%{User-Agent}i", 200, 5), "agent \\\"x\\\"\\x09");
        assert_eq!(render("%{sec}t %{begin:%Y}t", 200, 0), "17280000 1970");
    }

    #[test]
    fn honours_status_conditions() {
        assert_eq!(render("%400,501{User-Agent}i", 200, 0), "-");
        assert_eq!(render("%!200{X-Missing}i|%400s", 404, 0), "-|-");
        assert_eq!(render("%404s", 404, 0), "404");
    }

    #[test]
    fn omits_missing_error_fields() {
        let format = ErrorFormat::parse("[%l] [client\\ %a] %M% ,\\ host\\ %v").unwrap();
        let event = ErrorEvent {
            level: "error",
            module: "m",
            message: "boom",
            context: None,
        };
        assert_eq!(format.render(&event), "[error] [client ] boom");
        let context = RequestContext {
            client: Some("192.0.2.1:9".parse().unwrap()),
            server_name: "s.test".to_owned(),
            ..RequestContext::default()
        };
        let event = ErrorEvent {
            level: "error",
            module: "m",
            message: "boom",
            context: Some(&context),
        };
        assert_eq!(
            format.render(&event),
            "[error] [client 192.0.2.1] boom, host s.test"
        );
    }
}
