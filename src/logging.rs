//! Access and error log formatting and output.

use std::{
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    time::{Duration, Instant, SystemTime},
};

use http::{HeaderMap, Method, Version};
use http_body::{Body, Frame};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Stage {
    Bot,
    Waf,
    WafResponse,
    Spawn,
    Backend,
}

impl Stage {
    const ALL: [Self; 5] = [
        Self::Bot,
        Self::Waf,
        Self::WafResponse,
        Self::Spawn,
        Self::Backend,
    ];

    fn index(self) -> usize {
        match self {
            Self::Bot => 0,
            Self::Waf => 1,
            Self::WafResponse => 2,
            Self::Spawn => 3,
            Self::Backend => 4,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Bot => "bot",
            Self::Waf => "waf",
            Self::WafResponse => "waf_response",
            Self::Spawn => "spawn",
            Self::Backend => "backend",
        }
    }
}

pub(crate) struct RequestTiming {
    started: Instant,
    stages: [AtomicU64; 5],
    headers: AtomicU64,
    first_byte: AtomicU64,
}

impl RequestTiming {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            stages: std::array::from_fn(|_| AtomicU64::new(0)),
            headers: AtomicU64::new(0),
            first_byte: AtomicU64::new(0),
        }
    }

    fn elapsed_us(&self) -> u64 {
        duration_us(self.started.elapsed())
    }

    pub(crate) fn mark_headers(&self) {
        record_elapsed(&self.headers, self.elapsed_us());
    }

    fn mark_first_byte(&self) {
        record_elapsed(&self.first_byte, self.elapsed_us());
    }

    fn stage_us(&self, stage: Stage) -> Option<u64> {
        decode_duration(self.stages[stage.index()].load(Ordering::Relaxed))
    }

    fn metric_us(&self, name: &str) -> Option<u64> {
        match name {
            "total" => Some(self.elapsed_us()),
            "headers" => decode_duration(self.headers.load(Ordering::Relaxed)),
            "ttfb" => decode_duration(self.first_byte.load(Ordering::Relaxed)),
            "bot" => self.stage_us(Stage::Bot),
            "waf" => self.stage_us(Stage::Waf),
            "waf_response" => self.stage_us(Stage::WafResponse),
            "spawn" => self.stage_us(Stage::Spawn),
            "backend" => self.stage_us(Stage::Backend),
            _ => None,
        }
    }
}

fn duration_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX - 1)
}

fn record_elapsed(target: &AtomicU64, elapsed_us: u64) {
    let encoded = elapsed_us.saturating_add(1);
    let _ = target.compare_exchange(0, encoded, Ordering::Relaxed, Ordering::Relaxed);
}

fn decode_duration(value: u64) -> Option<u64> {
    value.checked_sub(1)
}

fn format_timing_duration(micros: u64, unit: &str) -> String {
    match unit {
        "ms" => format!("{:.3}", micros as f64 / 1_000.0),
        "s" => format!("{:.6}", micros as f64 / 1_000_000.0),
        _ => micros.to_string(),
    }
}

fn add_duration(target: &AtomicU64, duration: Duration) {
    let duration_us = duration_us(duration);
    let _ = target.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(if current == 0 {
            duration_us.saturating_add(1)
        } else {
            current.saturating_add(duration_us)
        })
    });
}

pub(crate) fn record_stage(stage: Stage, duration: Duration) {
    let _ = REQUEST_CONTEXT.try_with(|context| {
        if let Some(timing) = &context.timing {
            add_duration(&timing.stages[stage.index()], duration);
        }
    });
}

pub(crate) struct StageTimer {
    stage: Stage,
    started: Instant,
    finished: bool,
}

impl StageTimer {
    pub(crate) fn new(stage: Stage) -> Self {
        Self {
            stage,
            started: Instant::now(),
            finished: false,
        }
    }

    pub(crate) fn finish(mut self) {
        self.record();
    }

    fn record(&mut self) {
        if !self.finished {
            record_stage(self.stage, self.started.elapsed());
            self.finished = true;
        }
    }
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        self.record();
    }
}

pub(crate) fn server_timing_value(timing: &RequestTiming) -> String {
    let mut metrics = Vec::with_capacity(7);
    for stage in Stage::ALL {
        if let Some(micros) = timing.stage_us(stage) {
            metrics.push(format!(
                "{};dur={:.3}",
                stage.name(),
                micros as f64 / 1000.0
            ));
        }
    }
    if let Some(micros) = decode_duration(timing.headers.load(Ordering::Relaxed)) {
        metrics.push(format!("headers;dur={:.3}", micros as f64 / 1000.0));
    }
    // The status line and headers are the first bytes written to the client, so
    // the header is sent at the server-side time to first byte. A body byte that
    // was already produced (it cannot be at this point today) is preferred.
    let ttfb = decode_duration(timing.first_byte.load(Ordering::Relaxed))
        .or_else(|| decode_duration(timing.headers.load(Ordering::Relaxed)))
        .unwrap_or_else(|| timing.elapsed_us());
    metrics.push(format!(
        "ttfb;desc=\"Time to first byte\";dur={:.3}",
        ttfb as f64 / 1000.0
    ));
    metrics.push(format!(
        "total;dur={:.3}",
        timing.elapsed_us() as f64 / 1000.0
    ));
    metrics.join(", ")
}

enum LogMessage {
    Line(String),
    Flush(mpsc::Sender<()>),
}

#[derive(Clone)]
pub(crate) struct LogTarget(Arc<LogTargetKind>);

enum LogTargetKind {
    Synchronous(Mutex<Box<dyn Write + Send>>),
    Asynchronous(SyncSender<LogMessage>),
}

static FILE_LOGS: OnceLock<Mutex<Vec<SyncSender<LogMessage>>>> = OnceLock::new();

const LOG_QUEUE_CAPACITY: usize = 8192;

impl LogTarget {
    pub(crate) fn file(path: &Path) -> io::Result<Self> {
        let file = open_log_file(path)?;
        let (sender, receiver) = mpsc::sync_channel(LOG_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("charlotte-log-writer".to_owned())
            .spawn(move || file_log_writer(file, receiver))?;
        FILE_LOGS
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(sender.clone());
        Ok(Self(Arc::new(LogTargetKind::Asynchronous(sender))))
    }

    pub(crate) fn stdout() -> Self {
        Self(Arc::new(LogTargetKind::Synchronous(Mutex::new(Box::new(
            io::stdout(),
        )))))
    }

    pub(crate) fn stderr() -> Self {
        Self(Arc::new(LogTargetKind::Synchronous(Mutex::new(Box::new(
            io::stderr(),
        )))))
    }

    fn write_line(&self, line: &str) {
        match self.0.as_ref() {
            LogTargetKind::Synchronous(writer) => {
                let mut writer = writer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = writer.write_all(line.as_bytes());
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
            }
            LogTargetKind::Asynchronous(sender) => {
                let _ = sender.send(LogMessage::Line(line.to_owned()));
            }
        }
    }
}

fn file_log_writer(mut file: std::fs::File, receiver: Receiver<LogMessage>) {
    while let Ok(message) = receiver.recv() {
        match message {
            LogMessage::Line(line) => {
                let mut failed =
                    file.write_all(line.as_bytes()).is_err() || file.write_all(b"\n").is_err();
                while !failed {
                    match receiver.try_recv() {
                        Ok(LogMessage::Line(line)) => {
                            failed = file.write_all(line.as_bytes()).is_err()
                                || file.write_all(b"\n").is_err();
                        }
                        Ok(LogMessage::Flush(acknowledge)) => {
                            let _ = file.flush();
                            let _ = acknowledge.send(());
                        }
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                    }
                }
                let _ = file.flush();
            }
            LogMessage::Flush(acknowledge) => {
                let _ = file.flush();
                let _ = acknowledge.send(());
            }
        }
    }
    let _ = file.flush();
}

/// Flushes all file-backed log targets, waiting briefly for each writer thread.
pub fn flush_logs() {
    let Some(logs) = FILE_LOGS.get() else {
        return;
    };
    let logs = logs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    for sender in logs {
        let (acknowledge, receiver) = mpsc::channel();
        if sender.send(LogMessage::Flush(acknowledge)).is_ok() {
            let _ = receiver.recv_timeout(Duration::from_secs(2));
        }
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
            if !"aAbBDhHilmnopPqrstTuvVUCIOS".contains(code) {
                return Err(format!("unsupported access log format directive: %{code}"));
            }
            if code == 'n' && argument.as_deref().is_some_and(|arg| arg != "ja4") {
                return Err(format!(
                    "unsupported access log note: {}",
                    argument.unwrap()
                ));
            }
            if code == 'T'
                && let Some(argument) = argument.as_deref()
            {
                validate_timing_argument(argument)?;
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
        timing: &RequestTiming,
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
                        timing,
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

fn validate_timing_argument(argument: &str) -> Result<(), String> {
    if matches!(argument, "us" | "ms" | "s") {
        return Ok(());
    }
    let mut parts = argument.split(':');
    let name = parts.next().unwrap_or_default();
    let unit = parts.next().unwrap_or("us");
    if parts.next().is_some()
        || !matches!(
            name,
            "total" | "headers" | "ttfb" | "bot" | "waf" | "waf_response" | "spawn" | "backend"
        )
    {
        return Err(format!("unknown access log timing metric: {argument}"));
    }
    if !matches!(unit, "us" | "ms" | "s") {
        return Err(format!("unknown access log timing unit: {unit}"));
    }
    Ok(())
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
        timing: &RequestTiming,
        bytes: u64,
    ) {
        self.target.write_line(&self.format.render(
            &request,
            &response,
            timing,
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
    pub received: Arc<AtomicU64>,
    pub started: SystemTime,
}

#[derive(Clone)]
pub(crate) struct AccessResponse {
    pub status: u16,
    pub version: Version,
    pub headers: HeaderMap,
}

fn access_value(
    code: char,
    argument: Option<&str>,
    modifier: Option<char>,
    request: &AccessRequest,
    response: &AccessResponse,
    timing: &RequestTiming,
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
        'D' => timing.elapsed_us().to_string(),
        'h' => request.client.ip().to_string(),
        'H' => version_name(request.version).to_owned(),
        'I' => request_bytes(request).to_string(),
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
        'O' => response_bytes(response, bytes).to_string(),
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
        'S' => request_bytes(request)
            .saturating_add(response_bytes(response, bytes))
            .to_string(),
        't' => access_time(argument, request.started, finished),
        'T' => {
            let (metric, unit) = match argument {
                Some("ms") => ("total", "ms"),
                Some("us") => ("total", "us"),
                Some("s") | None => ("total", "s"),
                Some(argument) => argument
                    .split_once(':')
                    .map_or((argument, "us"), |(metric, unit)| (metric, unit)),
            };
            timing.metric_us(metric).map_or_else(
                || "-".to_owned(),
                |micros| format_timing_duration(micros, unit),
            )
        }
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

fn request_bytes(request: &AccessRequest) -> u64 {
    let request_line = (request.method.as_str().len() as u64)
        .saturating_add(1)
        .saturating_add(request.path.len() as u64)
        .saturating_add(1)
        .saturating_add(version_name(request.version).len() as u64)
        .saturating_add(2);
    request_line
        .saturating_add(header_bytes(&request.headers))
        .saturating_add(request.received.load(Ordering::Relaxed))
}

fn response_bytes(response: &AccessResponse, body: u64) -> u64 {
    let status = response.status.to_string();
    let reason = http::StatusCode::from_u16(response.status)
        .map_or("", |status| status.canonical_reason().unwrap_or(""));
    let status_line = (version_name(response.version).len() as u64)
        .saturating_add(1)
        .saturating_add(status.len() as u64)
        .saturating_add(1)
        .saturating_add(reason.len() as u64)
        .saturating_add(2);
    status_line
        .saturating_add(header_bytes(&response.headers))
        .saturating_add(body)
}

fn header_bytes(headers: &HeaderMap) -> u64 {
    headers.iter().fold(2u64, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len() as u64)
            .saturating_add(2)
            .saturating_add(value.as_bytes().len() as u64)
            .saturating_add(2)
    })
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
    pub timing: Option<Arc<RequestTiming>>,
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
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_debug(enabled: bool) {
    DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
}

pub(crate) fn debug_enabled() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

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
#[macro_export]
macro_rules! log_debug { ($($arg:tt)*) => { if $crate::logging::debug_enabled() { $crate::logging::log("debug", module_path!(), &format!($($arg)*)) } }; }

pub(crate) struct LoggedBody<B> {
    inner: std::pin::Pin<Box<B>>,
    log: Option<Arc<AccessLog>>,
    request: Option<AccessRequest>,
    response: Option<AccessResponse>,
    timing: Arc<RequestTiming>,
    debug: bool,
    context: RequestContext,
    bytes: u64,
}

pub(crate) struct CountedBody<B> {
    inner: std::pin::Pin<Box<B>>,
    received: Option<Arc<AtomicU64>>,
}

impl<B> CountedBody<B> {
    pub(crate) fn new(inner: B, received: Option<Arc<AtomicU64>>) -> Self {
        Self {
            inner: Box::pin(inner),
            received,
        }
    }
}

impl<B> Body for CountedBody<B>
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
        if let (std::task::Poll::Ready(Some(Ok(frame))), Some(received)) = (&result, &self.received)
            && let Some(data) = frame.data_ref()
        {
            let bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
            let _ = received.try_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(bytes))
            });
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

impl<B> LoggedBody<B> {
    pub(crate) fn new(
        inner: B,
        log: Option<Arc<AccessLog>>,
        request: Option<AccessRequest>,
        response: Option<AccessResponse>,
        timing: Arc<RequestTiming>,
        debug: bool,
        context: RequestContext,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            log,
            request,
            response,
            timing,
            debug,
            context,
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
        match &result {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if !data.is_empty() {
                        self.timing.mark_first_byte();
                    }
                    self.bytes = self.bytes.saturating_add(data.len() as u64);
                }
            }
            std::task::Poll::Ready(None) => self.timing.mark_first_byte(),
            _ => {}
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
        if let (Some(log), Some(request), Some(response)) =
            (&self.log, self.request.as_ref(), self.response.as_ref())
        {
            log.write(request.clone(), response.clone(), &self.timing, self.bytes);
        }
        if self.debug {
            let request = self.request.as_ref();
            let method = request.map_or("-", |request| request.method.as_str());
            let path = request.map_or("-", |request| request.path.as_str());
            let status = self
                .response
                .as_ref()
                .map_or_else(|| "-".to_owned(), |response| response.status.to_string());
            let line = format!(
                "request timing: {method} {path} status={status} headers={} ttfb={} total={} bot={} waf={} waf_response={} spawn={} backend={}",
                timing_field(self.timing.metric_us("headers")),
                timing_field(self.timing.metric_us("ttfb")),
                timing_field(self.timing.metric_us("total")),
                stage_field(&self.timing, Stage::Bot),
                stage_field(&self.timing, Stage::Waf),
                stage_field(&self.timing, Stage::WafResponse),
                stage_field(&self.timing, Stage::Spawn),
                stage_field(&self.timing, Stage::Backend),
            );
            write_context_log("debug", module_path!(), &line, &self.context);
        }
    }
}

fn timing_field(micros: Option<u64>) -> String {
    micros.map_or_else(|| "-".to_owned(), |micros| format!("{micros}us"))
}

fn stage_field(timing: &RequestTiming, stage: Stage) -> String {
    timing_field(timing.stage_us(stage))
}

fn write_context_log(level: &str, module: &str, message: &str, context: &RequestContext) {
    if let Some(log) = &context.error_log {
        log.write(level, module, message, Some(context));
    } else if let Some(log) = GLOBAL_ERROR_LOG.get() {
        log.write(level, module, message, Some(context));
    } else {
        let _ = writeln!(io::stderr().lock(), "{message}");
    }
}

pub(crate) fn open_log(path: &Path, kind: &str) -> Result<LogTarget, Box<dyn Error + Send + Sync>> {
    LogTarget::file(path).map_err(|error| format!("could not open {kind} log: {error}").into())
}

pub(crate) fn open_log_file(path: &Path) -> io::Result<std::fs::File> {
    use crate::pathctx::PathContext;

    if let Some(file) = crate::logopener::open(path)? {
        return Ok(file);
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(path)
        .path_context("open log file", path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_log_target_flushes_queued_lines() {
        let path = std::env::temp_dir().join(format!(
            "charlotte-log-writer-{}-{}.log",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time is after the epoch")
                .as_nanos()
        ));
        let target = LogTarget::file(&path).expect("create file log target");

        target.write_line("queued log line");
        flush_logs();

        let contents = std::fs::read_to_string(&path).expect("read flushed log file");
        assert_eq!(contents, "queued log line\n");
        drop(target);
        std::fs::remove_file(path).expect("remove test log file");
    }

    #[test]
    fn parses_common_and_combined_formats() {
        assert!(AccessFormat::parse("common").is_ok());
        assert!(AccessFormat::parse("combined").is_ok());
        assert!(AccessFormat::parse("%h %l %u %t \"%r\" %>s %b").is_ok());
    }

    #[test]
    fn debug_flag_can_be_toggled() {
        set_debug(true);
        assert!(debug_enabled());
        set_debug(false);
        assert!(!debug_enabled());
    }

    #[test]
    fn parses_mod_logio_directives() {
        assert!(AccessFormat::parse("%I %O %S").is_ok());
    }

    #[test]
    fn parses_named_timing_directives_and_rejects_unknown_metrics() {
        assert!(AccessFormat::parse("%{total}T %{backend:ms}T %{waf_response:s}T").is_ok());
        assert!(AccessFormat::parse("%{backend:ns}T").is_err());
        assert!(AccessFormat::parse("%{unknown}T").is_err());
    }

    #[test]
    fn renders_timing_metrics_and_missing_stages() {
        let response = AccessResponse {
            status: 200,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
        };
        let timing = RequestTiming::new();
        timing.stages[Stage::Backend.index()].store(123_457, Ordering::Relaxed);
        timing.headers.store(8_001, Ordering::Relaxed);
        timing.first_byte.store(234_568, Ordering::Relaxed);
        let line =
            AccessFormat::parse("%{backend}T %{waf}T %{backend:ms}T %{ttfb:s}T %{headers:us}T")
                .unwrap()
                .render(
                    &sample_request(),
                    &response,
                    &timing,
                    0,
                    SystemTime::UNIX_EPOCH,
                );

        assert_eq!(line, "123456 - 123.456 0.234567 8000");
    }

    #[test]
    fn server_timing_header_uses_millisecond_durations() {
        let timing = RequestTiming::new();
        timing.stages[Stage::Backend.index()].store(123_457, Ordering::Relaxed);
        timing.headers.store(8_001, Ordering::Relaxed);

        let value = server_timing_value(&timing);
        assert!(
            value.starts_with(
                "backend;dur=123.456, headers;dur=8.000, ttfb;desc=\"Time to first byte\";dur=8.000, total;dur="
            ),
            "{value}"
        );
    }

    #[test]
    fn server_timing_header_reports_ttfb_without_header_mark() {
        let timing = RequestTiming::new();

        let value = server_timing_value(&timing);
        assert!(
            value.starts_with("ttfb;desc=\"Time to first byte\";dur="),
            "{value}"
        );
        assert!(value.contains(", total;dur="), "{value}");
    }

    #[test]
    fn counts_request_body_data_frames() {
        let received = Arc::new(AtomicU64::new(0));
        let mut body = Box::pin(CountedBody::new(
            http_body_util::Full::new(bytes::Bytes::from_static(b"payload")),
            Some(Arc::clone(&received)),
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            body.as_mut().poll_frame(&mut context),
            std::task::Poll::Ready(Some(Ok(_)))
        ));
        assert_eq!(received.load(Ordering::Relaxed), 7);
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
            received: Arc::new(AtomicU64::new(5)),
            started: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(17_280_000),
        }
    }

    fn render(format: &str, status: u16, bytes: u64) -> String {
        let response = AccessResponse {
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
        };
        let timing = RequestTiming::new();
        AccessFormat::parse(format).unwrap().render(
            &sample_request(),
            &response,
            &timing,
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
    fn renders_mod_logio_byte_totals() {
        let request = sample_request();
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "value".parse().unwrap());
        let response = AccessResponse {
            status: 200,
            version: Version::HTTP_11,
            headers,
        };
        let format = AccessFormat::parse("%I %O %S").unwrap();
        let timing = RequestTiming::new();

        assert_eq!(
            format.render(&request, &response, &timing, 5, SystemTime::UNIX_EPOCH,),
            "52 39 91"
        );
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
