//! Loads ModSecurity rules and inspects HTTP requests and responses.

use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    future::Future,
    io,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use bytes::Bytes;
use futures_util::stream;
use http::{
    HeaderMap, HeaderValue, Request, Response, StatusCode, Version,
    header::{self, HOST},
};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use modsecurity::{Intervention, ModSecurity, Rules, Transaction};

use crate::response::{self, ResponseBody};

const CONNECTOR_INFO: &str = "project-charlotte/0.1.0";
/// How long a client may take to deliver a request body for inspection.
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
pub(crate) struct Waf {
    modsecurity: &'static ModSecurity,
    rules: &'static Rules,
    rule_files: &'static [PathBuf],
    request_body_limit: usize,
    response_body_limit: usize,
    response_body_policy: &'static ResponseBodyPolicy,
    response_body_override: Option<bool>,
    block_status: Option<StatusCode>,
}

#[derive(Clone, Debug)]
struct ResponseBodyPolicy {
    access: bool,
    mime_types: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuleIdSpec {
    start: u64,
    end: Option<u64>,
}

impl FromStr for RuleIdSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parse_id = |id: &str| {
            if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("invalid ModSecurity rule ID: {value}"));
            }
            let id = id
                .parse::<u64>()
                .map_err(|_| format!("invalid ModSecurity rule ID: {value}"))?;
            if id == 0 {
                return Err("ModSecurity rule ID must be greater than zero".to_owned());
            }
            Ok(id)
        };

        if let Some((start, end)) = value.split_once('-') {
            if end.contains('-') {
                return Err(format!("invalid ModSecurity rule ID range: {value}"));
            }
            let start = parse_id(start)?;
            let end = parse_id(end)?;
            if start > end {
                return Err(format!("ModSecurity rule ID range is reversed: {value}"));
            }
            Ok(Self {
                start,
                end: Some(end),
            })
        } else {
            Ok(Self {
                start: parse_id(value)?,
                end: None,
            })
        }
    }
}

impl std::fmt::Display for RuleIdSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(end) = self.end {
            write!(formatter, "{}-{end}", self.start)
        } else {
            write!(formatter, "{}", self.start)
        }
    }
}

impl ResponseBodyPolicy {
    fn conservative() -> Self {
        Self {
            access: true,
            mime_types: HashSet::new(),
        }
    }

    fn default() -> Self {
        Self {
            access: false,
            mime_types: HashSet::from(["text/plain".to_owned(), "text/html".to_owned()]),
        }
    }
}

fn scan_response_body_policy(rule_files: &[PathBuf]) -> io::Result<ResponseBodyPolicy> {
    let mut policy = ResponseBodyPolicy::default();
    let mut visited = HashSet::new();
    let mut dynamic_policy = false;
    for path in rule_files {
        scan_response_rule_file(path, &mut policy, &mut visited, &mut dynamic_policy)?;
    }
    if dynamic_policy {
        return Ok(ResponseBodyPolicy::conservative());
    }
    Ok(policy)
}

fn scan_response_rule_file(
    path: &Path,
    policy: &mut ResponseBodyPolicy,
    visited: &mut HashSet<PathBuf>,
    dynamic_policy: &mut bool,
) -> io::Result<()> {
    let path = path.canonicalize()?;
    if !visited.insert(path.clone()) {
        return Ok(());
    }
    let contents = std::fs::read_to_string(&path)?;
    let lines = continued_rule_lines(&contents);
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("ctl:responsebodyaccess")
            || lower.contains("ctl:responsebodymimetype")
            || lower.starts_with("secremoterules ")
        {
            *dynamic_policy = true;
            continue;
        }
        let (directive, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let value = value.trim();
        match directive.to_ascii_lowercase().as_str() {
            "secresponsebodyaccess" => {
                let value = value
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                match value.as_str() {
                    "on" => policy.access = true,
                    "off" => policy.access = false,
                    _ => return Err(io::Error::other("invalid SecResponseBodyAccess value")),
                }
            }
            "secresponsebodymimetype" => {
                for mime_type in value.split_whitespace() {
                    let mime_type = mime_type.trim_matches(['"', '\'']).to_ascii_lowercase();
                    if !mime_type.is_empty() {
                        policy.mime_types.insert(mime_type);
                    }
                }
            }
            "secresponsebodymimetypesclear" => policy.mime_types.clear(),
            "include" | "includeoptional" => {
                let optional = directive.eq_ignore_ascii_case("includeoptional");
                let include = value.trim_matches(['"', '\'']);
                let include_path = PathBuf::from(include);
                let mut matches = if include_path.is_absolute() {
                    expand_include_pattern(&include_path)?
                } else {
                    let relative = path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(&include_path);
                    let relative_matches = expand_include_pattern(&relative)?;
                    if relative_matches.is_empty() {
                        expand_include_pattern(&include_path)?
                    } else {
                        relative_matches
                    }
                };
                if matches.is_empty() && !optional {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("included rule file was not found: {include}"),
                    ));
                }
                matches.sort();
                for included in matches {
                    scan_response_rule_file(&included, policy, visited, dynamic_policy)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn continued_rule_lines(contents: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut continued = String::new();
    for line in contents.lines() {
        let line = line.trim_end();
        let continues = line.ends_with('\\');
        continued.push_str(line.trim_end_matches('\\'));
        if continues {
            continued.push(' ');
        } else {
            lines.push(std::mem::take(&mut continued));
        }
    }
    if !continued.is_empty() {
        lines.push(continued);
    }
    lines
}

fn expand_include_pattern(pattern: &Path) -> io::Result<Vec<PathBuf>> {
    let mut base = PathBuf::new();
    let mut components = Vec::new();
    for component in pattern.components() {
        match component {
            Component::RootDir => base.push("/"),
            Component::CurDir => {}
            Component::ParentDir => components.push("..".to_owned()),
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::Prefix(prefix) => {
                components.push(prefix.as_os_str().to_string_lossy().into_owned())
            }
        }
    }
    expand_include_components(&base, &components, 0)
}

fn expand_include_components(
    base: &Path,
    components: &[String],
    index: usize,
) -> io::Result<Vec<PathBuf>> {
    if index == components.len() {
        return Ok(if base.exists() {
            vec![base.to_path_buf()]
        } else {
            Vec::new()
        });
    }
    let component = &components[index];
    if !component.contains(['*', '?']) {
        return expand_include_components(&base.join(component), components, index + 1);
    }
    let directory = if base.as_os_str().is_empty() {
        Path::new(".")
    } else {
        base
    };
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| glob_component_matches(component, name))
        {
            matches.extend(expand_include_components(
                &base.join(name),
                components,
                index + 1,
            )?);
        }
    }
    Ok(matches)
}

fn glob_component_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let mut star = None;
    let mut star_value_index = 0;
    while value_index < value.len() {
        if pattern.get(pattern_index) == Some(&b'?')
            || pattern.get(pattern_index) == value.get(value_index)
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    pattern[pattern_index..].iter().all(|byte| *byte == b'*')
}

impl Waf {
    pub(crate) fn load(
        rule_files: &[PathBuf],
        request_body_limit: usize,
        response_body_limit: usize,
        block_status: Option<StatusCode>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut modsecurity = ModSecurity::new()?;
        modsecurity.set_connector_info(CONNECTOR_INFO)?;
        modsecurity.set_log_callback(|message| {
            crate::log_error!("ModSecurity: {}", String::from_utf8_lossy(message));
        });

        let rule_files = Box::leak(rule_files.to_vec().into_boxed_slice());
        let rules = build_rules(rule_files, &[])?;
        let response_body_policy = Box::leak(Box::new(
            scan_response_body_policy(rule_files).unwrap_or_else(|error| {
                crate::log_error!(
                    "could not determine ModSecurity response-body policy; inspecting all response bodies: {error}"
                );
                ResponseBodyPolicy::conservative()
            }),
        ));

        Ok(Self {
            modsecurity: Box::leak(Box::new(modsecurity)),
            rules: Box::leak(Box::new(rules)),
            rule_files,
            request_body_limit,
            response_body_limit,
            response_body_policy,
            response_body_override: None,
            block_status,
        })
    }

    pub(crate) fn with_block_status(mut self, block_status: Option<StatusCode>) -> Self {
        self.block_status = block_status;
        self
    }

    pub(crate) fn with_response_body(mut self, inspect: bool) -> Self {
        self.response_body_override = Some(inspect);
        self
    }

    pub(crate) fn without_rules(
        &self,
        ids: &[RuleIdSpec],
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let rules = build_rules(self.rule_files, ids)?;
        Ok(Self {
            modsecurity: self.modsecurity,
            rules: Box::leak(Box::new(rules)),
            rule_files: self.rule_files,
            request_body_limit: self.request_body_limit,
            response_body_limit: self.response_body_limit,
            response_body_policy: self.response_body_policy,
            response_body_override: self.response_body_override,
            block_status: self.block_status,
        })
    }

    pub(crate) async fn inspect<B, F, Fut>(
        &self,
        request: Request<B>,
        peer: SocketAddr,
        local: SocketAddr,
        next: F,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
        F: FnOnce(Request<Full<Bytes>>) -> Fut,
        Fut: Future<Output = Response<ResponseBody>>,
    {
        let waf_timing = crate::logging::StageTimer::new(crate::logging::Stage::Waf);
        let (parts, body) = request.into_parts();
        let request_version = parts.version;
        let mut transaction = match Transaction::new(self.modsecurity, self.rules) {
            Ok(transaction) => transaction,
            Err(error) => {
                crate::log_error!("ModSecurity transaction creation failed: {error}");
                return response::error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Request inspection failed\n",
                );
            }
        };

        let phase_result = process_request_headers(&mut transaction, &parts, peer, local);
        let intervention = match phase_result {
            Ok(intervention) => intervention,
            Err(error) => {
                crate::log_error!("ModSecurity request-header inspection failed: {error}");
                return fail_closed(&mut transaction);
            }
        };
        if let Some(intervention) = intervention {
            return finish_intervention(&mut transaction, intervention, self.block_status).await;
        }

        let collecting = Limited::new(body, self.request_body_limit).collect();
        let collected = match tokio::time::timeout(REQUEST_BODY_TIMEOUT, collecting).await {
            Err(_) => {
                if let Err(error) = finish_logging(&mut transaction) {
                    crate::log_error!("ModSecurity logging failed: {error}");
                }
                return response::error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "Request body timed out\n",
                );
            }
            Ok(Ok(body)) => body,
            Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
                if let Err(error) = finish_logging(&mut transaction) {
                    crate::log_error!("ModSecurity logging failed: {error}");
                    return response::error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Request inspection failed\n",
                    );
                }
                return response::error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large\n",
                );
            }
            Ok(Err(error)) => {
                crate::log_error!(
                    "Request body read failed during ModSecurity inspection: {error}"
                );
                if let Err(error) = finish_logging(&mut transaction) {
                    crate::log_error!("ModSecurity logging failed: {error}");
                    return response::error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Request inspection failed\n",
                    );
                }
                return response::error_response(StatusCode::BAD_REQUEST, "Invalid request body\n");
            }
        };
        let request_body = collected.to_bytes();
        let body_intervention = (|| {
            if !request_body.is_empty()
                && let Some(intervention) = transaction.append_request_body(&request_body)?
            {
                return Ok(Some(intervention));
            }
            transaction.process_request_body()
        })();
        match body_intervention {
            Ok(Some(intervention)) => {
                return finish_intervention(&mut transaction, intervention, self.block_status)
                    .await;
            }
            Ok(None) => {}
            Err(error) => {
                crate::log_error!("ModSecurity request-body inspection failed: {error}");
                return fail_closed(&mut transaction);
            }
        }

        // Response rules see one response at a time. Were ranges honoured, a
        // client could fetch blocked content in pieces that each pass, so
        // inspected requests are always answered in full.
        let mut parts = parts;
        parts.headers.remove(header::RANGE);
        parts.headers.remove(header::IF_RANGE);
        let request = Request::from_parts(parts, Full::new(request_body));
        waf_timing.finish();
        let response = next(request).await;
        self.inspect_response(response, transaction, request_version)
            .await
    }

    async fn inspect_response(
        &self,
        response: Response<ResponseBody>,
        mut transaction: Transaction<'static>,
        request_version: Version,
    ) -> Response<ResponseBody> {
        let _response_timing = crate::logging::StageTimer::new(crate::logging::Stage::WafResponse);
        let response_headers = response.headers().iter().try_for_each(|(name, value)| {
            transaction.add_response_header(name.as_str().as_bytes(), value.as_bytes())
        });
        let phase_result = response_headers.and_then(|()| {
            transaction.process_response_headers(
                i32::from(response.status().as_u16()),
                response_protocol(request_version),
            )
        });
        match phase_result {
            Ok(Some(intervention)) => {
                return finish_intervention(&mut transaction, intervention, self.block_status)
                    .await;
            }
            Ok(None) => {}
            Err(error) => {
                crate::log_error!("ModSecurity response-header inspection failed: {error}");
                return fail_closed(&mut transaction);
            }
        }

        let (parts, mut body) = response.into_parts();
        let inspect_body = self.inspect_response_body(&parts.headers);
        if !inspect_body {
            return Response::from_parts(
                parts,
                streaming_response_body(transaction, VecDeque::new(), None, body, false),
            );
        }
        let mut buffered = VecDeque::new();
        let mut buffered_bytes = 0usize;
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        let available = self.response_body_limit.saturating_sub(buffered_bytes);
                        if data.len() > available {
                            if available > 0 {
                                let prefix = data.slice(..available);
                                match transaction.append_response_body(&prefix) {
                                    Ok(Some(intervention)) => {
                                        return finish_intervention(
                                            &mut transaction,
                                            intervention,
                                            self.block_status,
                                        )
                                        .await;
                                    }
                                    Ok(None) => {}
                                    Err(error) => {
                                        crate::log_error!(
                                            "ModSecurity response-body inspection failed: {error}"
                                        );
                                        return fail_closed(&mut transaction);
                                    }
                                }
                                buffered.push_back(Frame::data(prefix));
                            }
                            let remainder = data.slice(available..);
                            return Response::from_parts(
                                parts,
                                streaming_response_body(
                                    transaction,
                                    buffered,
                                    Some(Frame::data(remainder)),
                                    body,
                                    true,
                                ),
                            );
                        }

                        match transaction.append_response_body(data) {
                            Ok(Some(intervention)) => {
                                return finish_intervention(
                                    &mut transaction,
                                    intervention,
                                    self.block_status,
                                )
                                .await;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                crate::log_error!(
                                    "ModSecurity response-body inspection failed: {error}"
                                );
                                return fail_closed(&mut transaction);
                            }
                        }
                        buffered_bytes += data.len();
                    }
                    buffered.push_back(frame);
                }
                Some(Err(error)) => {
                    crate::log_error!(
                        "Response body read failed during ModSecurity inspection: {error}"
                    );
                    return fail_closed(&mut transaction);
                }
                None => {
                    match transaction.process_response_body() {
                        Ok(Some(intervention)) => {
                            return finish_intervention(
                                &mut transaction,
                                intervention,
                                self.block_status,
                            )
                            .await;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            crate::log_error!(
                                "ModSecurity response-body inspection failed: {error}"
                            );
                            return fail_closed(&mut transaction);
                        }
                    }
                    if let Err(error) = finish_logging(&mut transaction) {
                        crate::log_error!("ModSecurity logging failed: {error}");
                        return response::error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Response inspection failed\n",
                        );
                    }
                    return Response::from_parts(parts, buffered_response_body(buffered));
                }
            }
        }
    }

    fn inspect_response_body(&self, headers: &HeaderMap) -> bool {
        if let Some(inspect) = self.response_body_override {
            return inspect;
        }
        if !self.response_body_policy.access {
            return false;
        }
        let mime_types = &self.response_body_policy.mime_types;
        if mime_types.is_empty() {
            return true;
        }
        let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
            return true;
        };
        let Ok(content_type) = content_type.to_str() else {
            return true;
        };
        let mime_type = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase();
        mime_types.contains(&mime_type)
    }
}

fn build_rules(
    rule_files: &[PathBuf],
    disabled_rules: &[RuleIdSpec],
) -> Result<Rules, Box<dyn Error + Send + Sync>> {
    let mut rules = Rules::new()?;
    for path in rule_files {
        rules.add_file(path)?;
    }
    if !disabled_rules.is_empty() {
        let ids = disabled_rules
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        rules.add_plain(&format!("SecRuleRemoveById {ids}"))?;
    }
    Ok(rules)
}

fn process_request_headers(
    transaction: &mut Transaction<'static>,
    parts: &http::request::Parts,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Option<Intervention>, Box<dyn Error + Send + Sync>> {
    if let Some(intervention) = transaction.process_connection(
        &peer.ip().to_string(),
        peer.port(),
        &local.ip().to_string(),
        local.port(),
    )? {
        return Ok(Some(intervention));
    }
    let uri = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), |value| value.as_str());
    if let Some(intervention) =
        transaction.process_uri(uri, parts.method.as_str(), request_protocol(parts.version))?
    {
        return Ok(Some(intervention));
    }

    let mut has_host = false;
    for (name, value) in &parts.headers {
        has_host |= name == HOST;
        transaction.add_request_header(name.as_str().as_bytes(), value.as_bytes())?;
    }
    if !has_host && let Some(authority) = parts.uri.authority() {
        transaction.add_request_header(HOST.as_str().as_bytes(), authority.as_str().as_bytes())?;
    }
    Ok(transaction.process_request_headers()?)
}

fn request_protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "1.1",
    }
}

fn response_protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

async fn finish_intervention(
    transaction: &mut Transaction<'static>,
    intervention: Intervention,
    block_status: Option<StatusCode>,
) -> Response<ResponseBody> {
    crate::log_error!("ModSecurity intervention: {intervention}");
    pause_for_intervention(&intervention).await;
    if let Err(error) = finish_logging(transaction) {
        crate::log_error!("ModSecurity logging failed: {error}");
        return response::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Request inspection failed\n",
        );
    }

    let status = intervention_status(
        intervention.url.is_some(),
        intervention.status as u16,
        block_status,
    );
    let mut response = response::error_response(status, "Request blocked by ModSecurity\n");
    if let Some(url) = intervention.url {
        let Ok(value) = HeaderValue::from_str(&url) else {
            return response::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid ModSecurity redirect\n",
            );
        };
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn intervention_status(
    redirect: bool,
    rule_status: u16,
    block_status: Option<StatusCode>,
) -> StatusCode {
    if redirect {
        StatusCode::from_u16(rule_status)
            .ok()
            .filter(|status| (300..400).contains(&status.as_u16()))
            .unwrap_or(StatusCode::FOUND)
    } else {
        block_status.unwrap_or_else(|| {
            StatusCode::from_u16(rule_status)
                .ok()
                .filter(|status| (400..600).contains(&status.as_u16()))
                .unwrap_or(StatusCode::FORBIDDEN)
        })
    }
}

async fn pause_for_intervention(intervention: &Intervention) {
    if intervention.pause > 0 {
        tokio::time::sleep(Duration::from_millis(intervention.pause as u64)).await;
    }
}

fn fail_closed(transaction: &mut Transaction<'static>) -> Response<ResponseBody> {
    if let Err(error) = finish_logging(transaction) {
        crate::log_error!("ModSecurity logging failed: {error}");
    }
    response::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Request inspection failed\n",
    )
}

fn finish_logging(
    transaction: &mut Transaction<'static>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    transaction.process_logging()?;
    Ok(())
}

fn buffered_response_body(frames: VecDeque<Frame<Bytes>>) -> ResponseBody {
    let frames = frames.into_iter().map(Ok::<_, io::Error>);
    StreamBody::new(stream::iter(frames)).boxed_unsync()
}

fn streaming_response_body(
    transaction: Transaction<'static>,
    buffered: VecDeque<Frame<Bytes>>,
    first_tail: Option<Frame<Bytes>>,
    body: ResponseBody,
    process_response_body: bool,
) -> ResponseBody {
    let state = StreamingBody {
        transaction: Some(transaction),
        buffered,
        first_tail,
        body,
        process_response_body,
    };
    let chunks = stream::unfold(state, |mut state| async move {
        if let Some(frame) = state.buffered.pop_front() {
            return Some((Ok(frame), state));
        }
        let frame = if let Some(frame) = state.first_tail.take() {
            Some(Ok(frame))
        } else {
            state.body.frame().await
        };
        match frame {
            Some(Ok(frame)) => {
                if state.process_response_body
                    && let Some(data) = frame.data_ref()
                    && let Some(transaction) = state.transaction.as_mut()
                {
                    match transaction.append_response_body(data) {
                        Ok(Some(intervention)) => {
                            crate::log_error!(
                                "ModSecurity response-body intervention: {intervention}"
                            );
                            pause_for_intervention(&intervention).await;
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response blocked by ModSecurity")),
                                state,
                            ));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            crate::log_error!(
                                "ModSecurity response-body inspection failed: {error}"
                            );
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response inspection failed")),
                                state,
                            ));
                        }
                    }
                }
                Some((Ok(frame), state))
            }
            Some(Err(error)) => {
                let _ = state.finish();
                Some((Err(error), state))
            }
            None => {
                if state.process_response_body
                    && let Some(transaction) = state.transaction.as_mut()
                {
                    match transaction.process_response_body() {
                        Ok(Some(intervention)) => {
                            crate::log_error!(
                                "ModSecurity response-body intervention: {intervention}"
                            );
                            pause_for_intervention(&intervention).await;
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response blocked by ModSecurity")),
                                state,
                            ));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            crate::log_error!(
                                "ModSecurity response-body inspection failed: {error}"
                            );
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response inspection failed")),
                                state,
                            ));
                        }
                    }
                }
                if let Err(error) = state.finish() {
                    crate::log_error!("ModSecurity logging failed: {error}");
                    return Some((Err(io::Error::other("ModSecurity logging failed")), state));
                }
                None
            }
        }
    });
    StreamBody::new(chunks).boxed_unsync()
}

struct StreamingBody {
    transaction: Option<Transaction<'static>>,
    buffered: VecDeque<Frame<Bytes>>,
    first_tail: Option<Frame<Bytes>>,
    body: ResponseBody,
    process_response_body: bool,
}

impl StreamingBody {
    fn finish(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(mut transaction) = self.transaction.take() {
            transaction.process_logging()?;
        }
        Ok(())
    }
}

impl Drop for StreamingBody {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            crate::log_error!("ModSecurity logging failed after response stream closed: {error}");
        }
    }
}

#[cfg(test)]
mod response_policy_tests {
    use std::path::PathBuf;

    use super::{glob_component_matches, scan_response_body_policy};

    fn rules_dir(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "charlotte-waf-policy-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn response_body_access_defaults_off() {
        let directory = rules_dir("default");
        let main = directory.join("main.conf");
        std::fs::write(&main, "SecRuleEngine On\n").unwrap();
        let policy = scan_response_body_policy(&[main]).unwrap();
        assert!(!policy.access);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn follows_glob_includes_and_mime_lists() {
        let directory = rules_dir("include");
        std::fs::create_dir(directory.join("rules")).unwrap();
        std::fs::write(
            directory.join("rules/a.conf"),
            "SecResponseBodyAccess On\nSecResponseBodyMimeTypesClear\n",
        )
        .unwrap();
        std::fs::write(
            directory.join("rules/b.conf"),
            "SecResponseBodyMimeType text/html \\\n    application/json\n",
        )
        .unwrap();
        let main = directory.join("main.conf");
        std::fs::write(&main, "Include \"rules/*.conf\"\n").unwrap();
        let policy = scan_response_body_policy(&[main]).unwrap();
        assert!(policy.access);
        assert!(policy.mime_types.contains("text/html"));
        assert!(policy.mime_types.contains("application/json"));
        assert!(!policy.mime_types.contains("text/plain"));
        assert!(!policy.mime_types.contains("application/octet-stream"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn runtime_response_body_controls_inspect_everything() {
        let directory = rules_dir("ctl");
        let main = directory.join("main.conf");
        std::fs::write(
            &main,
            "SecResponseBodyAccess Off\nSecRule REQUEST_URI \"@beginsWith /x\" \"id:1,phase:1,pass,ctl:responseBodyAccess=On\"\n",
        )
        .unwrap();
        let policy = scan_response_body_policy(&[main]).unwrap();
        assert!(policy.access);
        assert!(policy.mime_types.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_include_is_an_error() {
        let directory = rules_dir("missing");
        let main = directory.join("main.conf");
        std::fs::write(&main, "Include missing.conf\nIncludeOptional none/*.conf\n").unwrap();
        assert!(scan_response_body_policy(&[main]).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn matches_include_globs() {
        assert!(glob_component_matches("*.conf", "REQUEST-901.conf"));
        assert!(glob_component_matches("a?c", "abc"));
        assert!(!glob_component_matches("*.conf", "rules.conf.bak"));
    }
}

// The tests drive the WAF through the static file handler.
#[cfg(all(test, feature = "hosting"))]
mod tests {
    use std::sync::{Arc, OnceLock};

    use crate::{
        config::Config,
        fuzz_support::{self, FuzzRequest},
        vhost::Router,
    };

    use super::{RuleIdSpec, Waf, intervention_status};
    use http::StatusCode;

    /// Request bodies above this size are refused by the fuzz WAF. It is kept
    /// small so that the limit is within reach of fuzzer-sized inputs.
    const REQUEST_BODY_LIMIT: usize = 4096;
    /// `large.txt` exceeds this, which moves its response onto the streaming
    /// inspection path.
    const RESPONSE_BODY_LIMIT: usize = 1024 * 1024;
    const _: () = assert!(fuzz_support::LARGE_FILE_LEN > RESPONSE_BODY_LIMIT);

    #[test]
    fn blocking_status_override_takes_precedence() {
        assert_eq!(
            intervention_status(false, 418, Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)),
            StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
        );
    }

    #[test]
    fn blocking_status_uses_rule_status_or_forbidden_fallback() {
        assert_eq!(
            intervention_status(false, 418, None),
            StatusCode::IM_A_TEAPOT
        );
        assert_eq!(intervention_status(false, 399, None), StatusCode::FORBIDDEN);
        assert_eq!(intervention_status(false, 600, None), StatusCode::FORBIDDEN);
    }

    #[test]
    fn redirect_status_ignores_block_override() {
        assert_eq!(
            intervention_status(true, 302, Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)),
            StatusCode::FOUND
        );
        assert_eq!(
            intervention_status(true, 403, Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)),
            StatusCode::FOUND
        );
    }

    fn fuzz_waf() -> Waf {
        static WAF: OnceLock<Waf> = OnceLock::new();
        *WAF.get_or_init(|| {
            let fixture = fuzz_support::fixture();
            Waf::load(
                std::slice::from_ref(&fixture.rules),
                REQUEST_BODY_LIMIT,
                RESPONSE_BODY_LIMIT,
                None,
            )
            .expect("fuzz ModSecurity rules load")
        })
    }

    #[test_fuzz::test_fuzz]
    fn waf_request(input: FuzzRequest) {
        let Some(request) = input.build() else {
            return;
        };
        let fixture = fuzz_support::fixture();
        let mut config: Config = fuzz_support::fuzz_config(fixture.root.clone());
        config.fastcgi.clear();
        let (peer, local) = fuzz_support::addresses();
        let method = request.method().clone();
        let must_block = request
            .uri()
            .query()
            .is_some_and(|query| query.split('&').any(|pair| pair == "block=yes"));
        let collected = fuzz_support::collect(async {
            let router = Router::load(Arc::new(config), None, None, None, Some(fuzz_waf()))
                .await
                .expect("WAF router loads");
            router.dispatch(request, peer, local).await
        });
        // A streamed response may be cut short by a late intervention, so a
        // body error is acceptable here; what was delivered is still checked.
        fuzz_support::assert_response_invariants(&method, &collected);
        // The only fixture content holding the marker is smaller than the
        // inspection limit, so the response rule must always catch it.
        assert!(
            !fuzz_support::contains(&collected.body, fuzz_support::RESPONSE_SECRET),
            "response rule was bypassed"
        );
        if must_block {
            assert_eq!(
                collected.parts.status,
                http::StatusCode::FORBIDDEN,
                "request rule was bypassed"
            );
        }
    }

    #[test]
    fn fuzz_seed_waf_request() {
        waf_request(FuzzRequest::default());
        for uri in [
            "/response-secret.txt",
            "/safe.txt?block=yes",
            "/large.txt",
            "/listing/",
        ] {
            waf_request(FuzzRequest {
                uri: uri.to_owned(),
                ..FuzzRequest::default()
            });
        }
        waf_request(FuzzRequest {
            uri: "/response-secret.txt".to_owned(),
            headers: vec![("range".to_owned(), b"bytes=18-".to_vec())],
            ..FuzzRequest::default()
        });
        waf_request(FuzzRequest {
            method: "POST".to_owned(),
            headers: vec![(
                "content-type".to_owned(),
                b"application/x-www-form-urlencoded".to_vec(),
            )],
            body: b"block=yes".to_vec(),
            ..FuzzRequest::default()
        });
        waf_request(FuzzRequest {
            method: "POST".to_owned(),
            body: vec![b'a'; REQUEST_BODY_LIMIT + 1],
            ..FuzzRequest::default()
        });
    }

    #[test]
    fn range_requests_cannot_split_blocked_content() {
        let fixture = fuzz_support::fixture();
        let mut config: Config = fuzz_support::fuzz_config(fixture.root.clone());
        config.fastcgi.clear();
        let config = Arc::new(config);
        let (peer, local) = fuzz_support::addresses();
        // "SECRET" spans bytes 18-23; neither half contains the whole marker.
        for range in ["bytes=0-20", "bytes=21-"] {
            let request = FuzzRequest {
                uri: "/response-secret.txt".to_owned(),
                headers: vec![("range".to_owned(), range.as_bytes().to_vec())],
                ..FuzzRequest::default()
            }
            .build()
            .unwrap();
            let config = Arc::clone(&config);
            let collected = fuzz_support::collect(async {
                let router = Router::load(config, None, None, None, Some(fuzz_waf()))
                    .await
                    .unwrap();
                router.dispatch(request, peer, local).await
            });
            assert_eq!(
                collected.parts.status,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Range: {range}"
            );
            assert!(collected.body.len() < 40);
        }
    }

    /// Rule exclusions from vhost files are interpolated into a ModSecurity
    /// directive, so an accepted value must render as plain IDs and ranges.
    #[test_fuzz::test_fuzz]
    fn rule_id_spec(value: &str) {
        if let Ok(spec) = value.parse::<RuleIdSpec>() {
            let rendered = spec.to_string();
            assert!(
                rendered
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'-')
            );
            assert_eq!(rendered.parse::<RuleIdSpec>(), Ok(spec));
        }
    }

    #[test]
    fn fuzz_seed_rule_id_spec() {
        rule_id_spec("942100");
        rule_id_spec("0042-100000");
        rule_id_spec("1 2");
    }
}
