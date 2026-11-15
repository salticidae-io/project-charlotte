use std::{
    collections::HashMap,
    fs, io,
    path::{Component, Path, PathBuf},
};

const MAX_INCLUDE_DEPTH: usize = 128;

#[derive(Clone, Debug)]
pub(super) struct Location {
    pub(super) file: PathBuf,
    pub(super) line: usize,
}

impl std::fmt::Display for Location {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.file.display(), self.line)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Directive {
    pub(super) name: String,
    pub(super) args: Vec<String>,
    pub(super) raw: String,
    pub(super) location: Location,
}

#[derive(Clone, Debug)]
pub(super) struct Section {
    pub(super) name: String,
    pub(super) args: Vec<String>,
    pub(super) raw_open: String,
    pub(super) raw_close: String,
    pub(super) location: Location,
    pub(super) children: Vec<Node>,
}

#[derive(Clone, Debug)]
pub(super) enum Node {
    Directive(Directive),
    Section(Section),
}

#[derive(Clone, Debug, Default)]
pub(super) struct ParseOptions {
    pub(super) server_root: Option<PathBuf>,
    pub(super) defines: Vec<String>,
}

#[derive(Clone)]
struct SourceLine {
    raw: String,
    location: Location,
}

struct Expander {
    defines: HashMap<String, String>,
    server_root: PathBuf,
    fixed_server_root: bool,
    include_stack: Vec<PathBuf>,
}

struct Frame {
    name: String,
    args: Vec<String>,
    raw_open: String,
    location: Location,
    children: Vec<Node>,
}

pub(super) fn parse(input: &Path, options: &ParseOptions) -> io::Result<Vec<Node>> {
    let input = fs::canonicalize(input)?;
    let initial_root = options.server_root.as_ref().map_or_else(
        || input.parent().unwrap_or(Path::new(".")).to_path_buf(),
        Clone::clone,
    );
    let mut expander = Expander {
        defines: HashMap::new(),
        server_root: initial_root,
        fixed_server_root: options.server_root.is_some(),
        include_stack: Vec::new(),
    };
    for define in &options.defines {
        let (name, value) = define
            .split_once('=')
            .map_or((define.as_str(), "1"), |(name, value)| (name, value));
        if name.is_empty() {
            return Err(invalid_input("-D requires a non-empty name"));
        }
        expander.defines.insert(name.to_owned(), value.to_owned());
    }
    let lines = expander.expand_file(&input, 0)?;
    build_tree(lines)
}

impl Expander {
    fn expand_file(&mut self, path: &Path, depth: usize) -> io::Result<Vec<SourceLine>> {
        if depth >= MAX_INCLUDE_DEPTH {
            return Err(invalid_input(format!(
                "Include nesting exceeds {MAX_INCLUDE_DEPTH} files at {}",
                path.display()
            )));
        }
        let canonical = fs::canonicalize(path)?;
        if self.include_stack.contains(&canonical) {
            let mut chain = self.include_stack.clone();
            chain.push(canonical);
            return Err(invalid_input(format!(
                "Include cycle detected: {}",
                chain
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            )));
        }

        self.include_stack.push(canonical.clone());
        let result = (|| {
            let content = fs::read_to_string(&canonical)?;
            let mut output = Vec::new();
            let mut conditions: Vec<bool> = Vec::new();
            for source in logical_lines(&content, &canonical)? {
                let trimmed = source.raw.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let tokens = tokenize(trimmed)
                    .map_err(|message| invalid_input(format!("{}: {message}", source.location)))?;
                let expanded = tokens
                    .iter()
                    .map(|token| self.expand_variables(token))
                    .collect::<Vec<_>>();
                if let Some((closing, tag_name, arguments)) = section_tag(trimmed)? {
                    if tag_name.eq_ignore_ascii_case("IfDefine") {
                        if closing {
                            if conditions.pop().is_none() {
                                return Err(invalid_input(format!(
                                    "{}: unmatched </IfDefine>",
                                    source.location
                                )));
                            }
                        } else {
                            let parent_active = conditions.iter().all(|active| *active);
                            let condition = arguments
                                .first()
                                .map(|condition| self.expand_variables(condition))
                                .ok_or_else(|| {
                                    invalid_input(format!(
                                        "{}: <IfDefine> requires a name",
                                        source.location
                                    ))
                                })?;
                            let (negated, name) = condition
                                .strip_prefix('!')
                                .map_or((false, condition.as_str()), |name| (true, name));
                            let is_defined = self.defines.contains_key(name);
                            conditions.push(parent_active && (is_defined != negated));
                        }
                        continue;
                    }
                }
                if !conditions.iter().all(|active| *active) {
                    continue;
                }
                if expanded.is_empty() {
                    continue;
                }
                let name = expanded[0].to_ascii_lowercase();
                let args = &expanded[1..];
                match name.as_str() {
                    "define" if !args.is_empty() => {
                        self.defines.insert(
                            args[0].clone(),
                            args.get(1).cloned().unwrap_or_else(|| "1".to_owned()),
                        );
                    }
                    "undefine" if !args.is_empty() => {
                        self.defines.remove(&args[0]);
                    }
                    "serverroot" if !args.is_empty() && !self.fixed_server_root => {
                        let root = PathBuf::from(&args[0]);
                        self.server_root = if root.is_absolute() {
                            root
                        } else {
                            canonical.parent().unwrap_or(Path::new(".")).join(root)
                        };
                    }
                    "include" | "includeoptional" => {
                        let optional = name == "includeoptional";
                        for include in args {
                            let pattern = PathBuf::from(include);
                            let pattern = if pattern.is_absolute() {
                                pattern
                            } else {
                                self.server_root.join(pattern)
                            };
                            let matches = include_matches(&pattern)?;
                            if matches.is_empty() && !optional {
                                return Err(io::Error::new(
                                    io::ErrorKind::NotFound,
                                    format!(
                                        "{}: Include matched no files: {}",
                                        source.location,
                                        pattern.display()
                                    ),
                                ));
                            }
                            output.push(source.clone());
                            for included in matches {
                                output.extend(self.expand_file(&included, depth + 1)?);
                            }
                        }
                        if args.is_empty() {
                            return Err(invalid_input(format!(
                                "{}: {name} requires at least one path",
                                source.location
                            )));
                        }
                        continue;
                    }
                    _ => {}
                }
                output.push(SourceLine {
                    raw: source.raw,
                    location: source.location,
                });
            }
            if !conditions.is_empty() {
                return Err(invalid_input(format!(
                    "{}: unclosed <IfDefine>",
                    canonical.display()
                )));
            }
            Ok(output)
        })();
        self.include_stack.pop();
        result
    }

    fn expand_variables(&self, value: &str) -> String {
        let mut output = String::with_capacity(value.len());
        let mut remaining = value;
        while let Some(start) = remaining.find("${") {
            output.push_str(&remaining[..start]);
            let after_start = &remaining[start + 2..];
            let Some(end) = after_start.find('}') else {
                output.push_str(&remaining[start..]);
                return output;
            };
            let name = &after_start[..end];
            if let Some(value) = self.defines.get(name) {
                output.push_str(value);
            } else {
                output.push_str(&remaining[start..start + end + 3]);
            }
            remaining = &after_start[end + 1..];
        }
        output.push_str(remaining);
        output
    }
}

fn logical_lines(content: &str, file: &Path) -> io::Result<Vec<SourceLine>> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    let mut first_line = 1;
    for (index, physical) in content.lines().enumerate() {
        let line_number = index + 1;
        if pending.is_empty() {
            first_line = line_number;
        }
        let trimmed = physical.trim_end();
        let continued = has_unescaped_trailing_backslash(trimmed);
        let part = if continued {
            &trimmed[..trimmed.len() - 1]
        } else {
            physical
        };
        if !pending.is_empty() {
            pending.push(' ');
        }
        pending.push_str(part.trim_start());
        if !continued {
            lines.push(SourceLine {
                raw: std::mem::take(&mut pending),
                location: Location {
                    file: file.to_path_buf(),
                    line: first_line,
                },
            });
        }
    }
    if !pending.is_empty() {
        lines.push(SourceLine {
            raw: pending,
            location: Location {
                file: file.to_path_buf(),
                line: first_line,
            },
        });
    }
    Ok(lines)
}

fn has_unescaped_trailing_backslash(value: &str) -> bool {
    value
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'\\')
        .count()
        % 2
        == 1
}

pub(super) fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut chars = line.chars().peekable();
    let mut token_started = false;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (Some(current), value) if value == current => quote = None,
            (Some(_), '\\') => {
                let Some(next) = chars.next() else {
                    token.push('\\');
                    break;
                };
                if Some(next) == quote || next == '\\' {
                    token.push(next);
                } else {
                    token.push('\\');
                    token.push(next);
                }
                token_started = true;
            }
            (Some(_), value) => {
                token.push(value);
                token_started = true;
            }
            (None, '#') => break,
            (None, '"' | '\'') => {
                quote = Some(character);
                token_started = true;
            }
            (None, '\\') => {
                let Some(next) = chars.next() else {
                    token.push('\\');
                    token_started = true;
                    break;
                };
                if next.is_whitespace() || next == '#' || next == '"' || next == '\\' {
                    token.push(next);
                } else {
                    token.push('\\');
                    token.push(next);
                }
                token_started = true;
            }
            (None, value) if value.is_whitespace() => {
                if token_started {
                    tokens.push(std::mem::take(&mut token));
                    token_started = false;
                }
            }
            (None, value) => {
                token.push(value);
                token_started = true;
            }
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted string".to_owned());
    }
    if token_started {
        tokens.push(token);
    }
    Ok(tokens)
}

fn section_tag(line: &str) -> io::Result<Option<(bool, String, Vec<String>)>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('<') || !trimmed.ends_with('>') {
        return Ok(None);
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let (closing, inner) = inner
        .strip_prefix('/')
        .map_or((false, inner), |inner| (true, inner));
    let tokens = tokenize(inner).map_err(invalid_input)?;
    let Some(name) = tokens.first() else {
        return Err(invalid_input("empty section tag"));
    };
    Ok(Some((closing, name.clone(), tokens[1..].to_vec())))
}

fn build_tree(lines: Vec<SourceLine>) -> io::Result<Vec<Node>> {
    let mut root = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    for source in lines {
        if let Some((closing, name, args)) = section_tag(&source.raw)? {
            if closing {
                let Some(frame) = frames.pop() else {
                    return Err(invalid_input(format!(
                        "{}: unmatched closing section </{name}>",
                        source.location
                    )));
                };
                if !frame.name.eq_ignore_ascii_case(&name) {
                    return Err(invalid_input(format!(
                        "{}: expected </{}>, found </{name}>",
                        source.location, frame.name
                    )));
                }
                let section = Section {
                    name: frame.name,
                    args: frame.args,
                    raw_open: frame.raw_open,
                    raw_close: source.raw,
                    location: frame.location,
                    children: frame.children,
                };
                push_node(&mut root, &mut frames, Node::Section(section));
            } else {
                frames.push(Frame {
                    name,
                    args,
                    raw_open: source.raw,
                    location: source.location,
                    children: Vec::new(),
                });
            }
            continue;
        }
        let tokens = tokenize(&source.raw)
            .map_err(|message| invalid_input(format!("{}: {message}", source.location)))?;
        let Some(name) = tokens.first() else {
            continue;
        };
        push_node(
            &mut root,
            &mut frames,
            Node::Directive(Directive {
                name: name.clone(),
                args: tokens[1..].to_vec(),
                raw: source.raw,
                location: source.location,
            }),
        );
    }
    if let Some(frame) = frames.last() {
        return Err(invalid_input(format!(
            "{}: unclosed <{}>",
            frame.location, frame.name
        )));
    }
    Ok(root)
}

fn push_node(root: &mut Vec<Node>, frames: &mut [Frame], node: Node) {
    if let Some(frame) = frames.last_mut() {
        frame.children.push(node);
    } else {
        root.push(node);
    }
}

fn include_matches(pattern: &Path) -> io::Result<Vec<PathBuf>> {
    let absolute = if pattern.is_absolute() {
        pattern.to_path_buf()
    } else {
        std::env::current_dir()?.join(pattern)
    };
    let mut current = vec![PathBuf::from("/")];
    let components = absolute
        .components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::Normal(value) => Some(value.to_os_string()),
            Component::ParentDir => Some("..".into()),
            Component::Prefix(_) => None,
        })
        .collect::<Vec<_>>();
    for component in components {
        let pattern = component.to_string_lossy();
        let mut next = Vec::new();
        if has_glob_chars(&pattern) {
            for base in &current {
                let entries = match fs::read_dir(base) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                for entry in entries {
                    let entry = entry?;
                    if component_matches(&pattern, &entry.file_name().to_string_lossy()) {
                        next.push(entry.path());
                    }
                }
            }
        } else {
            next.extend(current.iter().map(|base| base.join(&component)));
        }
        next.sort();
        current = next;
    }

    let mut files = Vec::new();
    let mut visited_dirs = Vec::new();
    for path in current {
        if path.is_dir() {
            collect_directory_files(&path, &mut visited_dirs, &mut files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_directory_files(
    directory: &Path,
    visited: &mut Vec<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let canonical = fs::canonicalize(directory)?;
    if visited.contains(&canonical) {
        return Ok(());
    }
    visited.push(canonical);
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_directory_files(&entry.path(), visited, files)?;
        } else if file_type.is_file() || entry.path().is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn has_glob_chars(value: &str) -> bool {
    value
        .chars()
        .any(|character| matches!(character, '*' | '?' | '['))
}

fn component_matches(pattern: &str, value: &str) -> bool {
    fn matches(pattern: &[char], value: &[char]) -> bool {
        match pattern.first() {
            None => value.is_empty(),
            Some('*') => {
                matches(&pattern[1..], value)
                    || value.first().is_some_and(|_| matches(pattern, &value[1..]))
            }
            Some('?') => value
                .first()
                .is_some_and(|_| matches(&pattern[1..], &value[1..])),
            Some('[') => {
                let Some(end) = pattern.iter().position(|character| *character == ']') else {
                    return value.first() == pattern.first()
                        && value
                            .first()
                            .is_some_and(|_| matches(&pattern[1..], &value[1..]));
                };
                let Some(character) = value.first() else {
                    return false;
                };
                let mut range = &pattern[1..end];
                let negate = range
                    .first()
                    .is_some_and(|value| matches!(value, '!' | '^'));
                if negate {
                    range = &range[1..];
                }
                let mut index = 0;
                let mut included = false;
                while index < range.len() {
                    if range.get(index + 1) == Some(&'-')
                        && let Some(last) = range.get(index + 2)
                    {
                        included |= range[index] <= *character && *character <= *last;
                        index += 3;
                    } else {
                        included |= range[index] == *character;
                        index += 1;
                    }
                }
                (included != negate) && matches(&pattern[end + 1..], &value[1..])
            }
            Some(expected) => value
                .first()
                .is_some_and(|actual| actual == expected && matches(&pattern[1..], &value[1..])),
        }
    }
    matches(
        &pattern.chars().collect::<Vec<_>>(),
        &value.chars().collect::<Vec<_>>(),
    )
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::{component_matches, logical_lines, tokenize};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "apache2charlotte-parse-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn tokenizes_quotes_comments_and_continuations() {
        let tokens = tokenize(r#"Header set X-Test "a # b" \#literal # comment"#).unwrap();
        assert_eq!(tokens, ["Header", "set", "X-Test", "a # b", "#literal"]);

        let lines = logical_lines(
            "One two \\\n  three\n",
            PathBuf::from("test.conf").as_path(),
        )
        .unwrap();
        assert_eq!(lines[0].raw, "One two  three");
        assert_eq!(lines[0].location.line, 1);
    }

    #[test]
    fn matches_component_globs() {
        assert!(component_matches("v[12].conf", "v2.conf"));
        assert!(component_matches("*.conf", "site.conf"));
        assert!(!component_matches("*.conf", "site.yaml"));
        assert!(component_matches("site?.conf", "site1.conf"));
    }

    #[test]
    fn follows_includes_recursively_and_detects_cycles() {
        use super::{ParseOptions, parse};

        let root = temp_dir();
        let nested = root.join("conf.d/nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(root.join("httpd.conf"), "Include conf.d\n").unwrap();
        fs::write(root.join("conf.d/a.conf"), "ServerName a.example\n").unwrap();
        fs::write(nested.join("b.conf"), "ServerAlias b.example\n").unwrap();

        let nodes = parse(&root.join("httpd.conf"), &ParseOptions::default()).unwrap();
        assert_eq!(nodes.len(), 3);

        fs::write(root.join("conf.d/a.conf"), "Include httpd.conf\n").unwrap();
        let error = parse(&root.join("httpd.conf"), &ParseOptions::default()).unwrap_err();
        assert!(error.to_string().contains("cycle"));
        let _ = fs::remove_dir_all(root);
    }
}
