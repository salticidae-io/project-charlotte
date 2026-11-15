use std::{
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
pub(super) struct Block {
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
    Block(Block),
}

#[derive(Clone, Debug, Default)]
pub(super) struct ParseOptions {
    pub(super) prefix: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Word,
    Semicolon,
    OpenBrace,
    CloseBrace,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    value: String,
    start: usize,
    end: usize,
    line: usize,
}

struct Parser {
    prefix: PathBuf,
    include_stack: Vec<PathBuf>,
}

pub(super) fn parse(input: &Path, options: &ParseOptions) -> io::Result<Vec<Node>> {
    let input = fs::canonicalize(input)?;
    let prefix = match &options.prefix {
        Some(prefix) if prefix.is_absolute() => prefix.clone(),
        Some(prefix) => std::env::current_dir()?.join(prefix),
        None => input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    };
    Parser {
        prefix,
        include_stack: Vec::new(),
    }
    .parse_file(&input, 0)
}

impl Parser {
    fn parse_file(&mut self, path: &Path, depth: usize) -> io::Result<Vec<Node>> {
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
            let tokens = tokenize(&content, &canonical)?;
            let mut cursor = 0;
            let nodes =
                self.parse_nodes(&canonical, &content, &tokens, &mut cursor, depth, None)?;
            if cursor != tokens.len() {
                return Err(invalid_input(format!(
                    "{}:{}: unexpected closing brace",
                    canonical.display(),
                    tokens[cursor].line
                )));
            }
            Ok(nodes)
        })();
        self.include_stack.pop();
        result
    }

    fn parse_nodes(
        &mut self,
        path: &Path,
        content: &str,
        tokens: &[Token],
        cursor: &mut usize,
        depth: usize,
        parent: Option<(&str, &Location)>,
    ) -> io::Result<Vec<Node>> {
        let mut nodes = Vec::new();
        while let Some(token) = tokens.get(*cursor) {
            if token.kind == TokenKind::CloseBrace {
                if parent.is_none() {
                    return Err(invalid_input(format!(
                        "{}:{}: unexpected closing brace",
                        path.display(),
                        token.line
                    )));
                }
                *cursor += 1;
                return Ok(nodes);
            }

            let first = token.clone();
            let mut end_index = *cursor;
            while let Some(token) = tokens.get(end_index) {
                if token.kind != TokenKind::Word {
                    break;
                }
                end_index += 1;
            }
            let delimiter = tokens.get(end_index);
            match delimiter.map(|token| token.kind) {
                Some(TokenKind::Semicolon) => {
                    if end_index == *cursor {
                        return Err(invalid_input(format!(
                            "{}:{}: empty directive",
                            path.display(),
                            first.line
                        )));
                    }
                    let words = &tokens[*cursor..end_index];
                    let directive = Directive {
                        name: words[0].value.clone(),
                        args: words[1..].iter().map(|word| word.value.clone()).collect(),
                        raw: content[first.start..delimiter.unwrap().end]
                            .trim()
                            .to_owned(),
                        location: Location {
                            file: path.to_path_buf(),
                            line: first.line,
                        },
                    };
                    *cursor = end_index + 1;
                    if directive.name.eq_ignore_ascii_case("include") {
                        let include = directive.args.first().ok_or_else(|| {
                            invalid_input(format!(
                                "{}: include requires a path",
                                directive.location
                            ))
                        })?;
                        if directive.args.len() > 1 {
                            return Err(invalid_input(format!(
                                "{}: include accepts one path",
                                directive.location
                            )));
                        }
                        let pattern = PathBuf::from(include);
                        let pattern = if pattern.is_absolute() {
                            pattern
                        } else {
                            self.prefix.join(pattern)
                        };
                        let matches = include_matches(&pattern)?;
                        if matches.is_empty()
                            && !pattern.exists()
                            && !has_glob_chars(&pattern.to_string_lossy())
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::NotFound,
                                format!(
                                    "{}: included path does not exist: {}",
                                    directive.location,
                                    pattern.display()
                                ),
                            ));
                        }
                        for included in matches {
                            nodes.extend(self.parse_file(&included, depth + 1)?);
                        }
                    } else {
                        nodes.push(Node::Directive(directive));
                    }
                }
                Some(TokenKind::OpenBrace) => {
                    if end_index == *cursor {
                        return Err(invalid_input(format!(
                            "{}:{}: block requires a name",
                            path.display(),
                            first.line
                        )));
                    }
                    let words = &tokens[*cursor..end_index];
                    let open = &tokens[end_index];
                    let location = Location {
                        file: path.to_path_buf(),
                        line: first.line,
                    };
                    let raw_open = content[first.start..open.end].trim().to_owned();
                    *cursor = end_index + 1;
                    let children = self.parse_nodes(
                        path,
                        content,
                        tokens,
                        cursor,
                        depth,
                        Some((&words[0].value, &location)),
                    )?;
                    let close = tokens
                        .get(*cursor - 1)
                        .ok_or_else(|| invalid_input(format!("{}: unclosed block", location)))?;
                    let raw_close = content[close.start..close.end].to_owned();
                    let block = Block {
                        name: words[0].value.clone(),
                        args: words[1..].iter().map(|word| word.value.clone()).collect(),
                        raw_open,
                        raw_close,
                        location,
                        children,
                    };
                    nodes.push(Node::Block(block));
                }
                Some(TokenKind::CloseBrace) => {
                    return Err(invalid_input(format!(
                        "{}:{}: expected ';' or '{{' before closing brace",
                        path.display(),
                        tokens[end_index].line
                    )));
                }
                Some(TokenKind::Word) => {
                    return Err(invalid_input(format!(
                        "{}:{}: invalid directive token sequence",
                        path.display(),
                        first.line
                    )));
                }
                None => {
                    let location = Location {
                        file: path.to_path_buf(),
                        line: first.line,
                    };
                    if let Some((name, _)) = parent {
                        return Err(invalid_input(format!(
                            "{}: unclosed block {name:?}; directive is missing ';'",
                            location
                        )));
                    }
                    return Err(invalid_input(format!(
                        "{}: directive is missing ';' or '{{'",
                        location
                    )));
                }
            }
        }

        if let Some((name, location)) = parent {
            return Err(invalid_input(format!(
                "{}: unclosed block {name:?}",
                location
            )));
        }
        Ok(nodes)
    }
}

fn tokenize(content: &str, path: &Path) -> io::Result<Vec<Token>> {
    let chars = content.char_indices().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < chars.len() {
        let (start, character) = chars[index];
        if character.is_whitespace() {
            if character == '\n' {
                line += 1;
            }
            index += 1;
            continue;
        }
        if character == '#' {
            while index < chars.len() && chars[index].1 != '\n' {
                index += 1;
            }
            continue;
        }
        let kind = match character {
            ';' => Some(TokenKind::Semicolon),
            '{' => Some(TokenKind::OpenBrace),
            '}' => Some(TokenKind::CloseBrace),
            _ => None,
        };
        if let Some(kind) = kind {
            let end = start + character.len_utf8();
            tokens.push(Token {
                kind,
                value: character.to_string(),
                start,
                end,
                line,
            });
            index += 1;
            continue;
        }

        let token_line = line;
        let mut value = String::new();
        let mut quote = None;
        while index < chars.len() {
            let (_, character) = chars[index];
            if quote.is_none()
                && (character.is_whitespace() || matches!(character, ';' | '{' | '}' | '#'))
            {
                break;
            }
            if let Some(active_quote) = quote {
                index += 1;
                if character == active_quote {
                    quote = None;
                } else if character == '\\' {
                    let Some((_, escaped)) = chars.get(index).copied() else {
                        return Err(invalid_input(format!(
                            "{}:{token_line}: trailing escape in quoted argument",
                            path.display()
                        )));
                    };
                    value.push(escaped);
                    index += 1;
                } else {
                    if character == '\n' {
                        line += 1;
                    }
                    value.push(character);
                }
                continue;
            }
            if matches!(character, '"' | '\'') {
                quote = Some(character);
                index += 1;
            } else if character == '\\' {
                index += 1;
                let Some((_, escaped)) = chars.get(index).copied() else {
                    return Err(invalid_input(format!(
                        "{}:{token_line}: trailing escape in argument",
                        path.display()
                    )));
                };
                value.push(escaped);
                index += 1;
            } else {
                if character == '\n' {
                    line += 1;
                }
                value.push(character);
                index += 1;
            }
        }
        if quote.is_some() {
            return Err(invalid_input(format!(
                "{}:{token_line}: unterminated quoted argument",
                path.display()
            )));
        }
        let end = chars
            .get(index)
            .map_or(content.len(), |(offset, _)| *offset);
        tokens.push(Token {
            kind: TokenKind::Word,
            value,
            start,
            end,
            line: token_line,
        });
    }
    Ok(tokens)
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
    use super::{Node, ParseOptions, component_matches, parse, tokenize};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("nginx2charlotte-parse-{}-{id}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn tokenizes_quotes_comments_and_block_punctuation() {
        let tokens = tokenize(
            "listen 8080; # comment\nroot \"/srv/a b\";",
            PathBuf::from("test.conf").as_path(),
        )
        .unwrap();
        let values = tokens
            .iter()
            .map(|token| token.value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(values, ["listen", "8080", ";", "root", "/srv/a b", ";"]);
        assert_eq!(tokens[3].line, 2);
    }

    #[test]
    fn matches_component_globs() {
        assert!(component_matches("site[0-9]?.conf", "site12.conf"));
        assert!(!component_matches("site[0-9]?.conf", "siteab.conf"));
    }

    #[test]
    fn expands_recursive_includes_and_detects_cycles() {
        let root = temp_dir();
        fs::create_dir_all(root.join("conf.d/nested")).unwrap();
        fs::write(
            root.join("nginx.conf"),
            "http { include conf.d; include missing-*.conf; }\n",
        )
        .unwrap();
        fs::write(
            root.join("conf.d/a.conf"),
            "server { server_name a.test; }\n",
        )
        .unwrap();
        fs::write(
            root.join("conf.d/nested/b.conf"),
            "server { server_name b.test; }\n",
        )
        .unwrap();
        let nodes = parse(&root.join("nginx.conf"), &ParseOptions::default()).unwrap();
        let Node::Block(http) = &nodes[0] else {
            panic!("expected http block");
        };
        assert_eq!(http.children.len(), 2);

        fs::write(root.join("cycle-a.conf"), "include cycle-b.conf;\n").unwrap();
        fs::write(root.join("cycle-b.conf"), "include cycle-a.conf;\n").unwrap();
        assert!(parse(&root.join("cycle-a.conf"), &ParseOptions::default()).is_err());

        fs::write(root.join("broken.conf"), "http { server { listen 80 } }\n").unwrap();
        let error = parse(&root.join("broken.conf"), &ParseOptions::default()).unwrap_err();
        assert!(error.to_string().contains("expected ';'"));
        let _ = fs::remove_dir_all(root);
    }
}
