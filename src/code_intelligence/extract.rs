use std::path::Path;

use crate::workspace_authority::StateDigestV1;

use super::{
    CodeDefinitionV1, CodeExtractionCoverageV1, CodeFileV1, CodeImportV1, CodeIntelligenceLimitsV1,
    CodeIntelligenceUnknownKindV1, CodeIntelligenceUnknownV1, CodeLanguageV1, CodeSymbolKindV1,
    IndexedFileV1, OccurrenceV1, SourceLocatorV1, push_unknown_v1,
};

#[derive(Clone)]
struct TokenV1<'a> {
    text: &'a str,
    start: usize,
}

pub(super) fn extract_file_v1(
    path: &Path,
    language: CodeLanguageV1,
    bytes: &[u8],
    source_digest: &str,
    observation_digest: &str,
    limits: &CodeIntelligenceLimitsV1,
) -> IndexedFileV1 {
    let path_text = path.to_str().unwrap_or_default().to_owned();
    if bytes.contains(&0) {
        return skipped_file_v1(
            path_text,
            language,
            bytes.len(),
            source_digest,
            observation_digest,
            CodeIntelligenceUnknownKindV1::BinaryFile,
        );
    }
    let Ok(source) = std::str::from_utf8(bytes) else {
        return skipped_file_v1(
            path_text,
            language,
            bytes.len(),
            source_digest,
            observation_digest,
            CodeIntelligenceUnknownKindV1::NonUtf8Source,
        );
    };
    if looks_generated_v1(source) {
        return skipped_file_v1(
            path_text,
            language,
            bytes.len(),
            source_digest,
            observation_digest,
            CodeIntelligenceUnknownKindV1::GeneratedFileSkipped,
        );
    }

    let line_count = source.lines().count().max(1);
    let file_locator = locator_v1(&path_text, 1, 1, 1, 1, source_digest, observation_digest);
    let file = CodeFileV1 {
        path: path_text.clone(),
        language,
        bytes: bytes.len() as u64,
        lines: u32::try_from(line_count).unwrap_or(u32::MAX),
        module_name: module_name_v1(path, language),
        extraction_coverage: CodeExtractionCoverageV1::ConservativeSyntaxSubset,
        locator: file_locator,
    };
    let mut indexed = IndexedFileV1 {
        file,
        definitions: Vec::new(),
        occurrences: Vec::new(),
        imports: Vec::new(),
        unknowns: Vec::new(),
    };
    if line_count > limits.max_lines_per_file {
        push_unknown_v1(
            &mut indexed.unknowns,
            limits.max_unknowns,
            CodeIntelligenceUnknownV1::new(
                CodeIntelligenceUnknownKindV1::LineLimitExceeded,
                Some(path_text),
            ),
        );
        return indexed;
    }

    let mut rust_test_attribute = false;
    let mut go_import_block = false;
    let mut block_comment = false;
    let mut python_triple_quote: Option<&str> = None;
    for (line_index, line) in source.lines().enumerate() {
        let line_number = u32::try_from(line_index + 1).unwrap_or(u32::MAX);
        if line.len() > limits.max_line_bytes {
            push_unknown_v1(
                &mut indexed.unknowns,
                limits.max_unknowns,
                CodeIntelligenceUnknownV1::new(
                    CodeIntelligenceUnknownKindV1::LineByteLimitExceeded,
                    Some(path_text.clone()),
                ),
            );
            continue;
        }
        let sanitized =
            sanitize_line_v1(line, language, &mut block_comment, &mut python_triple_quote);
        let tokens = identifier_tokens_v1(&sanitized);
        if tokens.is_empty() {
            rust_test_attribute =
                language == CodeLanguageV1::Rust && sanitized.trim_start().starts_with("#[test");
            continue;
        }

        let definition =
            definition_on_line_v1(language, path, &sanitized, &tokens, rust_test_attribute);
        rust_test_attribute =
            language == CodeLanguageV1::Rust && sanitized.trim_start().starts_with("#[test");
        if let Some((name, kind, is_test, start)) = definition {
            if indexed.definitions.len() >= limits.max_definitions_per_file {
                push_unknown_v1(
                    &mut indexed.unknowns,
                    limits.max_unknowns,
                    CodeIntelligenceUnknownV1::new(
                        CodeIntelligenceUnknownKindV1::DefinitionLimitExceeded,
                        Some(path_text.clone()),
                    ),
                );
            } else {
                let locator = token_locator_v1(
                    &path_text,
                    line_number,
                    start,
                    name.len(),
                    source_digest,
                    observation_digest,
                );
                indexed.definitions.push(CodeDefinitionV1 {
                    definition_id: definition_identity_v1(&name, kind, &locator),
                    name,
                    kind,
                    is_test,
                    locator,
                });
            }
        }

        for (module, start, width) in
            imports_on_line_v1(language, line, &tokens, &mut go_import_block)
        {
            if indexed.imports.len() >= limits.max_imports_per_file {
                push_unknown_v1(
                    &mut indexed.unknowns,
                    limits.max_unknowns,
                    CodeIntelligenceUnknownV1::new(
                        CodeIntelligenceUnknownKindV1::ImportLimitExceeded,
                        Some(path_text.clone()),
                    ),
                );
                break;
            }
            indexed.imports.push(CodeImportV1 {
                module,
                locator: token_locator_v1(
                    &path_text,
                    line_number,
                    start,
                    width,
                    source_digest,
                    observation_digest,
                ),
            });
        }

        for token in tokens {
            if is_keyword_v1(token.text, language) {
                continue;
            }
            if indexed.occurrences.len() >= limits.max_occurrences_per_file {
                push_unknown_v1(
                    &mut indexed.unknowns,
                    limits.max_unknowns,
                    CodeIntelligenceUnknownV1::new(
                        CodeIntelligenceUnknownKindV1::OccurrenceLimitExceeded,
                        Some(path_text.clone()),
                    ),
                );
                break;
            }
            indexed.occurrences.push(OccurrenceV1 {
                name: token.text.to_owned(),
                locator: token_locator_v1(
                    &path_text,
                    line_number,
                    token.start,
                    token.text.len(),
                    source_digest,
                    observation_digest,
                ),
            });
        }
    }
    if block_comment || python_triple_quote.is_some() || !balanced_delimiters_v1(source) {
        push_unknown_v1(
            &mut indexed.unknowns,
            limits.max_unknowns,
            CodeIntelligenceUnknownV1::new(
                CodeIntelligenceUnknownKindV1::AmbiguousSyntax,
                Some(path_text),
            ),
        );
    }
    indexed.definitions.sort();
    indexed.definitions.dedup();
    indexed.imports.sort();
    indexed.imports.dedup();
    indexed
}

fn skipped_file_v1(
    path: String,
    language: CodeLanguageV1,
    bytes: usize,
    source_digest: &str,
    observation_digest: &str,
    kind: CodeIntelligenceUnknownKindV1,
) -> IndexedFileV1 {
    let locator = locator_v1(&path, 1, 1, 1, 1, source_digest, observation_digest);
    IndexedFileV1 {
        file: CodeFileV1 {
            module_name: module_name_v1(Path::new(&path), language),
            path: path.clone(),
            language,
            bytes: bytes as u64,
            lines: 0,
            extraction_coverage: CodeExtractionCoverageV1::ConservativeSyntaxSubset,
            locator,
        },
        definitions: Vec::new(),
        occurrences: Vec::new(),
        imports: Vec::new(),
        unknowns: vec![CodeIntelligenceUnknownV1::new(kind, Some(path))],
    }
}

fn definition_on_line_v1(
    language: CodeLanguageV1,
    path: &Path,
    line: &str,
    tokens: &[TokenV1<'_>],
    rust_test_attribute: bool,
) -> Option<(String, CodeSymbolKindV1, bool, usize)> {
    let path_is_test = is_test_path_v1(path, language);
    match language {
        CodeLanguageV1::Rust => {
            for (keyword, kind) in [
                ("fn", CodeSymbolKindV1::Function),
                ("struct", CodeSymbolKindV1::Struct),
                ("enum", CodeSymbolKindV1::Enum),
                ("trait", CodeSymbolKindV1::Trait),
                ("type", CodeSymbolKindV1::TypeAlias),
                ("mod", CodeSymbolKindV1::Module),
                ("const", CodeSymbolKindV1::Constant),
                ("static", CodeSymbolKindV1::Variable),
            ] {
                if let Some((name, start)) = token_after_v1(tokens, keyword) {
                    let is_test = keyword == "fn"
                        && (rust_test_attribute || path_is_test || name.starts_with("test_"));
                    return Some((
                        name.to_owned(),
                        if is_test {
                            CodeSymbolKindV1::Test
                        } else {
                            kind
                        },
                        is_test,
                        start,
                    ));
                }
            }
            let macro_position = line.find("macro_rules!")?;
            let tail = &line[macro_position + "macro_rules!".len()..];
            let token = identifier_tokens_v1(tail).into_iter().next()?;
            Some((
                token.text.to_owned(),
                CodeSymbolKindV1::Macro,
                false,
                macro_position + "macro_rules!".len() + token.start,
            ))
        }
        CodeLanguageV1::Python => {
            let (keyword, kind) = if token_sequence_v1(tokens, &["async", "def"])
                || tokens.first().is_some_and(|token| token.text == "def")
            {
                ("def", CodeSymbolKindV1::Function)
            } else if tokens.first().is_some_and(|token| token.text == "class") {
                ("class", CodeSymbolKindV1::Class)
            } else {
                return None;
            };
            let (name, start) = token_after_v1(tokens, keyword)?;
            let indented = line.len().saturating_sub(line.trim_start().len()) > 0;
            let is_test = path_is_test || name.starts_with("test_") || name.starts_with("Test");
            Some((
                name.to_owned(),
                if is_test {
                    CodeSymbolKindV1::Test
                } else if keyword == "def" && indented {
                    CodeSymbolKindV1::Method
                } else {
                    kind
                },
                is_test,
                start,
            ))
        }
        CodeLanguageV1::TypeScript | CodeLanguageV1::JavaScript => {
            if let Some(first) = tokens.first().filter(|token| {
                matches!(token.text, "test" | "it" | "describe") && line.contains('(')
            }) {
                return Some((
                    first.text.to_owned(),
                    CodeSymbolKindV1::Test,
                    true,
                    first.start,
                ));
            }
            for (keyword, kind) in [
                ("function", CodeSymbolKindV1::Function),
                ("class", CodeSymbolKindV1::Class),
                ("interface", CodeSymbolKindV1::Interface),
                ("type", CodeSymbolKindV1::TypeAlias),
                ("enum", CodeSymbolKindV1::Enum),
                ("const", CodeSymbolKindV1::Constant),
                ("let", CodeSymbolKindV1::Variable),
                ("var", CodeSymbolKindV1::Variable),
            ] {
                if let Some((name, start)) = token_after_v1(tokens, keyword) {
                    let is_test = path_is_test
                        || matches!(name, "test" | "it" | "describe")
                        || name.starts_with("test");
                    return Some((
                        name.to_owned(),
                        if is_test {
                            CodeSymbolKindV1::Test
                        } else {
                            kind
                        },
                        is_test,
                        start,
                    ));
                }
            }
            None
        }
        CodeLanguageV1::Go => {
            if tokens.first().is_some_and(|token| token.text == "func") {
                let name = if line.trim_start().starts_with("func (") {
                    let close = line.find(')')?;
                    identifier_tokens_v1(&line[close + 1..])
                        .into_iter()
                        .next()
                        .map(|token| (token.text, close + 1 + token.start))?
                } else {
                    token_after_v1(tokens, "func")?
                };
                let is_test = path_is_test && name.0.starts_with("Test");
                return Some((
                    name.0.to_owned(),
                    if is_test {
                        CodeSymbolKindV1::Test
                    } else if line.trim_start().starts_with("func (") {
                        CodeSymbolKindV1::Method
                    } else {
                        CodeSymbolKindV1::Function
                    },
                    is_test,
                    name.1,
                ));
            }
            if tokens.first().is_some_and(|token| token.text == "type") {
                let (name, start) = token_after_v1(tokens, "type")?;
                let kind = if tokens.iter().any(|token| token.text == "interface") {
                    CodeSymbolKindV1::Interface
                } else if tokens.iter().any(|token| token.text == "struct") {
                    CodeSymbolKindV1::Struct
                } else {
                    CodeSymbolKindV1::TypeAlias
                };
                return Some((name.to_owned(), kind, false, start));
            }
            for (keyword, kind) in [
                ("const", CodeSymbolKindV1::Constant),
                ("var", CodeSymbolKindV1::Variable),
            ] {
                if let Some((name, start)) = token_after_v1(tokens, keyword) {
                    return Some((name.to_owned(), kind, false, start));
                }
            }
            None
        }
    }
}

fn imports_on_line_v1(
    language: CodeLanguageV1,
    line: &str,
    tokens: &[TokenV1<'_>],
    go_import_block: &mut bool,
) -> Vec<(String, usize, usize)> {
    match language {
        CodeLanguageV1::Rust => {
            let Some(use_position) = tokens.iter().position(|token| token.text == "use") else {
                if let Some((name, start)) = token_after_v1(tokens, "mod") {
                    return vec![(name.to_owned(), start, name.len())];
                }
                return Vec::new();
            };
            let Some(first) = tokens.get(use_position + 1) else {
                return Vec::new();
            };
            vec![(first.text.to_owned(), first.start, first.text.len())]
        }
        CodeLanguageV1::Python => {
            if tokens.first().is_some_and(|token| token.text == "from") {
                return tokens
                    .get(1)
                    .map(|token| vec![(token.text.to_owned(), token.start, token.text.len())])
                    .unwrap_or_default();
            }
            if tokens.first().is_some_and(|token| token.text == "import") {
                return tokens
                    .iter()
                    .skip(1)
                    .filter(|token| token.text != "as")
                    .map(|token| (token.text.to_owned(), token.start, token.text.len()))
                    .collect();
            }
            Vec::new()
        }
        CodeLanguageV1::TypeScript | CodeLanguageV1::JavaScript => {
            if !tokens
                .iter()
                .any(|token| matches!(token.text, "import" | "export" | "require" | "from"))
            {
                return Vec::new();
            }
            quoted_values_v1(line)
        }
        CodeLanguageV1::Go => {
            let trimmed = line.trim();
            if trimmed.starts_with("import (") || trimmed == "import(" {
                *go_import_block = true;
                return Vec::new();
            }
            if *go_import_block && trimmed == ")" {
                *go_import_block = false;
                return Vec::new();
            }
            if *go_import_block || trimmed.starts_with("import ") {
                return quoted_values_v1(line);
            }
            Vec::new()
        }
    }
}

fn sanitize_line_v1(
    line: &str,
    language: CodeLanguageV1,
    block_comment: &mut bool,
    python_triple_quote: &mut Option<&'static str>,
) -> String {
    let bytes = line.as_bytes();
    let mut result = vec![b' '; bytes.len()];
    let mut index = 0usize;
    let mut quote: Option<u8> = None;
    'line: while index < bytes.len() {
        if language == CodeLanguageV1::Python {
            for marker in [b"\"\"\"".as_slice(), b"'''".as_slice()] {
                if quote.is_none() && bytes[index..].starts_with(marker) {
                    let marker_text = if marker[0] == b'\"' { "\"\"\"" } else { "'''" };
                    if python_triple_quote.is_none() {
                        *python_triple_quote = Some(marker_text);
                    } else if *python_triple_quote == Some(marker_text) {
                        *python_triple_quote = None;
                    }
                    index += 3;
                    continue 'line;
                }
            }
            if python_triple_quote.is_some() {
                index += 1;
                continue;
            }
        }
        if *block_comment {
            if bytes[index..].starts_with(b"*/") {
                *block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if quote.is_none()
            && language != CodeLanguageV1::Python
            && bytes[index..].starts_with(b"/*")
        {
            *block_comment = true;
            index += 2;
            continue;
        }
        if quote.is_none()
            && ((language == CodeLanguageV1::Python && bytes[index] == b'#')
                || (language != CodeLanguageV1::Python && bytes[index..].starts_with(b"//")))
        {
            break;
        }
        if let Some(active) = quote {
            if bytes[index] == b'\\' {
                index = (index + 2).min(bytes.len());
                continue;
            }
            if bytes[index] == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'\'' | b'\"' | b'`') {
            quote = Some(bytes[index]);
            index += 1;
            continue;
        }
        result[index] = bytes[index];
        index += 1;
    }
    String::from_utf8(result).expect("ASCII masking preserves UTF-8 boundaries")
}

fn identifier_tokens_v1(line: &str) -> Vec<TokenV1<'_>> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(TokenV1 {
                text: &line[start..index],
                start,
            });
        } else {
            index += 1;
        }
    }
    tokens
}

fn quoted_values_v1(line: &str) -> Vec<(String, usize, usize)> {
    let bytes = line.as_bytes();
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'\"' | b'`') {
            let quote = bytes[index];
            let start = index + 1;
            index += 1;
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else {
                    index += 1;
                }
            }
            if index <= bytes.len() && start < index {
                values.push((line[start..index].to_owned(), start, index - start));
            }
        }
        index += 1;
    }
    values
}

fn token_after_v1<'a>(tokens: &'a [TokenV1<'a>], keyword: &str) -> Option<(&'a str, usize)> {
    let index = tokens.iter().position(|token| token.text == keyword)?;
    let token = tokens.get(index + 1)?;
    Some((token.text, token.start))
}

fn token_sequence_v1(tokens: &[TokenV1<'_>], expected: &[&str]) -> bool {
    tokens
        .iter()
        .map(|token| token.text)
        .take(expected.len())
        .eq(expected.iter().copied())
}

fn is_keyword_v1(token: &str, language: CodeLanguageV1) -> bool {
    let common = matches!(
        token,
        "if" | "else"
            | "for"
            | "while"
            | "return"
            | "break"
            | "continue"
            | "true"
            | "false"
            | "self"
            | "this"
            | "new"
            | "match"
            | "switch"
            | "case"
    );
    common
        || match language {
            CodeLanguageV1::Rust => matches!(
                token,
                "fn" | "pub"
                    | "crate"
                    | "super"
                    | "struct"
                    | "enum"
                    | "trait"
                    | "impl"
                    | "type"
                    | "mod"
                    | "use"
                    | "let"
                    | "mut"
                    | "const"
                    | "static"
                    | "async"
                    | "await"
                    | "where"
            ),
            CodeLanguageV1::Python => matches!(
                token,
                "def"
                    | "class"
                    | "import"
                    | "from"
                    | "as"
                    | "async"
                    | "await"
                    | "with"
                    | "yield"
                    | "None"
                    | "True"
                    | "False"
                    | "try"
                    | "except"
                    | "finally"
                    | "raise"
            ),
            CodeLanguageV1::TypeScript | CodeLanguageV1::JavaScript => matches!(
                token,
                "function"
                    | "class"
                    | "interface"
                    | "type"
                    | "enum"
                    | "const"
                    | "let"
                    | "var"
                    | "import"
                    | "export"
                    | "from"
                    | "default"
                    | "extends"
                    | "implements"
                    | "async"
                    | "await"
                    | "undefined"
                    | "null"
            ),
            CodeLanguageV1::Go => matches!(
                token,
                "package"
                    | "import"
                    | "func"
                    | "type"
                    | "struct"
                    | "interface"
                    | "const"
                    | "var"
                    | "go"
                    | "defer"
                    | "chan"
                    | "select"
                    | "range"
                    | "map"
            ),
        }
}

fn is_test_path_v1(path: &Path, language: CodeLanguageV1) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    match language {
        CodeLanguageV1::Rust => path
            .components()
            .any(|component| component.as_os_str() == "tests"),
        CodeLanguageV1::Python => {
            name.starts_with("test_")
                || name.ends_with("_test.py")
                || path
                    .components()
                    .any(|component| component.as_os_str() == "tests")
        }
        CodeLanguageV1::TypeScript | CodeLanguageV1::JavaScript => {
            name.contains(".test.")
                || name.contains(".spec.")
                || path
                    .components()
                    .any(|component| component.as_os_str() == "__tests__")
        }
        CodeLanguageV1::Go => name.ends_with("_test.go"),
    }
}

fn module_name_v1(path: &Path, language: CodeLanguageV1) -> String {
    let without_extension = path.with_extension("");
    let components: Vec<_> = without_extension
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let separator = match language {
        CodeLanguageV1::Rust => "::",
        CodeLanguageV1::Python => ".",
        CodeLanguageV1::TypeScript | CodeLanguageV1::JavaScript | CodeLanguageV1::Go => "/",
    };
    components.join(separator)
}

fn looks_generated_v1(source: &str) -> bool {
    source
        .lines()
        .take(5)
        .map(str::to_ascii_lowercase)
        .any(|line| {
            line.contains("code generated")
                || line.contains("generated file")
                || line.contains("do not edit")
                || line.contains("autogenerated")
        })
}

fn balanced_delimiters_v1(source: &str) -> bool {
    let mut stack = Vec::new();
    for byte in source.bytes() {
        match byte {
            b'(' | b'[' | b'{' => stack.push(byte),
            b')' => {
                if stack.pop() != Some(b'(') {
                    return false;
                }
            }
            b']' => {
                if stack.pop() != Some(b'[') {
                    return false;
                }
            }
            b'}' => {
                if stack.pop() != Some(b'{') {
                    return false;
                }
            }
            _ => {}
        }
    }
    stack.is_empty()
}

fn definition_identity_v1(name: &str, kind: CodeSymbolKindV1, locator: &SourceLocatorV1) -> String {
    let bytes = serde_json::to_vec(&(name, kind, locator))
        .expect("bounded code definition identity serializes");
    StateDigestV1::from_domain_and_bytes(b"again.code-definition.v1", &bytes).to_hex()
}

fn token_locator_v1(
    path: &str,
    line: u32,
    start: usize,
    width: usize,
    source_digest: &str,
    observation_digest: &str,
) -> SourceLocatorV1 {
    let start_column = u32::try_from(start + 1).unwrap_or(u32::MAX);
    let end_column =
        u32::try_from(start.saturating_add(width).saturating_add(1)).unwrap_or(u32::MAX);
    locator_v1(
        path,
        line,
        start_column,
        line,
        end_column,
        source_digest,
        observation_digest,
    )
}

fn locator_v1(
    path: &str,
    start_line: u32,
    start_column_byte: u32,
    end_line: u32,
    end_column_byte: u32,
    source_digest: &str,
    observation_digest: &str,
) -> SourceLocatorV1 {
    SourceLocatorV1 {
        path: path.to_owned(),
        start_line,
        start_column_byte,
        end_line,
        end_column_byte,
        source_digest: source_digest.to_owned(),
        observation_digest: observation_digest.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_triple_quote_at_line_end_does_not_escape_the_line() {
        let mut block = false;
        let mut triple = None;
        assert_eq!(
            sanitize_line_v1(
                "value = \"\"\"",
                CodeLanguageV1::Python,
                &mut block,
                &mut triple
            ),
            "value =    "
        );
        assert_eq!(triple, Some("\"\"\""));
        assert_eq!(
            sanitize_line_v1("\"\"\"", CodeLanguageV1::Python, &mut block, &mut triple),
            "   "
        );
        assert_eq!(triple, None);
        assert_eq!(
            sanitize_line_v1("'''", CodeLanguageV1::Python, &mut block, &mut triple),
            "   "
        );
        assert_eq!(triple, Some("'''"));
        assert_eq!(
            sanitize_line_v1("'''", CodeLanguageV1::Python, &mut block, &mut triple),
            "   "
        );
        assert_eq!(triple, None);
    }

    #[test]
    fn python_quote_marker_inside_regular_string_stays_regular_string() {
        let mut block = false;
        let mut triple = None;
        let sanitized = sanitize_line_v1(
            "value = '\"\"\"' # comment",
            CodeLanguageV1::Python,
            &mut block,
            &mut triple,
        );
        assert!(sanitized.starts_with("value = "));
        assert_eq!(triple, None);
        assert_eq!(sanitized.len(), "value = '\"\"\"' # comment".len());
    }
}
