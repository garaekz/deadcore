use std::collections::BTreeMap;

use regex::Regex;

use crate::pipeline::PipelineResult;

#[derive(Debug, Clone)]
pub struct SourceClass {
    pub fqcn: String,
    pub class_name: String,
    pub namespace: String,
    pub relative_path: String,
    pub source_text: String,
    pub imports: BTreeMap<String, String>,
    pub extends: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SourceIndex {
    pub classes: BTreeMap<String, SourceClass>,
}

impl SourceIndex {
    pub fn build(result: &PipelineResult) -> Self {
        let mut classes = BTreeMap::new();

        for file in &result.files {
            if let Some(class) = parse_source_class(&file.source_text, &file.relative_path) {
                classes.insert(class.fqcn.clone(), class);
            }
        }

        Self { classes }
    }

    pub fn get(&self, fqcn: &str) -> Option<&SourceClass> {
        self.classes.get(fqcn)
    }

    pub fn find_model_by_basename(&self, basename: &str) -> Option<String> {
        let target = basename.trim_matches('\\');
        self.classes
            .iter()
            .find(|(fqcn, class)| {
                fqcn.starts_with("App\\Models\\")
                    && (class.class_name == target
                        || fqcn.rsplit('\\').next().is_some_and(|item| item == target))
            })
            .map(|(fqcn, _)| fqcn.clone())
    }
}

impl SourceClass {
    pub fn method_body(&self, method_name: &str) -> Option<String> {
        extract_method_body(&self.source_text, method_name)
    }

    pub fn resolve_name(&self, raw: &str) -> String {
        resolve_class_name(raw, &self.namespace, &self.imports)
    }
}

pub fn parse_source_class(source: &str, relative_path: &str) -> Option<SourceClass> {
    let class_re =
        Regex::new(r#"(?m)^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("class regex");
    let extends_re = Regex::new(
        r#"(?m)^\s*(?:final\s+|abstract\s+)?class\s+[A-Za-z_][A-Za-z0-9_]*\s+extends\s+([A-Za-z_\\][A-Za-z0-9_\\]*)"#,
    )
    .expect("extends regex");

    let class_name = class_re
        .captures(source)
        .and_then(|captures| captures.get(1))
        .map(|item| item.as_str().to_string())?;
    let namespace = extract_namespace(source);
    let imports = collect_imports(source);
    let fqcn = qualify_name(&namespace, &class_name);
    let extends = extends_re
        .captures(source)
        .and_then(|captures| captures.get(1))
        .map(|item| resolve_class_name(item.as_str(), &namespace, &imports));

    Some(SourceClass {
        fqcn,
        class_name,
        namespace,
        relative_path: relative_path.to_string(),
        source_text: source.to_string(),
        imports,
        extends,
    })
}

pub fn extract_namespace(source: &str) -> String {
    let namespace_re = Regex::new(r#"(?m)^\s*namespace\s+([^;]+);"#).expect("namespace regex");
    namespace_re
        .captures(source)
        .and_then(|captures| captures.get(1))
        .map(|item| item.as_str().trim().to_string())
        .unwrap_or_default()
}

pub fn collect_imports(source: &str) -> BTreeMap<String, String> {
    let use_re = Regex::new(r#"(?m)^\s*use\s+([^;]+);"#).expect("use regex");
    let alias_re =
        Regex::new(r#"(?i)^(.*?)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$"#).expect("alias regex");
    let mut imports = BTreeMap::new();

    for captures in use_re.captures_iter(source) {
        let Some(raw) = captures.get(1) else {
            continue;
        };
        let import = raw.as_str().trim();
        if import.contains('{') {
            continue;
        }

        let (path, alias) = if let Some(alias_caps) = alias_re.captures(import) {
            let path = alias_caps
                .get(1)
                .map(|item| item.as_str().trim())
                .unwrap_or(import);
            let alias = alias_caps
                .get(2)
                .map(|item| item.as_str().trim())
                .unwrap_or(import);
            (path, alias)
        } else {
            let alias = import.rsplit('\\').next().unwrap_or(import).trim();
            (import, alias)
        };

        imports.insert(alias.to_string(), path.trim_start_matches('\\').to_string());
    }

    imports
}

pub fn resolve_class_name(
    raw: &str,
    namespace: &str,
    imports: &BTreeMap<String, String>,
) -> String {
    let trimmed = raw.trim().trim_start_matches('\\');
    if trimmed.contains('\\') {
        return trimmed.to_string();
    }

    imports
        .get(trimmed)
        .cloned()
        .unwrap_or_else(|| qualify_name(namespace, trimmed))
}

pub fn qualify_name(namespace: &str, class_name: &str) -> String {
    if namespace.is_empty() {
        class_name.to_string()
    } else {
        format!("{namespace}\\{class_name}")
    }
}

pub fn extract_method_body(source: &str, method_name: &str) -> Option<String> {
    let method_re = Regex::new(&format!(
        r#"function\s+{}\s*\("#,
        regex::escape(method_name)
    ))
    .expect("method regex");
    let method_match = method_re.find(source)?;
    let brace_offset = source[method_match.end()..].find('{')?;
    let start = method_match.end() + brace_offset;
    extract_balanced_region(&source[start..], '{', '}').map(|value| value.0)
}

pub fn extract_return_array(method_body: &str) -> Option<String> {
    let return_re = Regex::new(r#"return\s+\["#).expect("return array regex");
    let return_match = return_re.find(method_body)?;
    let start = method_body[return_match.start()..].find('[')? + return_match.start();
    extract_balanced_region(&method_body[start..], '[', ']').map(|value| value.0)
}

pub fn extract_balanced_region(
    text: &str,
    open: char,
    close: char,
) -> Option<(String, usize, usize)> {
    let mut depth = 0usize;
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;

    for (index, ch) in text.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == active {
                quote = None;
            }
            continue;
        }

        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }

        if ch == open {
            if depth == 0 {
                start = Some(index);
            }
            depth += 1;
        } else if ch == close {
            if depth == 0 {
                return None;
            }
            depth -= 1;
            if depth == 0 {
                let region_start = start?;
                let inner = &text[(region_start + open.len_utf8())..index];
                return Some((inner.to_string(), region_start, index));
            }
        }
    }

    None
}

pub fn split_top_level(input: &str, delimiter: char) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote = None;
    let mut escaped = false;

    for ch in input.chars() {
        if let Some(active) = quote {
            current.push(ch);
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == active {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                current.push(ch);
            }
            '(' => {
                paren += 1;
                current.push(ch);
            }
            ')' => {
                paren = paren.saturating_sub(1);
                current.push(ch);
            }
            '[' => {
                bracket += 1;
                current.push(ch);
            }
            ']' => {
                bracket = bracket.saturating_sub(1);
                current.push(ch);
            }
            '{' => {
                brace += 1;
                current.push(ch);
            }
            '}' => {
                brace = brace.saturating_sub(1);
                current.push(ch);
            }
            _ if ch == delimiter && paren == 0 && bracket == 0 && brace == 0 => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    items.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        items.push(trimmed.to_string());
    }

    items
}

pub fn split_top_level_key_value(entry: &str) -> Option<(String, String)> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let chars = entry.char_indices().collect::<Vec<_>>();

    for (index, ch) in chars {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == active {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            '=' if paren == 0 && bracket == 0 && brace == 0 => {
                let rest = &entry[index..];
                if rest.starts_with("=>") {
                    let key = entry[..index].trim().to_string();
                    let value = entry[(index + 2)..].trim().to_string();
                    return Some((key, value));
                }
            }
            _ => {}
        }
    }

    None
}

pub fn strip_php_string(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let first = trimmed.chars().next()?;
    let last = trimmed.chars().last()?;
    if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
        Some(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        None
    }
}
