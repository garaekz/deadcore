use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::contracts::{ContractHttpInfo, ContractInertia, ContractResponse};
use crate::model::{ControllerMethod, ModelFacts};
use crate::source_index::{
    SourceIndex, extract_balanced_region, split_top_level, split_top_level_key_value,
    strip_php_string,
};

pub fn infer_inertia_response(
    controller: &ControllerMethod,
    http: Option<&ContractHttpInfo>,
    _source_index: &SourceIndex,
    _model_index: &BTreeMap<String, ModelFacts>,
) -> Option<ContractResponse> {
    let (source, component, props_schema) = extract_inertia_call(&controller.body_text)?;

    Some(ContractResponse {
        kind: "inertia".to_string(),
        status: http.map(|item| item.status).or(Some(200)),
        explicit: http.map(|item| item.explicit).or(Some(false)),
        content_type: Some("text/html".to_string()),
        headers: BTreeMap::new(),
        body_schema: Some(json!({ "type": "object" })),
        redirect: None,
        download: None,
        inertia: Some(ContractInertia {
            component,
            props_schema: Some(props_schema),
        }),
        source: Some(source.clone()),
        via: Some(source),
    })
}

fn extract_inertia_call(text: &str) -> Option<(String, String, Value)> {
    extract_inertia_call_with_name(text, "Inertia::render", "Inertia::render")
        .or_else(|| extract_inertia_call_with_name(text, "inertia", "inertia()"))
}

fn extract_inertia_call_with_name(
    text: &str,
    needle: &str,
    source: &str,
) -> Option<(String, String, Value)> {
    let open_index = find_actual_call(text, needle)?;
    let (arguments, _, _) = extract_balanced_region(&text[open_index..], '(', ')')?;
    let cleaned_arguments = strip_php_comments(&arguments);
    let parts = split_top_level(&cleaned_arguments, ',');
    let component = infer_inertia_component(parts.first()?.trim())?;
    let props_schema = parts
        .get(1)
        .map(|value| infer_inertia_schema(value))
        .unwrap_or_else(|| json!({ "type": "object" }));

    Some((source.to_string(), component, props_schema))
}

fn find_actual_call(text: &str, needle: &str) -> Option<usize> {
    let mut index = 0usize;
    let mut state = ScanState::Normal;

    while index < text.len() {
        let ch = text[index..].chars().next()?;

        match state {
            ScanState::Normal => {
                if text[index..].starts_with("//") {
                    state = ScanState::LineComment;
                    index += 2;
                    continue;
                }
                if text[index..].starts_with("/*") {
                    state = ScanState::BlockComment;
                    index += 2;
                    continue;
                }
                if ch == '#' {
                    state = ScanState::LineComment;
                    index += ch.len_utf8();
                    continue;
                }
                if ch == '\'' {
                    state = ScanState::SingleQuoted;
                    index += ch.len_utf8();
                    continue;
                }
                if ch == '"' {
                    state = ScanState::DoubleQuoted;
                    index += ch.len_utf8();
                    continue;
                }

                if text[index..].starts_with(needle) && has_call_boundary(text, index, needle) {
                    let mut open_index = index + needle.len();
                    while open_index < text.len() {
                        let next = text[open_index..].chars().next()?;
                        if next.is_whitespace() {
                            open_index += next.len_utf8();
                            continue;
                        }
                        break;
                    }

                    if text[open_index..].starts_with('(') {
                        return Some(open_index);
                    }
                }

                index += ch.len_utf8();
            }
            ScanState::LineComment => {
                index += ch.len_utf8();
                if ch == '\n' {
                    state = ScanState::Normal;
                }
            }
            ScanState::BlockComment => {
                if text[index..].starts_with("*/") {
                    index += 2;
                    state = ScanState::Normal;
                } else {
                    index += ch.len_utf8();
                }
            }
            ScanState::SingleQuoted => {
                if ch == '\\' {
                    index += ch.len_utf8();
                    if index < text.len() {
                        index += text[index..].chars().next()?.len_utf8();
                    }
                    continue;
                }
                index += ch.len_utf8();
                if ch == '\'' {
                    state = ScanState::Normal;
                }
            }
            ScanState::DoubleQuoted => {
                if ch == '\\' {
                    index += ch.len_utf8();
                    if index < text.len() {
                        index += text[index..].chars().next()?.len_utf8();
                    }
                    continue;
                }
                index += ch.len_utf8();
                if ch == '"' {
                    state = ScanState::Normal;
                }
            }
        }
    }

    None
}

fn has_call_boundary(text: &str, start: usize, needle: &str) -> bool {
    if start == 0 {
        return true;
    }

    let prefix = &text[..start];
    let mut chars = prefix.chars().rev();
    let Some(prev) = chars.next() else {
        return true;
    };

    if is_identifier_char(prev) || prev == '$' {
        return false;
    }

    if needle == "inertia" {
        if prev == '>' && chars.next() == Some('-') {
            return false;
        }
        if prev == ':' && chars.next() == Some(':') {
            return false;
        }
    }

    true
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn infer_inertia_schema(raw_value: &str) -> Value {
    let value = strip_php_comments(raw_value).trim().to_string();
    let value = value.as_str();

    if value.is_empty() {
        return json!({ "type": "object" });
    }
    if value.starts_with('[') {
        let Some((array_body, _, _)) = extract_balanced_region(value, '[', ']') else {
            return json!({ "type": "object" });
        };
        return infer_inertia_array_schema(&array_body);
    }
    if strip_php_string(value).is_some() {
        return json!({ "type": "string" });
    }
    if value == "true" || value == "false" {
        return json!({ "type": "boolean" });
    }
    if value == "null" {
        return json!({ "nullable": true });
    }
    if value.parse::<i64>().is_ok() {
        return json!({ "type": "integer" });
    }
    if value.parse::<f64>().is_ok() && value.contains('.') {
        return json!({ "type": "number" });
    }

    json!({ "type": "object" })
}

fn infer_inertia_component(raw_value: &str) -> Option<String> {
    let value = strip_php_comments(raw_value).trim().to_string();
    if value.is_empty() {
        return None;
    }

    if let Some(string_value) = strip_php_string(&value) {
        return Some(string_value);
    }

    Some(value)
}

#[derive(Copy, Clone)]
enum ScanState {
    Normal,
    LineComment,
    BlockComment,
    SingleQuoted,
    DoubleQuoted,
}

fn infer_inertia_array_schema(array_body: &str) -> Value {
    let mut properties = BTreeMap::<String, Value>::new();
    let mut items = Vec::<Value>::new();
    let mut associative = false;

    for entry in split_top_level(array_body, ',') {
        if let Some((raw_key, raw_value)) = split_top_level_key_value(&entry) {
            associative = true;
            let key = strip_php_string(&raw_key).unwrap_or_else(|| raw_key.trim().to_string());
            properties.insert(key, infer_inertia_schema(&raw_value));
        } else if !entry.trim().is_empty() {
            items.push(infer_inertia_schema(&entry));
        }
    }

    if associative {
        if properties.is_empty() {
            json!({ "type": "object" })
        } else {
            json!({ "type": "object", "properties": properties })
        }
    } else {
        let items_schema = items
            .into_iter()
            .next()
            .unwrap_or_else(|| json!({ "type": "object" }));
        json!({ "type": "array", "items": items_schema })
    }
}

fn strip_php_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut index = 0usize;
    let mut state = ScanState::Normal;

    while index < text.len() {
        let ch = text[index..].chars().next().expect("valid char boundary");

        match state {
            ScanState::Normal => {
                if text[index..].starts_with("//") {
                    state = ScanState::LineComment;
                    index += 2;
                    continue;
                }
                if text[index..].starts_with("/*") {
                    state = ScanState::BlockComment;
                    index += 2;
                    continue;
                }
                if ch == '#' {
                    state = ScanState::LineComment;
                    index += ch.len_utf8();
                    continue;
                }
                if ch == '\'' {
                    state = ScanState::SingleQuoted;
                } else if ch == '"' {
                    state = ScanState::DoubleQuoted;
                }
                output.push(ch);
                index += ch.len_utf8();
            }
            ScanState::LineComment => {
                if ch == '\n' {
                    output.push(ch);
                    state = ScanState::Normal;
                }
                index += ch.len_utf8();
            }
            ScanState::BlockComment => {
                if text[index..].starts_with("*/") {
                    state = ScanState::Normal;
                    index += 2;
                } else {
                    index += ch.len_utf8();
                }
            }
            ScanState::SingleQuoted => {
                output.push(ch);
                index += ch.len_utf8();
                if ch == '\\' {
                    if index < text.len() {
                        let next = text[index..].chars().next().expect("valid escaped char");
                        output.push(next);
                        index += next.len_utf8();
                    }
                    continue;
                }
                if ch == '\'' {
                    state = ScanState::Normal;
                }
            }
            ScanState::DoubleQuoted => {
                output.push(ch);
                index += ch.len_utf8();
                if ch == '\\' {
                    if index < text.len() {
                        let next = text[index..].chars().next().expect("valid escaped char");
                        output.push(next);
                        index += next.len_utf8();
                    }
                    continue;
                }
                if ch == '"' {
                    state = ScanState::Normal;
                }
            }
        }
    }

    output
}
