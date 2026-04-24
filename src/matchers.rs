use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use regex::Regex;
use tree_sitter::Node;

use crate::manifest::FeatureFlags;
use crate::model::{
    BroadcastFact, BroadcastParameterFact, ControllerMethod, FileFacts, ModelFacts,
    ModelRelationshipFact, PolymorphicFact, RequestUsageFact, ResourceUsageFact, ScopeUsageFact,
};
use crate::parser::ParsedUnit;

pub fn analyze_file(
    unit: &ParsedUnit,
    relative_path: &str,
    features: &FeatureFlags,
) -> Result<FileFacts> {
    let mut facts = FileFacts::default();
    let source_text = String::from_utf8_lossy(&unit.source);
    let namespace = extract_namespace(&source_text);
    let imports = collect_imports(&source_text);

    walk_node(
        unit.tree.root_node(),
        &unit.source,
        relative_path,
        &namespace,
        &imports,
        &mut facts,
        features,
    );

    if features.broadcast_channels
        && relative_path
            .replace('\\', "/")
            .ends_with("routes/channels.php")
    {
        facts.broadcast.extend(detect_broadcasts(&source_text));
    }

    facts
        .controllers
        .sort_by(|a, b| (&a.fqcn, &a.method_name).cmp(&(&b.fqcn, &b.method_name)));
    facts.models.sort_by(|a, b| a.fqcn.cmp(&b.fqcn));
    facts
        .polymorphic
        .sort_by(|a, b| (&a.name, &a.model, &a.relation).cmp(&(&b.name, &b.model, &b.relation)));
    Ok(facts)
}

fn walk_node(
    node: Node,
    source: &[u8],
    relative_path: &str,
    namespace: &str,
    imports: &BTreeMap<String, String>,
    facts: &mut FileFacts,
    features: &FeatureFlags,
) {
    if node.kind() == "class_declaration" {
        process_class(
            node,
            source,
            relative_path,
            namespace,
            imports,
            facts,
            features,
        );
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_node(
            child,
            source,
            relative_path,
            namespace,
            imports,
            facts,
            features,
        );
    }
}

fn process_class(
    class_node: Node,
    source: &[u8],
    relative_path: &str,
    namespace: &str,
    imports: &BTreeMap<String, String>,
    facts: &mut FileFacts,
    features: &FeatureFlags,
) {
    let class_name = extract_named_child_text(class_node, source, "name")
        .unwrap_or_else(|| "Anonymous".to_string());
    let class_text = node_text(class_node, source);
    let fqcn = qualify_name(namespace, &class_name);
    let methods = extract_class_methods(class_node, source);

    if is_controller(&class_text, relative_path, namespace) {
        for method in methods
            .iter()
            .filter(|method| method.is_public || method.name == "__invoke")
        {
            facts.controllers.push(build_controller_method(
                method,
                &fqcn,
                &class_name,
                namespace,
                imports,
                features,
            ));
        }
    }

    if is_model(&class_text, relative_path, namespace) {
        let scopes = if features.scopes_used {
            detect_model_scopes(&class_text)
        } else {
            Vec::new()
        };
        let attributes = if features.attribute_make {
            detect_model_attributes(&methods)
        } else {
            Vec::new()
        };
        let relationships = extract_model_relationships(&methods, namespace, imports);

        if features.polymorphic {
            for relationship in &relationships {
                if relationship.relation_type == "morphTo"
                    || relationship.relation_type == "morphedByMany"
                {
                    continue;
                }
                let Some(morph_name) = &relationship.morph_name else {
                    continue;
                };
                facts.polymorphic.push(PolymorphicFact {
                    name: morph_name.clone(),
                    discriminator: format!("{morph_name}_type"),
                    model: fqcn.clone(),
                    relation: relationship.name.clone(),
                });
            }
        }

        facts.models.push(ModelFacts {
            class_name,
            fqcn,
            relationships,
            scopes,
            attributes,
        });
    }
}

fn build_controller_method(
    method: &MethodInfo,
    fqcn: &str,
    class_name: &str,
    namespace: &str,
    imports: &BTreeMap<String, String>,
    features: &FeatureFlags,
) -> ControllerMethod {
    ControllerMethod {
        class_name: class_name.to_string(),
        fqcn: fqcn.to_string(),
        method_name: method.name.clone(),
        body_text: method.text.clone(),
        http_status: if features.http_status {
            detect_http_status(&method.text)
        } else {
            None
        },
        resource_usage: if features.resource_usage {
            detect_resources(&method.text, namespace, imports)
        } else {
            Vec::new()
        },
        request_usage: if features.request_usage {
            detect_request_usage(&method.text, namespace, imports)
        } else {
            Vec::new()
        },
        scopes_used: if features.scopes_used {
            detect_scope_usage(&method.text)
        } else {
            Vec::new()
        },
    }
}

#[derive(Debug, Clone)]
struct MethodInfo {
    name: String,
    text: String,
    is_public: bool,
}

fn extract_class_methods(class_node: Node, source: &[u8]) -> Vec<MethodInfo> {
    let mut methods = Vec::new();
    let mut cursor = class_node.walk();

    for child in class_node.children(&mut cursor) {
        if child.kind() != "declaration_list" {
            continue;
        }

        let mut body_cursor = child.walk();
        for member in child.children(&mut body_cursor) {
            if member.kind() != "method_declaration" {
                continue;
            }

            let name = extract_named_child_text(member, source, "name")
                .unwrap_or_else(|| "anonymous".to_string());
            let text = node_text(member, source);
            let is_public =
                text.contains("public function") || text.contains("public static function");

            methods.push(MethodInfo {
                name,
                text,
                is_public,
            });
        }
    }

    methods
}

fn collect_imports(source: &str) -> BTreeMap<String, String> {
    let use_re = Regex::new(r"(?m)^\s*use\s+([^;]+);").expect("use regex");
    let alias_re = Regex::new(r"(?i)^(.*?)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$").expect("alias regex");
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

fn extract_namespace(source: &str) -> String {
    let namespace_re = Regex::new(r"(?m)^\s*namespace\s+([^;]+);").expect("namespace regex");
    namespace_re
        .captures(source)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default()
}

fn is_controller(class_text: &str, relative_path: &str, namespace: &str) -> bool {
    let normalized_path = relative_path.replace('\\', "/");

    class_text.contains("extends Controller")
        || normalized_path.starts_with("app/Http/Controllers/")
        || namespace.ends_with("\\Http\\Controllers")
}

fn is_model(class_text: &str, relative_path: &str, namespace: &str) -> bool {
    let normalized_path = relative_path.replace('\\', "/");

    class_text.contains("extends Model")
        || normalized_path.starts_with("app/Models/")
        || namespace.ends_with("\\Models")
}

fn detect_http_status(method_text: &str) -> Option<u16> {
    let response_re =
        Regex::new(r#"(?s)response\((?:.|\n)*?,\s*(\d{3})\s*\)"#).expect("response regex");
    let json_re =
        Regex::new(r#"(?s)response\(\)->json\((?:.|\n)*?,\s*(\d{3})\s*\)"#).expect("json regex");
    let abort_re = Regex::new(r"abort\((\d{3})").expect("abort regex");
    let status_re = Regex::new(r"setStatusCode\((\d{3})\)").expect("status regex");

    json_re
        .captures(method_text)
        .or_else(|| response_re.captures(method_text))
        .or_else(|| abort_re.captures(method_text))
        .or_else(|| status_re.captures(method_text))
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<u16>().ok())
        .or_else(|| method_text.contains("noContent()").then_some(204))
}

fn detect_request_usage(
    method_text: &str,
    namespace: &str,
    imports: &BTreeMap<String, String>,
) -> Vec<RequestUsageFact> {
    let validate_re = Regex::new(r"validate\(\s*\[([^\]]*)\]").expect("validate regex");
    let only_re = Regex::new(r"only\(\s*\[([^\]]*)\]").expect("only regex");
    let file_re = Regex::new(r#"file\(\s*['"]([^'"]+)['"]\s*\)"#).expect("file regex");
    let request_param_re =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*Request)\s+\$([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("request param regex");
    let method_signature = method_text.split('{').next().unwrap_or(method_text);

    let mut usage = Vec::new();
    let mut seen_request_classes = BTreeSet::new();

    for captures in request_param_re.captures_iter(method_signature) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let Some(variable_name) = captures.get(2) else {
            continue;
        };
        let resolved_class_name = resolve_class_name(class_name.as_str(), namespace, imports);
        if !seen_request_classes.insert(resolved_class_name.clone()) {
            continue;
        }

        let method = if method_text.contains(&format!("${}->validated()", variable_name.as_str())) {
            "validated"
        } else {
            "typed_parameter"
        };

        usage.push(RequestUsageFact {
            method: method.to_string(),
            rules: Vec::new(),
            fields: Vec::new(),
            location: None,
            class_name: Some(resolved_class_name),
        });
    }

    for captures in validate_re.captures_iter(method_text) {
        if let Some(group) = captures.get(1) {
            let rules = dedup_preserving_order(
                parse_php_array_keys(group.as_str())
                    .into_iter()
                    .filter(|item| !item.contains('.'))
                    .collect(),
            );
            usage.push(RequestUsageFact {
                method: "validate".to_string(),
                rules,
                fields: Vec::new(),
                location: None,
                class_name: None,
            });
        }
    }

    for captures in only_re.captures_iter(method_text) {
        if let Some(group) = captures.get(1) {
            let fields = dedup_preserving_order(parse_php_string_list(group.as_str()));
            usage.push(RequestUsageFact {
                method: "only".to_string(),
                rules: Vec::new(),
                fields,
                location: Some("query".to_string()),
                class_name: None,
            });
        }
    }

    let mut file_fields = Vec::new();
    for captures in file_re.captures_iter(method_text) {
        if let Some(field) = captures.get(1) {
            file_fields.push(field.as_str().to_string());
        }
    }
    if !file_fields.is_empty() {
        file_fields = dedup_preserving_order(file_fields);
        usage.push(RequestUsageFact {
            method: "file".to_string(),
            rules: Vec::new(),
            fields: file_fields,
            location: Some("files".to_string()),
            class_name: None,
        });
    }

    if method_text.contains("$request->all()") || method_text.contains("$request->json()") {
        usage.push(RequestUsageFact {
            method: "body".to_string(),
            rules: vec!["*".to_string()],
            fields: Vec::new(),
            location: None,
            class_name: None,
        });
    }

    usage
}

fn detect_resources(
    method_text: &str,
    namespace: &str,
    imports: &BTreeMap<String, String>,
) -> Vec<ResourceUsageFact> {
    let response_re = Regex::new(
        r#"(?s)new\s+([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))\((?:.|\n)*?\)\s*->response\("#,
    )
    .expect("resource response regex");
    let collection_re =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))::collection\("#)
            .expect("resource collection regex");
    let make_re = Regex::new(r#"([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))::make\("#)
        .expect("resource make regex");
    let new_re = Regex::new(r#"new\s+([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))\("#)
        .expect("new resource regex");

    let mut items = Vec::new();
    let mut seen = BTreeSet::new();

    for captures in response_re.captures_iter(method_text) {
        if let Some(class_name) = captures.get(1) {
            let class_name = resolve_class_name(class_name.as_str(), namespace, imports);
            let key = (class_name.clone(), Some("response".to_string()));
            if seen.insert(key.clone()) {
                items.push(ResourceUsageFact {
                    class_name,
                    method: key.1,
                });
            }
        }
    }

    for captures in collection_re.captures_iter(method_text) {
        if let Some(class_name) = captures.get(1) {
            let class_name = resolve_class_name(class_name.as_str(), namespace, imports);
            let key = (class_name.clone(), Some("collection".to_string()));
            if seen.insert(key.clone()) {
                items.push(ResourceUsageFact {
                    class_name,
                    method: key.1,
                });
            }
        }
    }

    for captures in make_re.captures_iter(method_text) {
        if let Some(class_name) = captures.get(1) {
            let class_name = resolve_class_name(class_name.as_str(), namespace, imports);
            let key = (class_name.clone(), Some("make".to_string()));
            if seen.insert(key.clone()) {
                items.push(ResourceUsageFact {
                    class_name,
                    method: key.1,
                });
            }
        }
    }

    for captures in new_re.captures_iter(method_text) {
        if let Some(class_name) = captures.get(1) {
            let class_name = resolve_class_name(class_name.as_str(), namespace, imports);
            if seen.contains(&(class_name.clone(), Some("response".to_string())))
                || seen.contains(&(class_name.clone(), Some("collection".to_string())))
            {
                continue;
            }
            let method = if class_name.ends_with("Collection") {
                Some("collection".to_string())
            } else {
                Some("new".to_string())
            };
            let key = (class_name.clone(), method.clone());
            if seen.insert(key.clone()) {
                items.push(ResourceUsageFact { class_name, method });
            }
        }
    }

    items
}

fn detect_scope_usage(method_text: &str) -> Vec<ScopeUsageFact> {
    let chain_re =
        Regex::new(r#"(?:->|::)([A-Z]?[a-z][A-Za-z0-9_]*)\("#).expect("scope usage regex");
    let skip = [
        "json",
        "validate",
        "file",
        "only",
        "all",
        "input",
        "query",
        "create",
        "collection",
        "make",
        "setStatusCode",
        "with",
        "where",
        "whereHas",
        "orWhere",
        "paginate",
        "limit",
        "get",
        "load",
        "fresh",
        "delete",
        "update",
        "attach",
        "sync",
        "response",
        "user",
        "authorize",
        "has",
        "count",
        "latest",
    ];

    let mut scopes = Vec::new();
    let mut seen = BTreeSet::new();
    for captures in chain_re.captures_iter(method_text) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let candidate = name.as_str().to_string();
        if skip.iter().any(|item| *item == candidate) {
            continue;
        }
        if seen.insert(candidate.clone()) {
            scopes.push(ScopeUsageFact {
                name: candidate,
                on: None,
            });
        }
    }

    scopes
}

fn detect_model_scopes(class_text: &str) -> Vec<String> {
    let scope_re =
        Regex::new(r#"function\s+scope([A-Z][A-Za-z0-9_]*)\("#).expect("model scope regex");
    let mut scopes = Vec::new();

    for captures in scope_re.captures_iter(class_text) {
        if let Some(name) = captures.get(1) {
            let raw = name.as_str();
            let mut chars = raw.chars();
            let Some(first) = chars.next() else {
                continue;
            };
            let normalized = first.to_lowercase().collect::<String>() + chars.as_str();
            scopes.push(normalized);
        }
    }

    scopes.sort();
    scopes.dedup();
    scopes
}

fn detect_model_attributes(methods: &[MethodInfo]) -> Vec<String> {
    let mut attributes = methods
        .iter()
        .filter(|method| method.text.contains("Attribute::make"))
        .map(|method| method.name.clone())
        .collect::<Vec<_>>();
    attributes.sort();
    attributes.dedup();
    attributes
}

fn extract_model_relationships(
    methods: &[MethodInfo],
    namespace: &str,
    imports: &BTreeMap<String, String>,
) -> Vec<ModelRelationshipFact> {
    methods
        .iter()
        .filter_map(|method| detect_model_relationship(method, namespace, imports))
        .collect()
}

fn detect_model_relationship(
    method: &MethodInfo,
    namespace: &str,
    imports: &BTreeMap<String, String>,
) -> Option<ModelRelationshipFact> {
    let relation_re = Regex::new(
        r#"\$this->(belongsTo|hasMany|hasOne|belongsToMany|morphTo|morphOne|morphMany|morphToMany|morphedByMany)\("#,
    )
    .expect("relationship regex");
    let related_re = Regex::new(r#"\(\s*([A-Z][A-Za-z0-9_\\]*)::class"#).expect("related regex");
    let morph_name_re = Regex::new(r#"\(\s*[A-Z][A-Za-z0-9_\\]*::class\s*,\s*['"]([^'"]+)['"]"#)
        .expect("morph name regex");
    let with_pivot_re = Regex::new(r#"withPivot\(([^)]*)\)"#).expect("withPivot regex");
    let alias_re = Regex::new(r#"->as\(\s*['"]([^'"]+)['"]\s*\)"#).expect("pivot alias regex");

    let captures = relation_re.captures(&method.text)?;
    let relation_type = captures.get(1)?.as_str().to_string();
    let related = if relation_type == "morphTo" {
        None
    } else {
        related_re
            .captures(&method.text)
            .and_then(|caps| caps.get(1))
            .map(|item| resolve_class_name(item.as_str(), namespace, imports))
    };
    let morph_name = match relation_type.as_str() {
        "morphTo" => Some(method.name.clone()),
        "morphOne" | "morphMany" | "morphToMany" | "morphedByMany" => morph_name_re
            .captures(&method.text)
            .and_then(|caps| caps.get(1))
            .map(|item| item.as_str().to_string()),
        _ => None,
    };

    let mut pivot_columns = Vec::new();
    for captures in with_pivot_re.captures_iter(&method.text) {
        if let Some(group) = captures.get(1) {
            pivot_columns.extend(parse_php_string_list(group.as_str()));
        }
    }
    pivot_columns = dedup_preserving_order(pivot_columns);

    Some(ModelRelationshipFact {
        name: method.name.clone(),
        relation_type,
        related,
        pivot_columns,
        pivot_alias: alias_re
            .captures(&method.text)
            .and_then(|caps| caps.get(1))
            .map(|item| item.as_str().to_string()),
        pivot_timestamps: method.text.contains("withTimestamps("),
        morph_name,
    })
}

fn detect_broadcasts(source: &str) -> Vec<BroadcastFact> {
    let mut channels = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = 0;
    let marker = "Broadcast::channel(";

    while let Some(relative) = source[cursor..].find(marker) {
        let call_start = cursor + relative;
        let mut next = call_start + marker.len();
        let Some((channel_name, channel_end)) = extract_php_string_literal(source, next) else {
            cursor = next;
            continue;
        };
        next = channel_end;

        let Some(function_relative) = source[next..].find("function") else {
            cursor = next;
            continue;
        };
        let function_start = next + function_relative;
        let Some(params_open_relative) = source[function_start..].find('(') else {
            cursor = function_start + "function".len();
            continue;
        };
        let params_open = function_start + params_open_relative;
        let Some(params_close) = find_matching_delimiter(source, params_open, '(', ')') else {
            cursor = params_open + 1;
            continue;
        };
        let callback_params = extract_callback_params(&source[params_open + 1..params_close]);

        let Some(body_open_relative) = source[params_close..].find('{') else {
            cursor = params_close + 1;
            continue;
        };
        let body_open = params_close + body_open_relative;
        let Some(body_close) = find_matching_delimiter(source, body_open, '{', '}') else {
            cursor = body_open + 1;
            continue;
        };
        let body = &source[body_open + 1..body_close];

        cursor = body_close + 1;
        if !seen.insert(channel_name.clone()) {
            continue;
        }

        channels.push(BroadcastFact {
            channel: channel_name.clone(),
            channel_type: Some(infer_broadcast_visibility(&callback_params).to_string()),
            parameters: extract_broadcast_parameters(&channel_name, body),
        });
    }

    channels
}

fn extract_broadcast_parameters(
    channel: &str,
    _callback_body: &str,
) -> Vec<BroadcastParameterFact> {
    let param_name_re = Regex::new(r#"\{([^}]+)\}"#).expect("channel parameter regex");
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    for captures in param_name_re.captures_iter(channel) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let name = name.as_str().to_string();
        if !seen.insert(name.clone()) {
            continue;
        }

        let parameter_type = if name == "id" {
            Some("int".to_string())
        } else {
            Some("string".to_string())
        };

        items.push(BroadcastParameterFact {
            name,
            parameter_type,
        });
    }

    items
}

fn infer_broadcast_visibility(callback_params: &[String]) -> &'static str {
    let non_user_params = callback_params
        .iter()
        .filter(|name| name.as_str() != "user")
        .count();

    if non_user_params == 0 {
        if callback_params.iter().any(|name| name == "user") {
            "public"
        } else {
            "presence"
        }
    } else {
        "private"
    }
}

fn extract_callback_params(params: &str) -> Vec<String> {
    let callback_name_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)"#).expect("callback name regex");
    callback_name_re
        .captures_iter(params)
        .filter_map(|captures| captures.get(1).map(|item| item.as_str().to_string()))
        .collect()
}

fn extract_php_string_literal(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let quote = *bytes.get(cursor)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    cursor += 1;
    let literal_start = cursor;

    while cursor < bytes.len() {
        if bytes[cursor] == quote && bytes.get(cursor.wrapping_sub(1)) != Some(&b'\\') {
            return Some((source[literal_start..cursor].to_string(), cursor + 1));
        }
        cursor += 1;
    }

    None
}

fn find_matching_delimiter(
    source: &str,
    open_index: usize,
    open: char,
    close: char,
) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for (offset, ch) in source[open_index..].char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == active_quote {
                quote = None;
            }
            continue;
        }

        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }

        if ch == open {
            depth += 1;
            continue;
        }

        if ch == close {
            depth -= 1;
            if depth == 0 {
                return Some(open_index + offset);
            }
        }
    }

    None
}

fn extract_named_child_text(node: Node, source: &[u8], kind: &str) -> Option<String> {
    if let Some(child) = node.child_by_field_name(kind) {
        return Some(node_text(child, source));
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            return Some(node_text(child, source));
        }
    }
    None
}

fn node_text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source)
        .map(|text| text.to_string())
        .unwrap_or_default()
}

fn parse_php_string_list(input: &str) -> Vec<String> {
    let item_re = Regex::new(r#"['"]([^'"]+)['"]"#).expect("string list regex");
    let mut items = Vec::new();
    for captures in item_re.captures_iter(input) {
        if let Some(item) = captures.get(1) {
            items.push(item.as_str().to_string());
        }
    }
    items
}

fn parse_php_array_keys(input: &str) -> Vec<String> {
    let item_re = Regex::new(r#"['"]([^'"]+)['"]\s*=>"#).expect("array key regex");
    let mut items = Vec::new();
    for captures in item_re.captures_iter(input) {
        if let Some(item) = captures.get(1) {
            items.push(item.as_str().to_string());
        }
    }
    items
}

fn dedup_preserving_order(items: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            deduped.push(item);
        }
    }
    deduped
}

fn qualify_name(namespace: &str, class_name: &str) -> String {
    if namespace.is_empty() {
        class_name.to_string()
    } else {
        format!("{namespace}\\{class_name}")
    }
}

fn resolve_class_name(raw: &str, namespace: &str, imports: &BTreeMap<String, String>) -> String {
    let trimmed = raw.trim().trim_start_matches('\\');
    if trimmed.contains('\\') {
        return trimmed.to_string();
    }

    imports
        .get(trimmed)
        .cloned()
        .unwrap_or_else(|| qualify_name(namespace, trimmed))
}
