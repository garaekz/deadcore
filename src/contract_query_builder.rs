use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::contracts::{ContractRequestField, ShapeTree};
use crate::model::ControllerMethod;
use crate::source_index::{
    SourceClass, SourceIndex, extract_balanced_region, split_top_level, split_top_level_key_value,
    strip_php_string,
};

const QUERY_BUILDER_SOURCE: &str = "spatie/laravel-query-builder";

#[derive(Debug, Default)]
struct QueryBuilderRequestSpec {
    filters: BTreeSet<String>,
    includes: BTreeSet<String>,
    sorts: BTreeSet<String>,
    field_groups: BTreeMap<String, BTreeSet<String>>,
}

impl QueryBuilderRequestSpec {
    fn is_empty(&self) -> bool {
        self.filters.is_empty()
            && self.includes.is_empty()
            && self.sorts.is_empty()
            && self.field_groups.is_empty()
    }
}

pub fn extend_query_builder_request(
    controller: &ControllerMethod,
    source_index: &SourceIndex,
    _content_types: &mut BTreeSet<String>,
    field_map: &mut BTreeMap<(String, String), ContractRequestField>,
    _body: &mut ShapeTree,
    query: &mut ShapeTree,
    _files: &mut ShapeTree,
) {
    let Some(class) = source_index.get(&controller.fqcn) else {
        return;
    };

    let spec = collect_query_builder_spec(controller, class, source_index);
    if spec.is_empty() {
        return;
    }

    for filter in &spec.filters {
        register_query_field(
            field_map,
            query,
            "query",
            &format!("filter.{filter}"),
            Some("csv"),
            Some("string"),
            Some("string"),
            filter.clone(),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );
    }

    if !spec.filters.is_empty() {
        register_query_field(
            field_map,
            query,
            "query",
            "filter",
            Some("object"),
            Some("object"),
            None,
            spec.filters.iter().cloned().collect::<Vec<_>>().join(","),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );
    }

    if !spec.includes.is_empty() {
        register_query_field(
            field_map,
            query,
            "query",
            "include",
            Some("csv"),
            Some("string"),
            Some("string"),
            spec.includes.iter().cloned().collect::<Vec<_>>().join(","),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );
    }
    for include in &spec.includes {
        register_query_field(
            field_map,
            query,
            "query",
            &format!("include.{include}"),
            Some("csv"),
            Some("string"),
            Some("string"),
            include.clone(),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );
    }

    if !spec.sorts.is_empty() {
        register_query_field(
            field_map,
            query,
            "query",
            "sort",
            Some("csv"),
            Some("string"),
            Some("string"),
            spec.sorts.iter().cloned().collect::<Vec<_>>().join(","),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );
    }
    for sort in &spec.sorts {
        register_query_field(
            field_map,
            query,
            "query",
            &format!("sort.{sort}"),
            Some("csv"),
            Some("string"),
            Some("string"),
            sort.clone(),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );
    }

    if !spec.field_groups.is_empty() {
        register_query_field(
            field_map,
            query,
            "query",
            "fields",
            Some("object"),
            Some("object"),
            None,
            spec.field_groups
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );
    }

    for (group, values) in &spec.field_groups {
        register_query_field(
            field_map,
            query,
            "query",
            &format!("fields.{group}"),
            Some("csv"),
            Some("string"),
            Some("string"),
            values.iter().cloned().collect::<Vec<_>>().join(","),
            None,
            Some(QUERY_BUILDER_SOURCE),
        );

        for value in values {
            register_query_field(
                field_map,
                query,
                "query",
                &format!("fields.{group}.{value}"),
                Some("csv"),
                Some("string"),
                Some("string"),
                value.clone(),
                None,
                Some(QUERY_BUILDER_SOURCE),
            );
        }
    }
}

fn collect_query_builder_spec(
    controller: &ControllerMethod,
    class: &SourceClass,
    source_index: &SourceIndex,
) -> QueryBuilderRequestSpec {
    let mut spec = QueryBuilderRequestSpec::default();

    collect_filter_names(
        &controller.body_text,
        class,
        source_index,
        &mut spec.filters,
    );

    collect_allowed_values_from_call(
        &controller.body_text,
        class,
        source_index,
        "allowedIncludes",
        &mut spec.includes,
    );
    collect_allowed_values_from_call(
        &controller.body_text,
        class,
        source_index,
        "allowedSorts",
        &mut spec.sorts,
    );
    spec.sorts = spec
        .sorts
        .into_iter()
        .map(|value| value.trim_start_matches('-').to_string())
        .collect();

    if let Some(fields) = extract_invocation_arguments(&controller.body_text, "allowedFields") {
        let mut values = BTreeSet::new();
        collect_string_values(&fields, class, source_index, &mut values);
        for value in values {
            if let Some((group, field)) = value.split_once('.') {
                spec.field_groups
                    .entry(group.to_string())
                    .or_default()
                    .insert(field.to_string());
            }
        }
    }
    spec
}

fn collect_allowed_values_from_call(
    source: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
    method_name: &str,
    values: &mut BTreeSet<String>,
) {
    let Some(arguments) = extract_invocation_arguments(source, method_name) else {
        return;
    };
    collect_string_values(&arguments, class, source_index, values);
}

fn collect_filter_names(
    source: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
    values: &mut BTreeSet<String>,
) {
    let Some(arguments) = extract_invocation_arguments(source, "allowedFilters") else {
        return;
    };
    collect_filter_names_from_expression(&arguments, class, source_index, values);
}

fn collect_string_values(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
    values: &mut BTreeSet<String>,
) {
    for value in collect_expression_values(expression, class, source_index, string_leaf_values) {
        values.insert(value);
    }
}

fn collect_filter_names_from_expression(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
    values: &mut BTreeSet<String>,
) {
    for value in collect_expression_values(expression, class, source_index, filter_leaf_values) {
        values.insert(value);
    }
}

fn collect_expression_values(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
    leaf_parser: fn(&str, &SourceClass, &SourceIndex) -> Vec<String>,
) -> Vec<String> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Vec::new();
    }

    if let Some(resolved) = resolve_symbol_expression(expression, class, source_index) {
        return collect_expression_values(&resolved, class, source_index, leaf_parser);
    }

    if let Some((call_name, arguments)) = parse_function_call(expression) {
        if call_name == "array_merge" {
            let mut values = Vec::new();
            for argument in split_top_level(&arguments, ',') {
                values.extend(collect_expression_values(
                    &argument,
                    class,
                    source_index,
                    leaf_parser,
                ));
            }
            values.sort();
            values.dedup();
            return values;
        }
    }

    if expression.starts_with('[') {
        let Some((body, _, _)) = extract_balanced_region(expression, '[', ']') else {
            return Vec::new();
        };
        let mut values = Vec::new();
        for entry in split_top_level(&body, ',') {
            let item = split_top_level_key_value(&entry)
                .map(|(_, value)| value)
                .unwrap_or(entry);
            values.extend(collect_expression_values(
                &item,
                class,
                source_index,
                leaf_parser,
            ));
        }
        values.sort();
        values.dedup();
        return values;
    }

    let mut values = leaf_parser(expression, class, source_index);
    values.sort();
    values.dedup();
    values
}

fn string_leaf_values(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
) -> Vec<String> {
    let trimmed = expression.trim();
    if let Some(value) = strip_php_string(trimmed) {
        return vec![value];
    }

    if let Some(resolved) = resolve_class_constant_expression(trimmed, class, source_index) {
        return collect_expression_values(&resolved, class, source_index, string_leaf_values);
    }

    Vec::new()
}

fn filter_leaf_values(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
) -> Vec<String> {
    let trimmed = expression.trim();
    if let Some(value) = strip_php_string(trimmed) {
        return vec![value];
    }
    if let Some(name) = extract_allowed_filter_name(trimmed, class, source_index) {
        return vec![name];
    }

    if let Some(resolved) = resolve_class_constant_expression(trimmed, class, source_index) {
        return collect_expression_values(&resolved, class, source_index, filter_leaf_values);
    }

    Vec::new()
}

fn resolve_symbol_expression(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
) -> Option<String> {
    let expression = expression.trim();

    if let Some(method_name) = match_symbol_reference(expression, true) {
        let source_class = resolve_symbol_class(expression, class, source_index, true)?;
        return extract_method_return_expression(source_class, &method_name);
    }

    if let Some(const_name) = match_symbol_reference(expression, false) {
        return resolve_class_constant_expression(expression, class, source_index)
            .or_else(|| extract_class_constant_value(class, &const_name));
    }

    None
}

fn resolve_class_constant_expression(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
) -> Option<String> {
    let expression = expression.trim();
    let const_re = Regex::new(
        r#"^(?:(self|static|parent)|([A-Za-z_\\][A-Za-z0-9_\\]*))::([A-Za-z_][A-Za-z0-9_]*)$"#,
    )
    .expect("constant reference regex");
    let captures = const_re.captures(expression)?;
    let class_name = captures.get(1).map(|item| item.as_str()).or_else(|| {
        captures
            .get(2)
            .map(|item| item.as_str())
            .filter(|value| !value.is_empty())
    })?;
    let const_name = captures.get(3)?.as_str();
    let source_class = resolve_class_name(class_name, class, source_index)?;
    extract_class_constant_value(source_class, const_name)
}

fn resolve_symbol_class<'a>(
    expression: &str,
    class: &'a SourceClass,
    source_index: &'a SourceIndex,
    method: bool,
) -> Option<&'a SourceClass> {
    let regex = if method {
        Regex::new(
            r#"^(?:(self|static|parent)|([A-Za-z_\\][A-Za-z0-9_\\]*))::([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)$"#,
        )
        .expect("method reference regex")
    } else {
        Regex::new(
            r#"^(?:(self|static|parent)|([A-Za-z_\\][A-Za-z0-9_\\]*))::([A-Za-z_][A-Za-z0-9_]*)$"#,
        )
        .expect("constant reference regex")
    };

    let captures = regex.captures(expression.trim())?;
    let class_name = captures.get(1).map(|item| item.as_str()).or_else(|| {
        captures
            .get(2)
            .map(|item| item.as_str())
            .filter(|value| !value.is_empty())
    })?;

    resolve_class_name(class_name, class, source_index)
}

fn match_symbol_reference(expression: &str, method: bool) -> Option<String> {
    let regex = if method {
        Regex::new(
            r#"^(?:(self|static|parent)|([A-Za-z_\\][A-Za-z0-9_\\]*))::([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)$"#,
        )
        .expect("method reference regex")
    } else {
        Regex::new(
            r#"^(?:(self|static|parent)|([A-Za-z_\\][A-Za-z0-9_\\]*))::([A-Za-z_][A-Za-z0-9_]*)$"#,
        )
        .expect("constant reference regex")
    };

    let captures = regex.captures(expression.trim())?;
    captures.get(3).map(|item| item.as_str().to_string())
}

fn resolve_class_name<'a>(
    class_name: &str,
    class: &'a SourceClass,
    source_index: &'a SourceIndex,
) -> Option<&'a SourceClass> {
    match class_name {
        "self" | "static" | "parent" => Some(class),
        raw => {
            let fqcn = class.resolve_name(raw);
            source_index.get(&fqcn)
        }
    }
}

fn extract_method_return_expression(class: &SourceClass, method_name: &str) -> Option<String> {
    let method_body = class.method_body(method_name)?;
    for statement in split_top_level(&method_body, ';') {
        let trimmed = statement.trim_start();
        if let Some(expression) = trimmed.strip_prefix("return") {
            let expression = expression.trim_start();
            if !expression.is_empty() {
                return Some(expression.to_string());
            }
        }
    }

    None
}

fn extract_class_constant_value(class: &SourceClass, const_name: &str) -> Option<String> {
    let const_re = Regex::new(&format!(
        r#"(?m)^\s*(?:public|protected|private)?\s*const\s+{}\s*="#,
        regex::escape(const_name)
    ))
    .expect("constant regex");
    let const_match = const_re.find(&class.source_text)?;
    let start = const_match.end();
    extract_statement_expression(&class.source_text[start..])
}

fn extract_statement_expression(source: &str) -> Option<String> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote = None;
    let mut escaped = false;

    for (index, ch) in source.char_indices() {
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
            ';' if paren == 0 && bracket == 0 && brace == 0 => {
                return Some(source[..index].trim().to_string());
            }
            _ => {}
        }
    }

    None
}

fn extract_invocation_arguments(source: &str, method_name: &str) -> Option<String> {
    let regex =
        Regex::new(&format!(r#"{}\s*\("#, regex::escape(method_name))).expect("invocation regex");
    let mat = regex.find(source)?;
    let open = source[mat.start()..].find('(')? + mat.start();
    let (arguments, _, _) = extract_balanced_region(&source[open..], '(', ')')?;
    Some(arguments)
}

fn parse_function_call(expression: &str) -> Option<(String, String)> {
    let expression = expression.trim();
    let open = expression.find('(')?;
    if !expression.ends_with(')') {
        return None;
    }
    let name = expression[..open].trim().to_string();
    let (arguments, _, end) = extract_balanced_region(&expression[open..], '(', ')')?;
    if open + end + 1 != expression.len() {
        return None;
    }
    Some((name, arguments))
}

fn extract_allowed_filter_name(
    expression: &str,
    class: &SourceClass,
    source_index: &SourceIndex,
) -> Option<String> {
    let (call_name, arguments) = parse_function_call(expression)?;
    if !call_name.starts_with("AllowedFilter::") {
        return None;
    }

    let short_name = call_name.rsplit("::").next().unwrap_or_default();
    if short_name == "trashed" {
        return Some("trashed".to_string());
    }

    let first_argument = split_top_level(&arguments, ',').into_iter().next()?;
    let mut values = BTreeSet::new();
    collect_string_values(&first_argument, class, source_index, &mut values);
    values.into_iter().next()
}

fn register_query_field(
    field_map: &mut BTreeMap<(String, String), ContractRequestField>,
    query: &mut ShapeTree,
    location: &str,
    path: &str,
    kind: Option<&str>,
    type_name: Option<&str>,
    scalar_type: Option<&str>,
    allowed_values: impl Into<String>,
    via: Option<&str>,
    source: Option<&str>,
) {
    if path.is_empty() {
        return;
    }

    query.insert_path(path);

    let key = (location.to_string(), path.to_string());
    let entry = field_map
        .entry(key)
        .or_insert_with(|| ContractRequestField {
            location: location.to_string(),
            path: path.to_string(),
            kind: None,
            type_name: None,
            scalar_type: None,
            format: None,
            item_type: None,
            wrappers: Vec::new(),
            allowed_values: Vec::new(),
            required: None,
            optional: None,
            nullable: None,
            is_array: None,
            collection: None,
            source: None,
            via: None,
        });

    if entry.kind.is_none() {
        entry.kind = kind.map(str::to_string);
    }
    if entry.type_name.is_none() {
        entry.type_name = type_name.map(str::to_string);
    }
    if entry.scalar_type.is_none() {
        entry.scalar_type = scalar_type.map(str::to_string);
    }
    if entry.source.is_none() {
        entry.source = source.map(str::to_string);
    }
    if entry.via.is_none() {
        entry.via = via.map(str::to_string);
    }

    let allowed = allowed_values.into();
    if !allowed.is_empty() {
        let mut values = allowed
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        for value in values {
            if !entry.allowed_values.contains(&value) {
                entry.allowed_values.push(value);
            }
        }
        entry.allowed_values.sort();
        entry.allowed_values.dedup();
    }
}
