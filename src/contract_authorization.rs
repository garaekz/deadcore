use std::collections::BTreeSet;

use regex::Regex;

use crate::contracts::{ContractAuthorization, RuntimeRoute};
use crate::model::ControllerMethod;
use crate::source_index::{SourceClass, SourceIndex};

pub fn build_static_authorization(
    controller: &ControllerMethod,
    runtime_routes: &[RuntimeRoute],
    source_index: &SourceIndex,
) -> Vec<ContractAuthorization> {
    let authorize_re =
        Regex::new(
            r#"(?:\$this->authorize|Gate::authorize|Gate::allows)\(\s*['"]([^'"]+)['"]\s*,\s*([^\),]+)"#,
        )
            .expect("authorize regex");

    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    let class = source_index.get(&controller.fqcn);
    let form_request_classes = collect_form_request_classes(controller, class);
    let gate_allows_enforces_failure = controller.body_text.contains("$this->authorize(")
        || controller.body_text.contains("Gate::authorize(")
        || !form_request_classes.is_empty();

    for captures in authorize_re.captures_iter(&controller.body_text) {
        let Some(ability) = captures.get(1) else {
            continue;
        };
        let target = captures.get(2).map(|item| item.as_str().trim().to_string());
        let source = captures
            .get(0)
            .map(|item| item.as_str())
            .unwrap_or("$this->authorize");
        let key = format!("{}|{:?}|{}", ability.as_str(), target, source);
        if !seen.insert(key) {
            continue;
        }

        let (kind, enforces_failure_response, source_label) = if source.contains("Gate::allows") {
            (
                "allows".to_string(),
                gate_allows_enforces_failure,
                "Gate::allows".to_string(),
            )
        } else if source.contains("Gate::authorize") {
            ("policy".to_string(), true, "Gate::authorize".to_string())
        } else {
            ("policy".to_string(), true, "$this->authorize".to_string())
        };

        items.push(ContractAuthorization {
            kind,
            ability: Some(ability.as_str().to_string()),
            target_kind: target.as_ref().map(|_| "expression".to_string()),
            target,
            parameter: None,
            source: source_label,
            resolution: "explicit".to_string(),
            enforces_failure_response,
        });
    }

    if let Some(class) = class {
        if let Some(constructor_body) = class.method_body("__construct") {
            extend_authorize_resource_authorization(
                class,
                &controller.method_name,
                &constructor_body,
                &mut items,
                &mut seen,
            );
        }
    }

    for request_class in form_request_classes {
        extend_form_request_authorization(&request_class, source_index, &mut items, &mut seen);
    }

    let suppress_runtime_middleware = items
        .iter()
        .any(|item| item.resolution != "runtime" && item.kind != "middleware");

    for route in runtime_routes {
        extend_route_authorization(route, suppress_runtime_middleware, &mut items, &mut seen);
    }

    items.sort_by(|a, b| {
        (&a.kind, &a.source, &a.ability, &a.target, &a.parameter).cmp(&(
            &b.kind,
            &b.source,
            &b.ability,
            &b.target,
            &b.parameter,
        ))
    });
    items
}

fn extend_authorize_resource_authorization(
    class: &SourceClass,
    method_name: &str,
    constructor_body: &str,
    items: &mut Vec<ContractAuthorization>,
    seen: &mut BTreeSet<String>,
) {
    let authorize_resource_re = Regex::new(
        r#"(?s)\$this->authorizeResource\(\s*([^\),]+)\s*,\s*['"]([^'"]+)['"]\s*(?:,\s*(\[[^\)]*\]))?"#,
    )
    .expect("authorizeResource regex");

    for captures in authorize_resource_re.captures_iter(constructor_body) {
        let Some(target) = captures.get(1) else {
            continue;
        };
        let Some(parameter) = captures.get(2) else {
            continue;
        };

        let target = target.as_str().trim().trim_end_matches("::class").trim();
        let target = class.resolve_name(target);
        if target.is_empty() {
            continue;
        }
        let options = captures.get(3).map(|item| item.as_str()).unwrap_or("");
        if !authorize_resource_applies_to_method(options, method_name) {
            continue;
        }
        let parameter = parameter.as_str().trim().to_string();
        let key = format!("authorize_resource|{}|{}|{}", class.fqcn, target, parameter);
        if !seen.insert(key) {
            continue;
        }

        items.push(ContractAuthorization {
            kind: "policy".to_string(),
            ability: None,
            target_kind: Some("class".to_string()),
            target: Some(target),
            parameter: Some(parameter),
            source: "$this->authorizeResource".to_string(),
            resolution: "explicit".to_string(),
            enforces_failure_response: true,
        });
    }
}

fn authorize_resource_applies_to_method(options: &str, method_name: &str) -> bool {
    if options.is_empty() {
        return true;
    }

    let only_re = Regex::new(r#"['"]only['"]\s*=>\s*\[([^\]]*)\]"#).expect("only regex");
    if let Some(captures) = only_re.captures(options) {
        let methods = captures
            .get(1)
            .map(|item| item.as_str())
            .unwrap_or("")
            .split(',')
            .filter_map(|item| {
                let trimmed = item.trim();
                let trimmed = trimmed.trim_matches('\'').trim_matches('"');
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .collect::<Vec<_>>();
        return methods.contains(&method_name);
    }

    let except_re = Regex::new(r#"['"]except['"]\s*=>\s*\[([^\]]*)\]"#).expect("except regex");
    if let Some(captures) = except_re.captures(options) {
        let methods = captures
            .get(1)
            .map(|item| item.as_str())
            .unwrap_or("")
            .split(',')
            .filter_map(|item| {
                let trimmed = item.trim();
                let trimmed = trimmed.trim_matches('\'').trim_matches('"');
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .collect::<Vec<_>>();
        return !methods.contains(&method_name);
    }

    true
}

fn collect_form_request_classes(
    controller: &ControllerMethod,
    class: Option<&SourceClass>,
) -> BTreeSet<String> {
    let mut classes = BTreeSet::new();
    let Some(class) = class else {
        return classes;
    };

    let request_param_re =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*Request)\s+\$[A-Za-z_][A-Za-z0-9_]*"#)
            .expect("request parameter regex");

    for captures in request_param_re.captures_iter(&controller.body_text) {
        let Some(request_class) = captures.get(1) else {
            continue;
        };
        let resolved = class.resolve_name(request_class.as_str());
        if !resolved.is_empty() {
            classes.insert(resolved);
        }
    }

    for request in &controller.request_usage {
        if let Some(class_name) = &request.class_name {
            classes.insert(class_name.clone());
        }
    }

    classes
}

fn extend_route_authorization(
    route: &RuntimeRoute,
    suppress_runtime_middleware: bool,
    items: &mut Vec<ContractAuthorization>,
    seen: &mut BTreeSet<String>,
) {
    for middleware in &route.middleware {
        if let Some(spec) = middleware.strip_prefix("can:") {
            let mut parts = spec.split(',');
            let ability = parts.next().map(str::trim).filter(|item| !item.is_empty());
            let target = parts.next().map(str::trim).filter(|item| !item.is_empty());
            let key = format!("middleware|{:?}|{:?}|{}", ability, target, middleware);
            if !seen.insert(key) {
                continue;
            }
            items.push(ContractAuthorization {
                kind: "policy".to_string(),
                ability: ability.map(str::to_string),
                target_kind: target.map(|value| {
                    if value.contains('\\') {
                        "class".to_string()
                    } else {
                        "route_parameter".to_string()
                    }
                }),
                target: target.map(str::to_string),
                parameter: target
                    .filter(|value| !value.contains('\\'))
                    .map(str::to_string),
                source: middleware.clone(),
                resolution: "runtime".to_string(),
                enforces_failure_response: true,
            });
            continue;
        }

        if middleware.starts_with("auth") || middleware == "verified" || middleware == "signed" {
            if suppress_runtime_middleware {
                continue;
            }
            let key = format!("middleware|{}|{}", route.route_id, middleware);
            if !seen.insert(key) {
                continue;
            }
            items.push(ContractAuthorization {
                kind: "middleware".to_string(),
                ability: None,
                target_kind: None,
                target: None,
                parameter: None,
                source: middleware.clone(),
                resolution: "runtime".to_string(),
                enforces_failure_response: true,
            });
        }
    }
}

fn extend_form_request_authorization(
    class_name: &str,
    source_index: &SourceIndex,
    items: &mut Vec<ContractAuthorization>,
    seen: &mut BTreeSet<String>,
) {
    let Some(class) = source_index.get(class_name) else {
        return;
    };
    let Some(body) = class.method_body("authorize") else {
        return;
    };

    let compact = body.split_whitespace().collect::<String>();

    let can_re = Regex::new(
        r#"(?:->can|Gate::allows|Gate::authorize)\(\s*['"]([^'"]+)['"]\s*(?:,\s*([^\)]+))?"#,
    )
    .expect("form request authorize regex");
    let mut matched = false;

    for captures in can_re.captures_iter(&body) {
        let ability = captures.get(1).map(|item| item.as_str().to_string());
        let target = captures.get(2).map(|item| item.as_str().trim().to_string());
        let key = format!("form_request|{}|{:?}|{:?}", class.fqcn, ability, target);
        if !seen.insert(key) {
            continue;
        }
        matched = true;
        items.push(ContractAuthorization {
            kind: "form_request".to_string(),
            ability,
            target_kind: target.as_ref().map(|_| "expression".to_string()),
            target,
            parameter: None,
            source: "FormRequest::authorize".to_string(),
            resolution: "form_request".to_string(),
            enforces_failure_response: true,
        });
    }

    if matched {
        return;
    }

    let enforces_failure_response =
        compact.contains("returnfalse;") || compact.contains("abort(") || compact.contains("throw");
    let key = format!("form_request|{}|static", class.fqcn);
    if seen.insert(key) {
        items.push(ContractAuthorization {
            kind: "form_request".to_string(),
            ability: None,
            target_kind: None,
            target: None,
            parameter: None,
            source: "FormRequest::authorize".to_string(),
            resolution: "form_request".to_string(),
            enforces_failure_response,
        });
    }
}
