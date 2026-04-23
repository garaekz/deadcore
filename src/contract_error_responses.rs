use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::json;

use crate::contracts::{ContractHttpInfo, ContractResponse};
use crate::model::ControllerMethod;

pub fn infer_framework_error_responses(
    controller: &ControllerMethod,
    _http: Option<&ContractHttpInfo>,
) -> Vec<ContractResponse> {
    let mut responses = Vec::new();
    let mut seen = BTreeSet::new();
    let assignments = extract_local_integer_assignments(&controller.body_text);

    for status in extract_abort_statuses(&controller.body_text, &assignments) {
        push_error_response(&mut responses, &mut seen, status, "abort()");
    }

    if has_throw_new(&controller.body_text, "AuthorizationException") {
        push_error_response(
            &mut responses,
            &mut seen,
            403,
            "throw new AuthorizationException",
        );
    }

    if has_model_not_found_path(&controller.body_text) {
        push_error_response(
            &mut responses,
            &mut seen,
            404,
            "throw new ModelNotFoundException",
        );
    }

    if controller
        .body_text
        .contains("ValidationException::withMessages")
    {
        push_error_response(
            &mut responses,
            &mut seen,
            422,
            "ValidationException::withMessages",
        );
    }

    responses
}

#[allow(dead_code)]
fn json_error_response(status: u16, source: &str) -> ContractResponse {
    ContractResponse {
        kind: "json_object".to_string(),
        status: Some(status),
        explicit: Some(false),
        content_type: Some("application/json".to_string()),
        headers: BTreeMap::new(),
        body_schema: Some(json!({ "type": "object" })),
        redirect: None,
        download: None,
        inertia: None,
        source: Some(source.to_string()),
        via: Some(source.to_string()),
    }
}

fn extract_local_integer_assignments(body: &str) -> BTreeMap<String, u16> {
    let assignment_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\s*;"#).expect("assignment regex");
    let mut assignments = BTreeMap::new();

    for captures in assignment_re.captures_iter(body) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(value) = captures.get(2) else {
            continue;
        };
        if let Ok(status) = value.as_str().parse::<u16>() {
            assignments.insert(name.as_str().to_string(), status);
        }
    }

    assignments
}

fn extract_abort_statuses(body: &str, assignments: &BTreeMap<String, u16>) -> Vec<u16> {
    let abort_re = Regex::new(r#"\babort\(\s*([^,\)]+)"#).expect("abort regex");
    let conditional_abort_re = Regex::new(r#"(?s)\babort_(?:unless|if)\((?:.|\n)*?,\s*([^,\)]+)"#)
        .expect("conditional abort regex");
    let mut statuses = Vec::new();
    let mut seen = BTreeSet::new();

    for raw_status in abort_re
        .captures_iter(body)
        .filter_map(|captures| captures.get(1).map(|item| item.as_str().trim().to_string()))
        .chain(
            conditional_abort_re
                .captures_iter(body)
                .filter_map(|captures| {
                    captures.get(1).map(|item| item.as_str().trim().to_string())
                }),
        )
    {
        if let Some(status) = resolve_status(&raw_status, assignments) {
            if seen.insert(status) {
                statuses.push(status);
            }
        }
    }

    statuses
}

fn push_error_response(
    responses: &mut Vec<ContractResponse>,
    seen: &mut BTreeSet<String>,
    status: u16,
    source: &str,
) {
    let key = format!("{status}|{source}");
    if !seen.insert(key) {
        return;
    }

    responses.push(json_error_response(status, source));
}

fn has_throw_new(body: &str, class_name: &str) -> bool {
    let pattern = format!(r#"\bthrow\s+new\s+{}\s*\("#, regex::escape(class_name));
    Regex::new(&pattern).expect("throw regex").is_match(body)
}

fn has_model_not_found_path(body: &str) -> bool {
    if has_throw_new(body, "ModelNotFoundException") {
        return true;
    }

    let constructed_exception_re =
        Regex::new(r#"\bnew\s+ModelNotFoundException\s*\("#).expect("model not found regex");
    constructed_exception_re.is_match(body) || body.contains("firstOrFail(")
}

fn resolve_status(raw_status: &str, assignments: &BTreeMap<String, u16>) -> Option<u16> {
    if let Some(variable) = raw_status.strip_prefix('$') {
        return assignments.get(variable).copied();
    }

    raw_status.parse::<u16>().ok()
}
