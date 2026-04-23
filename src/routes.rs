use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RouteBinding {
    pub controller_fqcn: String,
    pub method_name: String,
    pub http_methods: Vec<String>,
}

pub fn extract_route_bindings(source: &str) -> Vec<RouteBinding> {
    let imports = collect_imports(source);
    let mut bindings = Vec::new();

    bindings.extend(extract_resource_routes(source, &imports));
    bindings.extend(extract_direct_routes(source, &imports));

    let mut deduped = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if deduped.iter().any(|existing: &RouteBinding| {
            existing.controller_fqcn == binding.controller_fqcn
                && existing.method_name == binding.method_name
                && existing.http_methods == binding.http_methods
        }) {
            continue;
        }
        deduped.push(binding);
    }
    deduped
}

fn collect_imports(source: &str) -> BTreeMap<String, String> {
    let use_re = Regex::new(r"(?m)^\s*use\s+([^;]+);").expect("use regex");
    let mut imports = BTreeMap::new();

    for captures in use_re.captures_iter(source) {
        let Some(raw) = captures.get(1) else {
            continue;
        };

        let import = raw.as_str().trim();
        if import.contains('{') {
            continue;
        }

        let alias = import
            .rsplit('\\')
            .next()
            .unwrap_or(import)
            .trim()
            .trim_start_matches('\\')
            .to_string();

        imports.insert(alias, import.trim_start_matches('\\').to_string());
    }

    imports
}

fn extract_resource_routes(source: &str, imports: &BTreeMap<String, String>) -> Vec<RouteBinding> {
    let resource_re = Regex::new(
        r#"Route::(apiResource|resource)\(\s*['"][^'"]+['"]\s*,\s*([A-Za-z_\\][A-Za-z0-9_\\]*)::class"#,
    )
    .expect("resource route regex");

    let mut bindings = Vec::new();
    for captures in resource_re.captures_iter(source) {
        let Some(kind) = captures.get(1) else {
            continue;
        };
        let Some(controller) = captures.get(2) else {
            continue;
        };

        let fqcn = resolve_class_name(controller.as_str(), imports);
        let is_api = kind.as_str() == "apiResource";
        for (method_name, http_methods) in resource_method_set(is_api) {
            bindings.push(RouteBinding {
                controller_fqcn: fqcn.clone(),
                method_name: method_name.to_string(),
                http_methods: http_methods
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            });
        }
    }

    bindings
}

fn extract_direct_routes(source: &str, imports: &BTreeMap<String, String>) -> Vec<RouteBinding> {
    let direct_re = Regex::new(
        r#"Route::(get|post|put|patch|delete|options|any|match)\([^;]*?\[\s*([A-Za-z_\\][A-Za-z0-9_\\]*)::class\s*,\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]"#,
    )
    .expect("direct route regex");
    let invokable_re = Regex::new(
        r#"Route::(get|post|put|patch|delete|options|any|match)\([^;]*?([A-Za-z_\\][A-Za-z0-9_\\]*)::class"#,
    )
    .expect("invokable route regex");

    let mut bindings = Vec::new();
    for captures in direct_re.captures_iter(source) {
        let Some(verb) = captures.get(1) else {
            continue;
        };
        let Some(controller) = captures.get(2) else {
            continue;
        };
        let Some(method_name) = captures.get(3) else {
            continue;
        };

        bindings.push(RouteBinding {
            controller_fqcn: resolve_class_name(controller.as_str(), imports),
            method_name: method_name.as_str().to_string(),
            http_methods: expand_http_methods(verb.as_str()),
        });
    }

    for captures in invokable_re.captures_iter(source) {
        let Some(verb) = captures.get(1) else {
            continue;
        };
        let Some(controller) = captures.get(2) else {
            continue;
        };
        let fqcn = resolve_class_name(controller.as_str(), imports);
        if bindings
            .iter()
            .any(|binding| binding.controller_fqcn == fqcn)
        {
            continue;
        }

        bindings.push(RouteBinding {
            controller_fqcn: fqcn,
            method_name: "__invoke".to_string(),
            http_methods: expand_http_methods(verb.as_str()),
        });
    }

    bindings
}

fn resource_method_set(is_api: bool) -> Vec<(&'static str, Vec<&'static str>)> {
    let mut routes = vec![
        ("index", vec!["GET"]),
        ("store", vec!["POST"]),
        ("show", vec!["GET"]),
        ("update", vec!["PUT", "PATCH"]),
        ("destroy", vec!["DELETE"]),
    ];

    if !is_api {
        routes.push(("create", vec!["GET"]));
        routes.push(("edit", vec!["GET"]));
    }

    routes
}

fn resolve_class_name(raw: &str, imports: &BTreeMap<String, String>) -> String {
    let trimmed = raw.trim().trim_start_matches('\\');
    if trimmed.contains('\\') {
        return trimmed.to_string();
    }

    imports
        .get(trimmed)
        .cloned()
        .unwrap_or_else(|| trimmed.to_string())
}

fn expand_http_methods(verb: &str) -> Vec<String> {
    match verb {
        "match" | "any" => vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        other => vec![other.to_ascii_uppercase()],
    }
}

#[cfg(test)]
mod tests {
    use super::extract_route_bindings;

    #[test]
    fn extracts_api_resource_and_direct_routes() {
        let source = r#"
            <?php
            use App\Http\Controllers\ProductController;
            use App\Http\Controllers\InvokeUserController;

            Route::apiResource('products', ProductController::class);
            Route::get('products/featured', [ProductController::class, 'featured']);
            Route::post('user/invoke', InvokeUserController::class);
        "#;

        let bindings = extract_route_bindings(source);
        assert!(bindings.iter().any(|binding| {
            binding.controller_fqcn == "App\\Http\\Controllers\\ProductController"
                && binding.method_name == "index"
                && binding.http_methods == vec!["GET"]
        }));
        assert!(bindings.iter().any(|binding| {
            binding.controller_fqcn == "App\\Http\\Controllers\\ProductController"
                && binding.method_name == "update"
                && binding.http_methods == vec!["PUT", "PATCH"]
        }));
        assert!(bindings.iter().any(|binding| {
            binding.controller_fqcn == "App\\Http\\Controllers\\ProductController"
                && binding.method_name == "featured"
                && binding.http_methods == vec!["GET"]
        }));
        assert!(bindings.iter().any(|binding| {
            binding.controller_fqcn == "App\\Http\\Controllers\\InvokeUserController"
                && binding.method_name == "__invoke"
                && binding.http_methods == vec!["POST"]
        }));
    }
}
