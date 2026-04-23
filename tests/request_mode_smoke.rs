use std::fs;
use std::path::{Path, PathBuf};

use oxinfer::contracts::{build_analysis_response, load_analysis_request_from_slice};
use oxinfer::pipeline::analyze_project;
use serde_json::{Value, json};

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn fixture_root(name: &str) -> String {
    repo_path(&format!("test/fixtures/integration/{name}"))
        .canonicalize()
        .expect("fixture root should exist")
        .to_string_lossy()
        .to_string()
}

fn replace_placeholder(value: &mut Value, needle: &str, replacement: &str) {
    match value {
        Value::String(text) => {
            if text.contains(needle) {
                *text = text.replace(needle, replacement);
            }
        }
        Value::Array(items) => {
            for item in items {
                replace_placeholder(item, needle, replacement);
            }
        }
        Value::Object(entries) => {
            for item in entries.values_mut() {
                replace_placeholder(item, needle, replacement);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn load_request_fixture(path: &str) -> Vec<u8> {
    let raw = fs::read_to_string(repo_path(path)).expect("request fixture should exist");
    let mut fixture: Value =
        serde_json::from_str(&raw).expect("request fixture should be valid JSON");
    replace_placeholder(
        &mut fixture,
        "__FIXTURE_ROOT__",
        &fixture_root("minimal-laravel"),
    );
    serde_json::to_vec(&fixture).expect("request fixture should encode")
}

#[test]
fn matched_invokable_contract_matches_golden() {
    let request = load_analysis_request_from_slice(
        &load_request_fixture("test/fixtures/contracts/request-mode/matched-invokable.json"),
        None,
    )
    .expect("request fixture should load");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    let response = build_analysis_response(&request, &result);
    let actual = serde_json::to_string(&response).expect("response should encode");
    let expected = fs::read_to_string(repo_path("test/golden/request-mode/matched-invokable.json"))
        .expect("golden should exist");

    assert_eq!(actual, expected.trim());
}

#[test]
fn missing_static_contract_matches_golden() {
    let request = load_analysis_request_from_slice(
        &load_request_fixture("test/fixtures/contracts/request-mode/missing-static.json"),
        None,
    )
    .expect("request fixture should load");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    let response = build_analysis_response(&request, &result);
    let actual = serde_json::to_string(&response).expect("response should encode");
    let expected = fs::read_to_string(repo_path("test/golden/request-mode/missing-static.json"))
        .expect("golden should exist");

    assert_eq!(actual, expected.trim());
}

#[test]
fn invalid_request_rejects_unknown_top_level_keys() {
    let invalid = br#"{"contractVersion":"oxcribe.oxinfer.v2","requestId":"bad","runtimeFingerprint":"fp","manifest":{},"runtime":{"app":{"basePath":"/tmp","laravelVersion":"12","phpVersion":"8.3","appEnv":"testing"},"routes":[]},"extra":true}"#;
    let error =
        load_analysis_request_from_slice(invalid, None).expect_err("invalid request should fail");

    let message = error.to_string();
    assert!(message.contains("missing field") || message.contains("unknown field"));
}

#[test]
fn api_contract_exposes_request_resources_and_responses() {
    let root = fixture_root("api-project");
    let payload = json!({
        "contractVersion": "oxcribe.oxinfer.v2",
        "requestId": "req-api",
        "runtimeFingerprint": "fp-api",
        "manifest": {
            "project": {
                "root": root,
                "composer": "composer.json"
            },
            "scan": {
                "targets": ["app", "routes"],
                "globs": ["**/*.php"]
            },
            "features": {
                "http_status": true,
                "request_usage": true,
                "resource_usage": true,
                "with_pivot": true,
                "attribute_make": true,
                "scopes_used": true,
                "polymorphic": true,
                "broadcast_channels": true
            }
        },
        "runtime": {
            "app": {
                "basePath": root,
                "laravelVersion": "12.0.0",
                "phpVersion": "8.3.0",
                "appEnv": "testing"
            },
            "routes": [
                {
                    "routeId": "products.store",
                    "methods": ["POST"],
                    "uri": "products",
                    "domain": null,
                    "name": "products.store",
                    "prefix": "api",
                    "middleware": ["api", "auth:sanctum", "can:create,App\\Models\\Product"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\ProductController",
                        "method": "store"
                    }
                }
            ]
        }
    });

    let request = load_analysis_request_from_slice(
        &serde_json::to_vec(&payload).expect("request should encode"),
        None,
    )
    .expect("request should decode");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    let analysis = build_analysis_response(&request, &result);

    assert_eq!(analysis.status, "ok");
    assert_eq!(analysis.delta.controllers.len(), 1);
    assert!(analysis.delta.resources.iter().any(|resource| {
        resource.fqcn == "App\\Http\\Resources\\ProductResource"
            && resource.class == "ProductResource"
    }));

    let controller = &analysis.delta.controllers[0];
    assert_eq!(controller.fqcn, "App\\Http\\Controllers\\ProductController");
    assert_eq!(controller.method, "store");
    assert!(controller.request.is_some());
    let request = controller
        .request
        .as_ref()
        .expect("request contract should exist");
    let name_field = request
        .fields
        .iter()
        .find(|field| field.path == "name")
        .expect("name field should exist");
    assert_eq!(name_field.type_name.as_deref(), Some("string"));
    assert_eq!(name_field.required, Some(true));
    let price_field = request
        .fields
        .iter()
        .find(|field| field.path == "price")
        .expect("price field should exist");
    assert_eq!(price_field.type_name.as_deref(), Some("number"));
    let tags_field = request
        .fields
        .iter()
        .find(|field| field.path == "tags")
        .expect("tags field should exist");
    assert_eq!(tags_field.type_name.as_deref(), Some("array"));
    assert_eq!(tags_field.collection, Some(true));
    assert!(controller.responses.iter().any(|item| {
        item.kind == "json_object"
            && item.status == Some(201)
            && item.source.as_deref() == Some("JsonResource::response")
    }));
    let contract_response = controller
        .responses
        .iter()
        .find(|item| item.status == Some(201))
        .expect("store response should exist");
    let body_schema = contract_response
        .body_schema
        .as_ref()
        .expect("response body schema should exist");
    assert_eq!(body_schema["ref"], "App\\Http\\Resources\\ProductResource");
    let product_resource = analysis
        .delta
        .resources
        .iter()
        .find(|resource| resource.fqcn == "App\\Http\\Resources\\ProductResource")
        .expect("product resource should exist");
    assert_eq!(
        product_resource.schema["properties"]["id"]["type"],
        "integer"
    );
    assert_eq!(
        product_resource.schema["properties"]["price"]["type"],
        "number"
    );
    assert_eq!(
        product_resource.schema["properties"]["created_at"]["format"],
        "date-time"
    );
    assert!(controller.resources.iter().any(|item| {
        item.fqcn.as_deref() == Some("App\\Http\\Resources\\ProductResource") && !item.collection
    }));
    assert!(!controller.authorization.iter().any(|item| {
        item.kind == "middleware" && item.source == "auth:sanctum" && item.resolution == "runtime"
    }));
    assert!(controller.authorization.iter().any(|item| {
        item.kind == "policy"
            && item.ability.as_deref() == Some("create")
            && item.target.as_deref() == Some("App\\Models\\Product")
            && item.source == "can:create,App\\Models\\Product"
    }));

    assert_eq!(
        product_resource.schema["properties"]["reviews_count"]["type"],
        "integer"
    );
    let top_level_resource = analysis
        .delta
        .resources
        .iter()
        .find(|resource| resource.fqcn == "App\\Http\\Resources\\ProductCollection");
    assert!(top_level_resource.is_some());
}

#[test]
fn complex_contract_exposes_polymorphic_and_broadcast_graph() {
    let root = fixture_root("complex-app");
    let payload = json!({
        "contractVersion": "oxcribe.oxinfer.v2",
        "requestId": "req-complex",
        "runtimeFingerprint": "fp-complex",
        "manifest": {
            "project": {
                "root": root,
                "composer": "composer.json"
            },
            "scan": {
                "targets": ["app", "routes"],
                "globs": ["**/*.php"]
            },
            "features": {
                "http_status": true,
                "request_usage": true,
                "resource_usage": true,
                "with_pivot": true,
                "attribute_make": true,
                "scopes_used": true,
                "polymorphic": true,
                "broadcast_channels": true
            }
        },
        "runtime": {
            "app": {
                "basePath": root,
                "laravelVersion": "12.0.0",
                "phpVersion": "8.3.0",
                "appEnv": "testing"
            },
            "routes": [
                {
                    "routeId": "posts.index",
                    "methods": ["GET"],
                    "uri": "posts",
                    "domain": null,
                    "name": "posts.index",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PostController",
                        "method": "index"
                    }
                }
            ]
        }
    });

    let request = load_analysis_request_from_slice(
        &serde_json::to_vec(&payload).expect("request should encode"),
        None,
    )
    .expect("request should decode");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    let response = build_analysis_response(&request, &result);

    assert_eq!(response.status, "ok");
    assert!(!response.delta.broadcast.is_empty());
    assert!(
        response
            .delta
            .broadcast
            .iter()
            .any(|item| item.visibility == "public")
    );
    assert!(
        response
            .delta
            .broadcast
            .iter()
            .any(|item| item.visibility == "private")
    );
    assert!(
        response
            .delta
            .broadcast
            .iter()
            .any(|item| item.visibility == "presence")
    );
    assert!(
        response
            .delta
            .polymorphic
            .iter()
            .any(|item| item.parent == "App\\Models\\Post")
    );

    let post_model = response
        .delta
        .models
        .iter()
        .find(|model| model.fqcn == "App\\Models\\Post")
        .expect("post model should exist");
    assert!(post_model.with_pivot.iter().any(|pivot| {
        pivot.relation == "tags"
            && pivot.columns.contains(&"relevance_score".to_string())
            && pivot.timestamps == Some(true)
    }));
    assert!(post_model.polymorphic.iter().any(|relation| {
        relation.relation == "comments" && relation.relation_type == "morphMany"
    }));
}

#[test]
fn static_authorization_wins_without_duplicate_runtime_middleware_entries() {
    let root = fixture_root("complex-app");
    let payload = json!({
        "contractVersion": "oxcribe.oxinfer.v2",
        "requestId": "req-auth",
        "runtimeFingerprint": "fp-auth",
        "manifest": {
            "project": {
                "root": root,
                "composer": "composer.json"
            },
            "scan": {
                "targets": ["app", "routes"],
                "globs": ["**/*.php"]
            },
            "features": {
                "http_status": true,
                "request_usage": true,
                "resource_usage": true,
                "with_pivot": true,
                "attribute_make": true,
                "scopes_used": true,
                "polymorphic": true,
                "broadcast_channels": true
            }
        },
        "runtime": {
            "app": {
                "basePath": root,
                "laravelVersion": "12.0.0",
                "phpVersion": "8.3.0",
                "appEnv": "testing"
            },
            "routes": [
                {
                    "routeId": "posts.update",
                    "methods": ["PUT"],
                    "uri": "posts/{post}",
                    "domain": null,
                    "name": "posts.update",
                    "prefix": "api",
                    "middleware": ["api", "auth:sanctum", "can:update,post"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PostController",
                        "method": "update"
                    }
                }
            ]
        }
    });

    let request = load_analysis_request_from_slice(
        &serde_json::to_vec(&payload).expect("request should encode"),
        None,
    )
    .expect("request should decode");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    let response = build_analysis_response(&request, &result);
    let controller = response
        .delta
        .controllers
        .iter()
        .find(|controller| controller.method == "update")
        .expect("update controller should be present");

    assert!(
        !controller
            .authorization
            .iter()
            .any(|item| { item.kind == "middleware" && item.source == "auth:sanctum" })
    );
    assert!(controller.authorization.iter().any(|item| {
        item.kind == "policy"
            && item.source == "can:update,post"
            && item.parameter.as_deref() == Some("post")
    }));
    assert!(controller.authorization.iter().any(|item| {
        item.kind == "policy"
            && item.source == "$this->authorize"
            && item.ability.as_deref() == Some("update")
            && item.target.as_deref() == Some("$post")
    }));
}

#[test]
fn request_mode_reports_partial_when_static_scan_hits_file_limit() {
    let root = fixture_root("complex-app");
    let payload = json!({
        "contractVersion": "oxcribe.oxinfer.v2",
        "requestId": "req-partial",
        "runtimeFingerprint": "fp-partial",
        "manifest": {
            "project": {
                "root": root,
                "composer": "composer.json"
            },
            "scan": {
                "targets": ["app", "routes"],
                "globs": ["**/*.php"]
            },
            "limits": {
                "max_files": 1
            },
            "features": {
                "http_status": true,
                "request_usage": true,
                "resource_usage": true,
                "with_pivot": true,
                "attribute_make": true,
                "scopes_used": true,
                "polymorphic": true,
                "broadcast_channels": true
            }
        },
        "runtime": {
            "app": {
                "basePath": root,
                "laravelVersion": "12.0.0",
                "phpVersion": "8.3.0",
                "appEnv": "testing"
            },
            "routes": []
        }
    });

    let request = load_analysis_request_from_slice(
        &serde_json::to_vec(&payload).expect("request should encode"),
        None,
    )
    .expect("request should decode");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    let response = build_analysis_response(&request, &result);

    assert_eq!(response.status, "partial");
    assert!(response.meta.partial);
    assert!(response.delta.meta.partial);
    assert!(
        response
            .diagnostics
            .iter()
            .any(|item| item.code == "analysis.static.partial")
    );
}
