use oxinfer::contracts::{build_analysis_response, load_analysis_request_from_slice};
use oxinfer::pipeline::analyze_project;
use serde_json::json;

#[path = "support/oxcribe_fixture_request.rs"]
mod oxcribe_fixture_request;

fn policy_fixture_root() -> String {
    oxcribe_fixture_request::oxcribe_fixture_root("PolicyLaravelApp")
}

#[test]
fn request_mode_preserves_static_policy_sources() {
    let root = policy_fixture_root();
    let payload = json!({
        "contractVersion": "oxcribe.oxinfer.v2",
        "requestId": "req-policy",
        "runtimeFingerprint": "fp-policy",
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
                    "routeId": "policy-fixture.posts.show",
                    "methods": ["GET"],
                    "uri": "policy/posts/{policyPost}",
                    "domain": null,
                    "name": "policy-fixture.posts.show",
                    "prefix": "api",
                    "middleware": ["api", "auth:sanctum"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PostPolicyController",
                        "method": "show"
                    }
                },
                {
                    "routeId": "policy-fixture.posts.preview",
                    "methods": ["GET"],
                    "uri": "policy/posts/{policyPost}/preview",
                    "domain": null,
                    "name": "policy-fixture.posts.preview",
                    "prefix": "api",
                    "middleware": ["api", "auth:sanctum"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PostPolicyController",
                        "method": "preview"
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
    let show = response
        .delta
        .controllers
        .iter()
        .find(|controller| {
            controller.fqcn == "App\\Http\\Controllers\\PostPolicyController"
                && controller.method == "show"
        })
        .expect("show controller should be present");

    let show_sources = show
        .authorization
        .iter()
        .map(|item| item.source.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let show_statuses = show
        .responses
        .iter()
        .filter_map(|response| response.status)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        show_sources,
        vec![
            "$this->authorize",
            "$this->authorizeResource",
            "FormRequest::authorize",
            "Gate::allows",
            "Gate::authorize",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
    );
    assert!(show_statuses.contains(&403));

    let preview = response
        .delta
        .controllers
        .iter()
        .find(|controller| {
            controller.fqcn == "App\\Http\\Controllers\\PostPolicyController"
                && controller.method == "preview"
        })
        .expect("preview controller should be present");
    let preview_statuses = preview
        .responses
        .iter()
        .filter_map(|response| response.status)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        !preview_statuses.contains(&403),
        "preview Gate::allows should not synthesize a 403 response"
    );
}
