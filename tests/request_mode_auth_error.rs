use serde_json::json;

#[path = "support/oxcribe_fixture_request.rs"]
mod oxcribe_fixture_request;

use oxcribe_fixture_request::{find_controller, run_fixture_request};

#[test]
fn request_mode_exposes_framework_error_responses() {
    let analysis = run_fixture_request(
        "AuthErrorLaravelApp",
        vec![json!({
            "routeId": "auth-error-fixture.secure-reports.errors",
            "methods": ["GET"],
            "uri": "/secure/reports/errors",
            "domain": null,
            "name": "auth-error-fixture.secure-reports.errors",
            "prefix": "api",
            "middleware": ["auth:sanctum", "throttle:api"],
            "where": {},
            "defaults": {},
            "bindings": [],
            "action": {
                "kind": "controller_method",
                "fqcn": "App\\Http\\Controllers\\SecureReportController",
                "method": "errors"
            }
        })],
    );

    let controller = find_controller(
        &analysis,
        "App\\Http\\Controllers\\SecureReportController",
        "errors",
    );

    for (status, source) in [
        (Some(200), "response()->json"),
        (Some(400), "abort()"),
        (Some(403), "throw new AuthorizationException"),
        (Some(404), "throw new ModelNotFoundException"),
        (Some(422), "ValidationException::withMessages"),
    ] {
        assert!(
            controller.responses.iter().any(|response| {
                response.status == status
                    && response.source.as_deref() == Some(source)
                    && response.kind == "json_object"
            }),
            "missing framework error response {status:?} from {source}"
        );
    }
}

#[test]
fn request_mode_merges_additional_resource_envelopes() {
    let analysis = run_fixture_request(
        "AuthErrorLaravelApp",
        vec![json!({
            "routeId": "auth-error-fixture.secure-reports.additional",
            "methods": ["GET"],
            "uri": "/secure/reports/additional",
            "domain": null,
            "name": "auth-error-fixture.secure-reports.additional",
            "prefix": "api",
            "middleware": ["auth:sanctum"],
            "where": {},
            "defaults": {},
            "bindings": [],
            "action": {
                "kind": "controller_method",
                "fqcn": "App\\Http\\Controllers\\SecureReportController",
                "method": "additionalResource"
            }
        })],
    );

    let controller = find_controller(
        &analysis,
        "App\\Http\\Controllers\\SecureReportController",
        "additionalResource",
    );
    let body_schema = controller
        .responses
        .first()
        .and_then(|response| response.body_schema.as_ref())
        .expect("additional resource response should expose a body schema");

    assert_eq!(body_schema["type"], json!("object"));
    assert_eq!(body_schema["properties"]["id"]["type"], json!("object"));
    assert_eq!(body_schema["properties"]["title"]["type"], json!("object"));
    assert_eq!(body_schema["properties"]["meta"]["type"], json!("object"));
    assert_eq!(
        body_schema["properties"]["meta"]["properties"]["version"]["type"],
        json!("integer")
    );
    assert_eq!(body_schema["properties"]["links"]["type"], json!("object"));
    assert_eq!(
        body_schema["properties"]["links"]["properties"]["self"]["type"],
        json!("string")
    );
    assert_eq!(
        body_schema["properties"]["links"]["properties"]["self"]["format"],
        json!("uri")
    );
}
