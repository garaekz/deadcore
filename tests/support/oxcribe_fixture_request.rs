#![allow(dead_code)]

use oxinfer::contracts::{
    AnalysisResponse, ContractController, build_analysis_response, load_analysis_request_from_slice,
};
use oxinfer::pipeline::analyze_project;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

pub fn oxcribe_fixture_root(name: &str) -> String {
    repo_path(&format!("test/fixtures/oxcribe/{name}"))
        .canonicalize()
        .or_else(|_| repo_path(&format!("../oxcribe/tests/Fixtures/{name}")).canonicalize())
        .expect("oxcribe fixture should exist")
        .to_string_lossy()
        .to_string()
}

pub fn run_fixture_request(fixture: &str, routes: Vec<Value>) -> AnalysisResponse {
    let root = oxcribe_fixture_root(fixture);
    let payload = json!({
        "contractVersion": "oxcribe.oxinfer.v2",
        "requestId": format!("req-{}", fixture),
        "runtimeFingerprint": format!("fp-{}", fixture),
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
            "routes": routes
        }
    });

    let request = load_analysis_request_from_slice(
        &serde_json::to_vec(&payload).expect("request should encode"),
        None,
    )
    .expect("request should decode");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    build_analysis_response(&request, &result)
}

pub fn find_controller<'a>(
    response: &'a AnalysisResponse,
    fqcn: &str,
    method: &str,
) -> &'a ContractController {
    response
        .delta
        .controllers
        .iter()
        .find(|controller| controller.fqcn == fqcn && controller.method == method)
        .expect("controller should exist")
}
