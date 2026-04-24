use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn reports_unused_form_request_resource_and_controller_class() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/http-adjacent.json",
    ))
    .expect("request fixture should exist");

    let mut child = Command::new(env!("CARGO_BIN_EXE_deadcore"))
        .args(["--request", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn deadcore");

    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(&request)
        .expect("failed to write request fixture");

    let output = child
        .wait_with_output()
        .expect("failed to wait for deadcore");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(payload["status"], "ok");

    let findings = payload["findings"]
        .as_array()
        .expect("findings should be an array");

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Requests\\UnusedAuditRequest"
                && finding["category"] == "unused_form_request"
        }),
        "expected unused form request finding, payload: {}",
        payload
    );

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Resources\\UnusedAuditResource"
                && finding["category"] == "unused_resource_class"
        }),
        "expected unused resource class finding, payload: {}",
        payload
    );

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Controllers\\DeadAdminController"
                && finding["category"] == "unused_controller_class"
        }),
        "expected unused controller class finding, payload: {}",
        payload
    );

    assert!(
        !findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Requests\\StoreOrderRequest"
        }),
        "reachable form request should not be flagged, payload: {}",
        payload
    );

    assert!(
        !findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Resources\\OrderResource"
        }),
        "reachable resource should not be flagged, payload: {}",
        payload
    );

    assert!(
        !findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Controllers\\ReachableOrderController"
        }),
        "reachable controller class should not be flagged, payload: {}",
        payload
    );
}
