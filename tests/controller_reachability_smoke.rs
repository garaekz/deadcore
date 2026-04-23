use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn reports_unused_controller_method_when_not_reachable_from_runtime_or_static_calls() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/controller-basic.json",
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
            finding["symbol"] == "App\\Http\\Controllers\\UserController::unused"
                && finding["category"] == "unused_controller_method"
                && finding["confidence"] == "high"
        }),
        "expected unused controller method finding, payload: {}",
        payload
    );

    assert!(
        !findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Controllers\\UserController::index"
        }),
        "reachable controller method should not be flagged, payload: {}",
        payload
    );
}

#[test]
fn does_not_report_same_controller_callee_when_reachable_from_routed_method() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/controller-basic.json",
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
        !findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Controllers\\UserController::reachableThroughIndex"
        }),
        "same-controller callee should stay reachable, payload: {}",
        payload
    );
}

#[test]
fn does_not_report_cross_controller_callee_when_reachable_from_routed_method() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/controller-basic.json",
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
        !findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Controllers\\HelperController::reachableHelper"
        }),
        "cross-controller callee should stay reachable, payload: {}",
        payload
    );

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Controllers\\HelperController::unusedHelper"
                && finding["category"] == "unused_controller_method"
                && finding["confidence"] == "high"
        }),
        "expected still-dead helper method finding, payload: {}",
        payload
    );
}

#[test]
fn does_not_report_cross_controller_instance_callee_when_reachable_from_routed_method() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/controller-basic.json",
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
        !findings.iter().any(|finding| {
            finding["symbol"] == "App\\Http\\Controllers\\HelperController::reachableInstanceHelper"
        }),
        "cross-controller instance callee should stay reachable, payload: {}",
        payload
    );
}
