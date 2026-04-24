use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn reports_unused_model_accessor_and_mutator() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/model-attributes.json",
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

    let symbols = payload["symbols"]
        .as_array()
        .expect("symbols should be an array");
    let findings = payload["findings"]
        .as_array()
        .expect("findings should be an array");

    assert!(
        symbols.iter().any(|symbol| {
            symbol["kind"] == "model_accessor"
                && symbol["symbol"] == "App\\Models\\User::display_name"
                && symbol["reachableFromRuntime"] == true
        }),
        "expected reachable model accessor symbol, payload: {}",
        payload
    );

    assert!(
        symbols.iter().any(|symbol| {
            symbol["kind"] == "model_mutator"
                && symbol["symbol"] == "App\\Models\\User::display_name"
                && symbol["reachableFromRuntime"] == true
        }),
        "expected reachable model mutator symbol, payload: {}",
        payload
    );

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Models\\User::secret_name"
                && finding["category"] == "unused_model_accessor"
                && finding["confidence"] == "high"
        }),
        "expected unused model accessor finding, payload: {}",
        payload
    );

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Models\\User::secret_name"
                && finding["category"] == "unused_model_mutator"
                && finding["confidence"] == "high"
        }),
        "expected unused model mutator finding, payload: {}",
        payload
    );
}
