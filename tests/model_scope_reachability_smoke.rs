use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn reports_unused_model_scope() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/model-scopes.json",
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
            symbol["kind"] == "model_scope"
                && symbol["symbol"] == "App\\Models\\Post::published"
                && symbol["reachableFromRuntime"] == true
        }),
        "expected reachable model scope symbol, payload: {}",
        payload
    );

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Models\\Post::archived"
                && finding["category"] == "unused_model_scope"
                && finding["confidence"] == "high"
        }),
        "expected unused model scope finding, payload: {}",
        payload
    );
}
