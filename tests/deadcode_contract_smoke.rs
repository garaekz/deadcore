use std::process::Command;

#[test]
fn request_mode_emits_deadcode_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_deadcore"))
        .args(["--request", "test/fixtures/contracts/deadcode/minimal.json"])
        .output()
        .expect("failed to run deadcore");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(payload["contractVersion"], "deadcode.analysis.v1");
    assert_eq!(payload["status"], "ok");
    assert!(payload["findings"].is_array());
    assert!(payload["removalPlan"].is_object());
}
