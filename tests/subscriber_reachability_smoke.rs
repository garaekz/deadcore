use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn reports_unused_subscriber_class() {
    let request = std::fs::read(fixture_path(
        "test/fixtures/contracts/deadcode/subscriber-reachability.json",
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
    let entrypoints = payload["entrypoints"]
        .as_array()
        .expect("entrypoints should be an array");
    let removal_change_sets = payload["removalPlan"]["changeSets"]
        .as_array()
        .expect("removal plan should contain change sets");

    assert!(
        entrypoints.iter().any(|entrypoint| {
            entrypoint["kind"] == "runtime_subscriber"
                && entrypoint["symbol"] == "App\\Listeners\\ReachableOrderSubscriber"
                && entrypoint["source"] == "App\\Listeners\\ReachableOrderSubscriber"
        }),
        "expected runtime subscriber entrypoint, payload: {}",
        payload
    );

    assert!(
        symbols.iter().any(|symbol| {
            symbol["symbol"] == "App\\Listeners\\ReachableOrderSubscriber"
                && symbol["kind"] == "subscriber_class"
                && symbol["reachableFromRuntime"] == true
        }),
        "expected reachable subscriber class symbol, payload: {}",
        payload
    );

    assert!(
        findings.iter().any(|finding| {
            finding["symbol"] == "App\\Listeners\\UnusedInventorySubscriber"
                && finding["category"] == "unused_subscriber_class"
                && finding["confidence"] == "high"
        }),
        "expected unused subscriber class finding, payload: {}",
        payload
    );

    assert!(
        !findings
            .iter()
            .any(|finding| { finding["symbol"] == "App\\Listeners\\ReachableOrderSubscriber" }),
        "reachable subscriber class should not be flagged, payload: {}",
        payload
    );

    assert!(
        removal_change_sets.iter().any(|change_set| {
            change_set["symbol"] == "App\\Listeners\\UnusedInventorySubscriber"
                && change_set["file"] == "app/Listeners/UnusedInventorySubscriber.php"
                && change_set["start_line"].is_number()
                && change_set["end_line"].is_number()
        }),
        "expected explicit removal plan for unused subscriber class, payload: {}",
        payload
    );
}
