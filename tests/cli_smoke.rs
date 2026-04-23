use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

fn temp_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("deadcore-{name}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&path).expect("temp dir should be created");
    path
}

fn fixture_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test")
        .join("fixtures")
        .join("integration")
        .join(name)
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("destination dir should be created");
    for entry in fs::read_dir(src).expect("source dir should be readable") {
        let entry = entry.expect("dir entry should load");
        let source = entry.path();
        let target = dst.join(entry.file_name());
        if source.is_dir() {
            copy_dir_all(&source, &target);
        } else {
            fs::copy(&source, &target).expect("file should be copied");
        }
    }
}

fn write_project_manifest(project_dir: &Path, manifest_path: &Path) {
    let manifest = json!({
        "project": {
            "root": project_dir,
            "composer": "composer.json"
        },
        "scan": {
            "targets": ["app", "routes"],
            "globs": ["**/*.php"]
        },
        "limits": {
            "max_workers": 4,
            "max_files": 1000,
            "max_depth": 6
        },
        "cache": {
            "enabled": true,
            "kind": "mtime"
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
    });
    fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest JSON should encode"),
    )
    .expect("manifest should be written");
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root).expect("dir should be readable") {
        let entry = entry.expect("dir entry should load");
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_files(&path));
        } else {
            files.push(path);
        }
    }
    files
}

fn strip_report_volatile(payload: &mut Value) {
    if let Some(meta) = payload.get_mut("meta").and_then(Value::as_object_mut) {
        meta.remove("duration_ms");
        meta.remove("cache_hits");
        meta.remove("cache_misses");
    }
}

fn parse_cache_counts(stderr: &str) -> (u64, u64) {
    let cache_line = stderr
        .lines()
        .find(|line| line.contains("cache="))
        .expect("stderr should contain cache stats");
    let cache_suffix = cache_line
        .split("cache=")
        .nth(1)
        .expect("cache line should include cache stats");
    let hits = cache_suffix
        .split(" hit(s)")
        .next()
        .expect("cache line should include hits")
        .parse()
        .expect("hits should parse");
    let misses = cache_suffix
        .split(", ")
        .nth(1)
        .expect("cache line should include misses")
        .split(" miss(es)")
        .next()
        .expect("cache line should include miss suffix")
        .parse()
        .expect("misses should parse");
    (hits, misses)
}

#[test]
fn manifest_mode_emits_deadcode_report_and_hash() {
    let output = Command::new(env!("CARGO_BIN_EXE_deadcore"))
        .args([
            "--manifest",
            "fixtures/minimal.manifest.json",
            "--log-level",
            "error",
            "--print-hash",
        ])
        .output()
        .expect("binary should execute");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("manifest output should be JSON");
    let meta = payload["meta"].as_object().expect("deadcode report should have meta");
    assert!(meta["duration_ms"].is_number());
    assert!(meta["cache_hits"].is_number());
    assert!(meta["cache_misses"].is_number());
    assert!(payload["entrypoints"].as_array().is_some_and(|items| items.is_empty()));
    assert!(payload["symbols"].as_array().is_some_and(|items| items.is_empty()));
    assert!(payload["findings"].as_array().is_some_and(|items| items.is_empty()));
    assert_eq!(payload["removalPlan"]["changeSets"], json!([]));

    let stderr = String::from_utf8_lossy(&output.stderr);
    let hash = stderr
        .lines()
        .find_map(|line| line.strip_prefix("canonical_sha256="))
        .expect("print-hash should emit canonical_sha256");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn cache_dir_override_writes_pipeline_cache() {
    let temp = temp_dir("cache");
    let project_dir = temp.join("project");
    copy_dir_all(&fixture_root("minimal-laravel"), &project_dir);

    let cache_dir = temp.join("cache");
    let manifest_path = temp.join("manifest.json");
    write_project_manifest(&project_dir, &manifest_path);

    let first = Command::new(env!("CARGO_BIN_EXE_deadcore"))
        .args([
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf-8"),
            "--cache-dir",
            cache_dir.to_str().expect("cache dir should be utf-8"),
            "--log-level",
            "info",
        ])
        .output()
        .expect("first run should execute");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let mut first_json: Value =
        serde_json::from_slice(&first.stdout).expect("first output should be valid JSON");
    assert!(first_json["entrypoints"].as_array().is_some_and(|items| items.is_empty()));
    assert!(first_json["symbols"].as_array().is_some_and(|items| items.is_empty()));
    assert!(first_json["findings"].as_array().is_some_and(|items| items.is_empty()));
    assert_eq!(first_json["removalPlan"]["changeSets"], json!([]));

    let cache_files = collect_files(&cache_dir);
    assert_eq!(cache_files.len(), 5, "expected one cache entry per scanned file");

    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert_eq!(parse_cache_counts(&first_stderr), (0, 5), "{first_stderr}");
    assert_eq!(first_json["meta"]["cache_hits"], 0);
    assert_eq!(first_json["meta"]["cache_misses"], 5);

    let second = Command::new(env!("CARGO_BIN_EXE_deadcore"))
        .args([
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf-8"),
            "--cache-dir",
            cache_dir.to_str().expect("cache dir should be utf-8"),
            "--log-level",
            "info",
        ])
        .output()
        .expect("second run should execute");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let mut second_json: Value =
        serde_json::from_slice(&second.stdout).expect("second output should be valid JSON");
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert_eq!(parse_cache_counts(&second_stderr), (5, 0), "{second_stderr}");
    assert_eq!(second_json["meta"]["cache_hits"], 5);
    assert_eq!(second_json["meta"]["cache_misses"], 0);

    strip_report_volatile(&mut first_json);
    strip_report_volatile(&mut second_json);
    assert_eq!(first_json, second_json);
}
