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
    let path = std::env::temp_dir().join(format!("oxinfer-{name}-{}-{unique}", std::process::id()));
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

#[test]
fn manifest_mode_stamp_and_hash_are_emitted() {
    let output = Command::new(env!("CARGO_BIN_EXE_oxinfer"))
        .args([
            "--manifest",
            "fixtures/minimal.manifest.json",
            "--log-level",
            "error",
            "--stamp",
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
    let generated_at = payload["meta"]["generatedAt"]
        .as_str()
        .expect("stamp should add meta.generatedAt");
    assert!(generated_at.ends_with('Z'));

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
    let cache_dir = temp.join("cache");
    let manifest_path = temp.join("manifest.json");
    let fixture_root = fixture_root("minimal-laravel");
    let manifest = json!({
        "project": {
            "root": fixture_root,
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
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest JSON should encode"),
    )
    .expect("manifest should be written");

    let first = Command::new(env!("CARGO_BIN_EXE_oxinfer"))
        .args([
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf-8"),
            "--cache-dir",
            cache_dir.to_str().expect("cache dir should be utf-8"),
        ])
        .output()
        .expect("first run should execute");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let cache_files = collect_files(&cache_dir);
    assert_eq!(
        cache_files.len(),
        5,
        "expected one cache entry per scanned file"
    );

    let second = Command::new(env!("CARGO_BIN_EXE_oxinfer"))
        .args([
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf-8"),
            "--cache-dir",
            cache_dir.to_str().expect("cache dir should be utf-8"),
        ])
        .output()
        .expect("second run should execute");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let first_json: Value =
        serde_json::from_slice(&first.stdout).expect("first output should be valid JSON");
    let second_json: Value =
        serde_json::from_slice(&second.stdout).expect("second output should be valid JSON");
    assert_eq!(first_json["controllers"], second_json["controllers"]);
    assert_eq!(first_json["models"], second_json["models"]);
    assert_eq!(
        first_json["meta"]["partial"],
        second_json["meta"]["partial"]
    );
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

struct CliRun {
    payload: Value,
    stderr: String,
}

fn write_cache_enabled_manifest(temp: &Path, fixture_manifest: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture_manifest);
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&source).expect("fixture manifest should be readable"))
            .expect("fixture manifest should decode");

    let project_root = source
        .parent()
        .expect("fixture manifest should have a parent")
        .join(
            manifest["project"]["root"]
                .as_str()
                .expect("fixture manifest should define project.root"),
        );
    manifest["project"]["root"] = Value::String(project_root.to_string_lossy().into_owned());
    manifest["cache"] = json!({
        "enabled": true,
        "kind": "mtime"
    });

    let target = temp.join(
        source
            .file_name()
            .expect("fixture manifest should have a file name"),
    );
    fs::write(
        &target,
        serde_json::to_vec_pretty(&manifest).expect("cache-enabled manifest should encode"),
    )
    .expect("cache-enabled manifest should be written");
    target
}

fn run_manifest_with_cache(manifest_path: &Path, cache_dir: &Path) -> CliRun {
    let output = Command::new(env!("CARGO_BIN_EXE_oxinfer"))
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
        .expect("binary should execute");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    CliRun {
        payload: serde_json::from_slice(&output.stdout).expect("output should be valid JSON"),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
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

fn strip_duration(payload: &mut Value) {
    if let Some(meta) = payload.get_mut("meta").and_then(Value::as_object_mut) {
        if let Some(stats) = meta.get_mut("stats").and_then(Value::as_object_mut) {
            stats.remove("durationMs");
        }
    }
}

fn run_cached_manifest(manifest_path: &Path, cache_dir: &Path) -> (Value, String, u64, u64) {
    let output = Command::new(env!("CARGO_BIN_EXE_oxinfer"))
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
        .expect("run should execute");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let (hits, misses) = parse_cache_counts(&stderr);
    (payload, stderr, hits, misses)
}

fn controller_method<'a>(payload: &'a Value, fqcn: &str, method_name: &str) -> &'a Value {
    payload["controllers"]
        .as_array()
        .expect("manifest output should include controllers")
        .iter()
        .find(|controller| controller["class"] == fqcn)
        .and_then(|controller| {
            controller["methods"]
                .as_array()
                .expect("controller should expose methods")
                .iter()
                .find(|method| method["name"] == method_name)
        })
        .expect("controller method should exist")
}

#[test]
fn cache_reuses_unchanged_files_surgically() {
    let temp = temp_dir("surgical-cache");
    let project_dir = temp.join("project");
    copy_dir_all(&fixture_root("minimal-laravel"), &project_dir);

    let cache_dir = temp.join("cache");
    let manifest_path = temp.join("manifest.json");
    write_project_manifest(&project_dir, &manifest_path);

    let first = Command::new(env!("CARGO_BIN_EXE_oxinfer"))
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
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    let files_parsed = first_json["meta"]["stats"]["filesParsed"]
        .as_u64()
        .expect("manifest output should report filesParsed");
    assert!(
        first_stderr.contains(&format!("cache=0 hit(s), {files_parsed} miss(es)")),
        "{first_stderr}"
    );

    let user_model = project_dir.join("app").join("Models").join("User.php");
    let mut contents = fs::read_to_string(&user_model).expect("fixture file should be readable");
    contents.push_str("\n// cache-bump\n");
    fs::write(&user_model, contents).expect("fixture file should be updated");

    let second = Command::new(env!("CARGO_BIN_EXE_oxinfer"))
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
    let (hits, misses) = parse_cache_counts(&second_stderr);
    assert_eq!(hits + misses, files_parsed, "{second_stderr}");
    assert!(hits > 0, "{second_stderr}");
    assert!(misses > 0, "{second_stderr}");

    strip_duration(&mut first_json);
    strip_duration(&mut second_json);
    assert_eq!(
        first_json, second_json,
        "changing a fixture comment should not change the manifest payload"
    );
}

#[test]
fn model_changes_invalidate_dependent_controller_analysis() {
    let temp = temp_dir("model-invalidation");
    let project_dir = temp.join("project");
    copy_dir_all(&fixture_root("api-project"), &project_dir);

    let cache_dir = temp.join("cache");
    let manifest_path = temp.join("manifest.json");
    write_project_manifest(&project_dir, &manifest_path);

    let (cold_payload, cold_stderr, cold_hits, cold_misses) =
        run_cached_manifest(&manifest_path, &cache_dir);
    assert_eq!(cold_hits, 0, "{cold_stderr}");
    assert!(cold_misses > 0, "{cold_stderr}");

    let featured_before = controller_method(
        &cold_payload,
        "App\\Http\\Controllers\\ProductController",
        "featured",
    );
    assert_eq!(
        featured_before["scopesUsed"][0]["name"],
        Value::String("featured".to_string())
    );

    let product_model = project_dir.join("app").join("Models").join("Product.php");
    let contents = fs::read_to_string(&product_model).expect("product model should be readable");
    let updated = contents.replace("scopeFeatured", "scopeSpotlight");
    fs::write(&product_model, updated).expect("product model should be updated");

    let (warm_payload, warm_stderr, hits, misses) = run_cached_manifest(&manifest_path, &cache_dir);
    assert!(hits > 0, "{warm_stderr}");
    assert!(misses > 1, "{warm_stderr}");

    let featured_after = controller_method(
        &warm_payload,
        "App\\Http\\Controllers\\ProductController",
        "featured",
    );
    assert!(
        featured_after["scopesUsed"]
            .as_array()
            .is_none_or(|scopes| scopes.is_empty()),
        "expected model scope rename to invalidate dependent controller output: {featured_after}"
    );
}

#[test]
fn request_changes_invalidate_dependent_controller_cache_entries() {
    let temp = temp_dir("request-invalidation");
    let project_dir = temp.join("project");
    copy_dir_all(&fixture_root("api-project"), &project_dir);

    let cache_dir = temp.join("cache");
    let manifest_path = temp.join("manifest.json");
    write_project_manifest(&project_dir, &manifest_path);

    let (mut cold_payload, cold_stderr, cold_hits, cold_misses) =
        run_cached_manifest(&manifest_path, &cache_dir);
    assert_eq!(cold_hits, 0, "{cold_stderr}");
    assert!(cold_misses > 0, "{cold_stderr}");

    let request_file = project_dir
        .join("app")
        .join("Http")
        .join("Requests")
        .join("StoreProductRequest.php");
    let mut contents = fs::read_to_string(&request_file).expect("request file should be readable");
    contents.push_str("\n// request-cache-bump\n");
    fs::write(&request_file, contents).expect("request file should be updated");

    let (mut warm_payload, warm_stderr, hits, misses) =
        run_cached_manifest(&manifest_path, &cache_dir);
    assert!(hits > 0, "{warm_stderr}");
    assert!(misses > 1, "{warm_stderr}");

    strip_duration(&mut cold_payload);
    strip_duration(&mut warm_payload);
    assert_eq!(
        cold_payload, warm_payload,
        "request-only comment changes should not alter the manifest payload"
    );
}

#[test]
fn resource_changes_invalidate_dependent_controller_cache_entries() {
    let temp = temp_dir("resource-invalidation");
    let project_dir = temp.join("project");
    copy_dir_all(&fixture_root("api-project"), &project_dir);

    let cache_dir = temp.join("cache");
    let manifest_path = temp.join("manifest.json");
    write_project_manifest(&project_dir, &manifest_path);

    let (mut cold_payload, cold_stderr, cold_hits, cold_misses) =
        run_cached_manifest(&manifest_path, &cache_dir);
    assert_eq!(cold_hits, 0, "{cold_stderr}");
    assert!(cold_misses > 0, "{cold_stderr}");

    let resource_file = project_dir
        .join("app")
        .join("Http")
        .join("Resources")
        .join("ProductResource.php");
    let mut contents =
        fs::read_to_string(&resource_file).expect("resource file should be readable");
    contents.push_str("\n// resource-cache-bump\n");
    fs::write(&resource_file, contents).expect("resource file should be updated");

    let (mut warm_payload, warm_stderr, hits, misses) =
        run_cached_manifest(&manifest_path, &cache_dir);
    assert!(hits > 0, "{warm_stderr}");
    assert!(misses > 1, "{warm_stderr}");

    strip_duration(&mut cold_payload);
    strip_duration(&mut warm_payload);
    assert_eq!(
        cold_payload, warm_payload,
        "resource-only comment changes should not alter the manifest payload"
    );
}

#[test]
fn fixture_manifests_reuse_full_cache_on_second_run() {
    let fixtures = [
        ("minimal", "fixtures/minimal.manifest.json"),
        ("api", "fixtures/api.manifest.json"),
        ("complex", "fixtures/complex.manifest.json"),
    ];

    for (name, fixture_manifest) in fixtures {
        let temp = temp_dir(&format!("{name}-warm-cache"));
        let cache_dir = temp.join("cache");
        let manifest_path = write_cache_enabled_manifest(&temp, fixture_manifest);

        let mut cold = run_manifest_with_cache(&manifest_path, &cache_dir);
        let files_parsed = cold.payload["meta"]["stats"]["filesParsed"]
            .as_u64()
            .expect("manifest output should report filesParsed");
        assert_eq!(
            parse_cache_counts(&cold.stderr),
            (0, files_parsed),
            "{name} cold run should populate the cache"
        );

        let mut warm = run_manifest_with_cache(&manifest_path, &cache_dir);
        assert_eq!(
            parse_cache_counts(&warm.stderr),
            (files_parsed, 0),
            "{name} warm run should reuse every parsed file"
        );

        strip_duration(&mut cold.payload);
        strip_duration(&mut warm.payload);
        assert_eq!(
            cold.payload, warm.payload,
            "{name} warm-cache output should match the cold run"
        );
    }
}
