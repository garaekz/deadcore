use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use deadcore::DEADCORE_VERSION;
use deadcore::contracts::{build_deadcode_response, load_analysis_request_from_slice};
use deadcore::manifest::Manifest;
use deadcore::output::build_report;
use deadcore::pipeline::{PipelineResult, analyze_project};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "deadcore")]
#[command(version = DEADCORE_VERSION)]
#[command(about = "Rust analysis core for Laravel dead code detection")]
struct Args {
    #[arg(long, conflicts_with = "request")]
    manifest: Option<PathBuf>,

    #[arg(long, conflicts_with = "manifest")]
    request: Option<PathBuf>,

    #[arg(long, default_value = "-")]
    out: String,

    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,

    #[arg(long = "log-level", value_enum, default_value_t = LogLevel::Warn)]
    log_level: LogLevel,

    #[arg(long)]
    no_color: bool,

    #[arg(long)]
    quiet: bool,

    #[arg(long = "print-hash")]
    print_hash: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Debug, serde::Serialize)]
struct CliErrorPayload {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "exit_code")]
    exit_code: u8,
}

#[derive(Debug)]
struct CliError {
    payload: CliErrorPayload,
}

impl CliError {
    fn validation(message: impl Into<String>) -> Self {
        Self {
            payload: CliErrorPayload {
                error_type: "validation".to_string(),
                message: message.into(),
                details: None,
                exit_code: 1,
            },
        }
    }

    fn validation_with_cause(message: impl Into<String>, cause: impl Into<String>) -> Self {
        let mut details = std::collections::BTreeMap::new();
        details.insert("underlying_error".to_string(), cause.into());
        Self {
            payload: CliErrorPayload {
                error_type: "validation".to_string(),
                message: message.into(),
                details: Some(details),
                exit_code: 1,
            },
        }
    }

    fn internal(message: impl Into<String>, cause: impl Into<String>) -> Self {
        let mut details = std::collections::BTreeMap::new();
        details.insert("underlying_error".to_string(), cause.into());
        Self {
            payload: CliErrorPayload {
                error_type: "internal".to_string(),
                message: message.into(),
                details: Some(details),
                exit_code: 2,
            },
        }
    }

    fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.payload.exit_code)
    }
}

fn main() -> ExitCode {
    match try_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!(
                "{}",
                serde_json::to_string(&err.payload).unwrap_or_else(|_| {
                    format!(
                        "{{\"type\":\"internal\",\"message\":\"{}\",\"exit_code\":2}}",
                        err.payload.message.replace('"', "'")
                    )
                })
            );
            err.exit_code()
        }
    }
}

fn try_main() -> Result<(), CliError> {
    let mut args = Args::parse();
    if args.manifest.is_none() && args.request.is_none() && !io::stdin().is_terminal() {
        args.manifest = Some(PathBuf::from("-"));
    }
    if args.quiet {
        args.log_level = LogLevel::Error;
    }

    if let Some(request_path) = &args.request {
        return execute_request_mode(request_path, &args);
    }

    let manifest_path = args.manifest.as_ref().ok_or_else(|| {
        CliError::validation("no manifest provided: set --manifest <path> or --manifest -")
    })?;
    execute_manifest_mode(manifest_path, &args)
}

fn execute_manifest_mode(manifest_path: &Path, args: &Args) -> Result<(), CliError> {
    let input = read_input_file(manifest_path, "manifest")?;
    let mut manifest: Manifest = serde_json::from_slice(&input.bytes).map_err(|err| {
        CliError::validation_with_cause("failed to decode manifest JSON", err.to_string())
    })?;
    if let Some(source_path) = input.source_path.as_deref() {
        manifest.resolve_paths(source_path);
    }
    validate_manifest(&manifest)?;
    apply_cache_dir_override(args.cache_dir.as_deref());
    warn_if_ignoring_stdin(args);

    let result = analyze_project(&manifest)
        .map_err(|err| CliError::internal("failed to run rust pipeline", err.to_string()))?;
    log_pipeline_summary(args, &manifest, &result);
    let report = build_report(result);
    let payload = serde_json::to_string_pretty(&report)
        .map_err(|err| CliError::internal("failed to encode report JSON", err.to_string()))?;
    if args.print_hash {
        eprintln!("canonical_sha256={}", sha256_hex(payload.as_bytes()));
    }
    emit_output(&args.out, &payload)
}

fn execute_request_mode(request_path: &Path, args: &Args) -> Result<(), CliError> {
    let input = read_input_file(request_path, "analysis request")?;
    let request = load_analysis_request_from_slice(&input.bytes, input.source_path.as_deref())
        .map_err(|err| {
            CliError::validation_with_cause("analysis request validation failed", err.to_string())
        })?;
    validate_manifest(&request.manifest)?;
    apply_cache_dir_override(args.cache_dir.as_deref());
    warn_if_ignoring_stdin(args);

    let result = analyze_project(&request.manifest)
        .map_err(|err| CliError::internal("failed to run rust pipeline", err.to_string()))?;
    log_pipeline_summary(args, &request.manifest, &result);
    let response = build_deadcode_response(&request, &result);
    let payload = serde_json::to_string(&response)
        .map_err(|err| CliError::internal("failed to encode deadcode response", err.to_string()))?;
    if args.print_hash {
        eprintln!("canonical_sha256={}", sha256_hex(payload.as_bytes()));
    }
    emit_output(&args.out, &payload)
}

struct InputFile {
    bytes: Vec<u8>,
    source_path: Option<PathBuf>,
}

fn read_input_file(path: &Path, kind: &str) -> Result<InputFile, CliError> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes).map_err(|err| {
            CliError::validation_with_cause(format!("failed to read {kind} data"), err.to_string())
        })?;
        return Ok(InputFile {
            bytes,
            source_path: None,
        });
    }

    let bytes = fs::read(path).map_err(|err| {
        CliError::validation_with_cause(
            format!("failed to open {kind} file \"{}\"", path.display()),
            err.to_string(),
        )
    })?;
    Ok(InputFile {
        bytes,
        source_path: Some(path.to_path_buf()),
    })
}

fn validate_manifest(manifest: &Manifest) -> Result<(), CliError> {
    let root = manifest.project.root.as_path();
    if root.as_os_str().is_empty() {
        return Err(CliError::validation("project.root cannot be empty"));
    }
    if !root.exists() {
        return Err(CliError::validation(format!(
            "project root path does not exist: \"{}\"",
            root.display()
        )));
    }
    if !root.is_dir() {
        return Err(CliError::validation(format!(
            "project root must be a directory, got file: \"{}\"",
            root.display()
        )));
    }
    Ok(())
}

fn emit_output(out: &str, payload: &str) -> Result<(), CliError> {
    if out == "-" {
        println!("{payload}");
        return Ok(());
    }

    let out_path = Path::new(out);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            CliError::internal("failed to create output directory", err.to_string())
        })?;
    }
    fs::write(out_path, payload)
        .map_err(|err| CliError::internal(format!("failed to write output {out}"), err.to_string()))
}

fn apply_cache_dir_override(cache_dir: Option<&Path>) {
    if let Some(cache_dir) = cache_dir {
        // This CLI mutates the process environment before worker threads are spawned.
        unsafe {
            std::env::set_var("DEADCORE_CACHE_DIR", cache_dir);
        }
    }
}

fn warn_if_ignoring_stdin(args: &Args) {
    if io::stdin().is_terminal() || !should_log(args.log_level, LogLevel::Warn) {
        return;
    }

    match (&args.manifest, &args.request) {
        (_, Some(path)) if path != Path::new("-") => {
            print_warning(
                args,
                "stdin input detected but --request is set; ignoring stdin",
            );
        }
        (Some(path), None) if path != Path::new("-") => {
            print_warning(
                args,
                "stdin input detected but --manifest is set; ignoring stdin",
            );
        }
        _ => {}
    }
}

fn print_warning(args: &Args, message: &str) {
    log_message(args, LogLevel::Warn, message);
}

fn log_pipeline_summary(args: &Args, manifest: &Manifest, result: &PipelineResult) {
    if should_log(args.log_level, LogLevel::Info) {
        let cache_summary = if manifest.cache.enabled {
            format!(
                "cache={} hit(s), {} miss(es)",
                result.cache_hits, result.cache_misses
            )
        } else {
            "cache=disabled".to_string()
        };
        log_message(
            args,
            LogLevel::Info,
            &format!(
                "analysis completed: files={} partial={} {cache_summary} durationMs={}",
                result.files.len(),
                result.partial,
                result.duration_ms
            ),
        );
    }

    if should_log(args.log_level, LogLevel::Debug) && manifest.cache.enabled {
        let cache_dir = args.cache_dir.clone().unwrap_or_else(|| {
            std::env::var("DEADCORE_CACHE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    manifest
                        .project
                        .root
                        .join(".deadcore")
                        .join("cache")
                        .join("v3")
                })
        });
        log_message(
            args,
            LogLevel::Debug,
            &format!(
                "cache configured: kind={} dir={}",
                manifest.cache.kind.as_deref().unwrap_or("sha256+mtime"),
                cache_dir.display()
            ),
        );
    }
}

fn should_log(current: LogLevel, required: LogLevel) -> bool {
    level_rank(current) >= level_rank(required)
}

fn level_rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
        LogLevel::Debug => 3,
    }
}

fn log_message(args: &Args, level: LogLevel, message: &str) {
    let label = match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warning",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
    };

    if args.no_color || !io::stderr().is_terminal() {
        eprintln!("{label}: {message}");
        return;
    }

    let color = match level {
        LogLevel::Error => "31",
        LogLevel::Warn => "33",
        LogLevel::Info => "36",
        LogLevel::Debug => "90",
    };
    eprintln!("\u{1b}[{color}m{label}:\u{1b}[0m {message}");
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
