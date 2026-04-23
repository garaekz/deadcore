use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::manifest::{FeatureFlags, Manifest};
use crate::model::AnalyzedFile;

const CACHE_SCHEMA_VERSION: &str = "v3";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
}

#[derive(Debug, Clone)]
pub struct PipelineCache {
    dir: Option<PathBuf>,
    kind: CacheKind,
    feature_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheKind {
    Mtime,
    Sha256AndMtime,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FileCacheEntry {
    schema_version: String,
    kind: String,
    feature_signature: String,
    file: CachedFileState,
    dependencies: Vec<CachedFileState>,
    analyzed_file: AnalyzedFile,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CachedFileState {
    relative_path: String,
    modified_ms: u128,
    size_bytes: u64,
    sha256: Option<String>,
}

impl PipelineCache {
    pub fn for_manifest(manifest: &Manifest) -> Result<Self> {
        if !manifest.cache.enabled {
            return Ok(Self {
                dir: None,
                kind: CacheKind::Sha256AndMtime,
                feature_signature: feature_signature(&manifest.features)?,
            });
        }

        let kind = CacheKind::from_manifest(manifest.cache.kind.as_deref());
        let cache_dir = resolve_cache_dir(&manifest.project.root);
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("failed to create cache directory {}", cache_dir.display()))?;

        Ok(Self {
            dir: Some(cache_dir),
            kind,
            feature_signature: feature_signature(&manifest.features)?,
        })
    }

    pub fn enabled(&self) -> bool {
        self.dir.is_some()
    }

    pub fn kind_name(&self) -> &'static str {
        self.kind.as_str()
    }

    pub fn directory(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    pub fn load_file(&self, root: &Path, path: &Path) -> Result<Option<AnalyzedFile>> {
        let Some(cache_path) = self.cache_path(root, path) else {
            return Ok(None);
        };
        if !cache_path.exists() {
            return Ok(None);
        }

        let bytes = match fs::read(&cache_path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(None),
        };
        let entry: FileCacheEntry = match serde_json::from_slice(&bytes) {
            Ok(entry) => entry,
            Err(_) => {
                let _ = fs::remove_file(&cache_path);
                return Ok(None);
            }
        };
        if entry.schema_version != CACHE_SCHEMA_VERSION
            || entry.kind != self.kind.as_str()
            || entry.feature_signature != self.feature_signature
        {
            let _ = fs::remove_file(&cache_path);
            return Ok(None);
        }

        let current_state = snapshot_file(root, path, self.kind)?;
        if entry.file != current_state {
            return Ok(None);
        }
        let current_dependencies = snapshot_paths(
            root,
            &cached_dependency_paths(root, &entry.dependencies),
            self.kind,
        )?;
        if entry.dependencies != current_dependencies {
            return Ok(None);
        }

        Ok(Some(entry.analyzed_file))
    }

    pub fn store_file(
        &self,
        root: &Path,
        path: &Path,
        analyzed_file: &AnalyzedFile,
        dependency_paths: &[PathBuf],
    ) -> Result<()> {
        let Some(cache_path) = self.cache_path(root, path) else {
            return Ok(());
        };

        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create cache parent directory {}",
                    parent.display()
                )
            })?;
        }

        let entry = FileCacheEntry {
            schema_version: CACHE_SCHEMA_VERSION.to_string(),
            kind: self.kind.as_str().to_string(),
            feature_signature: self.feature_signature.clone(),
            file: snapshot_file(root, path, self.kind)?,
            dependencies: snapshot_paths(root, dependency_paths, self.kind)?,
            analyzed_file: analyzed_file.clone(),
        };
        let payload =
            serde_json::to_vec(&entry).context("failed to encode per-file analysis cache")?;
        let file_name = cache_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("analysis-cache.json");
        let temp_path = cache_path.with_file_name(format!(".{file_name}.tmp"));
        fs::write(&temp_path, payload)
            .with_context(|| format!("failed to write cache temp file {}", temp_path.display()))?;
        fs::rename(&temp_path, &cache_path).with_context(|| {
            format!(
                "failed to atomically replace cache file {}",
                cache_path.display()
            )
        })?;
        Ok(())
    }

    fn cache_path(&self, root: &Path, path: &Path) -> Option<PathBuf> {
        let dir = self.dir.as_ref()?;
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let cache_key =
            sha256_hex(format!("{}:{relative_path}", self.feature_signature).as_bytes());
        Some(dir.join(&cache_key[..2]).join(format!("{cache_key}.json")))
    }
}

impl CacheKind {
    fn from_manifest(value: Option<&str>) -> Self {
        match value
            .unwrap_or("sha256+mtime")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "mtime" => Self::Mtime,
            _ => Self::Sha256AndMtime,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Mtime => "mtime",
            Self::Sha256AndMtime => "sha256+mtime",
        }
    }
}

fn resolve_cache_dir(project_root: &Path) -> PathBuf {
    if let Ok(override_dir) = std::env::var("DEADCORE_CACHE_DIR") {
        let trimmed = override_dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    project_root
        .join(".deadcore")
        .join("cache")
        .join(CACHE_SCHEMA_VERSION)
}

fn snapshot_file(root: &Path, path: &Path, kind: CacheKind) -> Result<CachedFileState> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    let modified = metadata
        .modified()
        .with_context(|| format!("failed to read modified time for {}", path.display()))?;
    let modified_ms = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let relative_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let sha256 = match kind {
        CacheKind::Mtime => None,
        CacheKind::Sha256AndMtime => {
            let bytes =
                fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
            Some(sha256_hex(&bytes))
        }
    };

    Ok(CachedFileState {
        relative_path,
        modified_ms,
        size_bytes: metadata.len(),
        sha256,
    })
}

fn snapshot_paths(root: &Path, paths: &[PathBuf], kind: CacheKind) -> Result<Vec<CachedFileState>> {
    let mut snapshots = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.exists() {
            continue;
        }
        snapshots.push(snapshot_file(root, path, kind)?);
    }
    snapshots.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(snapshots)
}

fn cached_dependency_paths(root: &Path, snapshots: &[CachedFileState]) -> Vec<PathBuf> {
    snapshots
        .iter()
        .map(|snapshot| {
            root.join(
                snapshot
                    .relative_path
                    .replace('/', std::path::MAIN_SEPARATOR_STR),
            )
        })
        .collect()
}

fn feature_signature(features: &FeatureFlags) -> Result<String> {
    let bytes =
        serde_json::to_vec(features).context("failed to encode feature flags for cache key")?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
