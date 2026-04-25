use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub project: ProjectConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub features: FeatureFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub root: PathBuf,
    #[serde(default)]
    pub composer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_targets")]
    pub targets: Vec<String>,
    #[serde(default = "default_globs")]
    pub globs: Vec<String>,
    #[serde(default)]
    pub vendor_whitelist: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default)]
    pub max_workers: Option<usize>,
    #[serde(default)]
    pub max_files: Option<usize>,
    #[serde(default)]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    #[serde(default = "default_true")]
    pub http_status: bool,
    #[serde(default = "default_true")]
    pub request_usage: bool,
    #[serde(default = "default_true")]
    pub resource_usage: bool,
    #[serde(default = "default_true")]
    pub with_pivot: bool,
    #[serde(default = "default_true")]
    pub attribute_make: bool,
    #[serde(default = "default_true")]
    pub scopes_used: bool,
    #[serde(default = "default_true")]
    pub polymorphic: bool,
    #[serde(default = "default_true")]
    pub broadcast_channels: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: default_targets(),
            globs: default_globs(),
            vendor_whitelist: Vec::new(),
        }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            http_status: true,
            request_usage: true,
            resource_usage: true,
            with_pivot: true,
            attribute_make: true,
            scopes_used: true,
            polymorphic: true,
            broadcast_channels: true,
        }
    }
}

impl Manifest {
    pub fn resolve_paths(&mut self, manifest_path: &Path) {
        let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        self.project.root = resolve_path(base_dir, &self.project.root);
    }
}

fn default_targets() -> Vec<String> {
    vec!["app".to_string(), "routes".to_string()]
}

fn default_globs() -> Vec<String> {
    vec!["**/*.php".to_string()]
}

fn default_true() -> bool {
    true
}

fn resolve_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    let resolved = base_dir.join(path);
    if resolved.exists() {
        return absolutize(resolved);
    }

    if let Ok(cwd) = std::env::current_dir() {
        let cwd_relative = cwd.join(path);
        if cwd_relative.exists() {
            return cwd_relative;
        }
    }

    absolutize(resolved)
}

fn absolutize(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }

    std::env::current_dir()
        .map(|cwd| cwd.join(&path))
        .unwrap_or(path)
}
