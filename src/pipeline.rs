use std::collections::BTreeSet;
use std::collections::{BTreeMap, BTreeSet as OrderedSet};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::cache::{CacheStats, PipelineCache};
use crate::discovery::discover_php_files;
use crate::manifest::Manifest;
use crate::matchers::analyze_file;
use crate::model::{AnalyzedFile, Delta};
use crate::output::build_delta;
use crate::parser::parse_file;
use crate::routes::{RouteBinding, extract_route_bindings};
use crate::source_index::{SourceClass, parse_source_class};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PipelineResult {
    pub files: Vec<AnalyzedFile>,
    pub route_bindings: Vec<RouteBinding>,
    pub partial: bool,
    pub duration_ms: u128,
    #[serde(default)]
    pub cache_hits: usize,
    #[serde(default)]
    pub cache_misses: usize,
}

impl PipelineResult {
    pub fn controller_methods(
        &self,
    ) -> impl Iterator<Item = (&AnalyzedFile, &crate::model::ControllerMethod)> {
        self.files.iter().flat_map(|file| {
            file.facts
                .controllers
                .iter()
                .map(move |controller| (file, controller))
        })
    }
}

pub fn run_pipeline(manifest: &Manifest) -> Result<Delta> {
    Ok(build_delta(analyze_project(manifest)?))
}

pub fn analyze_project(manifest: &Manifest) -> Result<PipelineResult> {
    let started = Instant::now();
    let discovered = discover_php_files(manifest)?;
    let cache = PipelineCache::for_manifest(manifest)?;
    let dependency_index = build_dependency_index(&manifest.project.root, &discovered.files)?;
    let worker_count = manifest
        .limits
        .max_workers
        .filter(|value| *value > 0)
        .unwrap_or_else(default_worker_count);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()
        .context("failed to build rayon worker pool")?;

    let root = manifest.project.root.clone();
    let (files, cache_stats) = pool.install(|| {
        analyze_files(
            &root,
            &discovered.files,
            manifest,
            &cache,
            &dependency_index,
        )
    })?;
    let route_bindings = collect_route_bindings(&files);
    let result = PipelineResult {
        files,
        route_bindings,
        partial: discovered.partial,
        duration_ms: started.elapsed().as_millis(),
        cache_hits: cache_stats.hits,
        cache_misses: cache_stats.misses,
    };
    Ok(result)
}

fn analyze_files(
    root: &PathBuf,
    discovered: &[PathBuf],
    manifest: &Manifest,
    cache: &PipelineCache,
    dependency_index: &DependencyIndex,
) -> Result<(Vec<AnalyzedFile>, CacheStats)> {
    let mut results = discovered
        .par_iter()
        .map(|path| analyze_single_file(root, path, manifest, cache, dependency_index))
        .collect::<Result<Vec<_>>>()?;

    let mut files = Vec::with_capacity(results.len());
    let mut cache_stats = CacheStats::default();
    for result in results.drain(..) {
        if result.hit {
            cache_stats.hits += 1;
        } else {
            cache_stats.misses += 1;
        }
        files.push(result.file);
    }

    filter_controller_scopes(&mut files);
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok((files, cache_stats))
}

struct CachedAnalysis {
    file: AnalyzedFile,
    hit: bool,
}

#[derive(Debug, Clone)]
struct DependencyIndex {
    files: BTreeMap<String, FileDependencySummary>,
    classes: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Clone, Default)]
struct FileDependencySummary {
    class: Option<SourceClass>,
    route_controllers: Vec<String>,
}

fn analyze_single_file(
    root: &PathBuf,
    path: &PathBuf,
    manifest: &Manifest,
    cache: &PipelineCache,
    dependency_index: &DependencyIndex,
) -> Result<CachedAnalysis> {
    if let Some(file) = cache.load_file(root, path)? {
        return Ok(CachedAnalysis { file, hit: true });
    }

    let relative_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    let parsed = parse_file(path)?;
    let source_text = String::from_utf8_lossy(&parsed.source).into_owned();
    let facts = analyze_file(&parsed, &relative_path, &manifest.features)
        .with_context(|| format!("failed to analyze {}", path.display()))?;

    let analyzed_file = AnalyzedFile {
        path: path.clone(),
        relative_path,
        source_text,
        facts,
    };
    let dependency_paths = dependency_paths_for_file(&analyzed_file, dependency_index);
    cache.store_file(root, path, &analyzed_file, &dependency_paths)?;
    Ok(CachedAnalysis {
        file: analyzed_file,
        hit: false,
    })
}

fn default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .max(4)
}

fn collect_route_bindings(files: &[AnalyzedFile]) -> Vec<RouteBinding> {
    let mut route_bindings = Vec::new();

    for file in files {
        if !file.relative_path.starts_with("routes/") {
            continue;
        }

        route_bindings.extend(extract_route_bindings(&file.source_text));
    }

    let mut deduped = Vec::with_capacity(route_bindings.len());
    for binding in route_bindings {
        if deduped.iter().any(|existing: &RouteBinding| {
            existing.controller_fqcn == binding.controller_fqcn
                && existing.method_name == binding.method_name
                && existing.http_methods == binding.http_methods
        }) {
            continue;
        }
        deduped.push(binding);
    }

    deduped
}

fn build_dependency_index(root: &PathBuf, discovered: &[PathBuf]) -> Result<DependencyIndex> {
    let mut files = BTreeMap::new();
    let mut classes = BTreeMap::new();

    for path in discovered {
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let source_text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let class = parse_source_class(&source_text, &relative_path);
        if let Some(class_info) = &class {
            classes.insert(class_info.fqcn.clone(), path.clone());
        }
        let route_controllers = if relative_path.starts_with("routes/") {
            extract_route_bindings(&source_text)
                .into_iter()
                .map(|binding| binding.controller_fqcn)
                .collect()
        } else {
            Vec::new()
        };
        files.insert(
            relative_path.clone(),
            FileDependencySummary {
                class,
                route_controllers,
            },
        );
    }

    Ok(DependencyIndex { files, classes })
}

fn dependency_paths_for_file(
    file: &AnalyzedFile,
    dependency_index: &DependencyIndex,
) -> Vec<PathBuf> {
    let mut dependencies = OrderedSet::new();

    if let Some(summary) = dependency_index.files.get(&file.relative_path) {
        if let Some(class) = &summary.class {
            for import in class.imports.values() {
                if let Some(path) = dependency_index.classes.get(import) {
                    dependencies.insert(path.clone());
                }
            }
            if let Some(extends) = &class.extends {
                if let Some(path) = dependency_index.classes.get(extends) {
                    dependencies.insert(path.clone());
                }
            }
        }
        for controller in &summary.route_controllers {
            if let Some(path) = dependency_index.classes.get(controller) {
                dependencies.insert(path.clone());
            }
        }
    }

    for controller in &file.facts.controllers {
        for usage in &controller.resource_usage {
            if let Some(path) = dependency_index.classes.get(&usage.class_name) {
                dependencies.insert(path.clone());
            }
        }
        for usage in &controller.request_usage {
            if let Some(class_name) = &usage.class_name {
                if let Some(path) = dependency_index.classes.get(class_name) {
                    dependencies.insert(path.clone());
                }
            }
        }
    }

    for model in &file.facts.models {
        for relationship in &model.relationships {
            if let Some(related) = &relationship.related {
                if let Some(path) = dependency_index.classes.get(related) {
                    dependencies.insert(path.clone());
                }
            }
        }
    }

    dependencies.remove(&file.path);
    dependencies.into_iter().collect()
}

fn filter_controller_scopes(files: &mut [AnalyzedFile]) {
    let known_scopes = files
        .iter()
        .flat_map(|file| file.facts.models.iter())
        .flat_map(|model| model.scopes.iter().cloned())
        .collect::<BTreeSet<_>>();

    if known_scopes.is_empty() {
        for file in files {
            for controller in &mut file.facts.controllers {
                controller.scopes_used.clear();
            }
        }
        return;
    }

    for file in files {
        for controller in &mut file.facts.controllers {
            controller
                .scopes_used
                .retain(|scope| known_scopes.contains(&scope.name));
        }
    }
}
