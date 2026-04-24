use std::collections::{BTreeMap, BTreeSet, VecDeque};

use regex::Regex;

use crate::contracts::{AnalysisRequest, Entrypoint, RemovalChangeSet, RemovalPlan};
use crate::deadcode_model::{
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, FINDING_CATEGORY_UNUSED_COMMAND_CLASS,
    FINDING_CATEGORY_UNUSED_CONTROLLER_CLASS, FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD,
    FINDING_CATEGORY_UNUSED_FORM_REQUEST, FINDING_CATEGORY_UNUSED_JOB_CLASS,
    FINDING_CATEGORY_UNUSED_LISTENER_CLASS, FINDING_CATEGORY_UNUSED_MODEL_METHOD,
    FINDING_CATEGORY_UNUSED_MODEL_SCOPE, FINDING_CATEGORY_UNUSED_POLICY_CLASS,
    FINDING_CATEGORY_UNUSED_RESOURCE_CLASS, FINDING_CATEGORY_UNUSED_SUBSCRIBER_CLASS, Finding,
    SYMBOL_KIND_COMMAND_CLASS, SYMBOL_KIND_CONTROLLER_CLASS, SYMBOL_KIND_CONTROLLER_METHOD,
    SYMBOL_KIND_FORM_REQUEST_CLASS, SYMBOL_KIND_JOB_CLASS, SYMBOL_KIND_LISTENER_CLASS,
    SYMBOL_KIND_MODEL_METHOD, SYMBOL_KIND_MODEL_SCOPE, SYMBOL_KIND_POLICY_CLASS,
    SYMBOL_KIND_RESOURCE_CLASS, SYMBOL_KIND_SUBSCRIBER_CLASS, SymbolRecord,
};
use crate::model::{AnalyzedFile, ControllerMethod, ModelMethodFact};
use crate::parser::line_range_for_span;
use crate::pipeline::PipelineResult;
use crate::source_index::{SourceClass, SourceIndex, extract_balanced_region};

pub struct ControllerReachabilityReport {
    pub entrypoints: Vec<Entrypoint>,
    pub symbols: Vec<SymbolRecord>,
    pub findings: Vec<Finding>,
    pub removal_plan: RemovalPlan,
}

#[derive(Debug, Clone)]
struct ControllerClassReport {
    fqcn: String,
    relative_path: String,
    reachable_from_runtime: bool,
    line_range: Option<(usize, usize)>,
}

pub fn analyze_controller_reachability(
    request: &AnalysisRequest,
    result: &PipelineResult,
) -> ControllerReachabilityReport {
    let source_index = SourceIndex::build(result);
    let call_graph = build_controller_call_graph(result, &source_index);
    let mut reachable_actions = BTreeSet::new();
    let mut worklist = VecDeque::new();
    let mut entrypoints = Vec::new();

    for route in &request.runtime.routes {
        let Some(action_key) = route.action.action_key() else {
            continue;
        };
        if reachable_actions.insert(action_key.clone()) {
            worklist.push_back(action_key.clone());
            entrypoints.push(Entrypoint {
                kind: "runtime_route".to_string(),
                symbol: action_key,
                source: route.route_id.clone(),
            });
        }
    }

    for command in &request.runtime.commands {
        entrypoints.push(Entrypoint {
            kind: "runtime_command".to_string(),
            symbol: command.fqcn.clone(),
            source: command.signature.clone(),
        });
    }

    for listener in &request.runtime.listeners {
        entrypoints.push(Entrypoint {
            kind: "runtime_listener".to_string(),
            symbol: listener.listener_fqcn.clone(),
            source: listener.event_fqcn.clone(),
        });
    }

    for subscriber in &request.runtime.subscribers {
        entrypoints.push(Entrypoint {
            kind: "runtime_subscriber".to_string(),
            symbol: subscriber.fqcn.clone(),
            source: subscriber.fqcn.clone(),
        });
    }

    for job in &request.runtime.jobs {
        entrypoints.push(Entrypoint {
            kind: "runtime_job".to_string(),
            symbol: job.fqcn.clone(),
            source: job.fqcn.clone(),
        });
    }

    for policy in &request.runtime.policies {
        entrypoints.push(Entrypoint {
            kind: "runtime_policy".to_string(),
            symbol: policy.policy_fqcn.clone(),
            source: policy.model_fqcn.clone(),
        });
    }

    while let Some(symbol) = worklist.pop_front() {
        let Some(callees) = call_graph.get(&symbol) else {
            continue;
        };
        for callee in callees {
            if reachable_actions.insert(callee.clone()) {
                worklist.push_back(callee.clone());
            }
        }
    }

    let reachable_commands = request
        .runtime
        .commands
        .iter()
        .map(|command| command.fqcn.clone())
        .collect::<BTreeSet<_>>();
    let reachable_listeners = request
        .runtime
        .listeners
        .iter()
        .map(|listener| listener.listener_fqcn.clone())
        .collect::<BTreeSet<_>>();
    let reachable_policies = request
        .runtime
        .policies
        .iter()
        .map(|policy| policy.policy_fqcn.clone())
        .collect::<BTreeSet<_>>();
    let reachable_subscribers = request
        .runtime
        .subscribers
        .iter()
        .map(|subscriber| subscriber.fqcn.clone())
        .collect::<BTreeSet<_>>();
    let reachable_jobs = collect_reachable_jobs(
        result,
        &source_index,
        &reachable_actions,
        &request.runtime.jobs,
    );
    let reachable_form_requests =
        collect_reachable_form_requests(result, &source_index, &reachable_actions);
    let reachable_resources = collect_reachable_resources(result, &reachable_actions);
    let reachable_model_methods = collect_reachable_model_methods(
        result,
        &source_index,
        &reachable_actions,
        &reachable_commands,
        &reachable_listeners,
        &reachable_subscribers,
        &reachable_jobs,
        &reachable_policies,
    );
    let reachable_model_scopes = collect_reachable_model_scopes(result, &reachable_actions);
    let mut symbols = Vec::new();
    let mut findings = Vec::new();
    let mut change_sets = Vec::new();
    let mut fully_dead_controller_classes = BTreeSet::new();
    let mut controller_classes = BTreeMap::<String, ControllerClassReport>::new();

    for (file, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        let reachable_from_runtime = reachable_actions.contains(&symbol);
        let line_range = find_method_line_range(file, controller);
        let (start_line, end_line) = line_range
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_CONTROLLER_METHOD.to_string(),
            symbol: symbol.clone(),
            file: file.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        controller_classes
            .entry(controller.fqcn.clone())
            .and_modify(|report| report.reachable_from_runtime |= reachable_from_runtime)
            .or_insert_with(|| ControllerClassReport {
                fqcn: controller.fqcn.clone(),
                relative_path: file.relative_path.clone(),
                reachable_from_runtime,
                line_range: source_index
                    .get(&controller.fqcn)
                    .and_then(find_class_line_range),
            });

        if reachable_from_runtime {
            continue;
        }

        findings.push(Finding {
            symbol: symbol.clone(),
            category: FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD.to_string(),
            confidence: CONFIDENCE_HIGH.to_string(),
            file: file.relative_path.clone(),
            start_line,
            end_line,
        });

        if let (Some(start_line), Some(end_line)) = (start_line, end_line) {
            change_sets.push(RemovalChangeSet {
                file: file.relative_path.clone(),
                symbol,
                start_line,
                end_line,
            });
        }
    }

    for report in controller_classes.into_values() {
        let (start_line, end_line) = report
            .line_range
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_CONTROLLER_CLASS.to_string(),
            symbol: report.fqcn.clone(),
            file: report.relative_path.clone(),
            reachable_from_runtime: report.reachable_from_runtime,
            start_line,
            end_line,
        });

        if report.reachable_from_runtime {
            continue;
        }

        findings.push(Finding {
            symbol: report.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_CONTROLLER_CLASS.to_string(),
            confidence: CONFIDENCE_HIGH.to_string(),
            file: report.relative_path.clone(),
            start_line,
            end_line,
        });

        fully_dead_controller_classes.insert(report.fqcn.clone());

        if let (Some(start_line), Some(end_line)) = (start_line, end_line) {
            change_sets.push(RemovalChangeSet {
                file: report.relative_path,
                symbol: report.fqcn,
                start_line,
                end_line,
            });
        }
    }

    for file in &result.files {
        for model in &file.facts.models {
            for method in &model.methods {
                let symbol = format!("{}::{}", model.fqcn, method.name);
                let reachable_from_runtime = reachable_model_methods.contains(&symbol);
                let line_range = find_model_method_line_range(file, method);
                let (start_line, end_line) = line_range
                    .map(|(start, end)| (Some(start), Some(end)))
                    .unwrap_or((None, None));

                symbols.push(SymbolRecord {
                    kind: SYMBOL_KIND_MODEL_METHOD.to_string(),
                    symbol: symbol.clone(),
                    file: file.relative_path.clone(),
                    reachable_from_runtime,
                    start_line,
                    end_line,
                });

                if reachable_from_runtime {
                    continue;
                }

                findings.push(Finding {
                    symbol: symbol.clone(),
                    category: FINDING_CATEGORY_UNUSED_MODEL_METHOD.to_string(),
                    confidence: CONFIDENCE_HIGH.to_string(),
                    file: file.relative_path.clone(),
                    start_line,
                    end_line,
                });

                if let (Some(start_line), Some(end_line)) = (start_line, end_line) {
                    change_sets.push(RemovalChangeSet {
                        file: file.relative_path.clone(),
                        symbol,
                        start_line,
                        end_line,
                    });
                }
            }

            for scope in &model.scopes {
                let symbol = format!("{}::{scope}", model.fqcn);
                let reachable_from_runtime = reachable_model_scopes.contains(&symbol);
                let line_range = find_model_scope_line_range(file, scope);
                let (start_line, end_line) = line_range
                    .map(|(start, end)| (Some(start), Some(end)))
                    .unwrap_or((None, None));

                symbols.push(SymbolRecord {
                    kind: SYMBOL_KIND_MODEL_SCOPE.to_string(),
                    symbol: symbol.clone(),
                    file: file.relative_path.clone(),
                    reachable_from_runtime,
                    start_line,
                    end_line,
                });

                if reachable_from_runtime {
                    continue;
                }

                findings.push(Finding {
                    symbol: symbol.clone(),
                    category: FINDING_CATEGORY_UNUSED_MODEL_SCOPE.to_string(),
                    confidence: CONFIDENCE_HIGH.to_string(),
                    file: file.relative_path.clone(),
                    start_line,
                    end_line,
                });

                if let (Some(start_line), Some(end_line)) = (start_line, end_line) {
                    change_sets.push(RemovalChangeSet {
                        file: file.relative_path.clone(),
                        symbol,
                        start_line,
                        end_line,
                    });
                }
            }
        }
    }

    if !fully_dead_controller_classes.is_empty() {
        change_sets.retain(|change_set| {
            !fully_dead_controller_classes
                .iter()
                .any(|fqcn| change_set.symbol.starts_with(&format!("{fqcn}::")))
        });
    }

    for class in source_index.classes.values() {
        if !is_command_class(class, &source_index, &mut BTreeSet::new()) {
            continue;
        }

        let (start_line, end_line) = find_class_line_range(class)
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));
        let reachable_from_runtime = reachable_commands.contains(&class.fqcn);

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_COMMAND_CLASS.to_string(),
            symbol: class.fqcn.clone(),
            file: class.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        if reachable_from_runtime {
            continue;
        }

        findings.push(Finding {
            symbol: class.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_COMMAND_CLASS.to_string(),
            confidence: command_class_confidence(class, start_line, end_line).to_string(),
            file: class.relative_path.clone(),
            start_line,
            end_line,
        });

        if let (Some(start_line), Some(end_line)) = (start_line, end_line) {
            change_sets.push(RemovalChangeSet {
                file: class.relative_path.clone(),
                symbol: class.fqcn.clone(),
                start_line,
                end_line,
            });
        }
    }

    for class in source_index.classes.values() {
        if !is_form_request_class(class, &source_index, &mut BTreeSet::new()) {
            continue;
        }

        let (start_line, end_line) = find_class_line_range(class)
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));
        let reachable_from_runtime = reachable_form_requests.contains(&class.fqcn);

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_FORM_REQUEST_CLASS.to_string(),
            symbol: class.fqcn.clone(),
            file: class.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        if reachable_from_runtime {
            continue;
        }

        findings.push(Finding {
            symbol: class.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_FORM_REQUEST.to_string(),
            confidence: CONFIDENCE_HIGH.to_string(),
            file: class.relative_path.clone(),
            start_line,
            end_line,
        });

        if let (Some(start_line), Some(end_line)) = (start_line, end_line) {
            change_sets.push(RemovalChangeSet {
                file: class.relative_path.clone(),
                symbol: class.fqcn.clone(),
                start_line,
                end_line,
            });
        }
    }

    for class in source_index.classes.values() {
        if !is_resource_class(class, &source_index, &mut BTreeSet::new()) {
            continue;
        }

        let (start_line, end_line) = find_class_line_range(class)
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));
        let reachable_from_runtime = reachable_resources.contains(&class.fqcn);

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_RESOURCE_CLASS.to_string(),
            symbol: class.fqcn.clone(),
            file: class.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        if reachable_from_runtime {
            continue;
        }

        findings.push(Finding {
            symbol: class.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_RESOURCE_CLASS.to_string(),
            confidence: CONFIDENCE_HIGH.to_string(),
            file: class.relative_path.clone(),
            start_line,
            end_line,
        });

        if let (Some(start_line), Some(end_line)) = (start_line, end_line) {
            change_sets.push(RemovalChangeSet {
                file: class.relative_path.clone(),
                symbol: class.fqcn.clone(),
                start_line,
                end_line,
            });
        }
    }

    for class in source_index.classes.values() {
        if !is_policy_class(class, &reachable_policies) {
            continue;
        }

        let line_range = find_class_line_range(class);
        let (start_line, end_line) = line_range
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));
        let reachable_from_runtime = reachable_policies.contains(&class.fqcn);
        let removal_range = explicit_policy_removal_range(class);

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_POLICY_CLASS.to_string(),
            symbol: class.fqcn.clone(),
            file: class.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        if reachable_from_runtime {
            continue;
        }

        findings.push(Finding {
            symbol: class.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_POLICY_CLASS.to_string(),
            confidence: policy_class_confidence(class, removal_range).to_string(),
            file: class.relative_path.clone(),
            start_line,
            end_line,
        });

        if let Some((start_line, end_line)) = removal_range {
            change_sets.push(RemovalChangeSet {
                file: class.relative_path.clone(),
                symbol: class.fqcn.clone(),
                start_line,
                end_line,
            });
        }
    }

    for class in source_index.classes.values() {
        if !is_job_class(class, &reachable_jobs) {
            continue;
        }

        let line_range = find_class_line_range(class);
        let (start_line, end_line) = line_range
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));
        let reachable_from_runtime = reachable_jobs.contains(&class.fqcn);

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_JOB_CLASS.to_string(),
            symbol: class.fqcn.clone(),
            file: class.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        if reachable_from_runtime {
            continue;
        }

        let removal_range = explicit_job_removal_range(class);
        findings.push(Finding {
            symbol: class.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_JOB_CLASS.to_string(),
            confidence: job_class_confidence(class, removal_range).to_string(),
            file: class.relative_path.clone(),
            start_line,
            end_line,
        });

        if let Some((start_line, end_line)) = removal_range {
            change_sets.push(RemovalChangeSet {
                file: class.relative_path.clone(),
                symbol: class.fqcn.clone(),
                start_line,
                end_line,
            });
        }
    }

    for class in source_index.classes.values() {
        if !is_listener_class(class, &reachable_listeners) {
            continue;
        }

        let line_range = find_class_line_range(class);
        let (start_line, end_line) = line_range
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));
        let reachable_from_runtime = reachable_listeners.contains(&class.fqcn);

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_LISTENER_CLASS.to_string(),
            symbol: class.fqcn.clone(),
            file: class.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        if reachable_from_runtime {
            continue;
        }

        let removal_range = explicit_listener_removal_range(class);
        findings.push(Finding {
            symbol: class.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_LISTENER_CLASS.to_string(),
            confidence: listener_class_confidence(class, removal_range).to_string(),
            file: class.relative_path.clone(),
            start_line,
            end_line,
        });

        if let Some((start_line, end_line)) = removal_range {
            change_sets.push(RemovalChangeSet {
                file: class.relative_path.clone(),
                symbol: class.fqcn.clone(),
                start_line,
                end_line,
            });
        }
    }

    for class in source_index.classes.values() {
        if !is_subscriber_class(class, &reachable_subscribers) {
            continue;
        }

        let line_range = find_class_line_range(class);
        let (start_line, end_line) = line_range
            .map(|(start, end)| (Some(start), Some(end)))
            .unwrap_or((None, None));
        let reachable_from_runtime = reachable_subscribers.contains(&class.fqcn);

        symbols.push(SymbolRecord {
            kind: SYMBOL_KIND_SUBSCRIBER_CLASS.to_string(),
            symbol: class.fqcn.clone(),
            file: class.relative_path.clone(),
            reachable_from_runtime,
            start_line,
            end_line,
        });

        if reachable_from_runtime {
            continue;
        }

        let removal_range = explicit_subscriber_removal_range(class);
        findings.push(Finding {
            symbol: class.fqcn.clone(),
            category: FINDING_CATEGORY_UNUSED_SUBSCRIBER_CLASS.to_string(),
            confidence: subscriber_class_confidence(class, removal_range).to_string(),
            file: class.relative_path.clone(),
            start_line,
            end_line,
        });

        if let Some((start_line, end_line)) = removal_range {
            change_sets.push(RemovalChangeSet {
                file: class.relative_path.clone(),
                symbol: class.fqcn.clone(),
                start_line,
                end_line,
            });
        }
    }

    entrypoints
        .sort_by(|a, b| (&a.kind, &a.symbol, &a.source).cmp(&(&b.kind, &b.symbol, &b.source)));
    symbols.sort_by(|a, b| (&a.symbol, &a.file).cmp(&(&b.symbol, &b.file)));
    findings.sort_by(|a, b| (&a.symbol, &a.file).cmp(&(&b.symbol, &b.file)));
    change_sets.sort_by(|a, b| (&a.symbol, &a.file).cmp(&(&b.symbol, &b.file)));

    ControllerReachabilityReport {
        entrypoints,
        symbols,
        findings,
        removal_plan: RemovalPlan { change_sets },
    }
}

fn collect_reachable_form_requests(
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_actions: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut reachable_form_requests = BTreeSet::new();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        for usage in &controller.request_usage {
            let Some(class_name) = &usage.class_name else {
                continue;
            };
            if is_form_request_fqcn(class_name, source_index, &mut BTreeSet::new()) {
                reachable_form_requests.insert(class_name.clone());
            }
        }
    }

    reachable_form_requests
}

fn collect_reachable_resources(
    result: &PipelineResult,
    reachable_actions: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut reachable_resources = BTreeSet::new();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        for usage in &controller.resource_usage {
            reachable_resources.insert(usage.class_name.clone());
        }
    }

    reachable_resources
}

fn collect_reachable_model_methods(
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_actions: &BTreeSet<String>,
    reachable_commands: &BTreeSet<String>,
    reachable_listeners: &BTreeSet<String>,
    reachable_subscribers: &BTreeSet<String>,
    reachable_jobs: &BTreeSet<String>,
    reachable_policies: &BTreeSet<String>,
) -> BTreeSet<String> {
    let model_methods = result
        .files
        .iter()
        .flat_map(|file| file.facts.models.iter())
        .map(|model| {
            (
                model.fqcn.clone(),
                model
                    .methods
                    .iter()
                    .map(|method| method.name.clone())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reachable_model_methods = BTreeSet::new();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        let Some(source_class) = source_index.get(&controller.fqcn) else {
            continue;
        };

        for (model_fqcn, method_name) in extract_called_model_methods_from_text(
            &controller.body_text,
            source_class,
            &model_methods,
        ) {
            reachable_model_methods.insert(format!("{model_fqcn}::{method_name}"));
        }
    }

    collect_reachable_model_methods_from_runtime_roots(
        &mut reachable_model_methods,
        source_index,
        reachable_commands,
        &["handle"],
        &model_methods,
    );
    collect_reachable_model_methods_from_runtime_roots(
        &mut reachable_model_methods,
        source_index,
        reachable_listeners,
        &["handle"],
        &model_methods,
    );
    collect_reachable_model_methods_from_runtime_roots(
        &mut reachable_model_methods,
        source_index,
        reachable_subscribers,
        &["subscribe"],
        &model_methods,
    );
    collect_reachable_model_methods_from_runtime_roots(
        &mut reachable_model_methods,
        source_index,
        reachable_jobs,
        &["handle"],
        &model_methods,
    );
    collect_reachable_model_methods_from_policies(
        &mut reachable_model_methods,
        source_index,
        reachable_policies,
        &model_methods,
    );

    reachable_model_methods
}

fn collect_reachable_model_scopes(
    result: &PipelineResult,
    reachable_actions: &BTreeSet<String>,
) -> BTreeSet<String> {
    let scope_owners = collect_model_scope_owners(result);
    let mut reachable_model_scopes = BTreeSet::new();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        for scope in &controller.scopes_used {
            let Some(owner) =
                resolve_model_scope_owner(&scope_owners, &scope.name, scope.on.as_deref())
            else {
                continue;
            };
            reachable_model_scopes.insert(format!("{owner}::{}", scope.name));
        }
    }

    reachable_model_scopes
}

fn collect_reachable_model_methods_from_runtime_roots(
    reachable_model_methods: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    runtime_roots: &BTreeSet<String>,
    entrypoint_methods: &[&str],
    model_methods: &BTreeMap<String, BTreeSet<String>>,
) {
    for fqcn in runtime_roots {
        let Some(source_class) = source_index.get(fqcn) else {
            continue;
        };

        for method_name in entrypoint_methods {
            let Some(method_text) = extract_method_text(&source_class.source_text, method_name)
            else {
                continue;
            };

            for (model_fqcn, method_name) in
                extract_called_model_methods_from_text(&method_text, source_class, model_methods)
            {
                reachable_model_methods.insert(format!("{model_fqcn}::{method_name}"));
            }
        }
    }
}

fn collect_reachable_model_methods_from_policies(
    reachable_model_methods: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    reachable_policies: &BTreeSet<String>,
    model_methods: &BTreeMap<String, BTreeSet<String>>,
) {
    for fqcn in reachable_policies {
        let Some(source_class) = source_index.get(fqcn) else {
            continue;
        };

        for method_text in extract_policy_entrypoint_texts(source_class) {
            for (model_fqcn, method_name) in
                extract_called_model_methods_from_text(&method_text, source_class, model_methods)
            {
                reachable_model_methods.insert(format!("{model_fqcn}::{method_name}"));
            }
        }
    }
}

fn collect_reachable_jobs(
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_actions: &BTreeSet<String>,
    runtime_jobs: &[crate::contracts::RuntimeJob],
) -> BTreeSet<String> {
    let mut reachable_jobs = runtime_jobs
        .iter()
        .map(|job| job.fqcn.clone())
        .collect::<BTreeSet<_>>();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        let Some(source_class) = source_index.get(&controller.fqcn) else {
            continue;
        };

        reachable_jobs.extend(extract_dispatched_jobs(&controller.body_text, source_class));
    }

    reachable_jobs
}

fn build_controller_call_graph(
    result: &PipelineResult,
    source_index: &SourceIndex,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut methods_by_controller = BTreeMap::<String, BTreeSet<String>>::new();
    let mut controller_records = Vec::new();

    for (file, controller) in result.controller_methods() {
        methods_by_controller
            .entry(controller.fqcn.clone())
            .or_default()
            .insert(controller.method_name.clone());
        controller_records.push((file.relative_path.clone(), controller));
    }

    let mut call_graph = BTreeMap::<String, BTreeSet<String>>::new();
    for (_, controller) in controller_records {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        let source_class = source_index.get(&controller.fqcn);
        let callees = collect_controller_callees(controller, source_class, &methods_by_controller);
        call_graph.insert(symbol, callees);
    }

    call_graph
}

fn find_method_line_range(
    file: &AnalyzedFile,
    controller: &ControllerMethod,
) -> Option<(usize, usize)> {
    file.source_text.find(&controller.body_text).map(|start| {
        line_range_for_span(
            file.source_text.as_bytes(),
            start,
            start + controller.body_text.len(),
        )
    })
}

fn find_model_method_line_range(
    file: &AnalyzedFile,
    method: &ModelMethodFact,
) -> Option<(usize, usize)> {
    file.source_text.find(&method.body_text).map(|start| {
        line_range_for_span(
            file.source_text.as_bytes(),
            start,
            start + method.body_text.len(),
        )
    })
}

fn find_model_scope_line_range(file: &AnalyzedFile, scope_name: &str) -> Option<(usize, usize)> {
    let scope_re = Regex::new(&format!(
        r#"(?m)\bfunction\s+scope{}\s*\("#,
        regex::escape(&scope_method_suffix(scope_name))
    ))
    .expect("model scope line range regex");
    let scope_match = scope_re.find(&file.source_text)?;
    let brace_offset = file.source_text[scope_match.end()..].find('{')?;
    let brace_start = scope_match.end() + brace_offset;
    let (_, _, scope_end_relative) =
        extract_balanced_region(&file.source_text[brace_start..], '{', '}')?;

    Some(line_range_for_span(
        file.source_text.as_bytes(),
        scope_match.start(),
        brace_start + scope_end_relative + 1,
    ))
}

fn find_class_line_range(class: &SourceClass) -> Option<(usize, usize)> {
    let class_re = Regex::new(&format!(
        r#"(?m)^\s*(?:final\s+|abstract\s+)?class\s+{}\b"#,
        regex::escape(&class.class_name)
    ))
    .expect("class line range regex");
    let class_match = class_re.find(&class.source_text)?;
    let brace_offset = class.source_text[class_match.end()..].find('{')?;
    let brace_start = class_match.end() + brace_offset;
    let (_, _, class_end_relative) =
        extract_balanced_region(&class.source_text[brace_start..], '{', '}')?;

    Some(line_range_for_span(
        class.source_text.as_bytes(),
        class_match.start(),
        brace_start + class_end_relative + 1,
    ))
}

fn collect_model_scope_owners(result: &PipelineResult) -> BTreeMap<String, BTreeSet<String>> {
    let mut owners = BTreeMap::<String, BTreeSet<String>>::new();

    for file in &result.files {
        for model in &file.facts.models {
            for scope in &model.scopes {
                owners
                    .entry(scope.clone())
                    .or_default()
                    .insert(model.fqcn.clone());
            }
        }
    }

    owners
}

fn resolve_model_scope_owner(
    scope_owners: &BTreeMap<String, BTreeSet<String>>,
    scope_name: &str,
    explicit_owner: Option<&str>,
) -> Option<String> {
    let owners = scope_owners.get(scope_name)?;

    let owner = explicit_owner.map(|owner| owner.trim_start_matches('\\'))?;
    owners.contains(owner).then(|| owner.to_string())
}

fn scope_method_suffix(scope_name: &str) -> String {
    let mut chars = scope_name.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };

    first.to_uppercase().collect::<String>() + chars.as_str()
}

fn is_form_request_class(
    class: &SourceClass,
    source_index: &SourceIndex,
    visited: &mut BTreeSet<String>,
) -> bool {
    is_form_request_fqcn(&class.fqcn, source_index, visited)
}

fn is_form_request_fqcn(
    fqcn: &str,
    source_index: &SourceIndex,
    visited: &mut BTreeSet<String>,
) -> bool {
    if fqcn == "Illuminate\\Foundation\\Http\\FormRequest" {
        return true;
    }

    if !visited.insert(fqcn.to_string()) {
        return false;
    }

    let Some(class) = source_index.get(fqcn) else {
        return false;
    };
    let Some(extends) = &class.extends else {
        return false;
    };

    is_form_request_fqcn(extends, source_index, visited)
}

fn is_resource_class(
    class: &SourceClass,
    source_index: &SourceIndex,
    visited: &mut BTreeSet<String>,
) -> bool {
    is_resource_fqcn(&class.fqcn, source_index, visited)
}

fn is_resource_fqcn(
    fqcn: &str,
    source_index: &SourceIndex,
    visited: &mut BTreeSet<String>,
) -> bool {
    if fqcn == "Illuminate\\Http\\Resources\\Json\\JsonResource"
        || fqcn == "Illuminate\\Http\\Resources\\Json\\ResourceCollection"
    {
        return true;
    }

    if !visited.insert(fqcn.to_string()) {
        return false;
    }

    let Some(class) = source_index.get(fqcn) else {
        return false;
    };
    let Some(extends) = &class.extends else {
        return false;
    };

    is_resource_fqcn(extends, source_index, visited)
}

fn is_policy_class(class: &SourceClass, reachable_policies: &BTreeSet<String>) -> bool {
    if reachable_policies.contains(&class.fqcn) {
        return true;
    }

    class.relative_path.starts_with("app/Policies/") && !class.fqcn.is_empty()
}

fn is_command_class(
    class: &SourceClass,
    source_index: &SourceIndex,
    visited: &mut BTreeSet<String>,
) -> bool {
    is_command_fqcn(&class.fqcn, source_index, visited)
}

fn is_command_fqcn(fqcn: &str, source_index: &SourceIndex, visited: &mut BTreeSet<String>) -> bool {
    if fqcn == "Illuminate\\Console\\Command" {
        return true;
    }

    if !visited.insert(fqcn.to_string()) {
        return false;
    }

    let Some(class) = source_index.get(fqcn) else {
        return false;
    };
    let Some(extends) = &class.extends else {
        return false;
    };

    is_command_fqcn(extends, source_index, visited)
}

fn command_class_confidence(
    class: &SourceClass,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> &'static str {
    if start_line.is_some()
        && end_line.is_some()
        && class.relative_path.starts_with("app/Console/Commands/")
        && class_declaration_count(&class.source_text) == 1
    {
        CONFIDENCE_HIGH
    } else {
        CONFIDENCE_MEDIUM
    }
}

fn policy_class_confidence(
    class: &SourceClass,
    removal_range: Option<(usize, usize)>,
) -> &'static str {
    if removal_range.is_some()
        && class.relative_path.starts_with("app/Policies/")
        && class_declaration_count(&class.source_text) == 1
    {
        CONFIDENCE_HIGH
    } else {
        CONFIDENCE_MEDIUM
    }
}

fn explicit_policy_removal_range(class: &SourceClass) -> Option<(usize, usize)> {
    if !class.relative_path.starts_with("app/Policies/")
        || class_declaration_count(&class.source_text) != 1
    {
        return None;
    }

    find_class_line_range(class)
}

fn listener_class_confidence(
    class: &SourceClass,
    removal_range: Option<(usize, usize)>,
) -> &'static str {
    if removal_range.is_some()
        && class.relative_path.starts_with("app/Listeners/")
        && class_declaration_count(&class.source_text) == 1
    {
        CONFIDENCE_HIGH
    } else {
        CONFIDENCE_MEDIUM
    }
}

fn explicit_listener_removal_range(class: &SourceClass) -> Option<(usize, usize)> {
    if !class.relative_path.starts_with("app/Listeners/")
        || class_declaration_count(&class.source_text) != 1
    {
        return None;
    }

    find_class_line_range(class)
}

fn subscriber_class_confidence(
    class: &SourceClass,
    removal_range: Option<(usize, usize)>,
) -> &'static str {
    if removal_range.is_some()
        && class.relative_path.starts_with("app/Listeners/")
        && class_declaration_count(&class.source_text) == 1
    {
        CONFIDENCE_HIGH
    } else {
        CONFIDENCE_MEDIUM
    }
}

fn explicit_subscriber_removal_range(class: &SourceClass) -> Option<(usize, usize)> {
    if !class.relative_path.starts_with("app/Listeners/")
        || class_declaration_count(&class.source_text) != 1
    {
        return None;
    }

    find_class_line_range(class)
}

fn job_class_confidence(
    class: &SourceClass,
    removal_range: Option<(usize, usize)>,
) -> &'static str {
    if removal_range.is_some()
        && class.relative_path.starts_with("app/Jobs/")
        && class_declaration_count(&class.source_text) == 1
    {
        CONFIDENCE_HIGH
    } else {
        CONFIDENCE_MEDIUM
    }
}

fn explicit_job_removal_range(class: &SourceClass) -> Option<(usize, usize)> {
    if !class.relative_path.starts_with("app/Jobs/")
        || class_declaration_count(&class.source_text) != 1
    {
        return None;
    }

    find_class_line_range(class)
}

fn class_declaration_count(source: &str) -> usize {
    Regex::new(r#"(?m)^\s*(?:final\s+|abstract\s+)?class\s+[A-Za-z_][A-Za-z0-9_]*\b"#)
        .expect("class declaration count regex")
        .find_iter(source)
        .count()
}

fn is_listener_class(class: &SourceClass, reachable_listeners: &BTreeSet<String>) -> bool {
    if reachable_listeners.contains(&class.fqcn) {
        return true;
    }

    class.relative_path.starts_with("app/Listeners/")
        && has_method(&class.source_text, "handle")
        && !has_method(&class.source_text, "subscribe")
}

fn is_subscriber_class(class: &SourceClass, reachable_subscribers: &BTreeSet<String>) -> bool {
    if reachable_subscribers.contains(&class.fqcn) {
        return true;
    }

    class.relative_path.starts_with("app/Listeners/")
        && has_method(&class.source_text, "subscribe")
        && !has_method(&class.source_text, "handle")
}

fn is_job_class(class: &SourceClass, reachable_jobs: &BTreeSet<String>) -> bool {
    if reachable_jobs.contains(&class.fqcn) {
        return true;
    }

    class.relative_path.starts_with("app/Jobs/") && has_method(&class.source_text, "handle")
}

fn has_method(source: &str, method_name: &str) -> bool {
    Regex::new(&format!(
        r#"(?m)\bfunction\s+{}\s*\("#,
        regex::escape(method_name)
    ))
    .expect("method detection regex")
    .is_match(source)
}

fn collect_controller_callees(
    controller: &ControllerMethod,
    source_class: Option<&SourceClass>,
    methods_by_controller: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut callees = BTreeSet::new();
    let same_controller_methods = methods_by_controller
        .get(&controller.fqcn)
        .cloned()
        .unwrap_or_default();

    let this_call_re =
        Regex::new(r#"\$this->([A-Za-z_][A-Za-z0-9_]*)\s*\("#).expect("this call regex");
    for captures in this_call_re.captures_iter(&controller.body_text) {
        let Some(method_name) = captures.get(1) else {
            continue;
        };
        register_controller_callee(
            &mut callees,
            methods_by_controller,
            &controller.fqcn,
            method_name.as_str(),
        );
    }

    let static_call_re =
        Regex::new(r#"(self|static)::([A-Za-z_][A-Za-z0-9_]*)\s*\("#).expect("static call regex");
    for captures in static_call_re.captures_iter(&controller.body_text) {
        let Some(method_name) = captures.get(2) else {
            continue;
        };
        register_controller_callee(
            &mut callees,
            methods_by_controller,
            &controller.fqcn,
            method_name.as_str(),
        );
    }

    let qualified_call_re =
        Regex::new(r#"([A-Za-z_\\][A-Za-z0-9_\\]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\("#)
            .expect("qualified call regex");
    for captures in qualified_call_re.captures_iter(&controller.body_text) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let Some(method_name) = captures.get(2) else {
            continue;
        };

        let resolved_class =
            resolve_called_controller(controller, source_class, class_name.as_str());

        register_controller_callee(
            &mut callees,
            methods_by_controller,
            &resolved_class,
            method_name.as_str(),
        );
    }

    let instance_call_re = Regex::new(
        r#"\(?\s*new\s+([A-Za-z_\\][A-Za-z0-9_\\]*)\s*\([^)]*\)\s*\)?->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("#,
    )
    .expect("instance call regex");
    for captures in instance_call_re.captures_iter(&controller.body_text) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let Some(method_name) = captures.get(2) else {
            continue;
        };

        let resolved_class =
            resolve_called_controller(controller, source_class, class_name.as_str());

        register_controller_callee(
            &mut callees,
            methods_by_controller,
            &resolved_class,
            method_name.as_str(),
        );
    }

    callees.remove(&format!("{}::{}", controller.fqcn, controller.method_name));
    for method_name in same_controller_methods {
        let symbol = format!("{}::{method_name}", controller.fqcn);
        if symbol == format!("{}::{}", controller.fqcn, controller.method_name) {
            callees.remove(&symbol);
        }
    }
    callees
}

fn extract_method_text(source: &str, method_name: &str) -> Option<String> {
    let method_re = Regex::new(&format!(
        r#"(?m)\bfunction\s+{}\s*\("#,
        regex::escape(method_name)
    ))
    .expect("method text regex");
    let method_match = method_re.find(source)?;
    let brace_offset = source[method_match.end()..].find('{')?;
    let brace_start = method_match.end() + brace_offset;
    let (_, _, body_end_relative) = extract_balanced_region(&source[brace_start..], '{', '}')?;

    Some(source[method_match.start()..(brace_start + body_end_relative + 1)].to_string())
}

fn extract_policy_entrypoint_texts(source_class: &SourceClass) -> Vec<String> {
    let public_method_re =
        Regex::new(r#"(?m)\bpublic\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"#)
            .expect("policy public method regex");
    let mut methods = Vec::new();
    let mut seen = BTreeSet::new();

    for captures in public_method_re.captures_iter(&source_class.source_text) {
        let Some(method_name) = captures.get(1) else {
            continue;
        };
        let Some(parameters) = captures.get(2) else {
            continue;
        };
        let method_name = method_name.as_str();
        if method_name == "__construct" || parameters.as_str().trim().is_empty() {
            continue;
        }
        if !seen.insert(method_name.to_string()) {
            continue;
        }
        if let Some(method_text) = extract_method_text(&source_class.source_text, method_name) {
            methods.push(method_text);
        }
    }

    methods
}

fn extract_called_model_methods_from_text(
    text: &str,
    source_class: &SourceClass,
    model_methods: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<(String, String)> {
    let mut called = BTreeSet::new();
    let model_variables = collect_model_variables_from_text(text, source_class, model_methods);

    let instance_call_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)\s*\("#)
            .expect("model instance call regex");
    for captures in instance_call_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(method_name) = captures.get(2) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        if model_methods
            .get(model_fqcn)
            .is_some_and(|methods| methods.contains(method_name.as_str()))
        {
            called.insert((model_fqcn.clone(), method_name.as_str().to_string()));
        }
    }

    let static_call_re = Regex::new(r#"([A-Z][A-Za-z0-9_\\]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\("#)
        .expect("model static call regex");
    for captures in static_call_re.captures_iter(text) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let Some(method_name) = captures.get(2) else {
            continue;
        };
        let resolved_class = source_class.resolve_name(class_name.as_str());
        if model_methods
            .get(&resolved_class)
            .is_some_and(|methods| methods.contains(method_name.as_str()))
        {
            called.insert((resolved_class, method_name.as_str().to_string()));
        }
    }

    called
}

fn collect_model_variables_from_text(
    text: &str,
    source_class: &SourceClass,
    model_methods: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, String> {
    let mut variables = BTreeMap::new();
    let parameter_re = Regex::new(r#"(?:(\??[A-Z][A-Za-z0-9_\\]*)\s+)\$([A-Za-z_][A-Za-z0-9_]*)"#)
        .expect("parameter regex");
    for captures in parameter_re.captures_iter(text) {
        let Some(raw_type) = captures.get(1) else {
            continue;
        };
        let Some(variable_name) = captures.get(2) else {
            continue;
        };
        let resolved = source_class.resolve_name(raw_type.as_str().trim_start_matches('?'));
        if model_methods.contains_key(&resolved) {
            variables.insert(variable_name.as_str().to_string(), resolved);
        }
    }

    let new_model_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+([A-Z][A-Za-z0-9_\\]*)\b"#)
            .expect("new model regex");
    for captures in new_model_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(class_name) = captures.get(2) else {
            continue;
        };
        let resolved = source_class.resolve_name(class_name.as_str());
        if model_methods.contains_key(&resolved) {
            variables.insert(variable_name.as_str().to_string(), resolved);
        }
    }

    let direct_model_loader_re = Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Z][A-Za-z0-9_\\]*)::(find|findOrFail|first|firstOrFail|firstOrNew|firstOrCreate|forceCreate|make|sole|updateOrCreate|create)\s*\("#,
    )
    .expect("direct model loader regex");
    for captures in direct_model_loader_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(class_name) = captures.get(2) else {
            continue;
        };
        let resolved = source_class.resolve_name(class_name.as_str());
        if model_methods.contains_key(&resolved) {
            variables.insert(variable_name.as_str().to_string(), resolved);
        }
    }

    let query_model_loader_re = Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Z][A-Za-z0-9_\\]*)::[A-Za-z_][A-Za-z0-9_]*\([^;]*?->(find|findOrFail|first|firstOrFail|sole)\s*\("#,
    )
    .expect("query model loader regex");
    for captures in query_model_loader_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(class_name) = captures.get(2) else {
            continue;
        };
        let resolved = source_class.resolve_name(class_name.as_str());
        if model_methods.contains_key(&resolved) {
            variables.insert(variable_name.as_str().to_string(), resolved);
        }
    }

    variables
}

fn resolve_called_controller(
    controller: &ControllerMethod,
    source_class: Option<&SourceClass>,
    class_name: &str,
) -> String {
    let called_class = class_name.trim_start_matches('\\');
    if called_class == controller.class_name || called_class == controller.fqcn {
        controller.fqcn.clone()
    } else if let Some(source_class) = source_class {
        source_class.resolve_name(called_class)
    } else {
        called_class.to_string()
    }
}

fn register_controller_callee(
    callees: &mut BTreeSet<String>,
    methods_by_controller: &BTreeMap<String, BTreeSet<String>>,
    controller_fqcn: &str,
    method_name: &str,
) {
    if methods_by_controller
        .get(controller_fqcn)
        .is_some_and(|known_methods| known_methods.contains(method_name))
    {
        callees.insert(format!("{controller_fqcn}::{method_name}"));
    }
}

fn extract_dispatched_jobs(method_body: &str, source_class: &SourceClass) -> BTreeSet<String> {
    let mut jobs = BTreeSet::new();

    let static_dispatch_re = Regex::new(r#"([A-Za-z_\\][A-Za-z0-9_\\]*)::dispatch\s*\("#)
        .expect("static dispatch regex");
    for captures in static_dispatch_re.captures_iter(method_body) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        if matches!(class_name.as_str(), "self" | "static" | "Bus") {
            continue;
        }
        let resolved = source_class.resolve_name(class_name.as_str());
        jobs.insert(resolved);
    }

    let dispatch_new_re =
        Regex::new(r#"(?m)(?:^|[^:])dispatch\s*\(\s*new\s+([A-Za-z_\\][A-Za-z0-9_\\]*)\b"#)
            .expect("dispatch new regex");
    for captures in dispatch_new_re.captures_iter(method_body) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let resolved = source_class.resolve_name(class_name.as_str());
        jobs.insert(resolved);
    }

    let bus_dispatch_re =
        Regex::new(r#"Bus::dispatch\s*\(\s*new\s+([A-Za-z_\\][A-Za-z0-9_\\]*)\b"#)
            .expect("bus dispatch regex");
    for captures in bus_dispatch_re.captures_iter(method_body) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let resolved = source_class.resolve_name(class_name.as_str());
        jobs.insert(resolved);
    }

    jobs
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::analyze_controller_reachability;
    use crate::contracts::AnalysisRequest;
    use crate::model::{
        AnalyzedFile, ControllerMethod, FileFacts, ModelFacts, ModelMethodFact, ScopeUsageFact,
    };
    use crate::pipeline::PipelineResult;

    #[test]
    fn reachable_command_keeps_explicitly_loaded_model_helper_alive() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let request: AnalysisRequest = serde_json::from_value(json!({
            "contractVersion": "deadcode.analysis.v1",
            "requestId": "req-model-method-command",
            "runtimeFingerprint": "fp-model-method-command",
            "manifest": {
                "project": {
                    "root": root,
                    "composer": "composer.json"
                },
                "scan": {
                    "targets": ["app"],
                    "globs": ["**/*.php"]
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
            },
            "runtime": {
                "app": {
                    "basePath": env!("CARGO_MANIFEST_DIR"),
                    "laravelVersion": "12.0.0",
                    "phpVersion": "8.3.0",
                    "appEnv": "testing"
                },
                "commands": [
                    {
                        "signature": "invoices:report",
                        "fqcn": "App\\Console\\Commands\\ReportInvoicesCommand",
                        "description": "Report invoices"
                    }
                ]
            }
        }))
        .expect("request should deserialize");
        let command_source = r#"<?php

namespace App\Console\Commands;

use App\Models\Invoice;
use Illuminate\Console\Command;

class ReportInvoicesCommand extends Command
{
    public function handle(): void
    {
        $invoice = Invoice::findOrFail($id);
        $invoice->summary();
    }

    public function helper(): void
    {
        $invoice = new Invoice();
        $invoice->debugLabel();
    }
}
"#;
        let model_source = r#"<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    public function summary(): string
    {
        return 'summary';
    }

    public function debugLabel(): string
    {
        return 'debug';
    }
}
"#;
        let result = PipelineResult {
            files: vec![
                AnalyzedFile {
                    path: root.join("app/Console/Commands/ReportInvoicesCommand.php"),
                    relative_path: "app/Console/Commands/ReportInvoicesCommand.php".to_string(),
                    source_text: command_source.to_string(),
                    facts: FileFacts::default(),
                },
                AnalyzedFile {
                    path: root.join("app/Models/Invoice.php"),
                    relative_path: "app/Models/Invoice.php".to_string(),
                    source_text: model_source.to_string(),
                    facts: FileFacts {
                        models: vec![ModelFacts {
                            class_name: "Invoice".to_string(),
                            fqcn: "App\\Models\\Invoice".to_string(),
                            relationships: Vec::new(),
                            scopes: Vec::new(),
                            attributes: Vec::new(),
                            methods: vec![
                                ModelMethodFact {
                                    name: "summary".to_string(),
                                    body_text: "public function summary(): string\n    {\n        return 'summary';\n    }"
                                        .to_string(),
                                },
                                ModelMethodFact {
                                    name: "debugLabel".to_string(),
                                    body_text: "public function debugLabel(): string\n    {\n        return 'debug';\n    }"
                                        .to_string(),
                                },
                            ],
                        }],
                        ..FileFacts::default()
                    },
                },
            ],
            route_bindings: Vec::new(),
            partial: false,
            duration_ms: 0,
            cache_hits: 0,
            cache_misses: 0,
        };

        let report = analyze_controller_reachability(&request, &result);

        assert!(report.symbols.iter().any(|symbol| {
            symbol.kind == "model_method"
                && symbol.symbol == "App\\Models\\Invoice::summary"
                && symbol.reachable_from_runtime
        }));
        assert!(!report.findings.iter().any(|finding| {
            finding.category == "unused_model_method"
                && finding.symbol == "App\\Models\\Invoice::summary"
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "unused_model_method"
                && finding.symbol == "App\\Models\\Invoice::debugLabel"
        }));
    }

    #[test]
    fn ambiguous_scope_owner_stays_unsupported_and_unused() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let request: AnalysisRequest = serde_json::from_value(json!({
            "contractVersion": "deadcode.analysis.v1",
            "requestId": "req-model-scope-ambiguous",
            "runtimeFingerprint": "fp-model-scope-ambiguous",
            "manifest": {
                "project": {
                    "root": root,
                    "composer": "composer.json"
                },
                "scan": {
                    "targets": ["app"],
                    "globs": ["**/*.php"]
                },
                "features": {
                    "http_status": true,
                    "request_usage": false,
                    "resource_usage": false,
                    "scopes_used": true
                }
            },
            "runtime": {
                "app": {
                    "basePath": env!("CARGO_MANIFEST_DIR"),
                    "laravelVersion": "12.0.0",
                    "phpVersion": "8.3.0",
                    "appEnv": "testing"
                },
                "routes": [
                    {
                        "routeId": "posts.index",
                        "methods": ["GET"],
                        "uri": "posts",
                        "domain": null,
                        "name": "posts.index",
                        "prefix": null,
                        "middleware": [],
                        "where": {},
                        "defaults": {},
                        "bindings": [],
                        "action": {
                            "kind": "controller_method",
                            "fqcn": "App\\Http\\Controllers\\PostController",
                            "method": "index"
                        }
                    }
                ]
            }
        }))
        .expect("request should deserialize");
        let controller_source = r#"<?php

namespace App\Http\Controllers;

use App\Models\Post;

final class PostController
{
    public function index(): array
    {
        return Post::query()->published()->get()->all();
    }
}
"#;
        let post_source = r#"<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function scopePublished($query)
    {
        return $query;
    }
}
"#;
        let article_source = r#"<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Article extends Model
{
    public function scopePublished($query)
    {
        return $query;
    }
}
"#;
        let result = PipelineResult {
            files: vec![
                AnalyzedFile {
                    path: root.join("app/Http/Controllers/PostController.php"),
                    relative_path: "app/Http/Controllers/PostController.php".to_string(),
                    source_text: controller_source.to_string(),
                    facts: FileFacts {
                        controllers: vec![ControllerMethod {
                            class_name: "PostController".to_string(),
                            fqcn: "App\\Http\\Controllers\\PostController".to_string(),
                            method_name: "index".to_string(),
                            body_text: "public function index(): array\n    {\n        return Post::query()->published()->get()->all();\n    }".to_string(),
                            scopes_used: vec![ScopeUsageFact {
                                name: "published".to_string(),
                                on: None,
                            }],
                            ..ControllerMethod::default()
                        }],
                        ..FileFacts::default()
                    },
                },
                AnalyzedFile {
                    path: root.join("app/Models/Post.php"),
                    relative_path: "app/Models/Post.php".to_string(),
                    source_text: post_source.to_string(),
                    facts: FileFacts {
                        models: vec![ModelFacts {
                            class_name: "Post".to_string(),
                            fqcn: "App\\Models\\Post".to_string(),
                            scopes: vec!["published".to_string()],
                            ..ModelFacts::default()
                        }],
                        ..FileFacts::default()
                    },
                },
                AnalyzedFile {
                    path: root.join("app/Models/Article.php"),
                    relative_path: "app/Models/Article.php".to_string(),
                    source_text: article_source.to_string(),
                    facts: FileFacts {
                        models: vec![ModelFacts {
                            class_name: "Article".to_string(),
                            fqcn: "App\\Models\\Article".to_string(),
                            scopes: vec!["published".to_string()],
                            ..ModelFacts::default()
                        }],
                        ..FileFacts::default()
                    },
                },
            ],
            route_bindings: Vec::new(),
            partial: false,
            duration_ms: 0,
            cache_hits: 0,
            cache_misses: 0,
        };

        let report = analyze_controller_reachability(&request, &result);

        assert!(!report.symbols.iter().any(|symbol| {
            symbol.kind == "model_scope"
                && symbol.symbol.ends_with("::published")
                && symbol.reachable_from_runtime
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "unused_model_scope"
                && finding.symbol == "App\\Models\\Post::published"
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "unused_model_scope"
                && finding.symbol == "App\\Models\\Article::published"
        }));
    }

    #[test]
    fn ownerless_scope_usage_stays_unsupported_even_with_single_owner() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let request: AnalysisRequest = serde_json::from_value(json!({
            "contractVersion": "deadcode.analysis.v1",
            "requestId": "req-model-scope-ownerless",
            "runtimeFingerprint": "fp-model-scope-ownerless",
            "manifest": {
                "project": {
                    "root": root,
                    "composer": "composer.json"
                },
                "scan": {
                    "targets": ["app"],
                    "globs": ["**/*.php"]
                },
                "features": {
                    "http_status": true,
                    "request_usage": false,
                    "resource_usage": false,
                    "scopes_used": true
                }
            },
            "runtime": {
                "app": {
                    "basePath": env!("CARGO_MANIFEST_DIR"),
                    "laravelVersion": "12.0.0",
                    "phpVersion": "8.3.0",
                    "appEnv": "testing"
                },
                "routes": [
                    {
                        "routeId": "posts.index",
                        "methods": ["GET"],
                        "uri": "posts",
                        "domain": null,
                        "name": "posts.index",
                        "prefix": null,
                        "middleware": [],
                        "where": {},
                        "defaults": {},
                        "bindings": [],
                        "action": {
                            "kind": "controller_method",
                            "fqcn": "App\\Http\\Controllers\\PostController",
                            "method": "index"
                        }
                    }
                ]
            }
        }))
        .expect("request should deserialize");
        let controller_source = r#"<?php

namespace App\Http\Controllers;

use App\Models\Post;
use App\Support\SomeClass;

final class PostController
{
    public function index(): array
    {
        return SomeClass::published();
    }
}
"#;
        let post_source = r#"<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function scopePublished($query)
    {
        return $query;
    }
}
"#;
        let result = PipelineResult {
            files: vec![
                AnalyzedFile {
                    path: root.join("app/Http/Controllers/PostController.php"),
                    relative_path: "app/Http/Controllers/PostController.php".to_string(),
                    source_text: controller_source.to_string(),
                    facts: FileFacts {
                        controllers: vec![ControllerMethod {
                            class_name: "PostController".to_string(),
                            fqcn: "App\\Http\\Controllers\\PostController".to_string(),
                            method_name: "index".to_string(),
                            body_text: "public function index(): array\n    {\n        return SomeClass::published();\n    }".to_string(),
                            scopes_used: vec![ScopeUsageFact {
                                name: "published".to_string(),
                                on: None,
                            }],
                            ..ControllerMethod::default()
                        }],
                        ..FileFacts::default()
                    },
                },
                AnalyzedFile {
                    path: root.join("app/Models/Post.php"),
                    relative_path: "app/Models/Post.php".to_string(),
                    source_text: post_source.to_string(),
                    facts: FileFacts {
                        models: vec![ModelFacts {
                            class_name: "Post".to_string(),
                            fqcn: "App\\Models\\Post".to_string(),
                            scopes: vec!["published".to_string()],
                            ..ModelFacts::default()
                        }],
                        ..FileFacts::default()
                    },
                },
            ],
            route_bindings: Vec::new(),
            partial: false,
            duration_ms: 0,
            cache_hits: 0,
            cache_misses: 0,
        };

        let report = analyze_controller_reachability(&request, &result);

        assert!(!report.symbols.iter().any(|symbol| {
            symbol.kind == "model_scope"
                && symbol.symbol == "App\\Models\\Post::published"
                && symbol.reachable_from_runtime
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "unused_model_scope"
                && finding.symbol == "App\\Models\\Post::published"
        }));
    }
}
