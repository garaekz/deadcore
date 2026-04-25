use std::collections::{BTreeMap, BTreeSet, VecDeque};

use regex::Regex;

use crate::contracts::{AnalysisRequest, Entrypoint, RemovalChangeSet, RemovalPlan};
use crate::deadcode_model::{
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, FINDING_CATEGORY_UNUSED_COMMAND_CLASS,
    FINDING_CATEGORY_UNUSED_CONTROLLER_CLASS, FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD,
    FINDING_CATEGORY_UNUSED_FORM_REQUEST, FINDING_CATEGORY_UNUSED_JOB_CLASS,
    FINDING_CATEGORY_UNUSED_LISTENER_CLASS, FINDING_CATEGORY_UNUSED_MODEL_ACCESSOR,
    FINDING_CATEGORY_UNUSED_MODEL_METHOD, FINDING_CATEGORY_UNUSED_MODEL_MUTATOR,
    FINDING_CATEGORY_UNUSED_MODEL_RELATIONSHIP, FINDING_CATEGORY_UNUSED_MODEL_SCOPE,
    FINDING_CATEGORY_UNUSED_POLICY_CLASS, FINDING_CATEGORY_UNUSED_RESOURCE_CLASS,
    FINDING_CATEGORY_UNUSED_SUBSCRIBER_CLASS, Finding, ReasonRecord, SYMBOL_KIND_COMMAND_CLASS,
    SYMBOL_KIND_CONTROLLER_CLASS, SYMBOL_KIND_CONTROLLER_METHOD, SYMBOL_KIND_FORM_REQUEST_CLASS,
    SYMBOL_KIND_JOB_CLASS, SYMBOL_KIND_LISTENER_CLASS, SYMBOL_KIND_MODEL_ACCESSOR,
    SYMBOL_KIND_MODEL_METHOD, SYMBOL_KIND_MODEL_MUTATOR, SYMBOL_KIND_MODEL_RELATIONSHIP,
    SYMBOL_KIND_MODEL_SCOPE, SYMBOL_KIND_POLICY_CLASS, SYMBOL_KIND_RESOURCE_CLASS,
    SYMBOL_KIND_SUBSCRIBER_CLASS, SymbolRecord,
};
use crate::model::{
    AnalyzedFile, ControllerMethod, ModelAttributeFact, ModelMethodFact, ModelRelationshipFact,
};
use crate::parser::line_range_for_span;
use crate::pipeline::PipelineResult;
use crate::source_index::{
    SourceClass, SourceIndex, extract_balanced_region, split_top_level, split_top_level_key_value,
    strip_php_string,
};

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

fn reason(code: &str, summary: &str) -> ReasonRecord {
    ReasonRecord {
        code: code.to_string(),
        summary: summary.to_string(),
        ..Default::default()
    }
}

fn build_symbol_record(
    kind: &str,
    symbol: String,
    file: String,
    reachable_from_runtime: bool,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> SymbolRecord {
    let (reason_summary, reachability_reasons) = if reachable_from_runtime {
        match kind {
            SYMBOL_KIND_CONTROLLER_METHOD => (
                Some(
                    "Reachable through Laravel runtime routing or supported controller call expansion."
                        .to_string(),
                ),
                vec![reason(
                    "supported_controller_reachability",
                    "Laravel runtime routes or supported controller call expansion keep this controller method alive.",
                )],
            ),
            SYMBOL_KIND_CONTROLLER_CLASS => (
                Some("Reachable because at least one extracted controller method is still alive.".to_string()),
                vec![reason(
                    "reachable_controller_method",
                    "At least one extracted controller method remains reachable, so the controller class is kept alive.",
                )],
            ),
            SYMBOL_KIND_FORM_REQUEST_CLASS => (
                Some("Reachable through a supported typed controller parameter.".to_string()),
                vec![reason(
                    "typed_controller_parameter",
                    "A reachable controller method uses this FormRequest as an explicit typed parameter.",
                )],
            ),
            SYMBOL_KIND_RESOURCE_CLASS => (
                Some("Reachable through supported controller resource usage.".to_string()),
                vec![reason(
                    "supported_resource_usage",
                    "A reachable controller method returns or references this resource through a supported pattern.",
                )],
            ),
            SYMBOL_KIND_COMMAND_CLASS => (
                Some("Reachable through runtime command registration.".to_string()),
                vec![reason(
                    "runtime_command",
                    "Laravel runtime command registration keeps this command class alive.",
                )],
            ),
            SYMBOL_KIND_LISTENER_CLASS => (
                Some("Reachable through runtime listener registration.".to_string()),
                vec![reason(
                    "runtime_listener",
                    "Laravel runtime listener registration keeps this listener class alive.",
                )],
            ),
            SYMBOL_KIND_SUBSCRIBER_CLASS => (
                Some("Reachable through explicit runtime subscriber registration.".to_string()),
                vec![reason(
                    "runtime_subscriber",
                    "Explicit Laravel runtime subscriber registration keeps this subscriber alive.",
                )],
            ),
            SYMBOL_KIND_JOB_CLASS => (
                Some("Reachable through supported explicit job dispatch patterns.".to_string()),
                vec![reason(
                    "supported_job_dispatch",
                    "A supported explicit job dispatch pattern keeps this job class alive.",
                )],
            ),
            SYMBOL_KIND_POLICY_CLASS => (
                Some("Reachable through the runtime Gate policy map.".to_string()),
                vec![reason(
                    "runtime_policy_map",
                    "The Laravel Gate policy map keeps this policy class alive.",
                )],
            ),
            SYMBOL_KIND_MODEL_METHOD => (
                Some("Reachable through a supported explicit model call from already-reachable code.".to_string()),
                vec![reason(
                    "supported_explicit_model_call",
                    "Already-reachable code calls this model helper through a supported explicit pattern.",
                )],
            ),
            SYMBOL_KIND_MODEL_SCOPE => (
                Some("Reachable through a supported explicit scope-call pattern.".to_string()),
                vec![reason(
                    "supported_scope_call",
                    "A supported explicit scope-call pattern keeps this local scope alive.",
                )],
            ),
            SYMBOL_KIND_MODEL_RELATIONSHIP => (
                Some("Reachable through supported explicit relationship access or eager loading.".to_string()),
                vec![reason(
                    "supported_relationship_usage",
                    "Supported explicit relationship access or eager-loading patterns keep this relationship alive.",
                )],
            ),
            SYMBOL_KIND_MODEL_ACCESSOR => (
                Some("Reachable through supported explicit attribute reads or append metadata.".to_string()),
                vec![reason(
                    "supported_attribute_read",
                    "Supported explicit attribute reads or append metadata keep this accessor alive.",
                )],
            ),
            SYMBOL_KIND_MODEL_MUTATOR => (
                Some("Reachable through supported explicit attribute writes.".to_string()),
                vec![reason(
                    "supported_attribute_write",
                    "Supported explicit attribute writes keep this mutator alive.",
                )],
            ),
            _ => (None, Vec::new()),
        }
    } else {
        (None, Vec::new())
    };

    SymbolRecord {
        kind: kind.to_string(),
        symbol,
        file,
        reachable_from_runtime,
        reason_summary,
        reachability_reasons,
        start_line,
        end_line,
    }
}

fn build_finding(
    symbol: String,
    category: &str,
    confidence: String,
    file: String,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Finding {
    let (reason_summary, evidence) = match category {
        FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD => (
            Some("No runtime route or supported controller call keeps this method alive.".to_string()),
            vec![reason(
                "no_supported_controller_reachability",
                "No Laravel runtime route or supported controller call expansion reaches this controller method.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_CONTROLLER_CLASS => (
            Some("All extracted controller methods are currently unreachable.".to_string()),
            vec![reason(
                "no_reachable_controller_methods",
                "Every extracted controller method is currently unreachable, so the controller class is dead.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_FORM_REQUEST => (
            Some("No supported typed controller parameter reaches this FormRequest.".to_string()),
            vec![reason(
                "no_supported_form_request_usage",
                "No reachable controller method uses this FormRequest as a supported explicit typed parameter.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_RESOURCE_CLASS => (
            Some("No supported controller resource usage reaches this resource.".to_string()),
            vec![reason(
                "no_supported_resource_usage",
                "No reachable controller method references this resource through a supported pattern.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_COMMAND_CLASS => (
            Some("This command is absent from runtime command registration.".to_string()),
            vec![reason(
                "not_runtime_registered_command",
                "Laravel runtime command registration does not include this command class.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_LISTENER_CLASS => (
            Some("This listener is absent from runtime listener registration.".to_string()),
            vec![reason(
                "not_runtime_registered_listener",
                "Laravel runtime listener registration does not include this listener class.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_SUBSCRIBER_CLASS => (
            Some("This subscriber is absent from explicit runtime subscriber registration.".to_string()),
            vec![reason(
                "not_runtime_registered_subscriber",
                "Explicit Laravel runtime subscriber registration does not include this subscriber class.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_JOB_CLASS => (
            Some("No supported explicit dispatch pattern reaches this job class.".to_string()),
            vec![reason(
                "no_supported_job_dispatch",
                "No supported explicit job dispatch pattern reaches this job class.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_POLICY_CLASS => (
            Some("This policy is absent from the runtime Gate policy map.".to_string()),
            vec![reason(
                "not_runtime_policy_map",
                "The Laravel Gate policy map does not reference this policy class.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_MODEL_METHOD => (
            Some("No supported explicit model call from already-reachable code reaches this method.".to_string()),
            vec![reason(
                "no_supported_model_call",
                "No supported explicit model helper call from already-reachable code reaches this method.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_MODEL_SCOPE => (
            Some("No supported explicit scope-call pattern reaches this local scope.".to_string()),
            vec![reason(
                "no_supported_scope_call",
                "No supported explicit scope-call pattern reaches this local scope.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_MODEL_RELATIONSHIP => (
            Some("No supported explicit relationship access or eager loading reaches this relationship.".to_string()),
            vec![reason(
                "no_supported_relationship_usage",
                "No supported explicit relationship access or eager-loading pattern reaches this relationship.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_MODEL_ACCESSOR => (
            Some("No supported explicit attribute read or append metadata reaches this accessor.".to_string()),
            vec![reason(
                "no_supported_attribute_read",
                "No supported explicit attribute read or append metadata reaches this accessor.",
            )],
        ),
        FINDING_CATEGORY_UNUSED_MODEL_MUTATOR => (
            Some("No supported explicit attribute write reaches this mutator.".to_string()),
            vec![reason(
                "no_supported_attribute_write",
                "No supported explicit attribute write reaches this mutator.",
            )],
        ),
        _ => (None, Vec::new()),
    };

    Finding {
        symbol,
        category: category.to_string(),
        confidence,
        file,
        reason_summary,
        evidence,
        start_line,
        end_line,
    }
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
    let reachable_model_relationships = collect_reachable_model_relationships(
        result,
        &source_index,
        &reachable_actions,
        &reachable_model_methods,
        &reachable_commands,
        &reachable_listeners,
        &reachable_subscribers,
        &reachable_jobs,
        &reachable_policies,
    );
    let reachable_model_accessors = collect_reachable_model_accessors(
        result,
        &source_index,
        &reachable_actions,
        &reachable_model_methods,
        &reachable_commands,
        &reachable_listeners,
        &reachable_subscribers,
        &reachable_jobs,
        &reachable_policies,
    );
    let reachable_model_mutators = collect_reachable_model_mutators(
        result,
        &source_index,
        &reachable_actions,
        &reachable_model_methods,
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            for accessor in &model.accessors {
                let symbol = format!("{}::{}", model.fqcn, accessor.name);
                let reachable_from_runtime = reachable_model_accessors.contains(&symbol);
                let line_range = find_model_attribute_line_range(file, accessor);
                let (start_line, end_line) = line_range
                    .map(|(start, end)| (Some(start), Some(end)))
                    .unwrap_or((None, None));

                symbols.push(SymbolRecord {
                    kind: SYMBOL_KIND_MODEL_ACCESSOR.to_string(),
                    symbol: symbol.clone(),
                    file: file.relative_path.clone(),
                    reachable_from_runtime,
                    start_line,
                    end_line,
                    ..Default::default()
                });

                if reachable_from_runtime {
                    continue;
                }

                findings.push(Finding {
                    symbol,
                    category: FINDING_CATEGORY_UNUSED_MODEL_ACCESSOR.to_string(),
                    confidence: CONFIDENCE_HIGH.to_string(),
                    file: file.relative_path.clone(),
                    start_line,
                    end_line,
                    ..Default::default()
                });
            }

            for mutator in &model.mutators {
                let symbol = format!("{}::{}", model.fqcn, mutator.name);
                let reachable_from_runtime = reachable_model_mutators.contains(&symbol);
                let line_range = find_model_attribute_line_range(file, mutator);
                let (start_line, end_line) = line_range
                    .map(|(start, end)| (Some(start), Some(end)))
                    .unwrap_or((None, None));

                symbols.push(SymbolRecord {
                    kind: SYMBOL_KIND_MODEL_MUTATOR.to_string(),
                    symbol: symbol.clone(),
                    file: file.relative_path.clone(),
                    reachable_from_runtime,
                    start_line,
                    end_line,
                    ..Default::default()
                });

                if reachable_from_runtime {
                    continue;
                }

                findings.push(Finding {
                    symbol,
                    category: FINDING_CATEGORY_UNUSED_MODEL_MUTATOR.to_string(),
                    confidence: CONFIDENCE_HIGH.to_string(),
                    file: file.relative_path.clone(),
                    start_line,
                    end_line,
                    ..Default::default()
                });
            }

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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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

            for relationship in &model.relationships {
                let symbol = format!("{}::{}", model.fqcn, relationship.name);
                let reachable_from_runtime = reachable_model_relationships.contains(&symbol);
                let line_range = find_model_relationship_line_range(file, relationship);
                let (start_line, end_line) = line_range
                    .map(|(start, end)| (Some(start), Some(end)))
                    .unwrap_or((None, None));

                symbols.push(SymbolRecord {
                    kind: SYMBOL_KIND_MODEL_RELATIONSHIP.to_string(),
                    symbol: symbol.clone(),
                    file: file.relative_path.clone(),
                    reachable_from_runtime,
                    start_line,
                    end_line,
                    ..Default::default()
                });

                if reachable_from_runtime {
                    continue;
                }

                findings.push(Finding {
                    symbol: symbol.clone(),
                    category: FINDING_CATEGORY_UNUSED_MODEL_RELATIONSHIP.to_string(),
                    confidence: CONFIDENCE_HIGH.to_string(),
                    file: file.relative_path.clone(),
                    start_line,
                    end_line,
                    ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

    for symbol in &mut symbols {
        if symbol.reason_summary.is_some() || !symbol.reachable_from_runtime {
            continue;
        }

        let enriched = build_symbol_record(
            &symbol.kind,
            symbol.symbol.clone(),
            symbol.file.clone(),
            symbol.reachable_from_runtime,
            symbol.start_line,
            symbol.end_line,
        );

        symbol.reason_summary = enriched.reason_summary;
        symbol.reachability_reasons = enriched.reachability_reasons;
    }

    for finding in &mut findings {
        if finding.reason_summary.is_some() {
            continue;
        }

        let enriched = build_finding(
            finding.symbol.clone(),
            &finding.category,
            finding.confidence.clone(),
            finding.file.clone(),
            finding.start_line,
            finding.end_line,
        );

        finding.reason_summary = enriched.reason_summary;
        finding.evidence = enriched.evidence;
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

fn collect_reachable_model_accessors(
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_actions: &BTreeSet<String>,
    reachable_model_methods: &BTreeSet<String>,
    reachable_commands: &BTreeSet<String>,
    reachable_listeners: &BTreeSet<String>,
    reachable_subscribers: &BTreeSet<String>,
    reachable_jobs: &BTreeSet<String>,
    reachable_policies: &BTreeSet<String>,
) -> BTreeSet<String> {
    let model_accessors = result
        .files
        .iter()
        .flat_map(|file| file.facts.models.iter())
        .map(|model| {
            (
                model.fqcn.clone(),
                model
                    .accessors
                    .iter()
                    .map(|accessor| accessor.name.clone())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let model_appends = result
        .files
        .iter()
        .flat_map(|file| file.facts.models.iter())
        .map(|model| (model.fqcn.clone(), model.appends.iter().cloned().collect()))
        .collect::<BTreeMap<String, BTreeSet<String>>>();
    let mut reachable_model_accessors = BTreeSet::new();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        let Some(source_class) = source_index.get(&controller.fqcn) else {
            continue;
        };

        collect_explicitly_read_model_attributes_from_text(
            &mut reachable_model_accessors,
            &controller.body_text,
            source_class,
            &model_accessors,
            &model_appends,
            None,
        );
    }

    collect_reachable_model_accessors_from_runtime_roots(
        &mut reachable_model_accessors,
        source_index,
        reachable_commands,
        &["handle"],
        &model_accessors,
        &model_appends,
    );
    collect_reachable_model_accessors_from_runtime_roots(
        &mut reachable_model_accessors,
        source_index,
        reachable_listeners,
        &["handle"],
        &model_accessors,
        &model_appends,
    );
    collect_reachable_model_accessors_from_runtime_roots(
        &mut reachable_model_accessors,
        source_index,
        reachable_subscribers,
        &["subscribe"],
        &model_accessors,
        &model_appends,
    );
    collect_reachable_model_accessors_from_runtime_roots(
        &mut reachable_model_accessors,
        source_index,
        reachable_jobs,
        &["handle"],
        &model_accessors,
        &model_appends,
    );
    collect_reachable_model_accessors_from_policies(
        &mut reachable_model_accessors,
        source_index,
        reachable_policies,
        &model_accessors,
        &model_appends,
    );
    collect_reachable_model_accessors_from_model_methods(
        &mut reachable_model_accessors,
        result,
        source_index,
        reachable_model_methods,
        &model_accessors,
        &model_appends,
    );

    reachable_model_accessors
}

fn collect_reachable_model_mutators(
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_actions: &BTreeSet<String>,
    reachable_model_methods: &BTreeSet<String>,
    reachable_commands: &BTreeSet<String>,
    reachable_listeners: &BTreeSet<String>,
    reachable_subscribers: &BTreeSet<String>,
    reachable_jobs: &BTreeSet<String>,
    reachable_policies: &BTreeSet<String>,
) -> BTreeSet<String> {
    let model_mutators = result
        .files
        .iter()
        .flat_map(|file| file.facts.models.iter())
        .map(|model| {
            (
                model.fqcn.clone(),
                model
                    .mutators
                    .iter()
                    .map(|mutator| mutator.name.clone())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reachable_model_mutators = BTreeSet::new();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        let Some(source_class) = source_index.get(&controller.fqcn) else {
            continue;
        };

        collect_explicitly_written_model_attributes_from_text(
            &mut reachable_model_mutators,
            &controller.body_text,
            source_class,
            &model_mutators,
            None,
        );
    }

    collect_reachable_model_mutators_from_runtime_roots(
        &mut reachable_model_mutators,
        source_index,
        reachable_commands,
        &["handle"],
        &model_mutators,
    );
    collect_reachable_model_mutators_from_runtime_roots(
        &mut reachable_model_mutators,
        source_index,
        reachable_listeners,
        &["handle"],
        &model_mutators,
    );
    collect_reachable_model_mutators_from_runtime_roots(
        &mut reachable_model_mutators,
        source_index,
        reachable_subscribers,
        &["subscribe"],
        &model_mutators,
    );
    collect_reachable_model_mutators_from_runtime_roots(
        &mut reachable_model_mutators,
        source_index,
        reachable_jobs,
        &["handle"],
        &model_mutators,
    );
    collect_reachable_model_mutators_from_policies(
        &mut reachable_model_mutators,
        source_index,
        reachable_policies,
        &model_mutators,
    );
    collect_reachable_model_mutators_from_model_methods(
        &mut reachable_model_mutators,
        result,
        source_index,
        reachable_model_methods,
        &model_mutators,
    );

    reachable_model_mutators
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

fn collect_reachable_model_relationships(
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_actions: &BTreeSet<String>,
    reachable_model_methods: &BTreeSet<String>,
    reachable_commands: &BTreeSet<String>,
    reachable_listeners: &BTreeSet<String>,
    reachable_subscribers: &BTreeSet<String>,
    reachable_jobs: &BTreeSet<String>,
    reachable_policies: &BTreeSet<String>,
) -> BTreeSet<String> {
    let model_relationships = result
        .files
        .iter()
        .flat_map(|file| file.facts.models.iter())
        .map(|model| {
            (
                model.fqcn.clone(),
                model
                    .relationships
                    .iter()
                    .map(|relationship| relationship.name.clone())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reachable_model_relationships = BTreeSet::new();

    for (_, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        if !reachable_actions.contains(&symbol) {
            continue;
        }

        let Some(source_class) = source_index.get(&controller.fqcn) else {
            continue;
        };

        for (model_fqcn, relationship_name) in extract_called_model_relationships_from_text(
            &controller.body_text,
            source_class,
            &model_relationships,
            None,
        ) {
            reachable_model_relationships.insert(format!("{model_fqcn}::{relationship_name}"));
        }
    }

    collect_reachable_model_relationships_from_runtime_roots(
        &mut reachable_model_relationships,
        source_index,
        reachable_commands,
        &["handle"],
        &model_relationships,
    );
    collect_reachable_model_relationships_from_runtime_roots(
        &mut reachable_model_relationships,
        source_index,
        reachable_listeners,
        &["handle"],
        &model_relationships,
    );
    collect_reachable_model_relationships_from_runtime_roots(
        &mut reachable_model_relationships,
        source_index,
        reachable_subscribers,
        &["subscribe"],
        &model_relationships,
    );
    collect_reachable_model_relationships_from_runtime_roots(
        &mut reachable_model_relationships,
        source_index,
        reachable_jobs,
        &["handle"],
        &model_relationships,
    );
    collect_reachable_model_relationships_from_policies(
        &mut reachable_model_relationships,
        source_index,
        reachable_policies,
        &model_relationships,
    );
    collect_reachable_model_relationships_from_model_methods(
        &mut reachable_model_relationships,
        result,
        source_index,
        reachable_model_methods,
        &model_relationships,
    );

    reachable_model_relationships
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

fn collect_reachable_model_accessors_from_runtime_roots(
    reachable_model_accessors: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    runtime_roots: &BTreeSet<String>,
    entrypoint_methods: &[&str],
    model_accessors: &BTreeMap<String, BTreeSet<String>>,
    model_appends: &BTreeMap<String, BTreeSet<String>>,
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

            collect_explicitly_read_model_attributes_from_text(
                reachable_model_accessors,
                &method_text,
                source_class,
                model_accessors,
                model_appends,
                None,
            );
        }
    }
}

fn collect_reachable_model_accessors_from_policies(
    reachable_model_accessors: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    reachable_policies: &BTreeSet<String>,
    model_accessors: &BTreeMap<String, BTreeSet<String>>,
    model_appends: &BTreeMap<String, BTreeSet<String>>,
) {
    for fqcn in reachable_policies {
        let Some(source_class) = source_index.get(fqcn) else {
            continue;
        };

        for method_text in extract_policy_entrypoint_texts(source_class) {
            collect_explicitly_read_model_attributes_from_text(
                reachable_model_accessors,
                &method_text,
                source_class,
                model_accessors,
                model_appends,
                None,
            );
        }
    }
}

fn collect_reachable_model_accessors_from_model_methods(
    reachable_model_accessors: &mut BTreeSet<String>,
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_model_methods: &BTreeSet<String>,
    model_accessors: &BTreeMap<String, BTreeSet<String>>,
    model_appends: &BTreeMap<String, BTreeSet<String>>,
) {
    for file in &result.files {
        for model in &file.facts.models {
            let Some(source_class) = source_index.get(&model.fqcn) else {
                continue;
            };

            for method in &model.methods {
                let symbol = format!("{}::{}", model.fqcn, method.name);
                if !reachable_model_methods.contains(&symbol) {
                    continue;
                }

                collect_explicitly_read_model_attributes_from_text(
                    reachable_model_accessors,
                    &method.body_text,
                    source_class,
                    model_accessors,
                    model_appends,
                    Some(&model.fqcn),
                );
            }
        }
    }
}

fn collect_reachable_model_mutators_from_runtime_roots(
    reachable_model_mutators: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    runtime_roots: &BTreeSet<String>,
    entrypoint_methods: &[&str],
    model_mutators: &BTreeMap<String, BTreeSet<String>>,
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

            collect_explicitly_written_model_attributes_from_text(
                reachable_model_mutators,
                &method_text,
                source_class,
                model_mutators,
                None,
            );
        }
    }
}

fn collect_reachable_model_mutators_from_policies(
    reachable_model_mutators: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    reachable_policies: &BTreeSet<String>,
    model_mutators: &BTreeMap<String, BTreeSet<String>>,
) {
    for fqcn in reachable_policies {
        let Some(source_class) = source_index.get(fqcn) else {
            continue;
        };

        for method_text in extract_policy_entrypoint_texts(source_class) {
            collect_explicitly_written_model_attributes_from_text(
                reachable_model_mutators,
                &method_text,
                source_class,
                model_mutators,
                None,
            );
        }
    }
}

fn collect_reachable_model_mutators_from_model_methods(
    reachable_model_mutators: &mut BTreeSet<String>,
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_model_methods: &BTreeSet<String>,
    model_mutators: &BTreeMap<String, BTreeSet<String>>,
) {
    for file in &result.files {
        for model in &file.facts.models {
            let Some(source_class) = source_index.get(&model.fqcn) else {
                continue;
            };

            for method in &model.methods {
                let symbol = format!("{}::{}", model.fqcn, method.name);
                if !reachable_model_methods.contains(&symbol) {
                    continue;
                }

                collect_explicitly_written_model_attributes_from_text(
                    reachable_model_mutators,
                    &method.body_text,
                    source_class,
                    model_mutators,
                    Some(&model.fqcn),
                );
            }
        }
    }
}

fn collect_reachable_model_relationships_from_runtime_roots(
    reachable_model_relationships: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    runtime_roots: &BTreeSet<String>,
    entrypoint_methods: &[&str],
    model_relationships: &BTreeMap<String, BTreeSet<String>>,
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

            for (model_fqcn, relationship_name) in extract_called_model_relationships_from_text(
                &method_text,
                source_class,
                model_relationships,
                None,
            ) {
                reachable_model_relationships.insert(format!("{model_fqcn}::{relationship_name}"));
            }
        }
    }
}

fn collect_reachable_model_relationships_from_policies(
    reachable_model_relationships: &mut BTreeSet<String>,
    source_index: &SourceIndex,
    reachable_policies: &BTreeSet<String>,
    model_relationships: &BTreeMap<String, BTreeSet<String>>,
) {
    for fqcn in reachable_policies {
        let Some(source_class) = source_index.get(fqcn) else {
            continue;
        };

        for method_text in extract_policy_entrypoint_texts(source_class) {
            for (model_fqcn, relationship_name) in extract_called_model_relationships_from_text(
                &method_text,
                source_class,
                model_relationships,
                None,
            ) {
                reachable_model_relationships.insert(format!("{model_fqcn}::{relationship_name}"));
            }
        }
    }
}

fn collect_reachable_model_relationships_from_model_methods(
    reachable_model_relationships: &mut BTreeSet<String>,
    result: &PipelineResult,
    source_index: &SourceIndex,
    reachable_model_methods: &BTreeSet<String>,
    model_relationships: &BTreeMap<String, BTreeSet<String>>,
) {
    for file in &result.files {
        for model in &file.facts.models {
            let Some(source_class) = source_index.get(&model.fqcn) else {
                continue;
            };

            for method in &model.methods {
                let symbol = format!("{}::{}", model.fqcn, method.name);
                if !reachable_model_methods.contains(&symbol) {
                    continue;
                }

                for (model_fqcn, relationship_name) in extract_called_model_relationships_from_text(
                    &method.body_text,
                    source_class,
                    model_relationships,
                    Some(&model.fqcn),
                ) {
                    reachable_model_relationships
                        .insert(format!("{model_fqcn}::{relationship_name}"));
                }
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

fn find_model_attribute_line_range(
    file: &AnalyzedFile,
    attribute: &ModelAttributeFact,
) -> Option<(usize, usize)> {
    file.source_text.find(&attribute.body_text).map(|start| {
        line_range_for_span(
            file.source_text.as_bytes(),
            start,
            start + attribute.body_text.len(),
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

fn find_model_relationship_line_range(
    file: &AnalyzedFile,
    relationship: &ModelRelationshipFact,
) -> Option<(usize, usize)> {
    let relationship_re = Regex::new(&format!(
        r#"(?m)\bfunction\s+{}\s*\("#,
        regex::escape(&relationship.name)
    ))
    .expect("model relationship line range regex");
    let relationship_match = relationship_re.find(&file.source_text)?;
    let brace_offset = file.source_text[relationship_match.end()..].find('{')?;
    let brace_start = relationship_match.end() + brace_offset;
    let (_, _, relationship_end_relative) =
        extract_balanced_region(&file.source_text[brace_start..], '{', '}')?;

    Some(line_range_for_span(
        file.source_text.as_bytes(),
        relationship_match.start(),
        brace_start + relationship_end_relative + 1,
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
    let known_models = model_methods.keys().cloned().collect::<BTreeSet<_>>();
    let model_variables =
        collect_model_variables_from_text(text, source_class, &known_models, None);

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

fn collect_explicitly_read_model_attributes_from_text(
    reachable_model_accessors: &mut BTreeSet<String>,
    text: &str,
    source_class: &SourceClass,
    model_accessors: &BTreeMap<String, BTreeSet<String>>,
    model_appends: &BTreeMap<String, BTreeSet<String>>,
    implicit_model_fqcn: Option<&str>,
) {
    for (model_fqcn, attribute_name) in extract_read_model_attributes_from_text(
        text,
        source_class,
        model_accessors,
        model_appends,
        implicit_model_fqcn,
    ) {
        reachable_model_accessors.insert(format!("{model_fqcn}::{attribute_name}"));
    }
}

fn collect_explicitly_written_model_attributes_from_text(
    reachable_model_mutators: &mut BTreeSet<String>,
    text: &str,
    source_class: &SourceClass,
    model_mutators: &BTreeMap<String, BTreeSet<String>>,
    implicit_model_fqcn: Option<&str>,
) {
    for (model_fqcn, attribute_name) in extract_written_model_attributes_from_text(
        text,
        source_class,
        model_mutators,
        implicit_model_fqcn,
    ) {
        reachable_model_mutators.insert(format!("{model_fqcn}::{attribute_name}"));
    }
}

fn extract_read_model_attributes_from_text(
    text: &str,
    source_class: &SourceClass,
    model_accessors: &BTreeMap<String, BTreeSet<String>>,
    model_appends: &BTreeMap<String, BTreeSet<String>>,
    implicit_model_fqcn: Option<&str>,
) -> BTreeSet<(String, String)> {
    let mut called = BTreeSet::new();
    let known_models = model_accessors.keys().cloned().collect::<BTreeSet<_>>();
    let model_variables =
        collect_model_variables_from_text(text, source_class, &known_models, implicit_model_fqcn);

    let instance_access_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)\b"#)
            .expect("accessor instance access regex");
    for captures in instance_access_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(attribute_name) = captures.get(2) else {
            continue;
        };
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let suffix = text[full_match.end()..].trim_start();
        if suffix.starts_with('(') || starts_with_assignment_operator(suffix) {
            continue;
        }
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        register_model_attribute_reference(
            &mut called,
            model_accessors,
            model_fqcn,
            attribute_name.as_str(),
        );
    }

    let get_attribute_re = Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)->(?:getAttribute|getAttributeValue)\s*\(\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .expect("explicit getAttribute regex");
    for captures in get_attribute_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(attribute_name) = captures.get(2) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        register_model_attribute_reference(
            &mut called,
            model_accessors,
            model_fqcn,
            attribute_name.as_str(),
        );
    }

    let serialize_re = Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)->(toArray|attributesToArray|toJson|jsonSerialize)\s*\("#,
    )
    .expect("model serialization regex");
    for captures in serialize_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        let Some(appended) = model_appends.get(model_fqcn) else {
            continue;
        };
        for attribute_name in appended {
            register_model_attribute_reference(
                &mut called,
                model_accessors,
                model_fqcn,
                attribute_name,
            );
        }
    }

    called
}

fn extract_written_model_attributes_from_text(
    text: &str,
    source_class: &SourceClass,
    model_mutators: &BTreeMap<String, BTreeSet<String>>,
    implicit_model_fqcn: Option<&str>,
) -> BTreeSet<(String, String)> {
    let mut called = BTreeSet::new();
    let known_models = model_mutators.keys().cloned().collect::<BTreeSet<_>>();
    let model_variables =
        collect_model_variables_from_text(text, source_class, &known_models, implicit_model_fqcn);

    let assignment_re = Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|\+=|-=|\.=|\*=|/=|%=|\?\?=)"#,
    )
    .expect("mutator assignment regex");
    for captures in assignment_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(attribute_name) = captures.get(2) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        register_model_attribute_reference(
            &mut called,
            model_mutators,
            model_fqcn,
            attribute_name.as_str(),
        );
    }

    let set_attribute_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)->setAttribute\s*\(\s*['"]([^'"]+)['"]\s*,"#)
            .expect("explicit setAttribute regex");
    for captures in set_attribute_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(attribute_name) = captures.get(2) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        register_model_attribute_reference(
            &mut called,
            model_mutators,
            model_fqcn,
            attribute_name.as_str(),
        );
    }

    let instance_bulk_write_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)->(fill|forceFill|update)\s*\("#)
            .expect("instance bulk write regex");
    for captures in instance_bulk_write_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        let args_start = full_match.end() - 1;
        let Some((argument_text, _, _)) = extract_balanced_region(&text[args_start..], '(', ')')
        else {
            continue;
        };
        register_model_attributes_from_argument_arrays(
            &mut called,
            model_mutators,
            model_fqcn,
            &argument_text,
        );
    }

    let static_bulk_write_re = Regex::new(
        r#"([A-Z][A-Za-z0-9_\\]*)::(create|forceCreate|firstOrCreate|firstOrNew|updateOrCreate)\s*\("#,
    )
    .expect("static bulk write regex");
    for captures in static_bulk_write_re.captures_iter(text) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let model_fqcn = source_class.resolve_name(class_name.as_str());
        if !model_mutators.contains_key(&model_fqcn) {
            continue;
        }
        let args_start = full_match.end() - 1;
        let Some((argument_text, _, _)) = extract_balanced_region(&text[args_start..], '(', ')')
        else {
            continue;
        };
        register_model_attributes_from_argument_arrays(
            &mut called,
            model_mutators,
            &model_fqcn,
            &argument_text,
        );
    }

    let constructor_hydration_re =
        Regex::new(r#"new\s+([A-Z][A-Za-z0-9_\\]*)\s*\("#).expect("constructor hydration regex");
    for captures in constructor_hydration_re.captures_iter(text) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let model_fqcn = source_class.resolve_name(class_name.as_str());
        if !model_mutators.contains_key(&model_fqcn) {
            continue;
        }
        let args_start = full_match.end() - 1;
        let Some((argument_text, _, _)) = extract_balanced_region(&text[args_start..], '(', ')')
        else {
            continue;
        };
        register_model_attributes_from_argument_arrays(
            &mut called,
            model_mutators,
            &model_fqcn,
            &argument_text,
        );
    }

    called
}

fn extract_called_model_relationships_from_text(
    text: &str,
    source_class: &SourceClass,
    model_relationships: &BTreeMap<String, BTreeSet<String>>,
    implicit_model_fqcn: Option<&str>,
) -> BTreeSet<(String, String)> {
    let mut called = BTreeSet::new();
    let known_models = model_relationships.keys().cloned().collect::<BTreeSet<_>>();
    let model_variables =
        collect_model_variables_from_text(text, source_class, &known_models, implicit_model_fqcn);

    let instance_call_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)\s*\("#)
            .expect("relationship instance call regex");
    for captures in instance_call_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(relationship_name) = captures.get(2) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        register_model_relationship_reference(
            &mut called,
            model_relationships,
            model_fqcn,
            relationship_name.as_str(),
        );
    }

    let instance_access_re =
        Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)\b"#)
            .expect("relationship instance access regex");
    for captures in instance_access_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(relationship_name) = captures.get(2) else {
            continue;
        };
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let suffix = &text[full_match.end()..];
        if suffix.trim_start().starts_with('(') {
            continue;
        }
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        register_model_relationship_reference(
            &mut called,
            model_relationships,
            model_fqcn,
            relationship_name.as_str(),
        );
    }

    let static_chain_re =
        Regex::new(r#"(?s)(\\?[A-Z][A-Za-z0-9_\\]*)::[A-Za-z_][A-Za-z0-9_]*\([^;]*"#)
            .expect("relationship static chain regex");
    for captures in static_chain_re.captures_iter(text) {
        let Some(class_name) = captures.get(1) else {
            continue;
        };
        let Some(chain_text) = captures.get(0) else {
            continue;
        };
        let model_fqcn = source_class.resolve_name(class_name.as_str());
        register_eager_loaded_model_relationships(
            &mut called,
            model_relationships,
            &model_fqcn,
            chain_text.as_str(),
        );
    }

    let eager_load_re = Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)->(load|loadMissing)\s*\("#)
        .expect("relationship instance eager load regex");
    for captures in eager_load_re.captures_iter(text) {
        let Some(variable_name) = captures.get(1) else {
            continue;
        };
        let Some(method_match) = captures.get(0) else {
            continue;
        };
        let Some(model_fqcn) = model_variables.get(variable_name.as_str()) else {
            continue;
        };
        let args_start = method_match.end() - 1;
        let Some((argument_text, _, _)) = extract_balanced_region(&text[args_start..], '(', ')')
        else {
            continue;
        };
        register_eager_loaded_model_relationships(
            &mut called,
            model_relationships,
            model_fqcn,
            &format!("->{}({argument_text})", &captures[2]),
        );
    }

    called
}

fn collect_model_variables_from_text(
    text: &str,
    source_class: &SourceClass,
    known_models: &BTreeSet<String>,
    implicit_model_fqcn: Option<&str>,
) -> BTreeMap<String, String> {
    let mut variables = BTreeMap::new();
    if let Some(model_fqcn) = implicit_model_fqcn {
        if known_models.contains(model_fqcn) {
            variables.insert("this".to_string(), model_fqcn.to_string());
        }
    }
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
        if known_models.contains(&resolved) {
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
        if known_models.contains(&resolved) {
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
        if known_models.contains(&resolved) {
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
        if known_models.contains(&resolved) {
            variables.insert(variable_name.as_str().to_string(), resolved);
        }
    }

    variables
}

fn register_model_attribute_reference(
    called: &mut BTreeSet<(String, String)>,
    model_attributes: &BTreeMap<String, BTreeSet<String>>,
    model_fqcn: &str,
    attribute_name: &str,
) {
    if model_attributes
        .get(model_fqcn)
        .is_some_and(|attributes| attributes.contains(attribute_name))
    {
        called.insert((model_fqcn.to_string(), attribute_name.to_string()));
    }
}

fn register_model_attributes_from_argument_arrays(
    called: &mut BTreeSet<(String, String)>,
    model_attributes: &BTreeMap<String, BTreeSet<String>>,
    model_fqcn: &str,
    argument_text: &str,
) {
    for argument in split_top_level(argument_text, ',') {
        for attribute_name in extract_php_array_attribute_keys(&argument) {
            register_model_attribute_reference(
                called,
                model_attributes,
                model_fqcn,
                &attribute_name,
            );
        }
    }
}

fn extract_php_array_attribute_keys(argument: &str) -> BTreeSet<String> {
    let Some((inner, _, _)) = extract_balanced_region(argument.trim(), '[', ']') else {
        return BTreeSet::new();
    };
    let mut attributes = BTreeSet::new();

    for entry in split_top_level(&inner, ',') {
        let Some((key, _)) = split_top_level_key_value(&entry) else {
            continue;
        };
        let Some(attribute_name) = strip_php_string(&key) else {
            continue;
        };
        attributes.insert(attribute_name);
    }

    attributes
}

fn starts_with_assignment_operator(value: &str) -> bool {
    ["=", "+=", "-=", ".=", "*=", "/=", "%=", "??="]
        .iter()
        .any(|operator| value.starts_with(operator))
}

fn register_model_relationship_reference(
    called: &mut BTreeSet<(String, String)>,
    model_relationships: &BTreeMap<String, BTreeSet<String>>,
    model_fqcn: &str,
    relationship_name: &str,
) {
    if model_relationships
        .get(model_fqcn)
        .is_some_and(|relationships| relationships.contains(relationship_name))
    {
        called.insert((model_fqcn.to_string(), relationship_name.to_string()));
    }
}

fn register_eager_loaded_model_relationships(
    called: &mut BTreeSet<(String, String)>,
    model_relationships: &BTreeMap<String, BTreeSet<String>>,
    model_fqcn: &str,
    text: &str,
) {
    let eager_load_re = Regex::new(r#"(?:->(?:with|load|loadMissing)|::with)\s*\("#)
        .expect("relationship eager load regex");
    let Some(known_relationships) = model_relationships.get(model_fqcn) else {
        return;
    };

    for method_match in eager_load_re.find_iter(text) {
        let args_start = method_match.end() - 1;
        let Some((argument_text, _, _)) = extract_balanced_region(&text[args_start..], '(', ')')
        else {
            continue;
        };

        for relationship_name in extract_eager_loaded_relationship_names(&argument_text) {
            if known_relationships.contains(&relationship_name) {
                called.insert((model_fqcn.to_string(), relationship_name));
            }
        }
    }
}

fn extract_eager_loaded_relationship_names(argument_text: &str) -> BTreeSet<String> {
    let mut relationships = BTreeSet::new();

    for argument in split_top_level(argument_text, ',') {
        collect_eager_loaded_relationship_names_from_value(&mut relationships, &argument);
    }

    relationships
}

fn collect_eager_loaded_relationship_names_from_value(
    relationships: &mut BTreeSet<String>,
    value: &str,
) {
    let trimmed = value.trim();

    if let Some(name) = strip_php_string(trimmed) {
        if let Some(normalized) = normalize_loaded_relationship_name(&name) {
            relationships.insert(normalized);
        }
        return;
    }

    if let Some((inner, _, _)) = extract_balanced_region(trimmed, '[', ']') {
        for entry in split_top_level(&inner, ',') {
            if let Some((key, raw_value)) = split_top_level_key_value(&entry) {
                if let Some(key_name) = strip_php_string(&key)
                    .and_then(|name| normalize_loaded_relationship_name(&name))
                {
                    relationships.insert(key_name);
                }
                collect_eager_loaded_relationship_names_from_value(relationships, &raw_value);
                continue;
            }

            collect_eager_loaded_relationship_names_from_value(relationships, &entry);
        }
    }
}

fn normalize_loaded_relationship_name(name: &str) -> Option<String> {
    let candidate = name
        .trim()
        .split(['.', ':'])
        .next()
        .unwrap_or_default()
        .trim();

    (!candidate.is_empty()).then(|| candidate.to_string())
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use serde_json::json;

    use super::{
        analyze_controller_reachability, extract_read_model_attributes_from_text,
        extract_written_model_attributes_from_text,
    };
    use crate::contracts::AnalysisRequest;
    use crate::model::{
        AnalyzedFile, ControllerMethod, FileFacts, ModelFacts, ModelMethodFact,
        ModelRelationshipFact, ScopeUsageFact,
    };
    use crate::pipeline::PipelineResult;
    use crate::source_index::parse_source_class;

    #[test]
    fn explicit_model_attribute_reads_and_writes_are_extracted_conservatively() {
        let controller_source = r#"<?php

namespace App\Http\Controllers;

use App\Models\User;

final class UserController
{
    public function index(): array
    {
        $user = new User();
        $user->display_name = trim($user->display_name);

        return [$user->display_name];
    }
}
"#;
        let source_class =
            parse_source_class(controller_source, "app/Http/Controllers/UserController.php")
                .expect("controller should parse");
        let model_accessors = BTreeMap::from([(
            "App\\Models\\User".to_string(),
            BTreeSet::from(["display_name".to_string(), "secret_name".to_string()]),
        )]);
        let model_mutators = BTreeMap::from([(
            "App\\Models\\User".to_string(),
            BTreeSet::from(["display_name".to_string(), "secret_name".to_string()]),
        )]);

        let reads = extract_read_model_attributes_from_text(
            controller_source,
            &source_class,
            &model_accessors,
            &BTreeMap::new(),
            None,
        );
        let writes = extract_written_model_attributes_from_text(
            controller_source,
            &source_class,
            &model_mutators,
            None,
        );

        assert!(reads.contains(&("App\\Models\\User".to_string(), "display_name".to_string())));
        assert!(!reads.contains(&("App\\Models\\User".to_string(), "secret_name".to_string())));
        assert!(writes.contains(&("App\\Models\\User".to_string(), "display_name".to_string())));
        assert!(!writes.contains(&("App\\Models\\User".to_string(), "secret_name".to_string())));
    }

    #[test]
    fn bulk_model_mutator_write_paths_are_extracted_conservatively() {
        let controller_source = r#"<?php

namespace App\Http\Controllers;

use App\Models\User;

final class UserController
{
    public function store(): void
    {
        $user = new User(['display_name' => 'Ada']);
        $user->fill(['display_name' => 'Grace']);
        $user->update(['display_name' => 'Linus']);
        User::create(['display_name' => 'Margaret']);
        User::updateOrCreate(['email' => 'ada@example.com'], ['display_name' => 'Ada']);
    }
}
"#;
        let source_class =
            parse_source_class(controller_source, "app/Http/Controllers/UserController.php")
                .expect("controller should parse");
        let model_mutators = BTreeMap::from([(
            "App\\Models\\User".to_string(),
            BTreeSet::from(["display_name".to_string(), "secret_name".to_string()]),
        )]);

        let writes = extract_written_model_attributes_from_text(
            controller_source,
            &source_class,
            &model_mutators,
            None,
        );

        assert!(writes.contains(&("App\\Models\\User".to_string(), "display_name".to_string())));
        assert!(!writes.contains(&("App\\Models\\User".to_string(), "secret_name".to_string())));
    }

    #[test]
    fn reachable_model_method_keeps_explicit_accessor_and_mutator_alive() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let request: AnalysisRequest = serde_json::from_value(json!({
            "contractVersion": "deadcode.analysis.v1",
            "requestId": "req-model-attribute-method-propagation",
            "runtimeFingerprint": "fp-model-attribute-method-propagation",
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
                    "attribute_make": true
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
                        "routeId": "users.show",
                        "methods": ["GET"],
                        "uri": "users/{user}",
                        "domain": null,
                        "name": "users.show",
                        "prefix": null,
                        "middleware": [],
                        "where": {},
                        "defaults": {},
                        "bindings": [],
                        "action": {
                            "kind": "controller_method",
                            "fqcn": "App\\Http\\Controllers\\UserController",
                            "method": "show"
                        }
                    }
                ]
            }
        }))
        .expect("request should deserialize");
        let controller_source = r#"<?php

namespace App\Http\Controllers;

use App\Models\User;

final class UserController
{
    public function show(User $user): array
    {
        return [$user->present()];
    }
}
"#;
        let model_source = r#"<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    public function present(): array
    {
        $this->display_name = trim($this->display_name);

        return [$this->display_name];
    }

    public function getDisplayNameAttribute($value)
    {
        return trim($value);
    }

    public function setDisplayNameAttribute($value)
    {
        $this->attributes['display_name'] = trim($value);
    }
}
"#;
        let result = PipelineResult {
            files: vec![
                AnalyzedFile {
                    path: root.join("app/Http/Controllers/UserController.php"),
                    relative_path: "app/Http/Controllers/UserController.php".to_string(),
                    source_text: controller_source.to_string(),
                    facts: FileFacts {
                        controllers: vec![ControllerMethod {
                            class_name: "UserController".to_string(),
                            fqcn: "App\\Http\\Controllers\\UserController".to_string(),
                            method_name: "show".to_string(),
                            body_text: "public function show(User $user): array\n    {\n        return [$user->present()];\n    }".to_string(),
                            ..ControllerMethod::default()
                        }],
                        ..FileFacts::default()
                    },
                },
                AnalyzedFile {
                    path: root.join("app/Models/User.php"),
                    relative_path: "app/Models/User.php".to_string(),
                    source_text: model_source.to_string(),
                    facts: FileFacts {
                        models: vec![ModelFacts {
                            class_name: "User".to_string(),
                            fqcn: "App\\Models\\User".to_string(),
                            accessors: vec![crate::model::ModelAttributeFact {
                                name: "display_name".to_string(),
                                body_text: "public function getDisplayNameAttribute($value)\n    {\n        return trim($value);\n    }".to_string(),
                                via: "legacy_accessor".to_string(),
                            }],
                            mutators: vec![crate::model::ModelAttributeFact {
                                name: "display_name".to_string(),
                                body_text: "public function setDisplayNameAttribute($value)\n    {\n        $this->attributes['display_name'] = trim($value);\n    }".to_string(),
                                via: "legacy_mutator".to_string(),
                            }],
                            methods: vec![ModelMethodFact {
                                name: "present".to_string(),
                                body_text: "public function present(): array\n    {\n        $this->display_name = trim($this->display_name);\n\n        return [$this->display_name];\n    }".to_string(),
                            }],
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

        assert!(report.symbols.iter().any(|symbol| {
            symbol.kind == "model_method"
                && symbol.symbol == "App\\Models\\User::present"
                && symbol.reachable_from_runtime
        }));
        assert!(report.symbols.iter().any(|symbol| {
            symbol.kind == "model_accessor"
                && symbol.symbol == "App\\Models\\User::display_name"
                && symbol.reachable_from_runtime
        }));
        assert!(report.symbols.iter().any(|symbol| {
            symbol.kind == "model_mutator"
                && symbol.symbol == "App\\Models\\User::display_name"
                && symbol.reachable_from_runtime
        }));
        assert!(!report.findings.iter().any(|finding| {
            finding.category == "unused_model_accessor"
                && finding.symbol == "App\\Models\\User::display_name"
        }));
        assert!(!report.findings.iter().any(|finding| {
            finding.category == "unused_model_mutator"
                && finding.symbol == "App\\Models\\User::display_name"
        }));
    }

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
                            accessors: Vec::new(),
                            mutators: Vec::new(),
                            appends: Vec::new(),
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

    #[test]
    fn reachable_model_method_keeps_explicit_relationship_alive() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let request: AnalysisRequest = serde_json::from_value(json!({
            "contractVersion": "deadcode.analysis.v1",
            "requestId": "req-model-relationship-method-propagation",
            "runtimeFingerprint": "fp-model-relationship-method-propagation",
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
                    "resource_usage": false
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
                        "routeId": "invoices.show",
                        "methods": ["GET"],
                        "uri": "invoices/{invoice}",
                        "domain": null,
                        "name": "invoices.show",
                        "prefix": null,
                        "middleware": [],
                        "where": {},
                        "defaults": {},
                        "bindings": [],
                        "action": {
                            "kind": "controller_method",
                            "fqcn": "App\\Http\\Controllers\\InvoiceController",
                            "method": "show"
                        }
                    }
                ]
            }
        }))
        .expect("request should deserialize");
        let controller_source = r#"<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

final class InvoiceController
{
    public function show(Invoice $invoice): array
    {
        return [$invoice->summary()];
    }
}
"#;
        let model_source = r#"<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    public function summary(): array
    {
        return [$this->customer];
    }

    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }

    public function legacyNotes()
    {
        return $this->hasMany(Note::class);
    }
}
"#;
        let result = PipelineResult {
            files: vec![
                AnalyzedFile {
                    path: root.join("app/Http/Controllers/InvoiceController.php"),
                    relative_path: "app/Http/Controllers/InvoiceController.php".to_string(),
                    source_text: controller_source.to_string(),
                    facts: FileFacts {
                        controllers: vec![ControllerMethod {
                            class_name: "InvoiceController".to_string(),
                            fqcn: "App\\Http\\Controllers\\InvoiceController".to_string(),
                            method_name: "show".to_string(),
                            body_text: "public function show(Invoice $invoice): array\n    {\n        return [$invoice->summary()];\n    }".to_string(),
                            ..ControllerMethod::default()
                        }],
                        ..FileFacts::default()
                    },
                },
                AnalyzedFile {
                    path: root.join("app/Models/Invoice.php"),
                    relative_path: "app/Models/Invoice.php".to_string(),
                    source_text: model_source.to_string(),
                    facts: FileFacts {
                        models: vec![ModelFacts {
                            class_name: "Invoice".to_string(),
                            fqcn: "App\\Models\\Invoice".to_string(),
                            relationships: vec![
                                ModelRelationshipFact {
                                    name: "customer".to_string(),
                                    relation_type: "belongsTo".to_string(),
                                    related: Some("App\\Models\\Customer".to_string()),
                                    pivot_columns: Vec::new(),
                                    pivot_alias: None,
                                    pivot_timestamps: false,
                                    morph_name: None,
                                },
                                ModelRelationshipFact {
                                    name: "legacyNotes".to_string(),
                                    relation_type: "hasMany".to_string(),
                                    related: Some("App\\Models\\Note".to_string()),
                                    pivot_columns: Vec::new(),
                                    pivot_alias: None,
                                    pivot_timestamps: false,
                                    morph_name: None,
                                },
                            ],
                            methods: vec![ModelMethodFact {
                                name: "summary".to_string(),
                                body_text: "public function summary(): array\n    {\n        return [$this->customer];\n    }".to_string(),
                            }],
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

        assert!(report.symbols.iter().any(|symbol| {
            symbol.kind == "model_method"
                && symbol.symbol == "App\\Models\\Invoice::summary"
                && symbol.reachable_from_runtime
        }));
        assert!(report.symbols.iter().any(|symbol| {
            symbol.kind == "model_relationship"
                && symbol.symbol == "App\\Models\\Invoice::customer"
                && symbol.reachable_from_runtime
        }));
        assert!(!report.findings.iter().any(|finding| {
            finding.category == "unused_model_relationship"
                && finding.symbol == "App\\Models\\Invoice::customer"
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "unused_model_relationship"
                && finding.symbol == "App\\Models\\Invoice::legacyNotes"
        }));
    }

    #[test]
    fn static_with_keeps_explicit_relationship_alive() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let request: AnalysisRequest = serde_json::from_value(json!({
            "contractVersion": "deadcode.analysis.v1",
            "requestId": "req-model-relationship-static-with",
            "runtimeFingerprint": "fp-model-relationship-static-with",
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
                    "resource_usage": false
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
                        "routeId": "invoices.index",
                        "methods": ["GET"],
                        "uri": "invoices",
                        "domain": null,
                        "name": "invoices.index",
                        "prefix": null,
                        "middleware": [],
                        "where": {},
                        "defaults": {},
                        "bindings": [],
                        "action": {
                            "kind": "controller_method",
                            "fqcn": "App\\Http\\Controllers\\InvoiceController",
                            "method": "index"
                        }
                    }
                ]
            }
        }))
        .expect("request should deserialize");
        let controller_source = r#"<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

final class InvoiceController
{
    public function index(): array
    {
        return [Invoice::with('customer')->firstOrFail()];
    }
}
"#;
        let model_source = r#"<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }

    public function legacyNotes()
    {
        return $this->hasMany(Note::class);
    }
}
"#;
        let result = PipelineResult {
            files: vec![
                AnalyzedFile {
                    path: root.join("app/Http/Controllers/InvoiceController.php"),
                    relative_path: "app/Http/Controllers/InvoiceController.php".to_string(),
                    source_text: controller_source.to_string(),
                    facts: FileFacts {
                        controllers: vec![ControllerMethod {
                            class_name: "InvoiceController".to_string(),
                            fqcn: "App\\Http\\Controllers\\InvoiceController".to_string(),
                            method_name: "index".to_string(),
                            body_text: "public function index(): array\n    {\n        return [Invoice::with('customer')->firstOrFail()];\n    }".to_string(),
                            ..ControllerMethod::default()
                        }],
                        ..FileFacts::default()
                    },
                },
                AnalyzedFile {
                    path: root.join("app/Models/Invoice.php"),
                    relative_path: "app/Models/Invoice.php".to_string(),
                    source_text: model_source.to_string(),
                    facts: FileFacts {
                        models: vec![ModelFacts {
                            class_name: "Invoice".to_string(),
                            fqcn: "App\\Models\\Invoice".to_string(),
                            relationships: vec![
                                ModelRelationshipFact {
                                    name: "customer".to_string(),
                                    relation_type: "belongsTo".to_string(),
                                    related: Some("App\\Models\\Customer".to_string()),
                                    pivot_columns: Vec::new(),
                                    pivot_alias: None,
                                    pivot_timestamps: false,
                                    morph_name: None,
                                },
                                ModelRelationshipFact {
                                    name: "legacyNotes".to_string(),
                                    relation_type: "hasMany".to_string(),
                                    related: Some("App\\Models\\Note".to_string()),
                                    pivot_columns: Vec::new(),
                                    pivot_alias: None,
                                    pivot_timestamps: false,
                                    morph_name: None,
                                },
                            ],
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

        assert!(report.symbols.iter().any(|symbol| {
            symbol.kind == "model_relationship"
                && symbol.symbol == "App\\Models\\Invoice::customer"
                && symbol.reachable_from_runtime
        }));
        assert!(!report.findings.iter().any(|finding| {
            finding.category == "unused_model_relationship"
                && finding.symbol == "App\\Models\\Invoice::customer"
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "unused_model_relationship"
                && finding.symbol == "App\\Models\\Invoice::legacyNotes"
        }));
    }
}
