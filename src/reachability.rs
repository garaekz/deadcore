use std::collections::{BTreeMap, BTreeSet, VecDeque};

use regex::Regex;

use crate::contracts::{AnalysisRequest, Entrypoint, RemovalChangeSet, RemovalPlan};
use crate::deadcode_model::{
    CONFIDENCE_HIGH, FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD, Finding,
    SYMBOL_KIND_CONTROLLER_METHOD, SymbolRecord,
};
use crate::model::ControllerMethod;
use crate::parser::line_range_for_span;
use crate::pipeline::PipelineResult;
use crate::source_index::{SourceClass, SourceIndex};

pub struct ControllerReachabilityReport {
    pub entrypoints: Vec<Entrypoint>,
    pub symbols: Vec<SymbolRecord>,
    pub findings: Vec<Finding>,
    pub removal_plan: RemovalPlan,
}

pub fn analyze_controller_reachability(
    request: &AnalysisRequest,
    result: &PipelineResult,
) -> ControllerReachabilityReport {
    let call_graph = build_controller_call_graph(result);
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

    let mut symbols = Vec::new();
    let mut findings = Vec::new();
    let mut change_sets = Vec::new();

    for (file, controller) in result.controller_methods() {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        let reachable_from_runtime = reachable_actions.contains(&symbol);
        let line_range = file.source_text.find(&controller.body_text).map(|start| {
            line_range_for_span(
                file.source_text.as_bytes(),
                start,
                start + controller.body_text.len(),
            )
        });

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

fn build_controller_call_graph(result: &PipelineResult) -> BTreeMap<String, BTreeSet<String>> {
    let mut methods_by_controller = BTreeMap::<String, BTreeSet<String>>::new();
    let mut controller_records = Vec::new();
    let source_index = SourceIndex::build(result);

    for (file, controller) in result.controller_methods() {
        methods_by_controller
            .entry(controller.fqcn.clone())
            .or_default()
            .insert(controller.method_name.clone());
        controller_records.push((file.relative_path.clone(), controller));
    }

    let mut call_graph = BTreeMap::<String, BTreeSet<String>>::new();
    for (relative_path, controller) in controller_records {
        let symbol = format!("{}::{}", controller.fqcn, controller.method_name);
        let source_class = source_index
            .classes
            .values()
            .find(|class| class.relative_path == relative_path);
        let callees = collect_controller_callees(controller, source_class, &methods_by_controller);
        call_graph.insert(symbol, callees);
    }

    call_graph
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

        let called_class = class_name.as_str().trim_start_matches('\\');
        let resolved_class =
            if called_class == controller.class_name || called_class == controller.fqcn {
                controller.fqcn.clone()
            } else if let Some(source_class) = source_class {
                source_class.resolve_name(called_class)
            } else {
                called_class.to_string()
            };

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
