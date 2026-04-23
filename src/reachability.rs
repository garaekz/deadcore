use std::collections::BTreeSet;

use crate::contracts::{AnalysisRequest, Entrypoint, RemovalChangeSet, RemovalPlan};
use crate::deadcode_model::{
    CONFIDENCE_HIGH, FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD, Finding,
    SYMBOL_KIND_CONTROLLER_METHOD, SymbolRecord,
};
use crate::parser::line_range_for_span;
use crate::pipeline::PipelineResult;

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
    let mut reachable_actions = BTreeSet::new();
    let mut entrypoints = Vec::new();

    for route in &request.runtime.routes {
        let Some(action_key) = route.action.action_key() else {
            continue;
        };
        if reachable_actions.insert(action_key.clone()) {
            entrypoints.push(Entrypoint {
                kind: "runtime_route".to_string(),
                symbol: action_key,
                source: route.route_id.clone(),
            });
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
