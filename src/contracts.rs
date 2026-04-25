#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::contract_authorization::build_static_authorization;
use crate::contract_error_responses::infer_framework_error_responses;
use crate::contract_inertia::infer_inertia_response;
use crate::contract_query_builder::extend_query_builder_request;
use crate::deadcode_model::{Finding, SymbolRecord};
use crate::manifest::Manifest;
use crate::model::{ControllerMethod, ModelFacts, ModelRelationshipFact, ResourceUsageFact};
use crate::pipeline::PipelineResult;
use crate::reachability::analyze_controller_reachability;
use crate::source_index::{
    SourceClass, SourceIndex, extract_balanced_region, extract_return_array, split_top_level,
    split_top_level_key_value, strip_php_string,
};

pub const CONTRACT_VERSION: &str = "deadcode.analysis.v1";
const ACTION_KIND_CONTROLLER_METHOD: &str = "controller_method";
const ACTION_KIND_INVOKABLE_CONTROLLER: &str = "invokable_controller";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeadCodeMeta {
    pub duration_ms: u128,
    pub cache_hits: usize,
    pub cache_misses: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportMeta {
    pub duration_ms: u128,
    pub cache_hits: usize,
    pub cache_misses: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entrypoint {
    pub kind: String,
    pub symbol: String,
    pub source: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemovalPlan {
    #[serde(rename = "changeSets")]
    pub change_sets: Vec<RemovalChangeSet>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemovalChangeSet {
    pub file: String,
    pub symbol: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeadCodeReport {
    pub meta: ReportMeta,
    pub entrypoints: Vec<Entrypoint>,
    pub symbols: Vec<SymbolRecord>,
    pub findings: Vec<Finding>,
    #[serde(rename = "removalPlan")]
    pub removal_plan: RemovalPlan,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeadCodeResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: String,
    pub meta: DeadCodeMeta,
    pub entrypoints: Vec<Entrypoint>,
    pub symbols: Vec<SymbolRecord>,
    pub findings: Vec<Finding>,
    #[serde(rename = "removalPlan")]
    pub removal_plan: RemovalPlan,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisRequest {
    #[serde(rename = "contractVersion")]
    pub contract_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "runtimeFingerprint")]
    pub runtime_fingerprint: String,
    pub manifest: Manifest,
    pub runtime: RuntimeSnapshot,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSnapshot {
    pub app: RuntimeApp,
    #[serde(default)]
    pub routes: Vec<RuntimeRoute>,
    #[serde(default)]
    pub policies: Vec<RuntimePolicy>,
    #[serde(default)]
    pub commands: Vec<RuntimeCommand>,
    #[serde(default)]
    pub listeners: Vec<RuntimeListener>,
    #[serde(default)]
    pub subscribers: Vec<RuntimeSubscriber>,
    #[serde(default)]
    pub jobs: Vec<RuntimeJob>,
    #[serde(default)]
    pub packages: Vec<RuntimePackage>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeApp {
    #[serde(rename = "basePath")]
    pub base_path: String,
    #[serde(rename = "laravelVersion")]
    pub laravel_version: String,
    #[serde(rename = "phpVersion")]
    pub php_version: String,
    #[serde(rename = "appEnv")]
    pub app_env: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRoute {
    #[serde(rename = "routeId")]
    pub route_id: String,
    #[serde(default)]
    pub methods: Vec<String>,
    pub uri: String,
    pub domain: Option<String>,
    pub name: Option<String>,
    pub prefix: Option<String>,
    #[serde(default)]
    pub middleware: Vec<String>,
    #[serde(rename = "where", default)]
    pub where_map: BTreeMap<String, Value>,
    #[serde(default)]
    pub defaults: BTreeMap<String, Value>,
    #[serde(default)]
    pub bindings: Vec<RouteBinding>,
    pub action: RouteAction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePackage {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCommand {
    pub signature: String,
    pub fqcn: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    #[serde(rename = "modelFqcn")]
    pub model_fqcn: String,
    #[serde(rename = "policyFqcn")]
    pub policy_fqcn: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeListener {
    #[serde(rename = "eventFqcn")]
    pub event_fqcn: String,
    #[serde(rename = "listenerFqcn")]
    pub listener_fqcn: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSubscriber {
    pub fqcn: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeJob {
    pub fqcn: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBinding {
    pub parameter: String,
    pub kind: String,
    #[serde(rename = "targetFqcn")]
    pub target_fqcn: Option<String>,
    #[serde(rename = "isImplicit")]
    pub is_implicit: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAction {
    pub kind: String,
    pub fqcn: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractController {
    pub fqcn: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<ContractHttpInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<ContractRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<ContractResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization: Vec<ContractAuthorization>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ContractControllerResource>,
    #[serde(default, rename = "scopesUsed", skip_serializing_if = "Vec::is_empty")]
    pub scopes_used: Vec<ContractScopeUsed>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub polymorphic: Vec<ContractPolymorphicRelation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractHttpInfo {
    pub status: u16,
    pub explicit: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractRequest {
    #[serde(
        default,
        rename = "contentTypes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub content_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<ShapeTree>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<ShapeTree>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<ShapeTree>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<ContractRequestField>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(transparent)]
pub struct ShapeTree(pub BTreeMap<String, ShapeTree>);

#[derive(Debug, Clone, Serialize)]
pub struct ContractRequestField {
    pub location: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(rename = "scalarType", skip_serializing_if = "Option::is_none")]
    pub scalar_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "itemType", skip_serializing_if = "Option::is_none")]
    pub item_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrappers: Vec<String>,
    #[serde(
        rename = "allowedValues",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_values: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(rename = "isArray", skip_serializing_if = "Option::is_none")]
    pub is_array: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractResponse {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit: Option<bool>,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(rename = "bodySchema", skip_serializing_if = "Option::is_none")]
    pub body_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<ContractRedirect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<ContractDownload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inertia: Option<ContractInertia>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractRedirect {
    #[serde(rename = "targetKind")]
    pub target_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractDownload {
    pub disposition: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractInertia {
    pub component: String,
    #[serde(rename = "propsSchema", skip_serializing_if = "Option::is_none")]
    pub props_schema: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractAuthorization {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ability: Option<String>,
    #[serde(rename = "targetKind", skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    pub source: String,
    pub resolution: String,
    #[serde(rename = "enforcesFailureResponse")]
    pub enforces_failure_response: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractControllerResource {
    pub class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqcn: Option<String>,
    pub collection: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractScopeUsed {
    pub on: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractPolymorphicRelation {
    pub relation: String,
    #[serde(rename = "type")]
    pub relation_type: String,
    #[serde(rename = "morphType", skip_serializing_if = "Option::is_none")]
    pub morph_type: Option<String>,
    #[serde(rename = "morphId", skip_serializing_if = "Option::is_none")]
    pub morph_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<ContractDiscriminator>,
    #[serde(
        default,
        rename = "relatedModels",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub related_models: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractDiscriminator {
    #[serde(rename = "propertyName")]
    pub property_name: String,
    pub mapping: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractModel {
    pub fqcn: String,
    #[serde(default, rename = "withPivot", skip_serializing_if = "Vec::is_empty")]
    pub with_pivot: Vec<ContractPivot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<ContractAttribute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub polymorphic: Vec<ContractPolymorphicRelation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractPivot {
    pub relation: String,
    pub columns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamps: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractAttribute {
    pub name: String,
    pub via: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractResource {
    pub fqcn: String,
    pub class: String,
    pub schema: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractPolymorphicGroup {
    pub parent: String,
    pub morph: ContractMorph,
    pub discriminator: ContractDiscriminator,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractMorph {
    pub key: String,
    #[serde(rename = "typeColumn")]
    pub type_column: String,
    #[serde(rename = "idColumn")]
    pub id_column: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractBroadcast {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub channel: String,
    pub params: Vec<String>,
    pub visibility: String,
    #[serde(rename = "payloadLiteral", skip_serializing_if = "Option::is_none")]
    pub payload_literal: Option<bool>,
}

#[derive(Debug, Clone, Default)]
struct ParsedRuleField {
    location: String,
    path: String,
    kind: Option<String>,
    type_name: Option<String>,
    scalar_type: Option<String>,
    format: Option<String>,
    item_type: Option<String>,
    wrappers: Vec<String>,
    allowed_values: Vec<String>,
    required: Option<bool>,
    optional: Option<bool>,
    nullable: Option<bool>,
    is_array: Option<bool>,
    collection: Option<bool>,
    source: Option<String>,
    via: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct SpatieDataFieldSpec {
    kind: Option<String>,
    type_name: Option<String>,
    scalar_type: Option<String>,
    item_type: Option<String>,
    wrappers: Vec<String>,
    required: Option<bool>,
    optional: Option<bool>,
    nullable: Option<bool>,
    is_array: Option<bool>,
    collection: Option<bool>,
}

#[derive(Debug, Clone, Default)]
struct ModelSchemaHint {
    fillable: BTreeSet<String>,
    hidden: BTreeSet<String>,
    casts: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct JsonResponseCall {
    payload: String,
    status: Option<u16>,
}

#[derive(Debug, Clone, Default)]
struct ControllerSourceState {
    parameters: BTreeMap<String, String>,
    assignments: BTreeMap<String, String>,
}

impl ShapeTree {
    pub(crate) fn insert_path(&mut self, path: &str) {
        if path.is_empty() || path == "*" {
            return;
        }

        let mut current = self;
        for segment in path.split('.').filter(|segment| !segment.is_empty()) {
            current = current.0.entry(segment.to_string()).or_default();
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AnalysisRequest {
    pub fn normalize(&mut self) {
        for route in &mut self.runtime.routes {
            if route.action.kind == ACTION_KIND_INVOKABLE_CONTROLLER
                && route.action.method.is_none()
            {
                route.action.method = Some("__invoke".to_string());
            }
        }
    }
}

impl RouteAction {
    pub fn action_key(&self) -> Option<String> {
        match self.kind.as_str() {
            ACTION_KIND_CONTROLLER_METHOD | ACTION_KIND_INVOKABLE_CONTROLLER => {
                let fqcn = self.fqcn.as_ref()?;
                let method = self.method.as_ref()?;
                if fqcn.is_empty() || method.is_empty() {
                    return None;
                }
                Some(format!("{fqcn}::{method}"))
            }
            _ => None,
        }
    }
}

pub fn load_analysis_request_from_slice(
    data: &[u8],
    source_path: Option<&Path>,
) -> Result<AnalysisRequest> {
    let mut request: AnalysisRequest = serde_json::from_slice(data)?;
    if request.contract_version != CONTRACT_VERSION {
        bail!("analysis request validation failed: unsupported contractVersion");
    }
    if let Some(path) = source_path {
        request.manifest.resolve_paths(path);
    }
    request.normalize();
    validate_request_business_rules(&request)?;
    Ok(request)
}

pub fn build_deadcode_response(
    request: &AnalysisRequest,
    result: &PipelineResult,
) -> DeadCodeResponse {
    let reachability = analyze_controller_reachability(request, result);

    DeadCodeResponse {
        contract_version: CONTRACT_VERSION.to_string(),
        request_id: request.request_id.clone(),
        status: if result.partial {
            "partial".to_string()
        } else {
            "ok".to_string()
        },
        meta: DeadCodeMeta {
            duration_ms: result.duration_ms,
            cache_hits: result.cache_hits,
            cache_misses: result.cache_misses,
        },
        entrypoints: reachability.entrypoints,
        symbols: reachability.symbols,
        findings: reachability.findings,
        removal_plan: reachability.removal_plan,
    }
}

fn validate_request_business_rules(request: &AnalysisRequest) -> Result<()> {
    let base_path = Path::new(&request.runtime.app.base_path);
    if !base_path.is_absolute() {
        bail!("runtime.app.basePath must be an absolute path");
    }

    let request_root = request.manifest.project.root.as_path();
    if request_root != base_path {
        bail!("runtime.app.basePath must match manifest.project.root after normalization");
    }

    let mut seen_route_ids = BTreeSet::new();
    for route in &request.runtime.routes {
        if !seen_route_ids.insert(route.route_id.clone()) {
            bail!(
                "runtime.routes contains duplicate routeId \"{}\"",
                route.route_id
            );
        }
    }

    let mut seen_command_signatures = BTreeSet::new();
    let mut seen_command_fqcns = BTreeSet::new();
    for command in &request.runtime.commands {
        if command.signature.trim().is_empty() {
            bail!("runtime.commands contains an empty signature");
        }
        if command.fqcn.trim().is_empty() {
            bail!(
                "runtime.commands contains an empty fqcn for signature \"{}\"",
                command.signature
            );
        }
        if !seen_command_signatures.insert(command.signature.clone()) {
            bail!(
                "runtime.commands contains duplicate signature \"{}\"",
                command.signature
            );
        }
        if !seen_command_fqcns.insert(command.fqcn.clone()) {
            bail!(
                "runtime.commands contains duplicate fqcn \"{}\"",
                command.fqcn
            );
        }
    }

    Ok(())
}

fn collect_static_controllers(
    result: &PipelineResult,
    source_index: &SourceIndex,
    runtime_routes: &BTreeMap<String, Vec<RuntimeRoute>>,
) -> BTreeMap<String, ContractController> {
    let route_methods = collect_route_methods(result);
    let scope_owners = collect_scope_owners(result);
    let related_models_by_morph = collect_related_models_by_morph(result);
    let model_index = collect_model_index(result);

    let mut controllers = BTreeMap::new();

    for file in &result.files {
        for controller in &file.facts.controllers {
            let action_key = format!("{}::{}", controller.fqcn, controller.method_name);
            let action_routes = runtime_routes
                .get(&action_key)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let http = build_http_info(controller, route_methods.get(&action_key), action_routes);
            let authorization = build_authorization(controller, action_routes, source_index);
            controllers.insert(
                action_key,
                ContractController {
                    fqcn: controller.fqcn.clone(),
                    method: controller.method_name.clone(),
                    http: http.clone(),
                    request: build_contract_request(controller, source_index),
                    responses: build_contract_responses(
                        controller,
                        http.as_ref(),
                        &authorization,
                        source_index,
                        &model_index,
                    ),
                    authorization,
                    resources: build_controller_resources(controller, source_index),
                    scopes_used: build_controller_scopes(controller, &scope_owners),
                    polymorphic: build_controller_polymorphic(
                        controller,
                        &related_models_by_morph,
                        source_index,
                    ),
                },
            );
        }
    }

    controllers
}

fn build_http_info(
    controller: &ControllerMethod,
    route_methods: Option<&Vec<String>>,
    runtime_routes: &[RuntimeRoute],
) -> Option<ContractHttpInfo> {
    if let Some(status) = controller.http_status {
        return Some(ContractHttpInfo {
            status,
            explicit: true,
        });
    }

    let runtime_method_count = runtime_routes
        .iter()
        .flat_map(|route| route.methods.iter())
        .count();
    if runtime_method_count > 0 {
        return Some(ContractHttpInfo {
            status: 200,
            explicit: false,
        });
    }

    route_methods.and_then(|methods| {
        (!methods.is_empty()).then_some(ContractHttpInfo {
            status: 200,
            explicit: false,
        })
    })
}

fn build_contract_request(
    controller: &ControllerMethod,
    source_index: &SourceIndex,
) -> Option<ContractRequest> {
    let mut content_types = BTreeSet::new();
    let mut field_map = BTreeMap::<(String, String), ContractRequestField>::new();
    let mut body = ShapeTree::default();
    let mut query = ShapeTree::default();
    let mut files = ShapeTree::default();

    for field in parse_inline_validate_fields(&controller.body_text) {
        register_request_field(
            field,
            &mut field_map,
            &mut content_types,
            &mut body,
            &mut query,
            &mut files,
        );
    }

    for field in parse_spatie_data_request_fields(controller, source_index) {
        register_request_field(
            field,
            &mut field_map,
            &mut content_types,
            &mut body,
            &mut query,
            &mut files,
        );
    }

    for item in &controller.request_usage {
        if let Some(class_name) = &item.class_name {
            for field in parse_form_request_fields(class_name, source_index) {
                register_request_field(
                    field,
                    &mut field_map,
                    &mut content_types,
                    &mut body,
                    &mut query,
                    &mut files,
                );
            }
        }
    }

    for item in &controller.request_usage {
        match item.method.as_str() {
            "validate" => {
                content_types.insert("application/json".to_string());
                content_types.insert("application/x-www-form-urlencoded".to_string());
                for path in &item.rules {
                    register_request_field(
                        ParsedRuleField {
                            location: "body".to_string(),
                            path: path.clone(),
                            kind: Some("field".to_string()),
                            source: Some("request validation".to_string()),
                            via: Some("validate".to_string()),
                            ..ParsedRuleField::default()
                        },
                        &mut field_map,
                        &mut content_types,
                        &mut body,
                        &mut query,
                        &mut files,
                    );
                }
            }
            "validated" => {
                content_types.insert("application/json".to_string());
                content_types.insert("application/x-www-form-urlencoded".to_string());
            }
            "only" => {
                for path in &item.fields {
                    register_request_field(
                        ParsedRuleField {
                            location: "query".to_string(),
                            path: path.clone(),
                            kind: Some("field".to_string()),
                            source: Some("request extraction".to_string()),
                            via: Some("only".to_string()),
                            ..ParsedRuleField::default()
                        },
                        &mut field_map,
                        &mut content_types,
                        &mut body,
                        &mut query,
                        &mut files,
                    );
                }
            }
            "file" => {
                content_types.insert("multipart/form-data".to_string());
                for path in &item.fields {
                    register_request_field(
                        ParsedRuleField {
                            location: "files".to_string(),
                            path: path.clone(),
                            kind: Some("file".to_string()),
                            type_name: Some("string".to_string()),
                            scalar_type: Some("binary".to_string()),
                            source: Some("request upload".to_string()),
                            via: Some("file".to_string()),
                            ..ParsedRuleField::default()
                        },
                        &mut field_map,
                        &mut content_types,
                        &mut body,
                        &mut query,
                        &mut files,
                    );
                }
            }
            "body" => {
                content_types.insert("application/json".to_string());
                content_types.insert("application/x-www-form-urlencoded".to_string());
            }
            _ => {}
        }
    }

    for field in parse_spatie_media_request_fields(&controller.body_text) {
        register_request_field(
            field,
            &mut field_map,
            &mut content_types,
            &mut body,
            &mut query,
            &mut files,
        );
    }

    extend_query_builder_request(
        controller,
        source_index,
        &mut content_types,
        &mut field_map,
        &mut body,
        &mut query,
        &mut files,
    );

    let mut fields = field_map.into_values().collect::<Vec<_>>();
    if content_types.is_empty() && fields.is_empty() {
        return None;
    }
    fields.sort_by(|a, b| (&a.location, &a.path, &a.via).cmp(&(&b.location, &b.path, &b.via)));
    Some(ContractRequest {
        content_types: content_types.into_iter().collect(),
        body: (!body.is_empty()).then_some(body),
        query: (!query.is_empty()).then_some(query),
        files: (!files.is_empty()).then_some(files),
        fields,
    })
}

fn build_contract_responses(
    controller: &ControllerMethod,
    http: Option<&ContractHttpInfo>,
    authorization: &[ContractAuthorization],
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
) -> Vec<ContractResponse> {
    let mut responses = infer_responses_from_body(controller, http, source_index, model_index);
    if responses.is_empty() {
        responses.extend(infer_responses_from_resources(
            controller,
            http,
            source_index,
            model_index,
        ));
    }
    if responses.is_empty() {
        responses.extend(infer_fallback_response(http));
    }

    extend_authorization_failure_responses(&mut responses, authorization);
    extend_validation_failure_responses(&mut responses, controller, source_index);

    let mut seen = BTreeSet::new();
    responses.retain(|response| {
        let key = format!(
            "{}|{:?}|{:?}|{:?}|{:?}|{:?}",
            response.kind,
            response.status,
            response.content_type,
            response.source,
            response.via,
            response.body_schema
        );
        seen.insert(key)
    });
    responses.sort_by(|a, b| {
        (&a.kind, &a.status, &a.source, &a.via).cmp(&(&b.kind, &b.status, &b.source, &b.via))
    });
    responses
}

fn infer_responses_from_body(
    controller: &ControllerMethod,
    http: Option<&ContractHttpInfo>,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
) -> Vec<ContractResponse> {
    let mut responses = Vec::new();
    let text = &controller.body_text;
    let status = http.map(|item| item.status);
    let explicit = http.map(|item| item.explicit);

    if text.contains("noContent()") || status == Some(204) {
        responses.push(ContractResponse {
            kind: "no_content".to_string(),
            status,
            explicit,
            content_type: None,
            headers: BTreeMap::new(),
            body_schema: None,
            redirect: None,
            download: None,
            inertia: None,
            source: Some("response()->noContent".to_string()),
            via: Some("response()->noContent".to_string()),
        });
        return responses;
    }

    if let Some(response) = infer_inertia_response(controller, http, source_index, model_index) {
        responses.push(response);
    }

    if let Some(target) = extract_inertia_location_target(text) {
        let mut headers = BTreeMap::new();
        headers.insert("X-Inertia-Location".to_string(), target.clone());
        responses.push(ContractResponse {
            kind: "redirect".to_string(),
            status: Some(409),
            explicit: Some(true),
            content_type: None,
            headers,
            body_schema: None,
            redirect: Some(ContractRedirect {
                target_kind: "inertia_location".to_string(),
                target: Some(target),
            }),
            download: None,
            inertia: None,
            source: Some("Inertia::location".to_string()),
            via: Some("Inertia::location".to_string()),
        });
    }

    if let Some(target) = extract_route_redirect_target(text) {
        responses.push(ContractResponse {
            kind: "redirect".to_string(),
            status: status.or(Some(302)),
            explicit: explicit.or(Some(false)),
            content_type: None,
            headers: BTreeMap::new(),
            body_schema: None,
            redirect: Some(ContractRedirect {
                target_kind: "route".to_string(),
                target: Some(target),
            }),
            download: None,
            inertia: None,
            source: Some("redirect()->route".to_string()),
            via: Some("redirect()->route".to_string()),
        });
    } else if text.contains("back()") {
        responses.push(ContractResponse {
            kind: "redirect".to_string(),
            status: status.or(Some(302)),
            explicit: explicit.or(Some(false)),
            content_type: None,
            headers: BTreeMap::new(),
            body_schema: None,
            redirect: Some(ContractRedirect {
                target_kind: "back".to_string(),
                target: None,
            }),
            download: None,
            inertia: None,
            source: Some("back".to_string()),
            via: Some("back".to_string()),
        });
    }

    if text.contains("streamDownload(") {
        responses.push(ContractResponse {
            kind: "stream".to_string(),
            status: status.or(Some(200)),
            explicit: explicit.or(Some(false)),
            content_type: Some("application/octet-stream".to_string()),
            headers: BTreeMap::new(),
            body_schema: None,
            redirect: None,
            download: None,
            inertia: None,
            source: Some("response()->streamDownload".to_string()),
            via: Some("response()->streamDownload".to_string()),
        });
    } else if text.contains("download(") {
        responses.push(ContractResponse {
            kind: "download".to_string(),
            status: status.or(Some(200)),
            explicit: explicit.or(Some(false)),
            content_type: Some("application/octet-stream".to_string()),
            headers: BTreeMap::new(),
            body_schema: None,
            redirect: None,
            download: Some(ContractDownload {
                disposition: "attachment".to_string(),
                filename: extract_download_filename(text),
            }),
            inertia: None,
            source: Some("response()->download".to_string()),
            via: Some("response()->download".to_string()),
        });
    }

    for call in extract_json_response_calls(text) {
        let inferred_schema = infer_schema_from_expression(
            &call.payload,
            controller,
            source_index,
            model_index,
            &mut BTreeSet::new(),
        );
        let kind = inferred_schema
            .as_ref()
            .and_then(schema_type)
            .map(|schema_type| {
                if schema_type == "array" {
                    "json_array".to_string()
                } else {
                    "json_object".to_string()
                }
            })
            .unwrap_or_else(|| "json_object".to_string());

        responses.push(ContractResponse {
            kind,
            status: call.status.or(status).or(Some(200)),
            explicit: Some(call.status.is_some() || explicit.unwrap_or(false)),
            content_type: Some("application/json".to_string()),
            headers: BTreeMap::new(),
            body_schema: inferred_schema.or_else(|| Some(json!({ "type": "object" }))),
            redirect: None,
            download: None,
            inertia: None,
            source: Some("response()->json".to_string()),
            via: Some("response()->json".to_string()),
        });
    }

    responses.extend(infer_framework_error_responses(controller, http));

    responses
}

fn extend_authorization_failure_responses(
    responses: &mut Vec<ContractResponse>,
    authorization: &[ContractAuthorization],
) {
    if responses
        .iter()
        .any(|response| response.status == Some(403))
    {
        return;
    }

    let Some(source) = authorization
        .iter()
        .find(|item| item.enforces_failure_response && item.kind != "middleware")
        .map(|item| item.source.clone())
    else {
        return;
    };

    responses.push(ContractResponse {
        kind: "json_object".to_string(),
        status: Some(403),
        explicit: Some(false),
        content_type: Some("application/json".to_string()),
        headers: BTreeMap::new(),
        body_schema: Some(json!({ "type": "object" })),
        redirect: None,
        download: None,
        inertia: None,
        source: Some(source),
        via: Some("authorization".to_string()),
    });
}

fn extend_validation_failure_responses(
    responses: &mut Vec<ContractResponse>,
    controller: &ControllerMethod,
    source_index: &SourceIndex,
) {
    if responses
        .iter()
        .any(|response| response.status == Some(422))
    {
        return;
    }

    let source = controller.request_usage.iter().find_map(|item| {
        if item.method == "validate" {
            return Some("validate".to_string());
        }
        if item.method == "validated" || item.class_name.is_some() {
            return Some("FormRequest".to_string());
        }
        None
    });

    let source = source.or_else(|| {
        let class = source_index.get(&controller.fqcn);
        let state = collect_controller_source_state(controller, class);
        state.parameters.values().find_map(|parameter_type| {
            let class = source_index.get(parameter_type)?;
            class.method_body("rules")?;
            Some("FormRequest".to_string())
        })
    });

    let Some(source) = source else {
        return;
    };

    responses.push(ContractResponse {
        kind: "json_object".to_string(),
        status: Some(422),
        explicit: Some(false),
        content_type: Some("application/json".to_string()),
        headers: BTreeMap::new(),
        body_schema: Some(json!({ "type": "object" })),
        redirect: None,
        download: None,
        inertia: None,
        source: Some(source),
        via: Some("validation".to_string()),
    });
}

fn infer_responses_from_resources(
    controller: &ControllerMethod,
    http: Option<&ContractHttpInfo>,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
) -> Vec<ContractResponse> {
    let default_status = http.map(|item| item.status).unwrap_or(200);
    let explicit = http.map(|item| item.explicit).unwrap_or(false);

    collect_controller_resource_usage(controller, source_index)
        .iter()
        .map(|resource| {
            let collection = is_collection_resource(resource);
            let source = match resource.method.as_deref() {
                Some("collection") => "JsonResource::collection",
                Some("response") => "JsonResource::response",
                _ => "JsonResource",
            };
            let additional_schema = extract_additional_resource_schema(
                &controller.body_text,
                source_index,
                model_index,
            );
            let mut body_schema = if additional_schema.is_some() {
                build_resource_schema(
                    &resource.class_name,
                    source_index,
                    model_index,
                    &mut BTreeSet::new(),
                )
            } else {
                build_response_schema(&resource.class_name, collection, source_index, model_index)
            };
            if let Some(additional_schema) = additional_schema {
                body_schema = merge_object_schema(body_schema, additional_schema);
            }
            ContractResponse {
                kind: "json_object".to_string(),
                status: Some(default_status),
                explicit: Some(explicit),
                content_type: Some("application/json".to_string()),
                headers: BTreeMap::new(),
                body_schema: Some(body_schema),
                redirect: None,
                download: None,
                inertia: None,
                source: Some(source.to_string()),
                via: Some(source.to_string()),
            }
        })
        .collect()
}

fn extract_additional_resource_schema(
    method_text: &str,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
) -> Option<Value> {
    let needle = "->additional(";
    let start = method_text.find(needle)? + needle.len() - 1;
    let (arguments, _, _) = extract_balanced_region(&method_text[start..], '(', ')')?;
    let first_argument = split_top_level(&arguments, ',').into_iter().next()?;
    let value = first_argument.trim();
    let (array_body, _, _) = extract_balanced_region(value, '[', ']')?;
    Some(parse_php_array_schema(
        &array_body,
        source_index,
        model_index,
        None,
        None,
        &mut BTreeSet::new(),
    ))
}

fn merge_object_schema(base: Value, extra: Value) -> Value {
    let mut base = base;
    let Value::Object(extra_object) = extra else {
        return base;
    };
    let Some(extra_properties) = extra_object.get("properties").and_then(Value::as_object) else {
        return base;
    };
    let Some(base_object) = base.as_object_mut() else {
        return base;
    };
    let properties = base_object
        .entry("properties".to_string())
        .or_insert_with(|| json!({}));
    let Some(properties_object) = properties.as_object_mut() else {
        return base;
    };
    for (key, value) in extra_properties {
        properties_object.insert(key.clone(), value.clone());
    }
    base
}

fn infer_fallback_response(http: Option<&ContractHttpInfo>) -> Vec<ContractResponse> {
    let Some(http) = http else {
        return Vec::new();
    };
    if http.status == 204 {
        return vec![ContractResponse {
            kind: "no_content".to_string(),
            status: Some(http.status),
            explicit: Some(http.explicit),
            content_type: None,
            headers: BTreeMap::new(),
            body_schema: None,
            redirect: None,
            download: None,
            inertia: None,
            source: None,
            via: None,
        }];
    }

    vec![ContractResponse {
        kind: "json_object".to_string(),
        status: Some(http.status),
        explicit: Some(http.explicit),
        content_type: Some("application/json".to_string()),
        headers: BTreeMap::new(),
        body_schema: Some(json!({ "type": "object" })),
        redirect: None,
        download: None,
        inertia: None,
        source: None,
        via: None,
    }]
}

fn build_authorization(
    controller: &ControllerMethod,
    runtime_routes: &[RuntimeRoute],
    source_index: &SourceIndex,
) -> Vec<ContractAuthorization> {
    build_static_authorization(controller, runtime_routes, source_index)
}

fn build_controller_resources(
    controller: &ControllerMethod,
    source_index: &SourceIndex,
) -> Vec<ContractControllerResource> {
    let mut resources = collect_controller_resource_usage(controller, source_index)
        .iter()
        .map(|resource| ContractControllerResource {
            class: class_basename(&resource.class_name),
            fqcn: Some(resource.class_name.clone()),
            collection: is_collection_resource(resource),
        })
        .collect::<Vec<_>>();

    resources.sort_by(|a, b| {
        (&a.fqcn, &a.class, &a.collection).cmp(&(&b.fqcn, &b.class, &b.collection))
    });
    resources
        .dedup_by(|a, b| a.fqcn == b.fqcn && a.class == b.class && a.collection == b.collection);
    resources
}

fn collect_controller_resource_usage(
    controller: &ControllerMethod,
    source_index: &SourceIndex,
) -> Vec<ResourceUsageFact> {
    let mut resources = controller.resource_usage.clone();
    let Some(class) = source_index.get(&controller.fqcn) else {
        return resources;
    };

    let response_re = Regex::new(
        r#"(?s)new\s+([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))\((?:.|\n)*?\)\s*->response\("#,
    )
    .expect("contract resource response regex");
    let collection_re =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))::collection\("#)
            .expect("contract resource collection regex");
    let make_re = Regex::new(r#"([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))::make\("#)
        .expect("contract resource make regex");
    let new_re = Regex::new(r#"new\s+([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))\("#)
        .expect("contract new resource regex");
    let mut seen = resources
        .iter()
        .map(|resource| (resource.class_name.clone(), resource.method.clone()))
        .collect::<BTreeSet<_>>();

    for (regex, method) in [
        (&response_re, Some("response".to_string())),
        (&collection_re, Some("collection".to_string())),
        (&make_re, Some("make".to_string())),
        (&new_re, Some("new".to_string())),
    ] {
        for captures in regex.captures_iter(&controller.body_text) {
            let Some(class_name) = captures.get(1) else {
                continue;
            };
            let class_name = class.resolve_name(class_name.as_str());
            let method = if class_name.ends_with("Collection") && method.as_deref() == Some("new") {
                Some("collection".to_string())
            } else {
                method.clone()
            };
            let key = (class_name.clone(), method.clone());
            if seen.insert(key.clone()) {
                resources.push(ResourceUsageFact { class_name, method });
            }
        }
    }

    resources
}

fn build_controller_scopes(
    controller: &ControllerMethod,
    scope_owners: &BTreeMap<String, Option<String>>,
) -> Vec<ContractScopeUsed> {
    let mut scopes = controller
        .scopes_used
        .iter()
        .filter_map(|scope| {
            let owner = scope
                .on
                .clone()
                .or_else(|| scope_owners.get(&scope.name).cloned().flatten())?;
            Some(ContractScopeUsed {
                on: owner,
                name: scope.name.clone(),
                args: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    scopes.sort_by(|a, b| (&a.on, &a.name).cmp(&(&b.on, &b.name)));
    scopes.dedup_by(|a, b| a.on == b.on && a.name == b.name);
    scopes
}

fn build_controller_polymorphic(
    controller: &ControllerMethod,
    related_models_by_morph: &BTreeMap<String, BTreeSet<String>>,
    source_index: &SourceIndex,
) -> Vec<ContractPolymorphicRelation> {
    let inferred_models = controller
        .resource_usage
        .iter()
        .map(|resource| resolve_model_fqcn_from_resource(&resource.class_name, source_index))
        .collect::<Vec<_>>();

    let mut items = Vec::new();
    for model in inferred_models {
        if let Some(related) = related_models_by_morph.get(&model.1) {
            items.push(ContractPolymorphicRelation {
                relation: model.1.clone(),
                relation_type: "morphTo".to_string(),
                morph_type: Some(format!("{}_type", model.1)),
                morph_id: Some(format!("{}_id", model.1)),
                model: model.0.clone(),
                discriminator: Some(ContractDiscriminator {
                    property_name: format!("{}_type", model.1),
                    mapping: build_discriminator_mapping(related),
                }),
                related_models: related.iter().cloned().collect(),
            });
        }
    }

    items.sort_by(|a, b| {
        (&a.relation, &a.relation_type, &a.model).cmp(&(&b.relation, &b.relation_type, &b.model))
    });
    items.dedup_by(|a, b| {
        a.relation == b.relation
            && a.relation_type == b.relation_type
            && a.model == b.model
            && a.related_models == b.related_models
    });
    items
}

fn collect_models(result: &PipelineResult, source_index: &SourceIndex) -> Vec<ContractModel> {
    let related_models_by_morph = collect_related_models_by_morph(result);
    let mut models = BTreeMap::<String, ContractModel>::new();

    for file in &result.files {
        for model in &file.facts.models {
            let hint = model_schema_hint(&model.fqcn, source_index);
            let entry = models
                .entry(model.fqcn.clone())
                .or_insert_with(|| ContractModel {
                    fqcn: model.fqcn.clone(),
                    with_pivot: Vec::new(),
                    attributes: Vec::new(),
                    polymorphic: Vec::new(),
                });

            entry.with_pivot.extend(
                model
                    .relationships
                    .iter()
                    .filter(|relationship| !relationship.pivot_columns.is_empty())
                    .map(|relationship| ContractPivot {
                        relation: relationship.name.clone(),
                        columns: relationship.pivot_columns.clone(),
                        alias: relationship.pivot_alias.clone(),
                        timestamps: relationship.pivot_timestamps.then_some(true),
                    }),
            );

            entry
                .attributes
                .extend(model.attributes.iter().map(|attribute| ContractAttribute {
                    name: attribute.clone(),
                    via: "Attribute::make".to_string(),
                }));
            entry.attributes.extend(
                collect_translatable_attributes(&model.fqcn, source_index)
                    .into_iter()
                    .map(|attribute| ContractAttribute {
                        name: attribute,
                        via: "spatie/laravel-translatable".to_string(),
                    }),
            );
            entry
                .attributes
                .extend(hint.fillable.iter().map(|attribute| ContractAttribute {
                    name: attribute.clone(),
                    via: "$fillable".to_string(),
                }));
            entry.attributes.extend(
                hint.casts
                    .iter()
                    .map(|(attribute, cast)| ContractAttribute {
                        name: attribute.clone(),
                        via: format!("$casts:{cast}"),
                    }),
            );

            entry
                .polymorphic
                .extend(model.relationships.iter().filter_map(|relationship| {
                    build_model_polymorphic_relation(relationship, &related_models_by_morph)
                }));
        }
    }

    for class in source_index.classes.values() {
        if models.contains_key(&class.fqcn) {
            continue;
        }
        if class.source_text.contains("abstract class ") {
            continue;
        }
        if !is_eloquent_model_class(&class.fqcn, source_index) {
            continue;
        }

        let translatable = collect_translatable_attributes(&class.fqcn, source_index);
        if translatable.is_empty() {
            continue;
        }

        let mut entry = ContractModel {
            fqcn: class.fqcn.clone(),
            with_pivot: Vec::new(),
            attributes: translatable
                .into_iter()
                .map(|attribute| ContractAttribute {
                    name: attribute,
                    via: "spatie/laravel-translatable".to_string(),
                })
                .collect(),
            polymorphic: Vec::new(),
        };
        entry
            .attributes
            .sort_by(|a, b| (&a.name, &a.via).cmp(&(&b.name, &b.via)));
        entry
            .attributes
            .dedup_by(|a, b| a.name == b.name && a.via == b.via);
        models.insert(class.fqcn.clone(), entry);
    }

    let mut models = models
        .into_values()
        .map(|mut model| {
            model.with_pivot.sort_by(|a, b| {
                (&a.relation, &a.columns, &a.alias, &a.timestamps).cmp(&(
                    &b.relation,
                    &b.columns,
                    &b.alias,
                    &b.timestamps,
                ))
            });
            model.with_pivot.dedup_by(|a, b| {
                a.relation == b.relation
                    && a.columns == b.columns
                    && a.alias == b.alias
                    && a.timestamps == b.timestamps
            });
            model
                .attributes
                .sort_by(|a, b| (&a.name, &a.via).cmp(&(&b.name, &b.via)));
            model
                .attributes
                .dedup_by(|a, b| a.name == b.name && a.via == b.via);
            model.polymorphic.sort_by(|a, b| {
                (&a.relation, &a.relation_type, &a.model, &a.related_models).cmp(&(
                    &b.relation,
                    &b.relation_type,
                    &b.model,
                    &b.related_models,
                ))
            });
            model.polymorphic.dedup_by(|a, b| {
                a.relation == b.relation
                    && a.relation_type == b.relation_type
                    && a.model == b.model
                    && a.related_models == b.related_models
            });
            model
        })
        .collect::<Vec<_>>();

    models.sort_by(|a, b| a.fqcn.cmp(&b.fqcn));
    models
}

fn build_model_polymorphic_relation(
    relationship: &ModelRelationshipFact,
    related_models_by_morph: &BTreeMap<String, BTreeSet<String>>,
) -> Option<ContractPolymorphicRelation> {
    if !is_polymorphic_relation_type(&relationship.relation_type) {
        return None;
    }

    let morph_name = relationship
        .morph_name
        .clone()
        .unwrap_or_else(|| relationship.name.clone());
    let related_models = related_models_by_morph
        .get(&morph_name)
        .map(|items| items.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let discriminator = ContractDiscriminator {
        property_name: format!("{morph_name}_type"),
        mapping: build_discriminator_mapping_from_vec(&related_models),
    };

    Some(ContractPolymorphicRelation {
        relation: relationship.name.clone(),
        relation_type: normalize_polymorphic_relation_type(&relationship.relation_type),
        morph_type: Some(format!("{morph_name}_type")),
        morph_id: Some(format!("{morph_name}_id")),
        model: relationship.related.clone(),
        discriminator: Some(discriminator),
        related_models,
    })
}

fn collect_resources(result: &PipelineResult, source_index: &SourceIndex) -> Vec<ContractResource> {
    let model_index = collect_model_index(result);
    let mut resources = BTreeMap::<String, ContractResource>::new();

    for class in source_index.classes.values() {
        if !is_resource_class(class) {
            continue;
        }

        resources
            .entry(class.fqcn.clone())
            .or_insert_with(|| ContractResource {
                fqcn: class.fqcn.clone(),
                class: class.class_name.clone(),
                schema: build_resource_schema(
                    &class.fqcn,
                    source_index,
                    &model_index,
                    &mut BTreeSet::new(),
                ),
            });
    }

    let mut resources = resources.into_values().collect::<Vec<_>>();
    resources.sort_by(|a, b| a.fqcn.cmp(&b.fqcn));
    resources
}

fn collect_top_level_polymorphic(result: &PipelineResult) -> Vec<ContractPolymorphicGroup> {
    let related_models_by_morph = collect_related_models_by_morph(result);
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();

    for file in &result.files {
        for relation in &file.facts.polymorphic {
            let key = (relation.model.clone(), relation.name.clone());
            if !seen.insert(key) {
                continue;
            }

            let related_models = related_models_by_morph
                .get(&relation.name)
                .cloned()
                .unwrap_or_default();
            items.push(ContractPolymorphicGroup {
                parent: relation.model.clone(),
                morph: ContractMorph {
                    key: relation.name.clone(),
                    type_column: relation.discriminator.clone(),
                    id_column: format!("{}_id", relation.name),
                },
                discriminator: ContractDiscriminator {
                    property_name: relation.discriminator.clone(),
                    mapping: build_discriminator_mapping(&related_models),
                },
            });
        }
    }

    items.sort_by(|a, b| (&a.parent, &a.morph.key).cmp(&(&b.parent, &b.morph.key)));
    items
}

fn collect_broadcast(result: &PipelineResult) -> Vec<ContractBroadcast> {
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();

    for file in &result.files {
        for broadcast in &file.facts.broadcast {
            let mut params = broadcast
                .parameters
                .iter()
                .map(|item| item.name.clone())
                .collect::<Vec<_>>();
            if params.is_empty() {
                params = extract_channel_params(&broadcast.channel);
            }
            params.sort();
            params.dedup();

            let key = (broadcast.channel.clone(), file.relative_path.clone());
            if !seen.insert(key) {
                continue;
            }

            items.push(ContractBroadcast {
                file: Some(file.relative_path.clone()),
                channel: broadcast.channel.clone(),
                params,
                visibility: infer_broadcast_visibility(
                    &broadcast.channel,
                    broadcast.channel_type.as_deref(),
                ),
                payload_literal: None,
            });
        }
    }

    items.sort_by(|a, b| (&a.channel, &a.file).cmp(&(&b.channel, &b.file)));
    items
}

fn collect_runtime_routes_by_action(
    request: &AnalysisRequest,
) -> BTreeMap<String, Vec<RuntimeRoute>> {
    let mut routes = BTreeMap::<String, Vec<RuntimeRoute>>::new();

    for route in &request.runtime.routes {
        let Some(action_key) = route.action.action_key() else {
            continue;
        };
        routes.entry(action_key).or_default().push(route.clone());
    }

    routes
}

fn collect_model_index(result: &PipelineResult) -> BTreeMap<String, ModelFacts> {
    let mut models = BTreeMap::new();

    for file in &result.files {
        for model in &file.facts.models {
            models.insert(model.fqcn.clone(), model.clone());
        }
    }

    models
}

fn register_request_field(
    field: ParsedRuleField,
    fields: &mut BTreeMap<(String, String), ContractRequestField>,
    content_types: &mut BTreeSet<String>,
    body: &mut ShapeTree,
    query: &mut ShapeTree,
    files: &mut ShapeTree,
) {
    let location = field.location.clone();
    let path = field.path.clone();
    if path.is_empty() {
        return;
    }

    let shape_path = match location.as_str() {
        "body" | "files" => {
            let array_path = if field.is_array == Some(true) || field.collection == Some(true) {
                if path.contains("[]") {
                    path.clone()
                } else {
                    format!("{path}[]")
                }
            } else {
                path.clone()
            };
            normalize_array_shape_path(&array_path)
        }
        _ => path.clone(),
    };

    match location.as_str() {
        "body" => {
            body.insert_path(&shape_path);
            content_types.insert("application/json".to_string());
            content_types.insert("application/x-www-form-urlencoded".to_string());
        }
        "query" => {
            query.insert_path(&path);
        }
        "files" => {
            files.insert_path(&shape_path);
            content_types.insert("multipart/form-data".to_string());
        }
        _ => {}
    }

    let key = (location.clone(), path.clone());
    let entry = fields.entry(key).or_insert_with(|| ContractRequestField {
        location,
        path,
        kind: None,
        type_name: None,
        scalar_type: None,
        format: None,
        item_type: None,
        wrappers: Vec::new(),
        allowed_values: Vec::new(),
        required: None,
        optional: None,
        nullable: None,
        is_array: None,
        collection: None,
        source: None,
        via: None,
    });

    if entry.kind.as_deref() == Some("array") && field.kind.as_deref() == Some("collection") {
        entry.kind = Some("collection".to_string());
    } else {
        merge_optional(&mut entry.kind, field.kind);
    }
    merge_optional(&mut entry.type_name, field.type_name);
    merge_optional(&mut entry.scalar_type, field.scalar_type);
    merge_optional(&mut entry.format, field.format);
    merge_optional(&mut entry.item_type, field.item_type);
    merge_optional_bool(&mut entry.required, field.required);
    merge_optional_bool(&mut entry.optional, field.optional);
    merge_optional_bool(&mut entry.nullable, field.nullable);
    merge_optional_bool(&mut entry.is_array, field.is_array);
    merge_optional_bool(&mut entry.collection, field.collection);
    merge_optional(&mut entry.source, field.source);
    merge_optional(&mut entry.via, field.via);
    extend_unique(&mut entry.wrappers, field.wrappers);
    extend_unique(&mut entry.allowed_values, field.allowed_values);
}

fn normalize_array_shape_path(path: &str) -> String {
    path.replace("[]", "._item")
}

fn merge_optional(target: &mut Option<String>, value: Option<String>) {
    if target.is_none() {
        *target = value;
    }
}

fn merge_optional_bool(target: &mut Option<bool>, value: Option<bool>) {
    if target.is_none() {
        *target = value;
    }
}

fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    target.extend(values);
    target.sort();
    target.dedup();
}

fn parse_inline_validate_fields(method_text: &str) -> Vec<ParsedRuleField> {
    let mut fields = Vec::new();
    let mut offset = 0usize;
    let needle = "validate(";

    while let Some(index) = method_text[offset..].find(needle) {
        let call_start = offset + index + needle.len();
        let Some(array_index) = method_text[call_start..].find('[') else {
            offset = call_start;
            continue;
        };
        let array_start = call_start + array_index;
        let Some((array_body, _, end_index)) =
            extract_balanced_region(&method_text[array_start..], '[', ']')
        else {
            offset = array_start + 1;
            continue;
        };

        fields.extend(parse_rule_array(
            &array_body,
            "request validation",
            "validate",
        ));
        offset = array_start + end_index + 1;
    }

    fields
}

fn parse_form_request_fields(class_name: &str, source_index: &SourceIndex) -> Vec<ParsedRuleField> {
    let Some(class) = source_index.get(class_name) else {
        return Vec::new();
    };
    let Some(method_body) = class.method_body("rules") else {
        return Vec::new();
    };
    let Some(array_body) = extract_return_array(&method_body) else {
        return Vec::new();
    };

    parse_rule_array(
        &array_body,
        &format!("{}::rules", class.fqcn),
        "FormRequest",
    )
}

fn parse_spatie_data_request_fields(
    controller: &ControllerMethod,
    source_index: &SourceIndex,
) -> Vec<ParsedRuleField> {
    let Some(class) = source_index.get(&controller.fqcn) else {
        return Vec::new();
    };

    let mut fields = Vec::new();
    let mut data_classes = BTreeSet::new();

    for parameter in
        extract_method_signature_parameters(&controller.body_text, controller.method_name.as_str())
            .into_iter()
            .flat_map(|params| split_top_level(&params, ','))
    {
        let Some((raw_type, _name, _default, _attrs)) = parse_typed_parameter(&parameter) else {
            continue;
        };
        let resolved = class.resolve_name(raw_type.trim_start_matches('?'));
        if is_spatie_data_class(&resolved, source_index) {
            data_classes.insert(resolved);
        }
    }

    let mut visited = BTreeSet::new();
    for data_class in data_classes {
        fields.extend(parse_spatie_data_class_fields(
            &data_class,
            source_index,
            "",
            &mut visited,
        ));
    }

    fields
}

fn parse_spatie_data_class_fields(
    class_fqcn: &str,
    source_index: &SourceIndex,
    prefix: &str,
    visited: &mut BTreeSet<String>,
) -> Vec<ParsedRuleField> {
    if !visited.insert(class_fqcn.to_string()) {
        return Vec::new();
    }

    let Some(class) = source_index.get(class_fqcn) else {
        visited.remove(class_fqcn);
        return Vec::new();
    };
    if !is_spatie_data_class(class_fqcn, source_index) {
        visited.remove(class_fqcn);
        return Vec::new();
    }

    let mut fields = Vec::new();

    if let Some(parent) = class.extends.as_deref() {
        if parent != "Spatie\\LaravelData\\Data" && is_spatie_data_class(parent, source_index) {
            fields.extend(parse_spatie_data_class_fields(
                parent,
                source_index,
                prefix,
                visited,
            ));
        }
    }

    fields.extend(expand_spatie_data_fields(
        parse_spatie_data_constructor_fields(class, source_index, prefix),
        source_index,
        visited,
    ));
    fields.extend(expand_spatie_data_fields(
        parse_spatie_data_property_fields(class, source_index, prefix),
        source_index,
        visited,
    ));

    visited.remove(class_fqcn);
    fields
}

fn parse_spatie_data_constructor_fields(
    class: &SourceClass,
    source_index: &SourceIndex,
    prefix: &str,
) -> Vec<ParsedRuleField> {
    let Some(parameters) = extract_method_signature_parameters(&class.source_text, "__construct")
    else {
        return Vec::new();
    };

    split_top_level(&parameters, ',')
        .into_iter()
        .filter_map(|parameter| {
            let Some((raw_type, name, default, attrs)) = parse_typed_parameter(&parameter) else {
                return None;
            };
            parse_spatie_data_member(
                class,
                source_index,
                prefix,
                &name,
                &raw_type,
                default.as_deref(),
                &attrs,
            )
        })
        .collect()
}

fn parse_spatie_data_property_fields(
    class: &SourceClass,
    source_index: &SourceIndex,
    prefix: &str,
) -> Vec<ParsedRuleField> {
    let Some(body) = extract_class_body(&class.source_text) else {
        return Vec::new();
    };

    let mut fields = Vec::new();
    let mut pending_attrs = Vec::new();
    let property_re = Regex::new(
        r#"^(?:(?:public|protected|private)\s+)?(?:readonly\s+)?(?:[A-Za-z_\\][A-Za-z0-9_\\<>\|\?\s]*)\s+\$[A-Za-z_][A-Za-z0-9_]*\s*(?:=\s*.+)?;\s*$"#,
    )
    .expect("property regex");

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            pending_attrs.clear();
            continue;
        }
        if trimmed.starts_with("#[") {
            pending_attrs.push(trimmed.to_string());
            continue;
        }

        if property_re.is_match(trimmed) {
            let candidate = if pending_attrs.is_empty() {
                trimmed.to_string()
            } else {
                format!("{} {}", pending_attrs.join(" "), trimmed)
            };
            if let Some((raw_type, name, default, attrs)) = parse_typed_parameter(&candidate) {
                if let Some(field) = parse_spatie_data_member(
                    class,
                    source_index,
                    prefix,
                    &name,
                    &raw_type,
                    default.as_deref(),
                    &attrs,
                ) {
                    fields.push(field);
                }
            }
        }

        pending_attrs.clear();
    }

    fields
}

fn parse_spatie_data_member(
    class: &SourceClass,
    source_index: &SourceIndex,
    prefix: &str,
    name: &str,
    raw_type: &str,
    default_value: Option<&str>,
    attrs: &str,
) -> Option<ParsedRuleField> {
    let meta = parse_spatie_data_member_meta(class, source_index, raw_type, default_value, attrs)?;
    let path = join_shape_path(prefix, name);

    let mut field = ParsedRuleField {
        location: "body".to_string(),
        path: path.clone(),
        kind: meta.kind,
        type_name: meta.type_name,
        scalar_type: meta.scalar_type,
        format: None,
        item_type: meta.item_type,
        wrappers: meta.wrappers,
        allowed_values: Vec::new(),
        required: meta.required,
        optional: meta.optional,
        nullable: meta.nullable,
        is_array: meta.is_array,
        collection: meta.collection,
        source: Some("spatie/laravel-data".to_string()),
        via: Some("data".to_string()),
    };

    if field.kind.as_deref() == Some("collection")
        && field.item_type.is_some()
        && field.is_array != Some(true)
    {
        field.is_array = Some(true);
    }

    Some(field)
}

fn expand_spatie_data_fields(
    fields: Vec<ParsedRuleField>,
    source_index: &SourceIndex,
    visited: &mut BTreeSet<String>,
) -> Vec<ParsedRuleField> {
    let mut expanded = Vec::new();

    for field in fields {
        let recurse_prefix = field.path.clone();
        let nested_class = match field.kind.as_deref() {
            Some("collection") => field.item_type.clone(),
            Some("object") => field.type_name.clone(),
            _ => None,
        };
        let is_collection =
            field.kind.as_deref() == Some("collection") || field.is_array == Some(true);

        expanded.push(field);

        let Some(nested_class) = nested_class else {
            continue;
        };

        let prefix = if is_collection {
            format!("{recurse_prefix}[]")
        } else {
            recurse_prefix
        };

        expanded.extend(parse_spatie_data_class_fields(
            &nested_class,
            source_index,
            &prefix,
            visited,
        ));
    }

    expanded
}

fn parse_spatie_data_member_meta(
    class: &SourceClass,
    source_index: &SourceIndex,
    raw_type: &str,
    default_value: Option<&str>,
    attrs: &str,
) -> Option<SpatieDataFieldSpec> {
    let mut wrappers = Vec::new();
    let mut nullable = false;
    let mut optional = false;
    let mut base_type = None;

    for token in raw_type.split('|') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if token == "Optional" || token == "Lazy" {
            wrappers.push(token.to_string());
            optional = true;
            continue;
        }
        if token == "null" {
            nullable = true;
            optional = true;
            continue;
        }

        let stripped = token.trim_start_matches('?');
        if stripped != token {
            nullable = true;
            optional = true;
        }
        if base_type.is_none() {
            base_type = Some(stripped.to_string());
        }
    }

    let base_type = base_type?;
    let default_is_null = default_value
        .map(|value| value.trim() == "null")
        .unwrap_or(false);
    if default_is_null {
        nullable = true;
        optional = true;
    }
    let required = Some(!(optional || nullable));

    let data_collection_target = extract_data_collection_target(attrs, class);
    let resolved_base = class.resolve_name(&base_type);

    match base_type.as_str() {
        "string" => Some(SpatieDataFieldSpec {
            kind: Some("scalar".to_string()),
            type_name: Some("string".to_string()),
            scalar_type: Some("string".to_string()),
            wrappers,
            required,
            optional: Some(!required.unwrap_or(false)),
            nullable: Some(nullable),
            ..SpatieDataFieldSpec::default()
        }),
        "integer" | "int" => Some(SpatieDataFieldSpec {
            kind: Some("scalar".to_string()),
            type_name: Some("integer".to_string()),
            scalar_type: Some("integer".to_string()),
            wrappers,
            required,
            optional: Some(!required.unwrap_or(false)),
            nullable: Some(nullable),
            ..SpatieDataFieldSpec::default()
        }),
        "bool" | "boolean" => Some(SpatieDataFieldSpec {
            kind: Some("scalar".to_string()),
            type_name: Some("boolean".to_string()),
            scalar_type: Some("boolean".to_string()),
            wrappers,
            required,
            optional: Some(!required.unwrap_or(false)),
            nullable: Some(nullable),
            ..SpatieDataFieldSpec::default()
        }),
        "float" | "double" | "numeric" | "decimal" => Some(SpatieDataFieldSpec {
            kind: Some("scalar".to_string()),
            type_name: Some("number".to_string()),
            scalar_type: Some("number".to_string()),
            wrappers,
            required,
            optional: Some(!required.unwrap_or(false)),
            nullable: Some(nullable),
            ..SpatieDataFieldSpec::default()
        }),
        "array" => {
            if let Some(target) = data_collection_target {
                Some(SpatieDataFieldSpec {
                    kind: Some("collection".to_string()),
                    type_name: Some("array".to_string()),
                    item_type: Some(target.clone()),
                    wrappers,
                    required,
                    optional: Some(!required.unwrap_or(false)),
                    nullable: Some(nullable),
                    is_array: Some(true),
                    collection: Some(true),
                    ..SpatieDataFieldSpec::default()
                })
            } else {
                Some(SpatieDataFieldSpec {
                    kind: Some("array".to_string()),
                    type_name: Some("array".to_string()),
                    wrappers,
                    required,
                    optional: Some(!required.unwrap_or(false)),
                    nullable: Some(nullable),
                    is_array: Some(true),
                    collection: Some(true),
                    ..SpatieDataFieldSpec::default()
                })
            }
        }
        _ => {
            if let Some(target) = data_collection_target {
                return Some(SpatieDataFieldSpec {
                    kind: Some("collection".to_string()),
                    type_name: Some("array".to_string()),
                    item_type: Some(target.clone()),
                    wrappers,
                    required,
                    optional: Some(!required.unwrap_or(false)),
                    nullable: Some(nullable),
                    is_array: Some(true),
                    collection: Some(true),
                    ..SpatieDataFieldSpec::default()
                });
            }

            if is_spatie_data_class(&resolved_base, source_index) {
                Some(SpatieDataFieldSpec {
                    kind: Some("object".to_string()),
                    type_name: Some(resolved_base.clone()),
                    wrappers,
                    required,
                    optional: Some(!required.unwrap_or(false)),
                    nullable: Some(nullable),
                    ..SpatieDataFieldSpec::default()
                })
            } else {
                Some(SpatieDataFieldSpec {
                    kind: Some("scalar".to_string()),
                    type_name: Some("string".to_string()),
                    scalar_type: Some("string".to_string()),
                    wrappers,
                    required,
                    optional: Some(!required.unwrap_or(false)),
                    nullable: Some(nullable),
                    ..SpatieDataFieldSpec::default()
                })
            }
        }
    }
}

fn extract_method_signature_parameters(source: &str, method_name: &str) -> Option<String> {
    let method_re = Regex::new(&format!(
        r#"function\s+{}\s*\("#,
        regex::escape(method_name)
    ))
    .expect("method signature regex");
    let method_match = method_re.find(source)?;
    let params_start = method_match.end().saturating_sub(1);
    extract_balanced_region(&source[params_start..], '(', ')').map(|value| value.0)
}

fn parse_typed_parameter(parameter: &str) -> Option<(String, String, Option<String>, String)> {
    let parameter = parameter.trim();
    if parameter.is_empty() {
        return None;
    }

    let param_re = Regex::new(
        r#"(?s)^(?P<attrs>(?:\s*#\[[^\]]+\]\s*)*)(?:(?P<visibility>public|protected|private)\s+)?(?P<type>[^$=]+?)\s+\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*(?P<default>.*?))?\s*[;,]?\s*$"#,
    )
    .expect("typed parameter regex");
    let captures = param_re.captures(parameter)?;
    let type_name = captures
        .name("type")
        .map(|item| item.as_str().trim().to_string())?;
    let name = captures
        .name("name")
        .map(|item| item.as_str().trim().to_string())?;
    let attrs = captures
        .name("attrs")
        .map(|item| item.as_str().trim().to_string())
        .unwrap_or_default();
    let default = captures
        .name("default")
        .map(|item| {
            item.as_str()
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string()
        })
        .filter(|value| !value.is_empty());

    Some((type_name, name, default, attrs))
}

fn extract_class_body(source: &str) -> Option<String> {
    let class_re = Regex::new(r#"(?m)^\s*(?:final\s+|abstract\s+)?class\s+[A-Za-z_][A-Za-z0-9_]*"#)
        .expect("class body regex");
    let class_match = class_re.find(source)?;
    let brace_offset = source[class_match.end()..].find('{')? + class_match.end();
    extract_balanced_region(&source[brace_offset..], '{', '}').map(|value| value.0)
}

fn extract_data_collection_target(attrs: &str, class: &SourceClass) -> Option<String> {
    let attr_re = Regex::new(r#"DataCollectionOf\(\s*([A-Za-z_\\][A-Za-z0-9_\\]*)::class\s*\)"#)
        .expect("data collection attr regex");
    let captures = attr_re.captures(attrs)?;
    let raw = captures.get(1)?.as_str();
    Some(class.resolve_name(raw))
}

fn is_spatie_data_class(class_fqcn: &str, source_index: &SourceIndex) -> bool {
    let Some(class) = source_index.get(class_fqcn) else {
        return false;
    };
    match class.extends.as_deref() {
        Some("Spatie\\LaravelData\\Data") => true,
        Some(parent) if parent != class_fqcn => is_spatie_data_class(parent, source_index),
        _ => false,
    }
}

fn join_shape_path(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}.{name}")
    }
}

fn parse_rule_array(array_body: &str, source: &str, via: &str) -> Vec<ParsedRuleField> {
    let mut fields = Vec::new();

    for entry in split_top_level(array_body, ',') {
        let Some((raw_key, raw_value)) = split_top_level_key_value(&entry) else {
            continue;
        };
        let Some(path) = strip_php_string(&raw_key) else {
            continue;
        };

        let mut field = ParsedRuleField {
            location: "body".to_string(),
            path,
            kind: Some("field".to_string()),
            source: Some(source.to_string()),
            via: Some(via.to_string()),
            ..ParsedRuleField::default()
        };

        for rule in parse_rule_tokens(&raw_value) {
            apply_rule_token(&mut field, &rule);
        }

        if field.location == "files" && field.kind.is_none() {
            field.kind = Some("file".to_string());
        }
        if field.location == "files" && field.type_name.is_none() {
            field.type_name = Some("string".to_string());
        }
        if field.location == "files" && field.scalar_type.is_none() {
            field.scalar_type = Some("binary".to_string());
        }

        fields.push(field);
    }

    fields
}

fn parse_spatie_media_request_fields(method_text: &str) -> Vec<ParsedRuleField> {
    let variable_assign_re =
        Regex::new(r#"(?m)^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(?P<body>.*?)\]\s*;"#)
            .expect("media array assignment regex");
    let media_single_re =
        Regex::new(r#"addMediaFromRequest\(\s*(?P<arg>[^)]+?)\s*\)"#).expect("media single regex");
    let media_multi_re = Regex::new(r#"addMultipleMediaFromRequest\(\s*(?P<arg>[^)]+?)\s*\)"#)
        .expect("media multi regex");

    let mut arrays = BTreeMap::<String, Vec<String>>::new();
    for captures in variable_assign_re.captures_iter(method_text) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let Some(body) = captures.name("body") else {
            continue;
        };
        arrays.insert(
            name.as_str().to_string(),
            split_top_level(body.as_str(), ',')
                .into_iter()
                .filter_map(|item| strip_php_string(&item))
                .collect(),
        );
    }

    let mut fields = Vec::new();
    let mut seen = BTreeSet::new();

    for captures in media_single_re.captures_iter(method_text) {
        let Some(arg) = captures.name("arg") else {
            continue;
        };
        for (path, is_collection) in resolve_spatie_media_request_paths(arg.as_str(), &arrays) {
            if seen.insert(path.clone()) {
                fields.push(spatie_media_request_field(
                    path,
                    "addMediaFromRequest",
                    is_collection,
                ));
            }
        }
    }

    for captures in media_multi_re.captures_iter(method_text) {
        let Some(arg) = captures.name("arg") else {
            continue;
        };
        for (path, is_collection) in resolve_spatie_media_request_paths(arg.as_str(), &arrays) {
            if seen.insert(path.clone()) {
                fields.push(spatie_media_request_field(
                    path,
                    "addMultipleMediaFromRequest",
                    is_collection,
                ));
            }
        }
    }

    fields
}

fn resolve_spatie_media_request_paths(
    raw: &str,
    arrays: &BTreeMap<String, Vec<String>>,
) -> Vec<(String, bool)> {
    let value = raw.trim();

    if value.starts_with('[') {
        return extract_balanced_region(value, '[', ']')
            .map(|(body, _, _)| {
                split_top_level(&body, ',')
                    .into_iter()
                    .filter_map(|item| strip_php_string(&item))
                    .map(|item| {
                        let is_collection = item.ends_with("[]");
                        (item.trim_end_matches("[]").to_string(), is_collection)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
    }

    if let Some(name) = value.strip_prefix('$') {
        return arrays
            .get(name)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                let is_collection = item.ends_with("[]");
                (item.trim_end_matches("[]").to_string(), is_collection)
            })
            .collect();
    }

    strip_php_string(value)
        .map(|item| {
            let is_collection = item.ends_with("[]");
            vec![(item.trim_end_matches("[]").to_string(), is_collection)]
        })
        .unwrap_or_default()
}

fn spatie_media_request_field(path: String, via: &str, is_collection: bool) -> ParsedRuleField {
    let normalized_path = path.trim_end_matches("[]").to_string();
    let is_collection = is_collection || normalized_path != path;

    if is_collection {
        ParsedRuleField {
            location: "files".to_string(),
            path: normalized_path,
            kind: Some("collection".to_string()),
            type_name: Some("array".to_string()),
            scalar_type: None,
            format: None,
            item_type: Some("file".to_string()),
            wrappers: Vec::new(),
            allowed_values: Vec::new(),
            required: None,
            optional: None,
            nullable: None,
            is_array: Some(true),
            collection: Some(true),
            source: Some("spatie/laravel-medialibrary".to_string()),
            via: Some(via.to_string()),
        }
    } else {
        ParsedRuleField {
            location: "files".to_string(),
            path: normalized_path,
            kind: Some("file".to_string()),
            type_name: Some("string".to_string()),
            scalar_type: Some("binary".to_string()),
            format: None,
            item_type: None,
            wrappers: Vec::new(),
            allowed_values: Vec::new(),
            required: None,
            optional: None,
            nullable: None,
            is_array: None,
            collection: None,
            source: Some("spatie/laravel-medialibrary".to_string()),
            via: Some(via.to_string()),
        }
    }
}

fn parse_rule_tokens(raw_value: &str) -> Vec<String> {
    let value = raw_value.trim();

    if let Some(string_value) = strip_php_string(value) {
        return string_value
            .split('|')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect();
    }

    if value.starts_with('[') {
        let Some((inner, _, _)) = extract_balanced_region(value, '[', ']') else {
            return vec![value.to_string()];
        };
        return split_top_level(&inner, ',')
            .into_iter()
            .map(|item| strip_php_string(&item).unwrap_or(item))
            .collect();
    }

    vec![value.to_string()]
}

fn apply_rule_token(field: &mut ParsedRuleField, rule: &str) {
    let normalized = rule.trim();
    if normalized.is_empty() {
        return;
    }

    match normalized {
        "required" => {
            field.required = Some(true);
            field.optional = Some(false);
        }
        "sometimes" => field.optional = Some(true),
        "nullable" => field.nullable = Some(true),
        "string" => {
            field.kind = Some("scalar".to_string());
            field.type_name = Some("string".to_string());
            field.scalar_type = Some("string".to_string());
        }
        "integer" => {
            field.kind = Some("scalar".to_string());
            field.type_name = Some("integer".to_string());
            field.scalar_type = Some("integer".to_string());
        }
        "numeric" | "decimal" => {
            field.kind = Some("scalar".to_string());
            field.type_name = Some("number".to_string());
            field.scalar_type = Some("number".to_string());
        }
        "boolean" => {
            field.kind = Some("scalar".to_string());
            field.type_name = Some("boolean".to_string());
            field.scalar_type = Some("boolean".to_string());
        }
        "array" => {
            field.kind = Some("array".to_string());
            field.type_name = Some("array".to_string());
            field.is_array = Some(true);
            field.collection = Some(true);
        }
        "email" => {
            field.kind = Some("scalar".to_string());
            field.type_name = Some("string".to_string());
            field.scalar_type = Some("string".to_string());
            field.format = Some("email".to_string());
        }
        "date" => {
            field.kind = Some("scalar".to_string());
            field.type_name = Some("string".to_string());
            field.scalar_type = Some("string".to_string());
            field.format = Some("date".to_string());
        }
        "datetime" => {
            field.kind = Some("scalar".to_string());
            field.type_name = Some("string".to_string());
            field.scalar_type = Some("string".to_string());
            field.format = Some("date-time".to_string());
        }
        "file" | "image" => {
            field.location = "files".to_string();
            field.kind = Some("file".to_string());
            field.type_name = Some("string".to_string());
            field.scalar_type = Some("binary".to_string());
            field.wrappers.push(normalized.to_string());
        }
        _ => {
            if let Some(values) = normalized.strip_prefix("in:") {
                field.allowed_values.extend(
                    values
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(str::to_string),
                );
                field.allowed_values.sort();
                field.allowed_values.dedup();
                field.wrappers.push("in".to_string());
                return;
            }

            if normalized.starts_with("mimes:") || normalized.starts_with("mimetypes:") {
                field.location = "files".to_string();
                field.kind = Some("file".to_string());
                field.type_name = Some("string".to_string());
                field.scalar_type = Some("binary".to_string());
            }

            if normalized.starts_with("exists:")
                || normalized.starts_with("unique:")
                || normalized.starts_with("max:")
                || normalized.starts_with("min:")
                || normalized.starts_with("confirmed")
                || normalized.starts_with("regex:")
            {
                field.wrappers.push(
                    normalized
                        .split(':')
                        .next()
                        .unwrap_or(normalized)
                        .to_string(),
                );
                return;
            }

            if normalized.starts_with("Rule::in(") {
                if let Some((inner, _, _)) = extract_balanced_region(normalized, '(', ')') {
                    let values = inner
                        .split_once('[')
                        .and_then(|(_, tail)| {
                            extract_balanced_region(&format!("[{tail}"), '[', ']')
                        })
                        .map(|(body, _, _)| {
                            split_top_level(&body, ',')
                                .into_iter()
                                .filter_map(|item| strip_php_string(&item))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    field.allowed_values.extend(values);
                    field.allowed_values.sort();
                    field.allowed_values.dedup();
                }
                field.wrappers.push("in".to_string());
                return;
            }

            if normalized.starts_with("Rule::unique(") {
                field.wrappers.push("unique".to_string());
                return;
            }

            if normalized.starts_with("Rule::exists(") {
                field.wrappers.push("exists".to_string());
                return;
            }
        }
    }
}

fn collect_route_methods(result: &PipelineResult) -> BTreeMap<String, Vec<String>> {
    let mut route_methods = BTreeMap::<String, BTreeSet<String>>::new();

    for binding in &result.route_bindings {
        let action_key = format!("{}::{}", binding.controller_fqcn, binding.method_name);
        route_methods
            .entry(action_key)
            .or_default()
            .extend(binding.http_methods.iter().cloned());
    }

    route_methods
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect()
}

fn collect_scope_owners(result: &PipelineResult) -> BTreeMap<String, Option<String>> {
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
        .into_iter()
        .map(|(scope, models)| {
            let owner = if models.len() == 1 {
                models.into_iter().next()
            } else {
                None
            };
            (scope, owner)
        })
        .collect()
}

fn collect_related_models_by_morph(result: &PipelineResult) -> BTreeMap<String, BTreeSet<String>> {
    let mut mapping = BTreeMap::<String, BTreeSet<String>>::new();

    for file in &result.files {
        for model in &file.facts.models {
            extend_related_models_for_model(model, &mut mapping);
        }
    }

    mapping
}

fn extend_related_models_for_model(
    model: &ModelFacts,
    mapping: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for relationship in &model.relationships {
        let Some(morph_name) = &relationship.morph_name else {
            continue;
        };
        let Some(related) = &relationship.related else {
            continue;
        };
        mapping
            .entry(morph_name.clone())
            .or_default()
            .insert(related.clone());
    }
}

fn class_basename(fqcn: &str) -> String {
    fqcn.rsplit('\\').next().unwrap_or(fqcn).to_string()
}

fn is_collection_resource(resource: &ResourceUsageFact) -> bool {
    matches!(resource.method.as_deref(), Some("collection"))
        || resource.class_name.ends_with("Collection")
}

fn is_polymorphic_relation_type(relation_type: &str) -> bool {
    matches!(
        relation_type,
        "morphTo" | "morphOne" | "morphMany" | "morphByMany" | "morphToMany" | "morphedByMany"
    )
}

fn normalize_polymorphic_relation_type(relation_type: &str) -> String {
    match relation_type {
        "morphedByMany" => "morphByMany".to_string(),
        other => other.to_string(),
    }
}

fn build_discriminator_mapping(values: &BTreeSet<String>) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|fqcn| (class_basename(fqcn), fqcn.clone()))
        .collect()
}

fn build_discriminator_mapping_from_vec(values: &[String]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|fqcn| (class_basename(fqcn), fqcn.clone()))
        .collect()
}

fn build_response_schema(
    fqcn: &str,
    collection: bool,
    _source_index: &SourceIndex,
    _model_index: &BTreeMap<String, ModelFacts>,
) -> Value {
    if collection && !fqcn.ends_with("Collection") {
        schema_resource_collection(schema_ref(fqcn))
    } else {
        schema_ref(fqcn)
    }
}

fn build_resource_schema(
    fqcn: &str,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    visited: &mut BTreeSet<String>,
) -> Value {
    if !visited.insert(fqcn.to_string()) {
        return schema_object(BTreeMap::new());
    }

    let schema = source_index
        .get(fqcn)
        .and_then(|class| {
            build_resource_schema_from_class(class, source_index, model_index, visited)
        })
        .unwrap_or_else(|| schema_object(BTreeMap::new()));

    visited.remove(fqcn);
    schema
}

fn build_resource_schema_from_class(
    class: &SourceClass,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    visited: &mut BTreeSet<String>,
) -> Option<Value> {
    let method_body = class.method_body("toArray")?;
    let array_body = extract_return_array(&method_body)?;
    let model_fqcn = resolve_model_fqcn_from_resource(&class.fqcn, source_index).0;

    Some(parse_php_array_schema(
        &array_body,
        source_index,
        model_index,
        Some(class),
        model_fqcn.as_deref(),
        visited,
    ))
}

fn parse_php_array_schema(
    array_body: &str,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    current_class: Option<&SourceClass>,
    current_model_fqcn: Option<&str>,
    visited: &mut BTreeSet<String>,
) -> Value {
    let entries = split_top_level(array_body, ',');
    let mut properties = BTreeMap::<String, Value>::new();
    let mut items = Vec::new();
    let mut associative = false;

    for entry in entries {
        if let Some((raw_key, raw_value)) = split_top_level_key_value(&entry) {
            associative = true;
            let key = strip_php_string(&raw_key).unwrap_or(raw_key.trim().to_string());
            properties.insert(
                key,
                infer_resource_reference_schema(&raw_value, current_class).unwrap_or_else(|| {
                    infer_value_schema(
                        &raw_value,
                        source_index,
                        model_index,
                        current_class,
                        current_model_fqcn,
                        visited,
                    )
                }),
            );
        } else {
            items.push(infer_value_schema(
                &entry,
                source_index,
                model_index,
                current_class,
                current_model_fqcn,
                visited,
            ));
        }
    }

    if associative {
        schema_object(properties)
    } else {
        let item_schema = items
            .into_iter()
            .next()
            .unwrap_or_else(|| schema_object(BTreeMap::new()));
        schema_array(item_schema)
    }
}

fn infer_value_schema(
    raw_value: &str,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    current_class: Option<&SourceClass>,
    current_model_fqcn: Option<&str>,
    visited: &mut BTreeSet<String>,
) -> Value {
    let value = raw_value.trim();

    if let Some(string_value) = strip_php_string(value) {
        return schema_for_php_string_literal(&string_value);
    }
    if value == "true" || value == "false" {
        return schema_boolean();
    }
    if value == "null" {
        return json!({ "nullable": true });
    }
    if value.parse::<i64>().is_ok() {
        return schema_integer();
    }
    if value.parse::<f64>().is_ok() && value.contains('.') {
        return schema_number();
    }
    if value.starts_with('[') {
        if let Some((inner, _, _)) = extract_balanced_region(value, '[', ']') {
            return parse_php_array_schema(
                &inner,
                source_index,
                model_index,
                current_class,
                current_model_fqcn,
                visited,
            );
        }
    }
    if let Some(captures) = Regex::new(r#"new\s+([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))\("#)
        .expect("resource new value regex")
        .captures(value)
    {
        if let Some(resource_name) = captures.get(1) {
            let fqcn = current_class
                .map(|class| class.resolve_name(resource_name.as_str()))
                .unwrap_or_else(|| resource_name.as_str().to_string());
            let schema = if current_class.is_some_and(is_resource_class) {
                schema_ref(&fqcn)
            } else {
                schema_openapi_ref(&fqcn)
            };
            return if value.contains("whenLoaded(") {
                schema_nullable(schema)
            } else {
                schema
            };
        }
    }
    if let Some(captures) =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))::collection\("#)
            .expect("resource collection value regex")
            .captures(value)
    {
        if let Some(resource_name) = captures.get(1) {
            let fqcn = current_class
                .map(|class| class.resolve_name(resource_name.as_str()))
                .unwrap_or_else(|| resource_name.as_str().to_string());
            let item_schema = if current_class.is_some_and(is_resource_class) {
                schema_ref(&fqcn)
            } else {
                schema_openapi_ref(&fqcn)
            };
            let schema = schema_array(item_schema);
            return if value.contains("whenLoaded(") {
                schema_nullable(schema)
            } else {
                schema
            };
        }
    }
    if value.contains("fn () =>") {
        if let Some((_, tail)) = value.split_once("fn () =>") {
            return infer_value_schema(
                tail.trim(),
                source_index,
                model_index,
                current_class,
                current_model_fqcn,
                visited,
            );
        }
    }
    if value.contains("->count()") {
        return schema_integer();
    }
    if value.contains("->avg(") {
        return schema_number();
    }
    if value.contains("->previousPageUrl()") || value.contains("->nextPageUrl()") {
        return schema_nullable(schema_string(None));
    }
    if value.contains("->url(") {
        return schema_string(None);
    }
    if value.contains("->total()")
        || value.contains("->perPage()")
        || value.contains("->currentPage()")
        || value.contains("->lastPage()")
    {
        return schema_integer();
    }
    if let Some(property) = value.strip_prefix("$this->") {
        let property = property
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .next()
            .unwrap_or(property);
        if property == "collection" {
            if let Some(class) = current_class {
                if let Some(resource_fqcn) =
                    infer_collection_item_resource(&class.fqcn, source_index)
                {
                    let item_schema =
                        build_resource_schema(&resource_fqcn, source_index, model_index, visited);
                    return schema_array(item_schema);
                }
            }
            return schema_array(schema_object(BTreeMap::new()));
        }
        if let Some(model_fqcn) = current_model_fqcn {
            if let Some(schema) = infer_model_property_schema(
                model_fqcn,
                property,
                source_index,
                model_index,
                visited,
            ) {
                return schema;
            }
        }
        return schema_object(BTreeMap::new());
    }

    schema_object(BTreeMap::new())
}

fn infer_model_property_schema(
    model_fqcn: &str,
    property: &str,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    visited: &mut BTreeSet<String>,
) -> Option<Value> {
    let hint = model_schema_hint(model_fqcn, source_index);
    if property == "id" {
        return Some(schema_integer());
    }
    if property == "created_at" || property == "updated_at" || property.ends_with("_at") {
        return Some(schema_string(Some("date-time")));
    }
    if property.ends_with("_count") {
        return Some(schema_integer());
    }
    if property.starts_with("is_") {
        return Some(schema_boolean());
    }
    if let Some(cast) = hint.casts.get(property) {
        return Some(schema_from_cast(cast));
    }
    if hint.fillable.contains(property) {
        return Some(schema_string(None));
    }

    let model = model_index.get(model_fqcn)?;
    let relationship = model
        .relationships
        .iter()
        .find(|item| item.name == property)?;
    let related = relationship.related.as_ref()?;
    let related_schema = build_model_object_schema(
        related,
        source_index,
        model_index,
        &BTreeSet::new(),
        visited,
    );

    Some(if relation_is_collection(&relationship.relation_type) {
        schema_array(related_schema)
    } else {
        related_schema
    })
}

fn build_model_object_schema(
    model_fqcn: &str,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    loaded_relations: &BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> Value {
    let visit_key = format!("model:{model_fqcn}");
    if !visited.insert(visit_key.clone()) {
        return schema_object(BTreeMap::new());
    }

    let hint = model_schema_hint(model_fqcn, source_index);
    let mut properties = BTreeMap::<String, Value>::new();

    for attribute in &hint.fillable {
        if hint.hidden.contains(attribute) {
            continue;
        }
        properties.insert(
            attribute.clone(),
            hint.casts
                .get(attribute)
                .map(|cast| schema_from_cast(cast))
                .unwrap_or_else(|| schema_string(None)),
        );
    }
    for (attribute, cast) in &hint.casts {
        if hint.hidden.contains(attribute) {
            continue;
        }
        properties
            .entry(attribute.clone())
            .or_insert_with(|| schema_from_cast(cast));
    }

    if let Some(model) = model_index.get(model_fqcn) {
        for relation_name in loaded_relations {
            let Some(relationship) = model
                .relationships
                .iter()
                .find(|item| &item.name == relation_name)
            else {
                continue;
            };
            let Some(related_fqcn) = &relationship.related else {
                continue;
            };
            let relation_schema = build_model_object_schema(
                related_fqcn,
                source_index,
                model_index,
                &BTreeSet::new(),
                visited,
            );
            properties.insert(
                relation_name.clone(),
                if relation_is_collection(&relationship.relation_type) {
                    schema_array(relation_schema)
                } else {
                    relation_schema
                },
            );
        }
    }

    visited.remove(&visit_key);
    schema_object(properties)
}

fn extract_json_response_calls(method_text: &str) -> Vec<JsonResponseCall> {
    let mut calls = Vec::new();
    let mut offset = 0usize;
    let needle = "response()->json(";

    while let Some(index) = method_text[offset..].find(needle) {
        let start = offset + index + "response()->json".len();
        let Some((args, _, end_index)) = extract_balanced_region(&method_text[start..], '(', ')')
        else {
            offset = start + 1;
            continue;
        };
        let arguments = split_top_level(&args, ',');
        let payload = arguments.first().cloned().unwrap_or_default();
        let status = arguments
            .get(1)
            .and_then(|value| value.trim().parse::<u16>().ok());
        calls.push(JsonResponseCall { payload, status });
        offset = start + end_index + 1;
    }

    calls
}

fn infer_schema_from_expression(
    expression: &str,
    controller: &ControllerMethod,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    visited: &mut BTreeSet<String>,
) -> Option<Value> {
    let expression = expression.trim();
    if expression.is_empty() {
        return None;
    }
    if let Some(string_value) = strip_php_string(expression) {
        return Some(schema_for_php_string_literal(&string_value));
    }
    if expression == "true" || expression == "false" {
        return Some(schema_boolean());
    }
    if expression.parse::<i64>().is_ok() {
        return Some(schema_integer());
    }
    if expression.parse::<f64>().is_ok() && expression.contains('.') {
        return Some(schema_number());
    }
    if expression.contains("->count()") {
        return Some(schema_integer());
    }
    if expression.contains("->avg(") {
        return Some(schema_number());
    }
    if expression.starts_with('[') {
        let (inner, _, _) = extract_balanced_region(expression, '[', ']')?;
        return Some(parse_php_array_schema(
            &inner,
            source_index,
            model_index,
            source_index.get(&controller.fqcn),
            resolve_primary_model_fqcn(controller, source_index).as_deref(),
            visited,
        ));
    }

    let class = source_index.get(&controller.fqcn);
    let state = collect_controller_source_state(controller, class);

    if let Some(captures) =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))::collection\("#)
            .expect("controller resource collection regex")
            .captures(expression)
    {
        let resource_name = captures.get(1)?.as_str();
        let fqcn = class
            .map(|value| value.resolve_name(resource_name))
            .unwrap_or_else(|| resource_name.to_string());
        return Some(schema_resource_collection(schema_ref(&fqcn)));
    }

    if let Some(captures) = Regex::new(r#"new\s+([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))\("#)
        .expect("controller new resource regex")
        .captures(expression)
    {
        let resource_name = captures.get(1)?.as_str();
        let fqcn = class
            .map(|value| value.resolve_name(resource_name))
            .unwrap_or_else(|| resource_name.to_string());
        let _ = (source_index, model_index, visited);
        return Some(schema_openapi_ref(&fqcn));
    }

    if let Some(variable_name) = expression.strip_prefix('$') {
        let variable = variable_name
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .next()
            .unwrap_or(variable_name);
        if let Some(parameter_type) = state.parameters.get(variable) {
            let loaded = extract_loaded_relations(expression);
            return Some(build_model_object_schema(
                parameter_type,
                source_index,
                model_index,
                &loaded,
                visited,
            ));
        }
        if let Some(assignment) = state.assignments.get(variable) {
            return infer_schema_from_assignment(
                assignment,
                controller,
                source_index,
                model_index,
                &state,
                visited,
            );
        }
    }

    infer_schema_from_assignment(
        expression,
        controller,
        source_index,
        model_index,
        &state,
        visited,
    )
}

fn infer_schema_from_assignment(
    expression: &str,
    controller: &ControllerMethod,
    source_index: &SourceIndex,
    model_index: &BTreeMap<String, ModelFacts>,
    state: &ControllerSourceState,
    visited: &mut BTreeSet<String>,
) -> Option<Value> {
    let expression = expression.trim();
    let controller_class = source_index.get(&controller.fqcn);

    if expression.contains("paginate(") {
        let model_fqcn =
            infer_model_fqcn_from_expression(expression, controller_class, source_index)?;
        let item_schema = build_model_object_schema(
            &model_fqcn,
            source_index,
            model_index,
            &BTreeSet::new(),
            visited,
        );
        return Some(schema_paginated(item_schema));
    }
    if expression.contains("::all()") || expression.contains("->get()") {
        let model_fqcn =
            infer_model_fqcn_from_expression(expression, controller_class, source_index)?;
        let item_schema = build_model_object_schema(
            &model_fqcn,
            source_index,
            model_index,
            &BTreeSet::new(),
            visited,
        );
        return Some(schema_array(item_schema));
    }
    if expression.contains("::create(") || expression.contains("->create(") {
        let model_fqcn =
            infer_model_fqcn_from_expression(expression, controller_class, source_index)?;
        return Some(build_model_object_schema(
            &model_fqcn,
            source_index,
            model_index,
            &extract_loaded_relations(expression),
            visited,
        ));
    }
    if expression.contains("->load(")
        || expression.contains("->fresh(")
        || expression.contains("->update(")
    {
        if let Some(variable_name) = expression.strip_prefix('$') {
            let variable = variable_name
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .next()
                .unwrap_or(variable_name);
            if let Some(parameter_type) = state.parameters.get(variable) {
                return Some(build_model_object_schema(
                    parameter_type,
                    source_index,
                    model_index,
                    &extract_loaded_relations(expression),
                    visited,
                ));
            }
        }
    }

    None
}

fn collect_controller_source_state(
    controller: &ControllerMethod,
    class: Option<&SourceClass>,
) -> ControllerSourceState {
    let mut state = ControllerSourceState::default();
    let signature_re =
        Regex::new(r#"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)"#).expect("signature regex");
    if let Some(captures) = signature_re.captures(&controller.body_text) {
        if let Some(group) = captures.get(1) {
            for parameter in split_top_level(group.as_str(), ',') {
                let param_re =
                    Regex::new(r#"(?:(\??[A-Z][A-Za-z0-9_\\]*)\s+)?\$([A-Za-z_][A-Za-z0-9_]*)"#)
                        .expect("parameter regex");
                let Some(captures) = param_re.captures(&parameter) else {
                    continue;
                };
                let Some(name) = captures.get(2) else {
                    continue;
                };
                let Some(type_name) = captures.get(1) else {
                    continue;
                };
                let raw_type = type_name.as_str().trim_start_matches('?');
                let resolved = class
                    .map(|item| item.resolve_name(raw_type))
                    .unwrap_or_else(|| raw_type.to_string());
                state.parameters.insert(name.as_str().to_string(), resolved);
            }
        }
    }

    let method_body = controller
        .body_text
        .find('{')
        .and_then(|index| extract_balanced_region(&controller.body_text[index..], '{', '}'))
        .map(|(body, _, _)| body)
        .unwrap_or_else(|| controller.body_text.clone());

    for statement in split_top_level(&method_body, ';') {
        let assign_re =
            Regex::new(r#"^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$"#).expect("assign regex");
        let Some(captures) = assign_re.captures(&statement) else {
            continue;
        };
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(value) = captures.get(2) else {
            continue;
        };
        state
            .assignments
            .insert(name.as_str().to_string(), value.as_str().trim().to_string());
    }

    state
}

fn infer_model_fqcn_from_expression(
    expression: &str,
    class: Option<&SourceClass>,
    source_index: &SourceIndex,
) -> Option<String> {
    let model_call_re =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*)::(?:query|with|create|all|get|find|where)"#)
            .expect("model call regex");
    if let Some(captures) = model_call_re.captures(expression) {
        let raw = captures.get(1)?.as_str();
        let fqcn = class
            .map(|item| item.resolve_name(raw))
            .unwrap_or_else(|| raw.to_string());
        return Some(fqcn);
    }

    let relation_create_re =
        Regex::new(r#"->([a-z][A-Za-z0-9_]*)\(\)->create\("#).expect("relation create regex");
    if let Some(captures) = relation_create_re.captures(expression) {
        let relation = captures.get(1)?.as_str();
        let singular = singularize(relation);
        return source_index.find_model_by_basename(&singular);
    }

    None
}

fn resolve_primary_model_fqcn(
    controller: &ControllerMethod,
    source_index: &SourceIndex,
) -> Option<String> {
    let controller_name = class_basename(&controller.fqcn);
    let model_name = controller_name.trim_end_matches("Controller");
    let singular = singularize(model_name);
    source_index.find_model_by_basename(&singular)
}

fn extract_loaded_relations(expression: &str) -> BTreeSet<String> {
    let load_re =
        Regex::new(r#"->(?:load|fresh)\(\s*\[([^\]]*)\]"#).expect("loaded relation regex");
    let Some(captures) = load_re.captures(expression) else {
        return BTreeSet::new();
    };
    let Some(group) = captures.get(1) else {
        return BTreeSet::new();
    };

    split_top_level(group.as_str(), ',')
        .into_iter()
        .filter_map(|item| strip_php_string(&item))
        .map(|relation| relation.split('.').next().unwrap_or(&relation).to_string())
        .collect()
}

fn model_schema_hint(model_fqcn: &str, source_index: &SourceIndex) -> ModelSchemaHint {
    let Some(class) = source_index.get(model_fqcn) else {
        return ModelSchemaHint::default();
    };

    ModelSchemaHint {
        fillable: parse_string_array_property(&class.source_text, "fillable"),
        hidden: parse_string_array_property(&class.source_text, "hidden"),
        casts: parse_string_map_property(&class.source_text, "casts"),
    }
}

fn parse_string_array_property(source: &str, property: &str) -> BTreeSet<String> {
    extract_array_property(source, property)
        .map(|body| {
            split_top_level(&body, ',')
                .into_iter()
                .filter_map(|item| strip_php_string(&item))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_string_map_property(source: &str, property: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let Some(body) = extract_array_property(source, property) else {
        return values;
    };

    for entry in split_top_level(&body, ',') {
        let Some((raw_key, raw_value)) = split_top_level_key_value(&entry) else {
            continue;
        };
        let Some(key) = strip_php_string(&raw_key) else {
            continue;
        };
        let value = strip_php_string(&raw_value).unwrap_or(raw_value.trim().to_string());
        values.insert(key, value);
    }

    values
}

fn collect_translatable_attributes(
    class_fqcn: &str,
    source_index: &SourceIndex,
) -> BTreeSet<String> {
    let mut attributes = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut current = Some(class_fqcn.to_string());

    while let Some(fqcn) = current {
        if !visited.insert(fqcn.clone()) {
            break;
        }

        let Some(class) = source_index.get(&fqcn) else {
            break;
        };

        attributes.extend(parse_translatable_array_property(&class.source_text));
        current = class.extends.clone();
    }

    attributes
}

fn is_eloquent_model_class(class_fqcn: &str, source_index: &SourceIndex) -> bool {
    let Some(class) = source_index.get(class_fqcn) else {
        return false;
    };

    match class.extends.as_deref() {
        Some("Illuminate\\Database\\Eloquent\\Model") => true,
        Some(parent) if parent != class_fqcn => is_eloquent_model_class(parent, source_index),
        _ => false,
    }
}

fn parse_translatable_array_property(source: &str) -> BTreeSet<String> {
    let Some(expression) = extract_property_assignment_expression(source, "translatable") else {
        return BTreeSet::new();
    };
    parse_php_string_array_expression(source, &expression)
}

fn extract_property_assignment_expression(source: &str, property: &str) -> Option<String> {
    let property_re = Regex::new(&format!(
        r#"(?s)(?:public|protected|private)\s+array\s+\${}\s*=\s*(.+?);"#,
        regex::escape(property)
    ))
    .expect("property assignment regex");
    property_re
        .captures(source)
        .and_then(|captures| captures.get(1))
        .map(|item| item.as_str().trim().to_string())
}

fn parse_php_string_array_expression(source: &str, expression: &str) -> BTreeSet<String> {
    let value = expression.trim();

    if value.starts_with('[') {
        return extract_balanced_region(value, '[', ']')
            .map(|(body, _, _)| {
                split_top_level(&body, ',')
                    .into_iter()
                    .filter_map(|item| strip_php_string(&item))
                    .collect()
            })
            .unwrap_or_default();
    }

    if let Some(const_name) = value
        .strip_prefix("self::")
        .or_else(|| value.strip_prefix("static::"))
    {
        return extract_const_array_property(source, const_name);
    }

    BTreeSet::new()
}

fn extract_const_array_property(source: &str, const_name: &str) -> BTreeSet<String> {
    let const_re = Regex::new(&format!(
        r#"(?s)(?:public|protected|private)?\s*const\s+{}\s*=\s*\["#,
        regex::escape(const_name)
    ))
    .expect("const array regex");
    let Some(const_match) = const_re.find(source) else {
        return BTreeSet::new();
    };
    let Some(start) = source[const_match.start()..]
        .find('[')
        .map(|index| index + const_match.start())
    else {
        return BTreeSet::new();
    };
    let Some((body, _, _)) = extract_balanced_region(&source[start..], '[', ']') else {
        return BTreeSet::new();
    };

    split_top_level(&body, ',')
        .into_iter()
        .filter_map(|item| strip_php_string(&item))
        .collect()
}

fn extract_array_property(source: &str, property: &str) -> Option<String> {
    let property_re = Regex::new(&format!(
        r#"(?s)(?:public|protected|private)\s+\${}\s*=\s*\["#,
        regex::escape(property)
    ))
    .expect("array property regex");
    let property_match = property_re.find(source)?;
    let start = source[property_match.start()..].find('[')? + property_match.start();
    extract_balanced_region(&source[start..], '[', ']').map(|(body, _, _)| body)
}

fn is_resource_class(class: &SourceClass) -> bool {
    class.fqcn.contains("\\Http\\Resources\\")
        || class.extends.as_ref().is_some_and(|extends| {
            extends.ends_with("JsonResource") || extends.ends_with("ResourceCollection")
        })
        || class.class_name.ends_with("Resource")
        || class.class_name.ends_with("Collection")
}

fn resolve_model_fqcn_from_resource(
    resource_fqcn: &str,
    source_index: &SourceIndex,
) -> (Option<String>, String) {
    let model_name = class_basename(resource_fqcn)
        .trim_end_matches("Collection")
        .trim_end_matches("Resource")
        .to_string();
    let relation = model_name.to_lowercase();
    let model_fqcn = source_index.find_model_by_basename(&model_name);
    (model_fqcn, relation)
}

fn infer_collection_item_resource(
    collection_fqcn: &str,
    source_index: &SourceIndex,
) -> Option<String> {
    let candidate = class_basename(collection_fqcn)
        .trim_end_matches("Collection")
        .to_string();
    let resource_fqcn = source_index
        .classes
        .keys()
        .find(|fqcn| fqcn.ends_with(&format!("\\{}Resource", candidate)))
        .cloned();
    resource_fqcn
}

fn schema_from_cast(cast: &str) -> Value {
    let normalized = cast.trim().to_ascii_lowercase();
    if normalized.starts_with("int") {
        schema_integer()
    } else if normalized.starts_with("decimal") || normalized.starts_with("float") {
        schema_number()
    } else if normalized.starts_with("bool") {
        schema_boolean()
    } else if normalized.starts_with("date") || normalized.starts_with("datetime") {
        schema_string(Some("date-time"))
    } else if normalized == "array" || normalized == "collection" || normalized == "json" {
        schema_array(schema_object(BTreeMap::new()))
    } else {
        schema_string(None)
    }
}

fn schema_type(schema: &Value) -> Option<&str> {
    schema.get("type").and_then(Value::as_str)
}

fn schema_object(properties: BTreeMap<String, Value>) -> Value {
    if properties.is_empty() {
        json!({ "type": "object" })
    } else {
        json!({ "type": "object", "properties": properties })
    }
}

fn schema_array(items: Value) -> Value {
    json!({ "type": "array", "items": items })
}

fn schema_resource_collection(items: Value) -> Value {
    json!({
        "type": "object",
        "required": ["data"],
        "properties": {
            "data": schema_array(items)
        }
    })
}

fn schema_paginated(item_schema: Value) -> Value {
    json!({
        "type": "object",
        "properties": {
            "data": schema_array(item_schema),
            "meta": { "type": "object" },
            "links": { "type": "object" }
        }
    })
}

fn schema_string(format: Option<&str>) -> Value {
    match format {
        Some(format) => json!({ "type": "string", "format": format }),
        None => json!({ "type": "string" }),
    }
}

fn infer_resource_reference_schema(
    raw_value: &str,
    current_class: Option<&SourceClass>,
) -> Option<Value> {
    let value = raw_value.trim();

    if let Some(captures) = Regex::new(r#"new\s+([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))\("#)
        .expect("resource ref new regex")
        .captures(value)
    {
        let resource_name = captures.get(1)?.as_str();
        let fqcn = current_class
            .map(|class| class.resolve_name(resource_name))
            .unwrap_or_else(|| resource_name.to_string());
        let schema = schema_ref(&fqcn);
        return Some(if value.contains("whenLoaded(") {
            schema_nullable(schema)
        } else {
            schema
        });
    }

    if let Some(captures) =
        Regex::new(r#"([A-Z][A-Za-z0-9_\\]*(?:Resource|Collection))::collection\("#)
            .expect("resource ref collection regex")
            .captures(value)
    {
        let resource_name = captures.get(1)?.as_str();
        let fqcn = current_class
            .map(|class| class.resolve_name(resource_name))
            .unwrap_or_else(|| resource_name.to_string());
        let schema = schema_array(schema_ref(&fqcn));
        return Some(if value.contains("whenLoaded(") {
            schema_nullable(schema)
        } else {
            schema
        });
    }

    None
}

fn schema_for_php_string_literal(value: &str) -> Value {
    if value.starts_with("http://") || value.starts_with("https://") {
        schema_string(Some("uri"))
    } else {
        schema_string(None)
    }
}

fn schema_integer() -> Value {
    json!({ "type": "integer" })
}

fn schema_number() -> Value {
    json!({ "type": "number" })
}

fn schema_boolean() -> Value {
    json!({ "type": "boolean" })
}

fn schema_nullable(schema: Value) -> Value {
    let mut value = schema;
    if let Some(object) = value.as_object_mut() {
        object.insert("nullable".to_string(), Value::Bool(true));
    }
    value
}

fn schema_ref(fqcn: &str) -> Value {
    json!({ "ref": fqcn })
}

fn schema_openapi_ref(fqcn: &str) -> Value {
    json!({ "$ref": fqcn })
}

fn relation_is_collection(relation_type: &str) -> bool {
    matches!(
        relation_type,
        "hasMany" | "belongsToMany" | "morphMany" | "morphToMany" | "morphByMany"
    )
}

fn singularize(value: &str) -> String {
    value.strip_suffix('s').unwrap_or(value).to_string()
}

fn extract_route_redirect_target(text: &str) -> Option<String> {
    let redirect_re = Regex::new(r#"(?:redirect\(\)->route|to_route)\(\s*['"]([^'"]+)['"]"#)
        .expect("redirect regex");
    redirect_re
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|item| item.as_str().to_string())
}

fn extract_inertia_location_target(text: &str) -> Option<String> {
    let inertia_location_re =
        Regex::new(r#"Inertia::location\(\s*['"]([^'"]+)['"]"#).expect("inertia location regex");
    inertia_location_re
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|item| item.as_str().to_string())
}

fn extract_download_filename(text: &str) -> Option<String> {
    let filename_re =
        Regex::new(r#"download\([^,]+,\s*['"]([^'"]+)['"]"#).expect("download filename regex");
    filename_re
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|item| item.as_str().to_string())
}

fn extract_channel_params(channel: &str) -> Vec<String> {
    let channel_re = Regex::new(r#"\{([^}]+)\}"#).expect("channel params regex");
    let mut params = channel_re
        .captures_iter(channel)
        .filter_map(|captures| captures.get(1).map(|item| item.as_str().to_string()))
        .collect::<Vec<_>>();
    params.sort();
    params.dedup();
    params
}

fn infer_broadcast_visibility(channel: &str, explicit: Option<&str>) -> String {
    if let Some(explicit) = explicit {
        return explicit.to_string();
    }

    let normalized = channel.to_ascii_lowercase();
    if normalized.contains("presence") {
        "presence".to_string()
    } else if normalized.contains("public") {
        "public".to_string()
    } else {
        "private".to_string()
    }
}
