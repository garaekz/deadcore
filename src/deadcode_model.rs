pub const SYMBOL_KIND_CONTROLLER_CLASS: &str = "controller_class";
pub const SYMBOL_KIND_CONTROLLER_METHOD: &str = "controller_method";
pub const SYMBOL_KIND_COMMAND_CLASS: &str = "command_class";
pub const SYMBOL_KIND_FORM_REQUEST_CLASS: &str = "form_request_class";
pub const SYMBOL_KIND_JOB_CLASS: &str = "job_class";
pub const SYMBOL_KIND_LISTENER_CLASS: &str = "listener_class";
pub const SYMBOL_KIND_MODEL_ACCESSOR: &str = "model_accessor";
pub const SYMBOL_KIND_MODEL_METHOD: &str = "model_method";
pub const SYMBOL_KIND_MODEL_MUTATOR: &str = "model_mutator";
pub const SYMBOL_KIND_MODEL_RELATIONSHIP: &str = "model_relationship";
pub const SYMBOL_KIND_MODEL_SCOPE: &str = "model_scope";
pub const SYMBOL_KIND_POLICY_CLASS: &str = "policy_class";
pub const SYMBOL_KIND_RESOURCE_CLASS: &str = "resource_class";
pub const SYMBOL_KIND_SUBSCRIBER_CLASS: &str = "subscriber_class";
pub const FINDING_CATEGORY_UNUSED_COMMAND_CLASS: &str = "unused_command_class";
pub const FINDING_CATEGORY_UNUSED_CONTROLLER_CLASS: &str = "unused_controller_class";
pub const FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD: &str = "unused_controller_method";
pub const FINDING_CATEGORY_UNUSED_FORM_REQUEST: &str = "unused_form_request";
pub const FINDING_CATEGORY_UNUSED_JOB_CLASS: &str = "unused_job_class";
pub const FINDING_CATEGORY_UNUSED_LISTENER_CLASS: &str = "unused_listener_class";
pub const FINDING_CATEGORY_UNUSED_MODEL_ACCESSOR: &str = "unused_model_accessor";
pub const FINDING_CATEGORY_UNUSED_MODEL_METHOD: &str = "unused_model_method";
pub const FINDING_CATEGORY_UNUSED_MODEL_MUTATOR: &str = "unused_model_mutator";
pub const FINDING_CATEGORY_UNUSED_MODEL_RELATIONSHIP: &str = "unused_model_relationship";
pub const FINDING_CATEGORY_UNUSED_MODEL_SCOPE: &str = "unused_model_scope";
pub const FINDING_CATEGORY_UNUSED_POLICY_CLASS: &str = "unused_policy_class";
pub const FINDING_CATEGORY_UNUSED_RESOURCE_CLASS: &str = "unused_resource_class";
pub const FINDING_CATEGORY_UNUSED_SUBSCRIBER_CLASS: &str = "unused_subscriber_class";
pub const CONFIDENCE_HIGH: &str = "high";
pub const CONFIDENCE_MEDIUM: &str = "medium";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ReasonRecord {
    pub code: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "relatedSymbol", skip_serializing_if = "Option::is_none")]
    pub related_symbol: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SymbolRecord {
    pub kind: String,
    pub symbol: String,
    pub file: String,
    #[serde(rename = "reachableFromRuntime")]
    pub reachable_from_runtime: bool,
    #[serde(rename = "reasonSummary", skip_serializing_if = "Option::is_none")]
    pub reason_summary: Option<String>,
    #[serde(
        rename = "reachabilityReasons",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub reachability_reasons: Vec<ReasonRecord>,
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub symbol: String,
    pub category: String,
    pub confidence: String,
    pub file: String,
    #[serde(rename = "reasonSummary", skip_serializing_if = "Option::is_none")]
    pub reason_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ReasonRecord>,
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
}
