pub const SYMBOL_KIND_CONTROLLER_CLASS: &str = "controller_class";
pub const SYMBOL_KIND_CONTROLLER_METHOD: &str = "controller_method";
pub const SYMBOL_KIND_COMMAND_CLASS: &str = "command_class";
pub const SYMBOL_KIND_FORM_REQUEST_CLASS: &str = "form_request_class";
pub const SYMBOL_KIND_RESOURCE_CLASS: &str = "resource_class";
pub const FINDING_CATEGORY_UNUSED_COMMAND_CLASS: &str = "unused_command_class";
pub const FINDING_CATEGORY_UNUSED_CONTROLLER_CLASS: &str = "unused_controller_class";
pub const FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD: &str = "unused_controller_method";
pub const FINDING_CATEGORY_UNUSED_FORM_REQUEST: &str = "unused_form_request";
pub const FINDING_CATEGORY_UNUSED_RESOURCE_CLASS: &str = "unused_resource_class";
pub const CONFIDENCE_HIGH: &str = "high";
pub const CONFIDENCE_MEDIUM: &str = "medium";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolRecord {
    pub kind: String,
    pub symbol: String,
    pub file: String,
    #[serde(rename = "reachableFromRuntime")]
    pub reachable_from_runtime: bool,
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub symbol: String,
    pub category: String,
    pub confidence: String,
    pub file: String,
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
}
