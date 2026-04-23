pub const SYMBOL_KIND_CONTROLLER_METHOD: &str = "controller_method";
pub const FINDING_CATEGORY_UNUSED_CONTROLLER_METHOD: &str = "unused_controller_method";
pub const CONFIDENCE_HIGH: &str = "high";

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
