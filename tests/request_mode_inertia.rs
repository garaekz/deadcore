use serde_json::json;
use std::collections::BTreeMap;

#[path = "support/oxcribe_fixture_request.rs"]
mod oxcribe_fixture_request;

use oxinfer::contract_inertia::infer_inertia_response;
use oxinfer::contracts::ContractHttpInfo;
use oxinfer::model::ControllerMethod;
use oxinfer::source_index::SourceIndex;

use oxcribe_fixture_request::{find_controller, run_fixture_request};

fn controller_with_body(body_text: &str) -> ControllerMethod {
    ControllerMethod {
        class_name: "DashboardController".to_string(),
        fqcn: "App\\Http\\Controllers\\DashboardController".to_string(),
        method_name: "__invoke".to_string(),
        body_text: body_text.to_string(),
        http_status: Some(200),
        resource_usage: Vec::new(),
        request_usage: Vec::new(),
        scopes_used: Vec::new(),
    }
}

#[test]
fn request_mode_exposes_inertia_props_schema() {
    let analysis = run_fixture_request(
        "InertiaLaravelApp",
        vec![
            json!({
                "routeId": "dashboard",
                "methods": ["GET"],
                "uri": "/dashboard",
                "domain": null,
                "name": "dashboard",
                "prefix": null,
                "middleware": [],
                "where": {},
                "defaults": {},
                "bindings": [],
                "action": {
                    "kind": "controller_method",
                    "fqcn": "App\\Http\\Controllers\\DashboardController",
                    "method": "__invoke"
                }
            }),
            json!({
                "routeId": "teams.show",
                "methods": ["GET"],
                "uri": "/teams",
                "domain": null,
                "name": "teams.show",
                "prefix": null,
                "middleware": [],
                "where": {},
                "defaults": {},
                "bindings": [],
                "action": {
                    "kind": "controller_method",
                    "fqcn": "App\\Http\\Controllers\\TeamsPageController",
                    "method": "show"
                }
            }),
        ],
    );

    let dashboard = find_controller(
        &analysis,
        "App\\Http\\Controllers\\DashboardController",
        "__invoke",
    );
    let dashboard_response = dashboard
        .responses
        .iter()
        .find(|response| response.kind == "inertia")
        .expect("dashboard inertia response should exist");
    let dashboard_inertia = dashboard_response
        .inertia
        .as_ref()
        .expect("dashboard inertia contract should exist");
    assert_eq!(dashboard_inertia.component, "Dashboard/Index");
    assert_eq!(
        dashboard_inertia
            .props_schema
            .as_ref()
            .expect("props schema should exist")["properties"]["stats"]["properties"]["count"]["type"],
        "integer"
    );
    assert_eq!(
        dashboard_inertia
            .props_schema
            .as_ref()
            .expect("props schema should exist")["properties"]["filters"]["properties"]["team"]["type"],
        "string"
    );

    let teams = find_controller(
        &analysis,
        "App\\Http\\Controllers\\TeamsPageController",
        "show",
    );
    let teams_response = teams
        .responses
        .iter()
        .find(|response| response.kind == "inertia")
        .expect("teams inertia response should exist");
    let teams_inertia = teams_response
        .inertia
        .as_ref()
        .expect("teams inertia contract should exist");
    assert_eq!(teams_inertia.component, "Teams/Show");
    assert_eq!(
        teams_inertia
            .props_schema
            .as_ref()
            .expect("props schema should exist")["properties"]["team"]["properties"]["name"]["type"],
        "string"
    );
}

#[test]
fn inertia_helper_does_not_match_identifier_substring() {
    let controller = controller_with_body(
        r#"
        return $this->inertiaHelper('Dashboard/Index', [
            'stats' => $stats['count'],
        ]);
        "#,
    );
    let response = infer_inertia_response(
        &controller,
        Some(&ContractHttpInfo {
            status: 200,
            explicit: false,
        }),
        &SourceIndex::default(),
        &BTreeMap::new(),
    );

    assert!(response.is_none());
}

#[test]
fn inertia_helper_does_not_treat_bracket_access_as_array_literal() {
    let controller = controller_with_body(
        r#"
        return inertia('Reports/Index', [
            'stats' => $stats['count'],
        ]);
        "#,
    );
    let response = infer_inertia_response(
        &controller,
        Some(&ContractHttpInfo {
            status: 200,
            explicit: false,
        }),
        &SourceIndex::default(),
        &BTreeMap::new(),
    )
    .expect("inertia response should exist");
    let inertia = response
        .inertia
        .as_ref()
        .expect("inertia contract should exist");

    assert_eq!(inertia.component, "Reports/Index");
    assert_ne!(
        inertia
            .props_schema
            .as_ref()
            .expect("props schema should exist")["properties"]["stats"]["type"],
        "array"
    );
}

#[test]
fn inertia_preserves_non_literal_component_expression() {
    let controller = controller_with_body(
        r#"
        return inertia(DashboardPage::COMPONENT, [
            'stats' => [
                'count' => 5,
            ],
        ]);
        "#,
    );
    let response = infer_inertia_response(
        &controller,
        Some(&ContractHttpInfo {
            status: 200,
            explicit: false,
        }),
        &SourceIndex::default(),
        &BTreeMap::new(),
    )
    .expect("inertia response should exist");
    let inertia = response
        .inertia
        .as_ref()
        .expect("inertia contract should exist");

    assert_eq!(inertia.component, "DashboardPage::COMPONENT");
    assert_eq!(
        inertia
            .props_schema
            .as_ref()
            .expect("props schema should exist")["properties"]["stats"]["properties"]["count"]["type"],
        "integer"
    );
}

#[test]
fn inertia_ignores_commented_call_arguments() {
    let controller = controller_with_body(
        r#"
        return inertia(
            'Reports/Index' /* , ignored component noise */,
            [
                'stats' => [
                    'count' => 5,
                ],
            ]
        );
        "#,
    );
    let response = infer_inertia_response(
        &controller,
        Some(&ContractHttpInfo {
            status: 200,
            explicit: false,
        }),
        &SourceIndex::default(),
        &BTreeMap::new(),
    )
    .expect("inertia response should exist");
    let inertia = response
        .inertia
        .as_ref()
        .expect("inertia contract should exist");

    assert_eq!(inertia.component, "Reports/Index");
    assert_eq!(
        inertia
            .props_schema
            .as_ref()
            .expect("props schema should exist")["properties"]["stats"]["properties"]["count"]["type"],
        "integer"
    );
}
