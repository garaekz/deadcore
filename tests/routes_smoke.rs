use std::fs;
use std::path::Path;

use deadcore::routes::extract_route_bindings;

fn read_fixture(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("route fixture should exist")
}

#[test]
fn minimal_fixture_exposes_user_resource_routes() {
    let source = read_fixture("test/fixtures/integration/minimal-laravel/routes/api.php");
    let bindings = extract_route_bindings(&source);

    assert!(bindings.iter().any(|binding| {
        binding.controller_fqcn == "App\\Http\\Controllers\\UserController"
            && binding.method_name == "index"
            && binding.http_methods == vec!["GET"]
    }));
    assert!(bindings.iter().any(|binding| {
        binding.controller_fqcn == "App\\Http\\Controllers\\UserController"
            && binding.method_name == "update"
            && binding.http_methods == vec!["PUT", "PATCH"]
    }));
}

#[test]
fn api_fixture_exposes_custom_featured_route() {
    let source = read_fixture("test/fixtures/integration/api-project/routes/api.php");
    let bindings = extract_route_bindings(&source);

    assert!(bindings.iter().any(|binding| {
        binding.controller_fqcn == "App\\Http\\Controllers\\ProductController"
            && binding.method_name == "featured"
            && binding.http_methods == vec!["GET"]
    }));
}
