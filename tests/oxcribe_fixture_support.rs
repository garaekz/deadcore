#[path = "support/oxcribe_fixture_request.rs"]
mod oxcribe_fixture_request;

#[test]
fn request_mode_fixtures_resolve_from_repo_local_copy() {
    let root = oxcribe_fixture_request::oxcribe_fixture_root("AuthErrorLaravelApp");

    assert!(
        root.ends_with("test\\fixtures\\oxcribe\\AuthErrorLaravelApp")
            || root.ends_with("test/fixtures/oxcribe/AuthErrorLaravelApp"),
        "expected bundled repo fixture path, got {root}"
    );
}
