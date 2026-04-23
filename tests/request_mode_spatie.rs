use oxinfer::contracts::{build_analysis_response, load_analysis_request_from_slice};
use oxinfer::pipeline::analyze_project;
use serde_json::json;

#[path = "support/oxcribe_fixture_request.rs"]
mod oxcribe_fixture_request;

fn spatie_fixture_root() -> String {
    oxcribe_fixture_request::oxcribe_fixture_root("SpatieLaravelApp")
}

fn controller<'a>(
    analysis: &'a oxinfer::contracts::AnalysisResponse,
    fqcn: &str,
    method: &str,
) -> &'a oxinfer::contracts::ContractController {
    analysis
        .delta
        .controllers
        .iter()
        .find(|item| item.fqcn == fqcn && item.method == method)
        .expect("controller should exist")
}

#[test]
fn request_mode_exposes_spatie_query_builder_fields() {
    let root = spatie_fixture_root();
    let payload = json!({
        "contractVersion": "oxcribe.oxinfer.v2",
        "requestId": "req-spatie",
        "runtimeFingerprint": "fp-spatie",
        "manifest": {
            "project": {
                "root": root,
                "composer": "composer.json"
            },
            "scan": {
                "targets": ["app", "routes"],
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
                "basePath": root,
                "laravelVersion": "12.0.0",
                "phpVersion": "8.3.0",
                "appEnv": "testing"
            },
            "routes": [
                {
                    "routeId": "posts.search",
                    "methods": ["GET"],
                    "uri": "posts/search",
                    "domain": null,
                    "name": "posts.search",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\SearchController",
                        "method": "index"
                    }
                },
                {
                    "routeId": "posts.index",
                    "methods": ["GET"],
                    "uri": "posts",
                    "domain": null,
                    "name": "posts.index",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PostController",
                        "method": "index"
                    }
                },
                {
                    "routeId": "posts.store",
                    "methods": ["POST"],
                    "uri": "posts",
                    "domain": null,
                    "name": "posts.store",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PostController",
                        "method": "store"
                    }
                },
                {
                    "routeId": "posts.show",
                    "methods": ["GET"],
                    "uri": "posts/{post}",
                    "domain": null,
                    "name": "posts.show",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [
                        {
                            "parameter": "post",
                            "kind": "model",
                            "targetFqcn": "App\\Models\\Post",
                            "isImplicit": true
                        }
                    ],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PostController",
                        "method": "show"
                    }
                },
                {
                    "routeId": "posts.publish",
                    "methods": ["POST"],
                    "uri": "posts/{post}/publish",
                    "domain": null,
                    "name": "posts.publish",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [
                        {
                            "parameter": "post",
                            "kind": "model",
                            "targetFqcn": "App\\Models\\Post",
                            "isImplicit": true
                        }
                    ],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PublishController",
                        "method": "store"
                    }
                },
                {
                    "routeId": "posts.publish-advanced",
                    "methods": ["POST"],
                    "uri": "posts/{post}/publish-advanced",
                    "domain": null,
                    "name": "posts.publish-advanced",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [
                        {
                            "parameter": "post",
                            "kind": "model",
                            "targetFqcn": "App\\Models\\Post",
                            "isImplicit": true
                        }
                    ],
                    "action": {
                        "kind": "invokable_controller",
                        "fqcn": "App\\Http\\Controllers\\AdvancedPublishController",
                        "method": null
                    }
                },
                {
                    "routeId": "media.store",
                    "methods": ["POST"],
                    "uri": "media",
                    "domain": null,
                    "name": "media.store",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\MediaController",
                        "method": "store"
                    }
                },
                {
                    "routeId": "media.attachments",
                    "methods": ["POST"],
                    "uri": "media/attachments",
                    "domain": null,
                    "name": "media.attachments",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\MediaAttachmentsController",
                        "method": "store"
                    }
                },
                {
                    "routeId": "media.gallery",
                    "methods": ["POST"],
                    "uri": "media/gallery",
                    "domain": null,
                    "name": "media.gallery",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\MediaController",
                        "method": "gallery"
                    }
                },
                {
                    "routeId": "posts.advanced-search",
                    "methods": ["GET"],
                    "uri": "posts/advanced-search",
                    "domain": null,
                    "name": "posts.advanced-search",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\AdvancedSearchController",
                        "method": "index"
                    }
                },
                {
                    "routeId": "pages.update",
                    "methods": ["PATCH"],
                    "uri": "pages/{page}",
                    "domain": null,
                    "name": "pages.update",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [
                        {
                            "parameter": "page",
                            "kind": "model",
                            "targetFqcn": "App\\Models\\Page",
                            "isImplicit": true
                        }
                    ],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\PageController",
                        "method": "update"
                    }
                },
                {
                    "routeId": "series.update",
                    "methods": ["PATCH"],
                    "uri": "series/{series}",
                    "domain": null,
                    "name": "series.update",
                    "prefix": "api",
                    "middleware": ["api"],
                    "where": {},
                    "defaults": {},
                    "bindings": [
                        {
                            "parameter": "series",
                            "kind": "model",
                            "targetFqcn": "App\\Models\\Series",
                            "isImplicit": true
                        }
                    ],
                    "action": {
                        "kind": "controller_method",
                        "fqcn": "App\\Http\\Controllers\\SeriesController",
                        "method": "update"
                    }
                }
            ]
        }
    });

    let request = load_analysis_request_from_slice(
        &serde_json::to_vec(&payload).expect("request should encode"),
        None,
    )
    .expect("request should decode");
    let result = analyze_project(&request.manifest).expect("analysis should succeed");
    let response = build_analysis_response(&request, &result);

    assert_eq!(response.status, "ok");

    let search = controller(
        &response,
        "App\\Http\\Controllers\\SearchController",
        "index",
    );
    let search_request = search
        .request
        .as_ref()
        .expect("search request should exist");
    let search_query = search_request
        .query
        .as_ref()
        .expect("search query should exist");
    assert_eq!(
        serde_json::to_value(search_query).expect("query should serialize"),
        json!({
            "fields": {
                "authors": {
                    "email": {},
                    "name": {}
                },
                "posts": {
                    "id": {},
                    "status": {},
                    "summary": {},
                    "title": {}
                }
            },
            "filter": {
                "author": {},
                "published": {},
                "status": {},
                "trashed": {}
            },
            "include": {
                "author": {
                    "profile": {}
                },
                "comments": {
                    "user": {}
                },
                "tags": {}
            },
            "sort": {
                "published_at": {},
                "status": {},
                "title": {}
            }
        })
    );
    assert_eq!(
        search
            .responses
            .first()
            .and_then(|response| response.body_schema.as_ref())
            .expect("search response body should exist"),
        &json!({
            "type": "object",
            "required": ["data"],
            "properties": {
                "data": {
                    "type": "array",
                    "items": {
                        "ref": "App\\Http\\Resources\\PostResource"
                    }
                }
            }
        })
    );

    let search_fields = &search_request.fields;
    assert!(search_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "fields.posts"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values
                == vec![
                    "id".to_string(),
                    "status".to_string(),
                    "summary".to_string(),
                    "title".to_string(),
                ]
    }));
    assert!(search_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "include"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values
                == vec![
                    "author.profile".to_string(),
                    "comments.user".to_string(),
                    "tags".to_string(),
                ]
    }));

    let store = controller(&response, "App\\Http\\Controllers\\PostController", "store");
    let store_request = store.request.as_ref().expect("store request should exist");
    assert_eq!(
        serde_json::to_value(
            store_request
                .body
                .as_ref()
                .expect("store request body should exist")
        )
        .expect("store body should serialize"),
        json!({
            "title": {},
            "summary": {},
            "seo": {
                "slug": {}
            }
        })
    );

    let publish = controller(
        &response,
        "App\\Http\\Controllers\\PublishController",
        "store",
    );
    let publish_request = publish
        .request
        .as_ref()
        .expect("publish request should exist");
    assert_eq!(
        serde_json::to_value(
            publish_request
                .body
                .as_ref()
                .expect("publish request body should exist")
        )
        .expect("publish body should serialize"),
        json!({
            "seo": {
                "slug": {}
            },
            "reviewer": {
                "name": {},
                "approval": {
                    "slug": {}
                }
            },
            "notes": {}
        })
    );
    assert_eq!(
        publish
            .responses
            .first()
            .and_then(|response| response.body_schema.as_ref())
            .expect("publish response body should exist"),
        &json!({
            "$ref": "App\\Http\\Resources\\PostResource"
        })
    );

    let page = controller(
        &response,
        "App\\Http\\Controllers\\PageController",
        "update",
    );
    let page_request = page.request.as_ref().expect("page request should exist");
    assert_eq!(
        serde_json::to_value(
            page_request
                .body
                .as_ref()
                .expect("page request body should exist")
        )
        .expect("page body should serialize"),
        json!({
            "title": {},
            "seo": {
                "slug": {}
            }
        })
    );

    let series = controller(
        &response,
        "App\\Http\\Controllers\\SeriesController",
        "update",
    );
    let series_request = series
        .request
        .as_ref()
        .expect("series request should exist");
    assert_eq!(
        serde_json::to_value(
            series_request
                .body
                .as_ref()
                .expect("series request body should exist")
        )
        .expect("series body should serialize"),
        json!({
            "title": {},
            "subtitle": {},
            "seo": {
                "slug": {}
            }
        })
    );

    let advanced = controller(
        &response,
        "App\\Http\\Controllers\\AdvancedSearchController",
        "index",
    );
    let advanced_request = advanced
        .request
        .as_ref()
        .expect("advanced request should exist");
    let advanced_query = advanced_request
        .query
        .as_ref()
        .expect("advanced query should exist");
    assert_eq!(
        serde_json::to_value(advanced_query).expect("advanced query should serialize"),
        json!({
            "fields": {
                "authors": {
                    "email": {},
                    "name": {}
                },
                "media": {
                    "name": {}
                },
                "posts": {
                    "id": {},
                    "status": {},
                    "summary": {},
                    "title": {}
                }
            },
            "filter": {
                "ownedBy": {},
                "published_after": {},
                "state": {},
                "tagged": {},
                "trashed": {}
            },
            "include": {
                "author": {
                    "profile": {}
                },
                "comments": {
                    "user": {}
                },
                "tags": {
                    "media": {}
                }
            },
            "sort": {
                "published_at": {},
                "status": {},
                "title": {},
                "updated_at": {}
            }
        })
    );

    let advanced_fields = &advanced_request.fields;
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "filter.state"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values == vec!["state".to_string()]
            && field.source.as_deref() == Some("spatie/laravel-query-builder")
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "filter.ownedBy"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values == vec!["ownedBy".to_string()]
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "filter.published_after"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values == vec!["published_after".to_string()]
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "filter.tagged"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values == vec!["tagged".to_string()]
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "filter.trashed"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values == vec!["trashed".to_string()]
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "fields.posts"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values
                == vec![
                    "id".to_string(),
                    "status".to_string(),
                    "summary".to_string(),
                    "title".to_string(),
                ]
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "fields.media"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values == vec!["name".to_string()]
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "include"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values
                == vec![
                    "author.profile".to_string(),
                    "comments.user".to_string(),
                    "tags.media".to_string(),
                ]
    }));
    assert!(advanced_fields.iter().any(|field| {
        field.location == "query"
            && field.path == "sort"
            && field.kind.as_deref() == Some("csv")
            && field.allowed_values
                == vec![
                    "published_at".to_string(),
                    "status".to_string(),
                    "title".to_string(),
                    "updated_at".to_string(),
                ]
    }));

    let advanced_publish = controller(
        &response,
        "App\\Http\\Controllers\\AdvancedPublishController",
        "__invoke",
    );
    let advanced_publish_request = advanced_publish
        .request
        .as_ref()
        .expect("advanced publish request should exist");
    assert_eq!(
        serde_json::to_value(
            advanced_publish_request
                .body
                .as_ref()
                .expect("advanced publish request body should exist")
        )
        .expect("advanced publish body should serialize"),
        json!({
            "title": {},
            "summary": {},
            "seo": {
                "slug": {}
            },
            "featured": {},
            "reviewers": {
                "_item": {
                    "name": {},
                    "approval": {
                        "slug": {}
                    }
                }
            },
            "approvalHistory": {
                "_item": {
                    "name": {},
                    "approval": {
                        "slug": {}
                    }
                }
            },
            "preview": {
                "slug": {}
            },
            "teaser": {
                "slug": {}
            },
            "reviewer": {
                "name": {},
                "approval": {
                    "slug": {}
                }
            }
        })
    );

    let media_store = controller(
        &response,
        "App\\Http\\Controllers\\MediaController",
        "store",
    );
    let media_store_request = media_store
        .request
        .as_ref()
        .expect("media store request should exist");
    assert_eq!(
        media_store_request.content_types,
        vec!["multipart/form-data".to_string()]
    );
    assert_eq!(
        serde_json::to_value(
            media_store_request
                .files
                .as_ref()
                .expect("media store files should exist")
        )
        .expect("media store files should serialize"),
        json!({
            "avatar": {},
            "cover": {},
            "gallery": {}
        })
    );

    let media_gallery = controller(
        &response,
        "App\\Http\\Controllers\\MediaController",
        "gallery",
    );
    let media_gallery_request = media_gallery
        .request
        .as_ref()
        .expect("media gallery request should exist");
    assert_eq!(
        media_gallery_request.content_types,
        vec!["multipart/form-data".to_string()]
    );
    assert_eq!(
        serde_json::to_value(
            media_gallery_request
                .files
                .as_ref()
                .expect("media gallery files should exist")
        )
        .expect("media gallery files should serialize"),
        json!({
            "attachments": {},
            "hero_image": {}
        })
    );

    let media_attachments = controller(
        &response,
        "App\\Http\\Controllers\\MediaAttachmentsController",
        "store",
    );
    let media_attachments_request = media_attachments
        .request
        .as_ref()
        .expect("media attachments request should exist");
    assert_eq!(
        media_attachments_request.content_types,
        vec!["multipart/form-data".to_string()]
    );
    assert_eq!(
        serde_json::to_value(
            media_attachments_request
                .files
                .as_ref()
                .expect("media attachments files should exist")
        )
        .expect("media attachments files should serialize"),
        json!({
            "attachments": {},
            "gallery_images": {
                "_item": {}
            },
            "preview_pdf": {},
            "thumbnail": {}
        })
    );

    let resources = response
        .delta
        .resources
        .iter()
        .map(|resource| (resource.fqcn.as_str(), &resource.schema))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        resources["App\\Http\\Resources\\PostResource"]["properties"]["seo"],
        json!({
            "ref": "App\\Http\\Resources\\SeoResource",
            "nullable": true
        })
    );
    assert_eq!(
        resources["App\\Http\\Resources\\PostResource"]["properties"]["tags"],
        json!({
            "type": "array",
            "nullable": true,
            "items": {
                "ref": "App\\Http\\Resources\\TagResource"
            }
        })
    );

    let models = response
        .delta
        .models
        .iter()
        .map(|model| (model.fqcn.as_str(), model))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(models.contains_key("App\\Models\\Series"));
    assert!(
        models["App\\Models\\Series"]
            .attributes
            .iter()
            .any(|attribute| {
                attribute.name == "title" && attribute.via == "spatie/laravel-translatable"
            })
    );
    assert!(
        models["App\\Models\\Series"]
            .attributes
            .iter()
            .any(|attribute| {
                attribute.name == "subtitle" && attribute.via == "spatie/laravel-translatable"
            })
    );
    assert!(
        models["App\\Models\\Series"]
            .attributes
            .iter()
            .any(|attribute| {
                attribute.name == "description" && attribute.via == "spatie/laravel-translatable"
            })
    );
}
