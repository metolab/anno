//! Embedded frontend static file serving.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../frontend/dist"]
struct Assets;

pub async fn static_handler(req: Request<Body>) -> impl IntoResponse {
    let uri_path = req.uri().path();

    // Never SPA-fallback for API / metrics paths. Without this, a typo like
    // `/api/cleints` would return `index.html` with HTTP 200 and the
    // frontend would log "unexpected HTML" instead of getting a usable
    // 404 JSON body. Same for `/metrics` when no scraper-friendly content
    // is found.
    if uri_path.starts_with("/api/") || uri_path == "/metrics" {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"code":"not_found","message":"route not found"}"#,
            ))
            .unwrap();
    }

    let path = uri_path.trim_start_matches('/');

    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(Body::from(content.data.to_vec()))
            .unwrap();
    }

    // For SPA routing: serve index.html for non-asset paths.
    if let Some(content) = Assets::get("index.html") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(content.data.to_vec()))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not Found"))
        .unwrap()
}
