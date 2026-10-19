use std::collections::HashMap;

use serde_json::{json, Value};

use crate::http_types::{HttpRequest, HttpResponse};

pub async fn handle(
    action: &str,
    request: HttpRequest,
    _params: HashMap<String, String>,
    max_body_bytes: usize,
    metrics: Value,
) -> HttpResponse {
    match action {
        "health" => HttpResponse::json(200, json!({ "status": "ok" })),
        "status" => HttpResponse::json(
            200,
            json!({
                "service": "websrv",
                "version": env!("CARGO_PKG_VERSION"),
                "protocols": ["https/3", "http/1.1", "https/1.1", "http/2", "https/2"]
            }),
        ),
        "metrics" => HttpResponse::json(200, metrics),
        "echo" => echo(request, max_body_bytes).await,
        _ => HttpResponse::error(404, "unknown controller action"),
    }
}

async fn echo(request: HttpRequest, max_body_bytes: usize) -> HttpResponse {
    if request.body.len() > max_body_bytes || request.body_too_large {
        return HttpResponse::error(413, "request body exceeds configured limit");
    }
    let content_type = request
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("");
    let body: Value = if request.body.is_empty() {
        Value::Null
    } else if content_type.starts_with("application/json") {
        match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(_) => return HttpResponse::error(400, "request body is not valid JSON"),
        }
    } else {
        json!(String::from_utf8_lossy(&request.body).to_string())
    };
    HttpResponse::json(
        200,
        json!({
            "method": request.method,
            "path": request.path,
            "query": request.query,
            "body": body
        }),
    )
}
