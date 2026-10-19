//! Modular, in-process REST controllers. A hostname chooses a controller route table;
//! each configured route maps to a Rust handler, not to a subprocess or FastCGI worker.

mod core;
mod items;

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::{
    config::{ControllerConfig, ControllerRouteConfig},
    http_types::{HttpRequest, HttpResponse},
};

pub type ItemStore = Rc<RefCell<BTreeMap<String, Value>>>;

#[derive(Clone)]
struct CompiledRoute {
    method: String,
    path: String,
    handler: String,
}

#[derive(Clone)]
pub struct ControllerRuntime {
    tables: Rc<HashMap<String, Vec<CompiledRoute>>>,
    item_store: ItemStore,
    max_body_bytes: usize,
}

impl ControllerRuntime {
    pub fn new(
        configs: &BTreeMap<String, ControllerConfig>,
        max_body_bytes: usize,
    ) -> Result<Self> {
        let mut tables = HashMap::new();
        for (name, config) in configs {
            let mut routes = Vec::with_capacity(config.routes.len());
            for route in &config.routes {
                routes.push(
                    compile_route(route)
                        .with_context(|| format!("invalid route in controller {name:?}"))?,
                );
            }
            tables.insert(name.clone(), routes);
        }
        Ok(Self {
            tables: Rc::new(tables),
            item_store: Rc::new(RefCell::new(BTreeMap::new())),
            max_body_bytes,
        })
    }

    pub async fn dispatch(
        &self,
        controller_name: &str,
        request: HttpRequest,
        metrics: serde_json::Value,
    ) -> HttpResponse {
        if request.body_too_large || request.body.len() > self.max_body_bytes {
            return HttpResponse::error(413, "request body exceeds configured limit");
        }
        let Some(routes) = self.tables.get(controller_name) else {
            return HttpResponse::error(500, "controller is not registered");
        };

        let requested_method = request.method.to_ascii_uppercase();
        let mut path_matched = false;
        let mut allowed_methods = Vec::<String>::new();

        for route in routes {
            let Some(params) = match_path(&route.path, &request.path) else {
                continue;
            };
            path_matched = true;
            if !allowed_methods.iter().any(|method| method == &route.method) {
                allowed_methods.push(route.method.clone());
            }
            let method_matches = route.method == requested_method
                || (requested_method == "HEAD" && route.method == "GET");
            if !method_matches {
                continue;
            }

            let mut response = match route.handler.as_str() {
                "health" | "status" | "metrics" | "echo" => {
                    core::handle(
                        &route.handler,
                        request.clone(),
                        params,
                        self.max_body_bytes,
                        metrics.clone(),
                    )
                    .await
                }
                "items" => {
                    items::handle(
                        request.clone(),
                        params,
                        self.item_store.clone(),
                        self.max_body_bytes,
                    )
                    .await
                }
                _ => HttpResponse::error(500, "configured handler is not implemented"),
            };
            if requested_method == "HEAD" {
                response.head_only = true;
            }
            return response;
        }

        if path_matched {
            allowed_methods.sort();
            HttpResponse::json(
                405,
                serde_json::json!({
                    "error": "method not allowed",
                    "allow": allowed_methods.join(", ")
                }),
            )
        } else {
            HttpResponse::error(404, "route not found")
        }
    }
}

fn compile_route(route: &ControllerRouteConfig) -> Result<CompiledRoute> {
    let method = route.method.to_ascii_uppercase();
    anyhow::ensure!(
        matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ),
        "invalid HTTP method {:?}",
        route.method
    );
    anyhow::ensure!(
        route.path.starts_with('/'),
        "route path must start with '/'"
    );
    Ok(CompiledRoute {
        method,
        path: route.path.clone(),
        handler: route.handler.clone(),
    })
}

fn match_path(pattern: &str, requested: &str) -> Option<HashMap<String, String>> {
    let pattern_segments: Vec<&str> = pattern.split('/').skip(1).collect();
    let request_segments: Vec<&str> = requested.split('/').skip(1).collect();
    if pattern_segments.len() != request_segments.len() {
        return None;
    }
    let mut params = HashMap::new();
    for (pattern_segment, request_segment) in pattern_segments.iter().zip(request_segments.iter()) {
        let decoded = percent_encoding::percent_decode_str(request_segment)
            .decode_utf8()
            .ok()?;
        if decoded.chars().any(|c| matches!(c, '/' | '\\' | '\0'))
            || decoded == "."
            || decoded == ".."
        {
            return None;
        }
        if pattern_segment.starts_with('{') && pattern_segment.ends_with('}') {
            if decoded.is_empty() {
                return None;
            }
            params.insert(
                pattern_segment[1..pattern_segment.len() - 1].to_owned(),
                decoded.into_owned(),
            );
        } else if decoded.as_ref() != *pattern_segment {
            return None;
        }
    }
    Some(params)
}

#[cfg(test)]
mod tests {
    use super::match_path;

    #[test]
    fn matches_named_path_parameters_and_rejects_encoded_traversal() {
        let params = match_path("/v1/items/{id}", "/v1/items/abc-123").unwrap();
        assert_eq!(params.get("id").map(String::as_str), Some("abc-123"));
        assert!(match_path("/v1/items/{id}", "/v1/items/%2e%2e").is_none());
        assert!(match_path("/v1/items/{id}", "/v1/items/%2fetc").is_none());
    }
}
