use std::collections::HashMap;

use serde_json::{json, Value};

use crate::http_types::{HttpRequest, HttpResponse};

use super::ItemStore;

pub async fn handle(
    request: HttpRequest,
    params: HashMap<String, String>,
    store: ItemStore,
    max_body_bytes: usize,
) -> HttpResponse {
    if request.body_too_large || request.body.len() > max_body_bytes {
        return HttpResponse::error(413, "request body exceeds configured limit");
    }
    let method = request.method.to_ascii_uppercase();
    let id = params.get("id").cloned();

    match (method.as_str(), id) {
        ("GET", None) | ("HEAD", None) => {
            let items = store.borrow();
            HttpResponse::json(200, json!({ "items": &*items }))
        }
        ("POST", None) => {
            let value = match parse_json(&request.body) {
                Ok(value) => value,
                Err(response) => return response,
            };
            let id = value
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("item-{}", store.borrow().len() + 1));
            if !valid_id(&id) {
                return HttpResponse::error(400, "invalid item id");
            }
            store.borrow_mut().insert(id.clone(), value.clone());
            HttpResponse::json(201, json!({ "id": id, "item": value }))
        }
        ("GET", Some(id)) | ("HEAD", Some(id)) => {
            if !valid_id(&id) {
                return HttpResponse::error(400, "invalid item id");
            }
            match store.borrow().get(&id).cloned() {
                Some(item) => HttpResponse::json(200, json!({ "id": id, "item": item })),
                None => HttpResponse::error(404, "item not found"),
            }
        }
        ("PUT", Some(id)) | ("PATCH", Some(id)) => {
            if !valid_id(&id) {
                return HttpResponse::error(400, "invalid item id");
            }
            let value = match parse_json(&request.body) {
                Ok(value) => value,
                Err(response) => return response,
            };
            let mut items = store.borrow_mut();
            if !items.contains_key(&id) {
                return HttpResponse::error(404, "item not found");
            }
            items.insert(id.clone(), value.clone());
            HttpResponse::json(200, json!({ "id": id, "item": value }))
        }
        ("DELETE", Some(id)) => {
            if !valid_id(&id) {
                return HttpResponse::error(400, "invalid item id");
            }
            if store.borrow_mut().remove(&id).is_some() {
                HttpResponse::new(204, "application/json", Vec::<u8>::new())
            } else {
                HttpResponse::error(404, "item not found")
            }
        }
        _ => HttpResponse::error(405, "unsupported method for items controller"),
    }
}

fn parse_json(body: &[u8]) -> Result<Value, HttpResponse> {
    if body.is_empty() {
        return Err(HttpResponse::error(400, "expected a JSON request body"));
    }
    serde_json::from_slice(body)
        .map_err(|_| HttpResponse::error(400, "request body is not valid JSON"))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}
