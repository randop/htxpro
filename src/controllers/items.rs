use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Value};

use crate::http_types::{HttpRequest, HttpResponse};

use super::ItemStore;

const MAX_ITEMS: usize = 1024;
const MAX_STORED_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub struct StoreState {
    items: BTreeMap<String, StoredItem>,
    body_bytes: usize,
    next_id: u64,
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct StoredItem {
    value: Value,
    #[serde(skip)]
    body_bytes: usize,
}

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
            HttpResponse::json(200, json!({ "items": &items.items }))
        }
        ("POST", None) => {
            let value = match parse_json(&request.body) {
                Ok(value) => value,
                Err(response) => return response,
            };
            let mut items = store.borrow_mut();
            let id = match value.get("id").and_then(Value::as_str) {
                Some(id) => id.to_owned(),
                None => {
                    let Some(next_id) = items.next_id.checked_add(1) else {
                        return HttpResponse::error(503, "item id space exhausted");
                    };
                    items.next_id = next_id;
                    format!("item-{next_id}")
                }
            };
            if !valid_id(&id) {
                return HttpResponse::error(400, "invalid item id");
            }
            if items.items.contains_key(&id) {
                return HttpResponse::error(409, "item already exists");
            }
            if items.items.len() >= MAX_ITEMS
                || request.body.len() > MAX_STORED_BODY_BYTES - items.body_bytes
            {
                return HttpResponse::error(503, "item store capacity reached");
            }
            items.body_bytes += request.body.len();
            items.items.insert(
                id.clone(),
                StoredItem {
                    value: value.clone(),
                    body_bytes: request.body.len(),
                },
            );
            HttpResponse::json(201, json!({ "id": id, "item": value }))
        }
        ("GET", Some(id)) | ("HEAD", Some(id)) => {
            if !valid_id(&id) {
                return HttpResponse::error(400, "invalid item id");
            }
            match store.borrow().items.get(&id) {
                Some(item) => HttpResponse::json(200, json!({ "id": id, "item": item.value })),
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
            let Some(previous) = items.items.get(&id) else {
                return HttpResponse::error(404, "item not found");
            };
            let retained_bytes = items.body_bytes - previous.body_bytes;
            if request.body.len() > MAX_STORED_BODY_BYTES - retained_bytes {
                return HttpResponse::error(503, "item store capacity reached");
            }
            items.body_bytes = retained_bytes + request.body.len();
            items.items.insert(
                id.clone(),
                StoredItem {
                    value: value.clone(),
                    body_bytes: request.body.len(),
                },
            );
            HttpResponse::json(200, json!({ "id": id, "item": value }))
        }
        ("DELETE", Some(id)) => {
            if !valid_id(&id) {
                return HttpResponse::error(400, "invalid item id");
            }
            let mut items = store.borrow_mut();
            if let Some(item) = items.items.remove(&id) {
                items.body_bytes -= item.body_bytes;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    fn call(store: &ItemStore, method: &str, id: Option<&str>, body: &[u8]) -> HttpResponse {
        let request = HttpRequest {
            method: method.into(),
            authority: "example.com".into(),
            path: "/items".into(),
            query: None,
            headers: HashMap::new(),
            body: body.to_vec(),
            body_too_large: false,
        };
        let params = id
            .map(|id| HashMap::from([("id".into(), id.into())]))
            .unwrap_or_default();
        futures::executor::block_on(handle(request, params, store.clone(), usize::MAX))
    }

    fn response_id(response: HttpResponse) -> String {
        assert_eq!(response.status, 201);
        serde_json::from_slice::<Value>(&response.body).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn ids_increase_after_delete_and_duplicates_do_not_overwrite() {
        let store = Rc::new(RefCell::new(StoreState::default()));
        assert_eq!(response_id(call(&store, "POST", None, b"{}")), "item-1");
        assert_eq!(call(&store, "DELETE", Some("item-1"), b"").status, 204);
        assert_eq!(response_id(call(&store, "POST", None, b"{}")), "item-2");
        assert_eq!(
            call(&store, "POST", None, br#"{"id":"item-2"}"#).status,
            409
        );
        assert_eq!(
            call(&store, "POST", None, br#"{"id":"item-3"}"#).status,
            201
        );
        assert_eq!(call(&store, "POST", None, b"{}").status, 409);
        assert_eq!(call(&store, "POST", None, br#"{"id":".."}"#).status, 400);
        assert_eq!(store.borrow().body_bytes, 2 + br#"{"id":"item-3"}"#.len());
        let list = call(&store, "GET", None, b"");
        assert_eq!(
            serde_json::from_slice::<Value>(&list.body).unwrap()["items"]["item-2"],
            json!({})
        );
        assert_eq!(response_id(call(&store, "POST", None, b"{}")), "item-4");
    }

    #[test]
    fn count_limit_allows_replacement_and_delete_releases_capacity() {
        let store = Rc::new(RefCell::new(StoreState::default()));
        for _ in 0..MAX_ITEMS {
            assert_eq!(call(&store, "POST", None, b"{}").status, 201);
        }
        assert_eq!(call(&store, "POST", None, b"{}").status, 503);
        assert_eq!(call(&store, "PUT", Some("item-1"), b"null").status, 200);
        assert_eq!(call(&store, "DELETE", Some("item-1"), b"").status, 204);
        assert_eq!(call(&store, "POST", None, b"{}").status, 201);
        assert_eq!(store.borrow().body_bytes, MAX_ITEMS * 2);
    }

    #[test]
    fn byte_limit_accounts_for_replacements_and_rejected_writes() {
        let store = Rc::new(RefCell::new(StoreState::default()));
        let mut full_body = vec![b' '; MAX_STORED_BODY_BYTES];
        full_body[..2].copy_from_slice(b"{}");
        assert_eq!(call(&store, "POST", None, &full_body).status, 201);
        assert_eq!(call(&store, "POST", None, b"{}").status, 503);
        full_body.push(b' ');
        assert_eq!(call(&store, "PUT", Some("item-1"), &full_body).status, 503);
        assert_eq!(store.borrow().body_bytes, MAX_STORED_BODY_BYTES);
        full_body.pop();
        assert_eq!(call(&store, "PUT", Some("item-1"), &full_body).status, 200);
        assert_eq!(call(&store, "PATCH", Some("item-1"), b"null").status, 200);
        assert_eq!(store.borrow().body_bytes, 4);
        assert_eq!(call(&store, "POST", None, b"{}").status, 201);
        assert_eq!(store.borrow().body_bytes, 6);
        assert_eq!(call(&store, "DELETE", Some("item-1"), b"").status, 204);
        assert_eq!(store.borrow().body_bytes, 2);
        full_body.truncate(MAX_STORED_BODY_BYTES - 2);
        assert_eq!(call(&store, "PUT", Some("item-3"), &full_body).status, 200);
        assert_eq!(call(&store, "POST", None, b"{}").status, 201);
        assert_eq!(store.borrow().body_bytes, MAX_STORED_BODY_BYTES);
    }
}
