use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub authority: String,
    /// Absolute-path component only; query is held separately.
    pub path: String,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub body_too_large: bool,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub cache_control: Option<String>,
    pub body: Vec<u8>,
    pub head_only: bool,
}

impl HttpResponse {
    pub fn new(status: u16, content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            cache_control: None,
            body: body.into(),
            head_only: false,
        }
    }

    pub fn json(status: u16, value: serde_json::Value) -> Self {
        let body = serde_json::to_vec(&value)
            .unwrap_or_else(|_| b"{\"error\":\"serialization failed\"}".to_vec());
        let mut response = Self::new(status, "application/json; charset=utf-8", body);
        response.cache_control = Some("no-store".to_owned());
        response
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self::json(status, serde_json::json!({ "error": message }))
    }

    pub fn with_cache(mut self, value: impl Into<String>) -> Self {
        self.cache_control = Some(value.into());
        self
    }

    pub fn not_found() -> Self {
        Self::error(404, "not found")
    }
}
