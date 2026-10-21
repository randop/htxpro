//! WorkOS AuthKit/User Management OAuth2 authorization-code module.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::{parse_http_url, SecurityModuleConfig};

use super::http_client::{self, Endpoint};

#[derive(Clone)]
pub struct WorkosModule {
    name: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    provider: String,
    scopes: Vec<String>,
    callback_path: String,
    token_endpoint: Endpoint,
    http_timeout: Duration,
}

pub struct WorkosUser {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Deserialize)]
struct AuthenticateResponse {
    user: RawWorkosUser,
}

#[derive(Deserialize)]
struct RawWorkosUser {
    id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
}

impl WorkosModule {
    pub fn new(name: &str, config: &SecurityModuleConfig) -> Result<Self> {
        let redirect = parse_http_url(&config.redirect_uri)?;
        let token = parse_http_url(&config.token_endpoint)?;
        Ok(Self {
            name: name.to_owned(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            redirect_uri: config.redirect_uri.clone(),
            authorization_endpoint: config.authorization_endpoint.clone(),
            provider: config.provider.clone(),
            scopes: config.scopes.clone(),
            callback_path: redirect.path_and_query,
            token_endpoint: Endpoint::resolve(&token)?,
            http_timeout: Duration::from_millis(config.http_timeout_ms),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn callback_path(&self) -> &str {
        &self.callback_path
    }

    pub fn authorization_url(&self, state: &str, challenge: &str) -> String {
        let mut params = vec![
            ("response_type", "code".to_owned()),
            ("client_id", self.client_id.clone()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("state", state.to_owned()),
            ("code_challenge", challenge.to_owned()),
            ("code_challenge_method", "S256".to_owned()),
        ];
        if !self.provider.is_empty() {
            params.push(("provider", self.provider.clone()));
        }
        if !self.scopes.is_empty() {
            params.push(("scope", self.scopes.join(" ")));
        }
        let separator = if self.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let query = params
            .into_iter()
            .map(|(name, value)| format!("{name}={}", super::encode_query_value(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{}{separator}{query}", self.authorization_endpoint)
    }

    pub async fn exchange_code(
        &self,
        tls: &std::sync::Arc<rustls::ClientConfig>,
        code: &str,
        verifier: &str,
    ) -> Result<WorkosUser> {
        let body = serde_json::json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
        })
        .to_string();
        let (status, response) = http_client::post_json(
            &self.token_endpoint,
            tls,
            body.as_bytes(),
            self.http_timeout,
        )
        .await?;
        if !(200..300).contains(&status) {
            let detail = String::from_utf8_lossy(&response);
            anyhow::bail!(
                "WorkOS token endpoint returned HTTP {status}: {}",
                detail.chars().take(512).collect::<String>()
            );
        }
        let response: AuthenticateResponse = serde_json::from_slice(&response)
            .context("WorkOS token endpoint returned invalid JSON")?;
        let user = response.user;
        anyhow::ensure!(!user.id.is_empty(), "WorkOS returned a user without an id");
        let name = match (user.first_name, user.last_name) {
            (Some(first), Some(last)) if !first.is_empty() && !last.is_empty() => {
                Some(format!("{first} {last}"))
            }
            (Some(first), _) if !first.is_empty() => Some(first),
            (_, Some(last)) if !last.is_empty() => Some(last),
            _ => None,
        };
        Ok(WorkosUser {
            id: user.id,
            email: user.email,
            name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::WorkosModule;
    use crate::config::SecurityModuleConfig;

    fn module() -> WorkosModule {
        WorkosModule::new(
            "workos",
            &SecurityModuleConfig {
                kind: "oauth2_workos".into(),
                client_id: "client_123".into(),
                client_secret: "secret".into(),
                redirect_uri: "https://app.example.test/_htxpro/auth/workos/callback".into(),
                authorization_endpoint: "https://api.workos.com/user_management/authorize".into(),
                token_endpoint: "http://127.0.0.1:9/user_management/authenticate".into(),
                provider: "authkit".into(),
                scopes: vec!["openid".into(), "email".into()],
                http_timeout_ms: 1_000,
            },
        )
        .unwrap()
    }

    #[test]
    fn authorization_url_contains_encoded_oauth_parameters() {
        let url = module().authorization_url("state value", "challenge");
        assert!(
            url.starts_with("https://api.workos.com/user_management/authorize?response_type=code")
        );
        assert!(url.contains("client_id=client_123"));
        assert!(url.contains(
            "redirect_uri=https%3A%2F%2Fapp.example.test%2F_htxpro%2Fauth%2Fworkos%2Fcallback"
        ));
        assert!(url.contains("state=state%20value"));
        assert!(url.contains("code_challenge=challenge"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("provider=authkit"));
        assert!(url.contains("scope=openid%20email"));
    }

    #[test]
    fn callback_path_is_derived_from_redirect_uri() {
        assert_eq!(module().callback_path(), "/_htxpro/auth/workos/callback");
    }
}
