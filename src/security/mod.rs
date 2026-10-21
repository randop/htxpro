//! Configurable host security. Virtual hosts (static or controller) may
//! reference a named security module; successful authentication attaches an
//! `AuthIdentity` to the request before dispatch.
//!
//! Named modules are held in a registry so multiple instances can be
//! configured. The only implemented module type is the WorkOS OAuth2 web
//! authorization-code flow.

mod http_client;
mod workos;

use std::{
    collections::HashMap,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::{
    config::{SecurityConfig, VirtualHostConfig},
    http_types::{AuthIdentity, HttpRequest, HttpResponse},
};

const TOKEN_VERSION: u8 = 1;

#[derive(Clone)]
pub struct SecurityRuntime {
    settings: Option<Rc<SecuritySettings>>,
    modules: Rc<HashMap<String, SecurityModule>>,
}

struct SecuritySettings {
    cookie_name: String,
    state_cookie_name: String,
    cookie_secure: bool,
    session_ttl: Duration,
    state_ttl: Duration,
    key: hmac::Key,
    tls: std::sync::Arc<rustls::ClientConfig>,
}

#[derive(Clone)]
enum SecurityModule {
    Oauth2Workos(workos::WorkosModule),
}

pub enum SecurityOutcome {
    Allow(HttpRequest),
    Respond(HttpResponse),
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    v: u8,
    m: String,
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StateClaims {
    v: u8,
    m: String,
    state: String,
    verifier: String,
    return_to: String,
    exp: u64,
}

impl SecurityRuntime {
    pub fn new(config: Option<&SecurityConfig>) -> Result<Self> {
        let Some(config) = config else {
            return Ok(Self {
                settings: None,
                modules: Rc::new(HashMap::new()),
            });
        };
        let tls = http_client::make_tls_config()?;
        let settings = Rc::new(SecuritySettings {
            cookie_name: config.cookie_name.clone(),
            state_cookie_name: format!("{}_state", config.cookie_name),
            cookie_secure: config.cookie_secure,
            session_ttl: Duration::from_secs(config.session_ttl_seconds),
            state_ttl: Duration::from_secs(config.state_ttl_seconds),
            key: hmac::Key::new(hmac::HMAC_SHA256, config.session_secret.as_bytes()),
            tls,
        });
        let mut modules = HashMap::new();
        for (name, module) in &config.modules {
            let compiled = match module.kind.as_str() {
                "oauth2_workos" => SecurityModule::Oauth2Workos(
                    workos::WorkosModule::new(name, module).with_context(|| {
                        format!("could not initialize security module {name:?}")
                    })?,
                ),
                other => anyhow::bail!("security module {name:?} has unsupported type {other:?}"),
            };
            modules.insert(name.clone(), compiled);
        }
        Ok(Self {
            settings: Some(settings),
            modules: Rc::new(modules),
        })
    }

    pub async fn guard(
        &self,
        vhost: &VirtualHostConfig,
        mut request: HttpRequest,
    ) -> SecurityOutcome {
        let Some(host_security) = &vhost.security else {
            return SecurityOutcome::Allow(request);
        };
        let (Some(settings), Some(module)) = (
            self.settings.as_deref(),
            self.modules.get(&host_security.module),
        ) else {
            return SecurityOutcome::Respond(HttpResponse::error(
                500,
                "configured security module is not available",
            ));
        };

        match module {
            SecurityModule::Oauth2Workos(module) => {
                if request.path == module.callback_path() {
                    return SecurityOutcome::Respond(
                        handle_callback(settings, module, &request).await,
                    );
                }
                if let Some(identity) = verify_session(settings, module, &request) {
                    request.auth = Some(identity);
                    return SecurityOutcome::Allow(request);
                }
                if (request.method.eq_ignore_ascii_case("GET")
                    || request.method.eq_ignore_ascii_case("HEAD"))
                    && (vhost.static_site.is_some() || prefers_html(&request))
                {
                    return SecurityOutcome::Respond(begin_login(settings, module, &request));
                }
                SecurityOutcome::Respond(HttpResponse::error(401, "authentication required"))
            }
        }
    }
}

async fn handle_callback(
    settings: &SecuritySettings,
    module: &workos::WorkosModule,
    request: &HttpRequest,
) -> HttpResponse {
    let params = parse_query(request.query.as_deref().unwrap_or_default());
    if let Some(error) = params.get("error") {
        warn!(
            module = module.name(),
            error = %error,
            description = params.get("error_description").map(String::as_str).unwrap_or(""),
            "OAuth provider returned an authentication error"
        );
        return HttpResponse::error(401, "authentication was not completed")
            .with_cookie(clear_cookie(settings, &settings.state_cookie_name));
    }
    let (Some(code), Some(state)) = (params.get("code"), params.get("state")) else {
        return HttpResponse::error(400, "OAuth callback is missing code or state")
            .with_cookie(clear_cookie(settings, &settings.state_cookie_name));
    };

    let claims = cookie_value(&request.headers, &settings.state_cookie_name)
        .and_then(|token| verify_token::<StateClaims>(&settings.key, token));
    let Some(claims) = claims.filter(|claims| {
        claims.v == TOKEN_VERSION
            && claims.m == module.name()
            && bool::from(claims.state.as_bytes().ct_eq(state.as_bytes()))
            && claims.exp > now_unix()
    }) else {
        return HttpResponse::error(400, "OAuth state is missing, expired, or invalid")
            .with_cookie(clear_cookie(settings, &settings.state_cookie_name));
    };

    let user = match module
        .exchange_code(&settings.tls, code, &claims.verifier)
        .await
    {
        Ok(user) => user,
        Err(error) => {
            warn!(
                module = module.name(),
                %error,
                "WorkOS authorization-code exchange failed"
            );
            return HttpResponse::error(502, "authentication provider rejected the login")
                .with_cookie(clear_cookie(settings, &settings.state_cookie_name));
        }
    };

    let exp = now_unix().saturating_add(settings.session_ttl.as_secs());
    let session = SessionClaims {
        v: TOKEN_VERSION,
        m: module.name().to_owned(),
        sub: user.id,
        email: user.email,
        name: user.name,
        exp,
    };
    let token = match issue_token(&settings.key, &session) {
        Ok(token) => token,
        Err(error) => {
            warn!(%error, "could not create a session cookie");
            return HttpResponse::error(500, "could not create an authenticated session")
                .with_cookie(clear_cookie(settings, &settings.state_cookie_name));
        }
    };
    let return_to = safe_return_to(&claims.return_to).unwrap_or_else(|| "/".to_owned());
    HttpResponse::redirect(303, return_to)
        .with_cookie(session_cookie(settings, &token))
        .with_cookie(clear_cookie(settings, &settings.state_cookie_name))
}

fn begin_login(
    settings: &SecuritySettings,
    module: &workos::WorkosModule,
    request: &HttpRequest,
) -> HttpResponse {
    let state = match random_token() {
        Ok(token) => token,
        Err(error) => {
            warn!(%error, "could not generate OAuth state");
            return HttpResponse::error(500, "could not start authentication");
        }
    };
    let verifier = match random_token() {
        Ok(token) => token,
        Err(error) => {
            warn!(%error, "could not generate PKCE verifier");
            return HttpResponse::error(500, "could not start authentication");
        }
    };
    let challenge = pkce_challenge(&verifier);
    let return_to = return_to(request);
    let claims = StateClaims {
        v: TOKEN_VERSION,
        m: module.name().to_owned(),
        state: state.clone(),
        verifier,
        return_to,
        exp: now_unix().saturating_add(settings.state_ttl.as_secs()),
    };
    let token = match issue_token(&settings.key, &claims) {
        Ok(token) => token,
        Err(error) => {
            warn!(%error, "could not create OAuth state cookie");
            return HttpResponse::error(500, "could not start authentication");
        }
    };
    HttpResponse::redirect(302, module.authorization_url(&state, &challenge)).with_cookie(cookie(
        settings,
        &settings.state_cookie_name,
        &token,
        settings.state_ttl.as_secs(),
    ))
}

fn verify_session(
    settings: &SecuritySettings,
    module: &workos::WorkosModule,
    request: &HttpRequest,
) -> Option<AuthIdentity> {
    let token = cookie_value(&request.headers, &settings.cookie_name)?;
    let claims = verify_token::<SessionClaims>(&settings.key, token)?;
    if claims.v != TOKEN_VERSION
        || claims.m != module.name()
        || claims.sub.is_empty()
        || claims.exp <= now_unix()
    {
        return None;
    }
    Some(AuthIdentity {
        module: claims.m,
        subject: claims.sub,
        email: claims.email,
        name: claims.name,
    })
}

fn session_cookie(settings: &SecuritySettings, token: &str) -> String {
    cookie(
        settings,
        &settings.cookie_name,
        token,
        settings.session_ttl.as_secs(),
    )
}

fn cookie(settings: &SecuritySettings, name: &str, value: &str, max_age_seconds: u64) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{}",
        if settings.cookie_secure {
            "; Secure"
        } else {
            ""
        }
    )
}

fn clear_cookie(settings: &SecuritySettings, name: &str) -> String {
    format!(
        "{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT{}",
        if settings.cookie_secure { "; Secure" } else { "" }
    )
}

fn issue_token<T: Serialize>(key: &hmac::Key, claims: &T) -> Result<String> {
    let payload = serde_json::to_vec(claims).context("could not serialize security token")?;
    let tag = hmac::sign(key, &payload);
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(tag.as_ref())
    ))
}

fn verify_token<T: DeserializeOwned>(key: &hmac::Key, token: &str) -> Option<T> {
    let (payload, signature) = token.rsplit_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    hmac::verify(key, &payload, &signature).ok()?;
    serde_json::from_slice(&payload).ok()
}

fn cookie_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get("cookie")?.split(';').find_map(|part| {
        let (cookie_name, value) = part.trim().split_once('=')?;
        (cookie_name == name).then_some(value)
    })
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = digest::digest(&digest::SHA256, verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("system random source failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn prefers_html(request: &HttpRequest) -> bool {
    request.headers.get("accept").is_some_and(|accept| {
        accept.split(',').any(|entry| {
            entry.trim().split(';').next().is_some_and(|media_type| {
                media_type.eq_ignore_ascii_case("text/html")
                    || media_type.eq_ignore_ascii_case("application/xhtml+xml")
            })
        })
    })
}

fn return_to(request: &HttpRequest) -> String {
    let mut target = request.path.clone();
    if let Some(query) = &request.query {
        target.push('?');
        target.push_str(query);
    }
    safe_return_to(&target).unwrap_or_else(|| "/".to_owned())
}

fn safe_return_to(target: &str) -> Option<String> {
    if target.is_empty()
        || target.len() > 2_048
        || !target.starts_with('/')
        || target.starts_with("//")
        || !target
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'\\')
    {
        return None;
    }
    // Reject decoded separators/control bytes so the redirect cannot be
    // reinterpreted as a scheme-relative URL or a header injection.
    let decoded = percent_decode_str(target).collect::<Vec<u8>>();
    if decoded.starts_with(b"//")
        || decoded
            .iter()
            .any(|byte| *byte == b'\\' || *byte < 0x20 || *byte == 0x7f)
    {
        return None;
    }
    Some(target.to_owned())
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode_component(name);
        let value = decode_component(value);
        params.entry(name).or_insert(value);
    }
    params
}

fn decode_component(value: &str) -> String {
    percent_decode_str(&value.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

fn encode_query_value(value: &str) -> String {
    // Keep RFC 3986 unreserved characters readable while encoding delimiters.
    const QUERY_VALUE: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'$')
        .add(b'%')
        .add(b'&')
        .add(b'\'')
        .add(b'(')
        .add(b')')
        .add(b'*')
        .add(b'+')
        .add(b',')
        .add(b'/')
        .add(b':')
        .add(b';')
        .add(b'<')
        .add(b'=')
        .add(b'>')
        .add(b'?')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'`')
        .add(b'{')
        .add(b'|')
        .add(b'}');
    utf8_percent_encode(value, QUERY_VALUE).to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse_query, safe_return_to, verify_token, StateClaims, TOKEN_VERSION};

    fn key() -> ring::hmac::Key {
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn signed_tokens_round_trip_and_reject_tampering() {
        let claims = StateClaims {
            v: TOKEN_VERSION,
            m: "workos".into(),
            state: "state".into(),
            verifier: "verifier".into(),
            return_to: "/dashboard?tab=one".into(),
            exp: 4_000_000_000,
        };
        let token = super::issue_token(&key(), &claims).unwrap();
        let decoded: StateClaims = verify_token(&key(), &token).unwrap();
        assert_eq!(decoded.state, "state");
        assert_eq!(decoded.return_to, "/dashboard?tab=one");

        let mut tampered = token.into_bytes();
        let index = tampered.len() / 2;
        tampered[index] = if tampered[index] == b'a' { b'b' } else { b'a' };
        assert!(
            verify_token::<StateClaims>(&key(), std::str::from_utf8(&tampered).unwrap()).is_none()
        );
    }

    #[test]
    fn query_and_return_targets_are_decoded_and_bounded() {
        let params = parse_query("code=abc%2F123&state=x+y&empty=");
        assert_eq!(params.get("code").map(String::as_str), Some("abc/123"));
        assert_eq!(params.get("state").map(String::as_str), Some("x y"));
        assert!(safe_return_to("/items/1?q=a").is_some());
        assert!(safe_return_to("//evil.example").is_none());
        assert!(safe_return_to("https://evil.example").is_none());
        assert!(safe_return_to("/line\r\nInjected: yes").is_none());
        assert!(safe_return_to("/path with space").is_none());
        assert!(safe_return_to("/caf\u{e9}").is_none());
        assert!(safe_return_to("/caf%C3%A9").is_some());
        assert!(safe_return_to("/%2F%2Fevil.example").is_none());
        assert!(safe_return_to("/%5Cevil.example").is_none());
        assert!(safe_return_to("/line%0D%0AInjected%3A%20yes").is_none());
    }

    #[test]
    fn pkce_challenge_is_stable_for_a_verifier() {
        assert_eq!(
            super::pkce_challenge("test-verifier"),
            "JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0"
        );
    }
}
