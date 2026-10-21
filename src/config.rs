use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use http_validation::validate_header_value;
use serde::Deserialize;

const DEFAULT_BODY_LIMIT: usize = 1024 * 1024;
const DEFAULT_STATIC_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_http1_secure_enabled")]
    http1_secure_enabled: bool,
    #[serde(default)]
    http1_plain_enabled: bool,
    #[serde(default = "default_plain_listen")]
    plain_listen: String,
    #[serde(default = "default_http2_secure_enabled")]
    http2_secure_enabled: bool,
    #[serde(default)]
    http2_plain_enabled: bool,
    #[serde(default = "default_cert_path")]
    tls_cert: TlsPaths,
    #[serde(default = "default_key_path")]
    tls_key: TlsPaths,
    #[serde(default = "default_body_limit")]
    max_request_body_bytes: usize,
    #[serde(default = "default_static_limit")]
    max_static_file_bytes: usize,
    #[serde(default)]
    timeouts: TimeoutConfig,
    #[serde(default)]
    limits: LimitConfig,
    #[serde(default)]
    rate_limit: RateLimitConfig,
    #[serde(default = "default_log_filter")]
    log_filter: String,
    #[serde(default)]
    default_host: Option<String>,
    #[serde(default)]
    security: Option<SecurityConfig>,
    virtual_hosts: Vec<VirtualHostConfig>,
    #[serde(default)]
    controllers: BTreeMap<String, ControllerConfig>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Address used for QUIC/HTTP/3 UDP and for secure TCP when either secure protocol is enabled.
    pub listen: SocketAddr,
    pub http1_secure_enabled: bool,
    pub http1_plain_enabled: bool,
    /// Shared cleartext TCP listener for HTTP/1.1 and HTTP/2 prior-knowledge (h2c).
    pub plain_listen: SocketAddr,
    pub http2_secure_enabled: bool,
    pub http2_plain_enabled: bool,
    pub cert_paths: Vec<PathBuf>,
    pub key_paths: Vec<PathBuf>,
    pub max_request_body_bytes: usize,
    pub max_static_file_bytes: usize,
    pub timeouts: TimeoutConfig,
    pub limits: LimitConfig,
    pub rate_limit: RateLimitConfig,
    pub log_filter: String,
    pub default_host: Option<String>,
    pub security: Option<SecurityConfig>,
    pub virtual_hosts: Vec<VirtualHostConfig>,
    pub controllers: BTreeMap<String, ControllerConfig>,
}

/// Global authentication settings. Named modules are referenced by virtual
/// hosts; multiple modules may be configured, but only `oauth2_workos` is
/// implemented by this build.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default = "default_session_cookie")]
    pub cookie_name: String,
    #[serde(default = "default_cookie_secure")]
    pub cookie_secure: bool,
    #[serde(default = "default_session_ttl_seconds")]
    pub session_ttl_seconds: u64,
    #[serde(default = "default_state_ttl_seconds")]
    pub state_ttl_seconds: u64,
    pub session_secret: String,
    pub modules: BTreeMap<String, SecurityModuleConfig>,
}

/// Configuration for one named security module. Fields are shared by module
/// kinds so unknown YAML keys and unsupported `type` values are rejected
/// during configuration loading.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityModuleConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default = "default_authorization_endpoint")]
    pub authorization_endpoint: String,
    #[serde(default = "default_token_endpoint")]
    pub token_endpoint: String,
    #[serde(default = "default_oauth_provider")]
    pub provider: String,
    #[serde(default = "default_oauth_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_oauth_http_timeout_ms")]
    pub http_timeout_ms: u64,
}

/// A virtual host may require one named security module. The same setting
/// applies to static sites and controller route tables.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSecurityConfig {
    pub module: String,
}

/// Deadlines in milliseconds. These are request/phase budgets, not a global
/// wall-clock timer for an entire keep-alive connection.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutConfig {
    pub tls_handshake_ms: u64,
    pub request_headers_ms: u64,
    pub request_body_ms: u64,
    pub request_process_ms: u64,
    pub response_write_ms: u64,
    pub keep_alive_idle_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            tls_handshake_ms: 5_000,
            request_headers_ms: 5_000,
            request_body_ms: 10_000,
            request_process_ms: 5_000,
            response_write_ms: 10_000,
            keep_alive_idle_ms: 15_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitConfig {
    pub max_inflight_requests: usize,
    pub max_inflight_requests_per_ip: usize,
    pub max_inflight_requests_per_host: usize,
    pub max_inflight_static_requests: usize,
    pub max_inflight_controller_requests: usize,
    pub max_concurrent_streams_per_connection: u32,
    pub max_header_bytes: usize,
    pub max_tcp_connections: usize,
    pub max_tcp_connections_per_ip: usize,
    pub max_quic_connections: usize,
    pub max_quic_connections_per_ip: usize,
    pub max_tracked_client_ips: usize,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            max_inflight_requests: 256,
            max_inflight_requests_per_ip: 32,
            max_inflight_requests_per_host: 128,
            max_inflight_static_requests: 16,
            max_inflight_controller_requests: 128,
            max_concurrent_streams_per_connection: 128,
            max_header_bytes: 64 * 1024,
            max_tcp_connections: 256,
            max_tcp_connections_per_ip: 32,
            max_quic_connections: 512,
            max_quic_connections_per_ip: 64,
            max_tracked_client_ips: 65_536,
        }
    }
}

/// Per-source token-bucket limits. IP state is bounded and inactive entries
/// are expired, preventing random-source floods from growing it indefinitely.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub global_requests_per_second: u32,
    pub global_burst: u32,
    pub requests_per_second_per_ip: u32,
    pub burst_per_ip: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_requests_per_second: 1_000,
            global_burst: 2_000,
            requests_per_second_per_ip: 20,
            burst_per_ip: 40,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirtualHostConfig {
    pub host: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default, rename = "static")]
    pub static_site: Option<StaticSiteConfig>,
    /// Names a Rust controller route table declared under `controllers`.
    #[serde(default)]
    pub controller: Option<String>,
    /// Optional named security module guarding this host.
    #[serde(default)]
    pub security: Option<HostSecurityConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticSiteConfig {
    pub root: PathBuf,
    #[serde(default = "default_index")]
    pub index: String,
    #[serde(default)]
    pub spa_fallback: bool,
    #[serde(default = "default_cache_control")]
    pub cache_control: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    pub routes: Vec<ControllerRouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerRouteConfig {
    pub method: String,
    pub path: String,
    pub handler: String,
}

fn default_listen() -> String {
    "0.0.0.0:8443".to_owned()
}
fn default_http1_secure_enabled() -> bool {
    true
}
fn default_http2_secure_enabled() -> bool {
    true
}
fn default_plain_listen() -> String {
    "0.0.0.0:8080".to_owned()
}
/// A TLS path setting accepts either one path or a list of paths. A list makes
/// it possible to keep separate fullchain/key files per domain; concatenated
/// PEM files remain supported when a single path is configured.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum TlsPaths {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

impl TlsPaths {
    fn into_vec(self) -> Vec<PathBuf> {
        match self {
            Self::One(path) => vec![path],
            Self::Many(paths) => paths,
        }
    }
}

fn default_cert_path() -> TlsPaths {
    TlsPaths::One(PathBuf::from("certs/fullchain.pem"))
}
fn default_key_path() -> TlsPaths {
    TlsPaths::One(PathBuf::from("certs/privkey.pem"))
}
fn default_body_limit() -> usize {
    DEFAULT_BODY_LIMIT
}
fn default_static_limit() -> usize {
    DEFAULT_STATIC_LIMIT
}
fn default_log_filter() -> String {
    concat!("info,", env!("CARGO_PKG_NAME"), "=info").to_owned()
}
fn default_index() -> String {
    "index.html".to_owned()
}
fn default_cache_control() -> String {
    "public, max-age=60".to_owned()
}
fn default_session_cookie() -> String {
    "htxpro_session".to_owned()
}
fn default_cookie_secure() -> bool {
    true
}
fn default_session_ttl_seconds() -> u64 {
    3_600
}
fn default_state_ttl_seconds() -> u64 {
    600
}
fn default_authorization_endpoint() -> String {
    "https://api.workos.com/user_management/authorize".to_owned()
}
fn default_token_endpoint() -> String {
    "https://api.workos.com/user_management/authenticate".to_owned()
}
fn default_oauth_provider() -> String {
    "authkit".to_owned()
}
fn default_oauth_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ]
}
fn default_oauth_http_timeout_ms() -> u64 {
    10_000
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let canonical_config = std::fs::canonicalize(path)
            .with_context(|| format!("cannot resolve configuration file {}", path.display()))?;
        let contents = std::fs::read_to_string(&canonical_config).with_context(|| {
            format!(
                "cannot read configuration file {}",
                canonical_config.display()
            )
        })?;
        let mut raw: RawConfig = yaml_serde::from_str(&contents).with_context(|| {
            format!(
                "invalid YAML configuration in {}",
                canonical_config.display()
            )
        })?;

        let listen = raw
            .listen
            .parse::<SocketAddr>()
            .context("listen must be a socket address such as 0.0.0.0:8443")?;
        let plain_listen = raw
            .plain_listen
            .parse::<SocketAddr>()
            .context("plain_listen must be a socket address such as 0.0.0.0:8080")?;
        anyhow::ensure!(listen.port() != 0, "listen port must be non-zero so secure TCP and QUIC UDP listeners can share the configured port");
        anyhow::ensure!(
            plain_listen.port() != 0,
            "plain_listen port must be non-zero"
        );
        let any_secure_enabled = raw.http1_secure_enabled || raw.http2_secure_enabled;
        let any_plain_enabled = raw.http1_plain_enabled || raw.http2_plain_enabled;
        anyhow::ensure!(
            !(any_plain_enabled && any_secure_enabled && plain_listen.port() == listen.port()),
            "plain_listen must use a different TCP port from listen when secure HTTP and plain HTTP are both enabled",
        );
        anyhow::ensure!(
            raw.max_request_body_bytes > 0 && raw.max_request_body_bytes <= 16 * 1024 * 1024,
            "max_request_body_bytes must be between 1 byte and 16 MiB"
        );
        anyhow::ensure!(
            raw.max_static_file_bytes > 0 && raw.max_static_file_bytes <= 32 * 1024 * 1024,
            "max_static_file_bytes must be between 1 byte and 32 MiB"
        );
        validate_timeouts(&raw.timeouts)?;
        validate_limits(&raw.limits)?;
        validate_rate_limit(&raw.rate_limit)?;
        anyhow::ensure!(
            !raw.log_filter.trim().is_empty(),
            "log_filter must not be empty"
        );
        anyhow::ensure!(
            !raw.virtual_hosts.is_empty(),
            "at least one virtual_hosts entry is required"
        );

        let base_dir = canonical_config.parent().unwrap_or_else(|| Path::new("."));
        let resolve_path = |configured: PathBuf| {
            if configured.is_absolute() {
                configured
            } else {
                base_dir.join(configured)
            }
        };
        let cert_paths = raw
            .tls_cert
            .into_vec()
            .into_iter()
            .map(&resolve_path)
            .collect::<Vec<_>>();
        let key_paths = raw
            .tls_key
            .into_vec()
            .into_iter()
            .map(&resolve_path)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            !cert_paths.is_empty(),
            "tls_cert must contain at least one certificate path"
        );
        anyhow::ensure!(
            !key_paths.is_empty(),
            "tls_key must contain at least one private key path"
        );

        for vhost in &mut raw.virtual_hosts {
            vhost.host = normalize_host_pattern(&vhost.host)?;
            for alias in &mut vhost.aliases {
                *alias = normalize_host_pattern(alias)?;
            }
            anyhow::ensure!(
                vhost.static_site.is_some() ^ vhost.controller.is_some(),
                "virtual host {:?} must define exactly one of 'static' or 'controller'",
                vhost.host
            );
            if let Some(site) = &mut vhost.static_site {
                site.root = resolve_path(site.root.clone());
                site.root = std::fs::canonicalize(&site.root).with_context(|| {
                    format!(
                        "cannot resolve static root for host {:?}: {}",
                        vhost.host,
                        site.root.display()
                    )
                })?;
                anyhow::ensure!(
                    site.root.is_dir(),
                    "static root for host {:?} is not a directory",
                    vhost.host
                );
                validate_index(&site.index)?;
                validate_header_value(&site.cache_control).with_context(|| {
                    format!("invalid static.cache_control for host {:?}", vhost.host)
                })?;
            }
            if let Some(controller_name) = &vhost.controller {
                anyhow::ensure!(
                    raw.controllers.contains_key(controller_name),
                    "virtual host {:?} references unknown controller {:?}",
                    vhost.host,
                    controller_name
                );
            }
        }

        let mut assigned_names = HashSet::new();
        for vhost in &raw.virtual_hosts {
            for name in std::iter::once(&vhost.host).chain(vhost.aliases.iter()) {
                anyhow::ensure!(
                    assigned_names.insert(name.clone()),
                    "host pattern/alias {name:?} is configured more than once"
                );
            }
        }
        if let Some(default_host) = &mut raw.default_host {
            *default_host = normalize_exact_host(default_host)?;
            anyhow::ensure!(
                assigned_names.contains(default_host),
                "default_host must refer to a configured exact host or alias (not a wildcard)"
            );
            anyhow::ensure!(
                !default_host.starts_with("*."),
                "default_host cannot be a wildcard"
            );
        }

        for (controller_name, controller) in &raw.controllers {
            anyhow::ensure!(
                !controller_name.trim().is_empty(),
                "controller names must not be empty"
            );
            anyhow::ensure!(
                !controller.routes.is_empty(),
                "controller {controller_name:?} must define at least one route"
            );
            let mut route_keys = HashSet::new();
            for route in &controller.routes {
                let method = route.method.to_ascii_uppercase();
                anyhow::ensure!(
                    matches!(
                        method.as_str(),
                        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
                    ),
                    "unsupported method {:?} in controller {controller_name:?}",
                    route.method
                );
                validate_route_pattern(&route.path)?;
                anyhow::ensure!(matches!(route.handler.as_str(), "health" | "status" | "metrics" | "echo" | "items" | "whoami"),
                    "unknown handler {:?}; supported handlers are health, status, metrics, echo, items, whoami", route.handler);
                anyhow::ensure!(
                    route_keys.insert((method, route.path.clone())),
                    "duplicate route {:?} {:?} in controller {controller_name:?}",
                    route.method,
                    route.path
                );
            }
        }

        for vhost in &raw.virtual_hosts {
            if let Some(host_security) = &vhost.security {
                let security = raw.security.as_ref().with_context(|| {
                    format!(
                        "virtual host {:?} configures security but no top-level 'security' section exists",
                        vhost.host
                    )
                })?;
                anyhow::ensure!(
                    security.modules.contains_key(&host_security.module),
                    "virtual host {:?} references unknown security module {:?}",
                    vhost.host,
                    host_security.module
                );
            }
        }
        if let Some(security) = &raw.security {
            validate_security(security)?;
        }

        Ok(Self {
            listen,
            http1_secure_enabled: raw.http1_secure_enabled,
            http1_plain_enabled: raw.http1_plain_enabled,
            http2_secure_enabled: raw.http2_secure_enabled,
            http2_plain_enabled: raw.http2_plain_enabled,
            plain_listen,
            cert_paths,
            key_paths,
            max_request_body_bytes: raw.max_request_body_bytes,
            max_static_file_bytes: raw.max_static_file_bytes,
            timeouts: raw.timeouts,
            limits: raw.limits,
            rate_limit: raw.rate_limit,
            log_filter: raw.log_filter,
            default_host: raw.default_host,
            security: raw.security,
            virtual_hosts: raw.virtual_hosts,
            controllers: raw.controllers,
        })
    }

    pub fn resolve_host(&self, authority: &str) -> Option<&VirtualHostConfig> {
        let host = normalize_authority(authority);
        // Match exact hostnames before wildcard names, regardless of YAML declaration order.
        for vhost in &self.virtual_hosts {
            if std::iter::once(&vhost.host)
                .chain(vhost.aliases.iter())
                .any(|pattern| !pattern.starts_with("*.") && pattern == &host)
            {
                return Some(vhost);
            }
        }
        for vhost in &self.virtual_hosts {
            if std::iter::once(&vhost.host)
                .chain(vhost.aliases.iter())
                .any(|pattern| pattern.starts_with("*.") && host_matches(pattern, &host))
            {
                return Some(vhost);
            }
        }
        self.default_host.as_ref().and_then(|default| {
            self.virtual_hosts.iter().find(|vhost| {
                vhost.host == *default || vhost.aliases.iter().any(|alias| alias == default)
            })
        })
    }
}

/// Parsed absolute HTTP(S) URL used by security module endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedHttpUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

pub(crate) fn parse_http_url(input: &str) -> Result<ParsedHttpUrl> {
    anyhow::ensure!(
        !input
            .chars()
            .any(|character| character.is_control() || character.is_whitespace()),
        "URL contains whitespace or control characters"
    );
    anyhow::ensure!(
        input.is_ascii(),
        "URL must be ASCII; percent-encode non-ASCII components"
    );
    let (scheme, rest) = input
        .split_once("://")
        .context("URL must include an http:// or https:// scheme")?;
    let scheme = scheme.to_ascii_lowercase();
    anyhow::ensure!(
        matches!(scheme.as_str(), "http" | "https"),
        "URL scheme must be http or https"
    );
    let default_port = if scheme == "https" { 443 } else { 80 };
    let boundary = rest.find(['/', '?', '#']);
    let (authority, path_and_query) = match boundary {
        Some(index) if rest[index..].starts_with('/') => (&rest[..index], &rest[index..]),
        Some(_) => anyhow::bail!("URL must include a path starting with '/'"),
        None => (rest, "/"),
    };
    anyhow::ensure!(!authority.is_empty(), "URL host must not be empty");
    anyhow::ensure!(!authority.contains('@'), "URL userinfo is not supported");
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, rest) = inner
            .split_once(']')
            .context("invalid bracketed IPv6 host in URL")?;
        let port = match rest {
            "" => default_port,
            rest => {
                let value = rest
                    .strip_prefix(':')
                    .context("unexpected characters after bracketed IPv6 host")?;
                parse_port(value)?
            }
        };
        (host.to_owned(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        anyhow::ensure!(
            !host.contains(':'),
            "IPv6 URL hosts must be enclosed in brackets"
        );
        (host.to_owned(), parse_port(port)?)
    } else {
        (authority.to_owned(), default_port)
    };
    anyhow::ensure!(!host.is_empty(), "URL host must not be empty");
    anyhow::ensure!(
        !host
            .chars()
            .any(|character| character.is_control() || character.is_whitespace()),
        "URL host contains whitespace or control characters"
    );
    anyhow::ensure!(
        host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':' | b'*')
        }),
        "URL host contains invalid characters"
    );
    anyhow::ensure!(
        path_and_query.starts_with('/'),
        "URL path must start with '/'"
    );
    anyhow::ensure!(
        !path_and_query.contains('#'),
        "URL fragments are not supported"
    );
    Ok(ParsedHttpUrl {
        scheme,
        host,
        port,
        path_and_query: path_and_query.to_owned(),
    })
}

fn parse_port(value: &str) -> Result<u16> {
    anyhow::ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "URL port must be numeric"
    );
    let port = value.parse::<u16>().context("URL port is out of range")?;
    anyhow::ensure!(port != 0, "URL port must not be zero");
    Ok(port)
}

fn validate_security(security: &SecurityConfig) -> Result<()> {
    anyhow::ensure!(
        is_http_token(&security.cookie_name),
        "security.cookie_name must be a valid HTTP cookie name"
    );
    anyhow::ensure!(
        security.cookie_secure
            || !(security.cookie_name.starts_with("__Host-")
                || security.cookie_name.starts_with("__Secure-")),
        "security.cookie_name uses a secure prefix, which requires cookie_secure: true"
    );
    anyhow::ensure!(
        security.session_secret.len() >= 32,
        "security.session_secret must contain at least 32 bytes of entropy"
    );
    anyhow::ensure!(
        (60..=31_536_000).contains(&security.session_ttl_seconds),
        "security.session_ttl_seconds must be between 60 and 31536000 seconds"
    );
    anyhow::ensure!(
        (30..=3_600).contains(&security.state_ttl_seconds),
        "security.state_ttl_seconds must be between 30 and 3600 seconds"
    );
    anyhow::ensure!(
        !security.modules.is_empty(),
        "security.modules must define at least one module"
    );
    for (name, module) in &security.modules {
        anyhow::ensure!(
            !name.trim().is_empty()
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric()
                        || matches!(character, '-' | '_' | '.')),
            "security module names must be non-empty ASCII identifiers"
        );
        match module.kind.as_str() {
            "oauth2_workos" => validate_workos_module(name, module)?,
            other => anyhow::bail!(
                "security module {name:?} has unsupported type {other:?}; supported types are: oauth2_workos"
            ),
        }
    }
    Ok(())
}

fn validate_workos_module(name: &str, module: &SecurityModuleConfig) -> Result<()> {
    anyhow::ensure!(
        !module.client_id.trim().is_empty(),
        "security module {name:?} client_id must not be empty"
    );
    anyhow::ensure!(
        !module.client_secret.trim().is_empty(),
        "security module {name:?} client_secret must not be empty"
    );
    let redirect = parse_http_url(&module.redirect_uri)
        .with_context(|| format!("invalid redirect_uri for security module {name:?}"))?;
    anyhow::ensure!(
        !redirect.path_and_query.contains('?'),
        "security module {name:?} redirect_uri must not contain a query string"
    );
    anyhow::ensure!(
        redirect.path_and_query != "/",
        "security module {name:?} redirect_uri must include a non-root callback path"
    );
    let authorization = parse_http_url(&module.authorization_endpoint)
        .with_context(|| format!("invalid authorization_endpoint for security module {name:?}"))?;
    ensure_secure_endpoint(name, "authorization_endpoint", &authorization)?;
    anyhow::ensure!(
        !authorization.path_and_query.contains('#'),
        "security module {name:?} authorization_endpoint must not contain a fragment"
    );
    let token = parse_http_url(&module.token_endpoint)
        .with_context(|| format!("invalid token_endpoint for security module {name:?}"))?;
    ensure_secure_endpoint(name, "token_endpoint", &token)?;
    anyhow::ensure!(
        !token.path_and_query.contains('?'),
        "security module {name:?} token_endpoint must not contain a query string"
    );
    anyhow::ensure!(
        !module.provider.is_empty()
            && !module
                .provider
                .chars()
                .any(|character| character.is_control() || character.is_whitespace()),
        "security module {name:?} provider must not be empty or contain whitespace"
    );
    for scope in &module.scopes {
        anyhow::ensure!(
            !scope.is_empty()
                && !scope
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace()),
            "security module {name:?} scopes must be non-empty tokens without whitespace"
        );
    }
    anyhow::ensure!(
        (100..=120_000).contains(&module.http_timeout_ms),
        "security module {name:?} http_timeout_ms must be between 100 and 120000 milliseconds"
    );
    Ok(())
}

fn ensure_secure_endpoint(module_name: &str, field: &str, endpoint: &ParsedHttpUrl) -> Result<()> {
    anyhow::ensure!(
        endpoint.scheme == "https" || is_loopback_host(&endpoint.host),
        "security module {module_name:?} {field} must use https unless it targets a loopback host"
    );
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn validate_rate_limit(rate_limit: &RateLimitConfig) -> Result<()> {
    anyhow::ensure!(
        rate_limit.global_requests_per_second > 0,
        "rate_limit.global_requests_per_second must be greater than zero"
    );
    anyhow::ensure!(
        rate_limit.global_burst > 0,
        "rate_limit.global_burst must be greater than zero"
    );
    anyhow::ensure!(
        rate_limit.requests_per_second_per_ip > 0,
        "rate_limit.requests_per_second_per_ip must be greater than zero"
    );
    anyhow::ensure!(
        rate_limit.burst_per_ip > 0,
        "rate_limit.burst_per_ip must be greater than zero"
    );
    anyhow::ensure!(
        rate_limit.global_requests_per_second <= 1_000_000
            && rate_limit.global_burst <= 1_000_000
            && rate_limit.requests_per_second_per_ip <= 1_000_000
            && rate_limit.burst_per_ip <= 1_000_000,
        "rate-limit values must not exceed 1,000,000"
    );
    Ok(())
}

fn validate_timeouts(timeouts: &TimeoutConfig) -> Result<()> {
    for (name, value) in [
        ("tls_handshake_ms", timeouts.tls_handshake_ms),
        ("request_headers_ms", timeouts.request_headers_ms),
        ("request_body_ms", timeouts.request_body_ms),
        ("request_process_ms", timeouts.request_process_ms),
        ("response_write_ms", timeouts.response_write_ms),
        ("keep_alive_idle_ms", timeouts.keep_alive_idle_ms),
    ] {
        anyhow::ensure!(
            (1..=300_000).contains(&value),
            "timeouts.{name} must be between 1 and 300000 milliseconds"
        );
    }
    Ok(())
}

fn validate_limits(limits: &LimitConfig) -> Result<()> {
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_inflight_requests),
        "limits.max_inflight_requests must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_inflight_requests_per_ip),
        "limits.max_inflight_requests_per_ip must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_inflight_requests_per_host),
        "limits.max_inflight_requests_per_host must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_inflight_static_requests),
        "limits.max_inflight_static_requests must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_inflight_controller_requests),
        "limits.max_inflight_controller_requests must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=65_535).contains(&limits.max_concurrent_streams_per_connection),
        "limits.max_concurrent_streams_per_connection must be between 1 and 65535"
    );
    anyhow::ensure!(
        (1..=1024 * 1024).contains(&limits.max_header_bytes),
        "limits.max_header_bytes must be between 1 byte and 1 MiB"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_tcp_connections),
        "limits.max_tcp_connections must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_tcp_connections_per_ip),
        "limits.max_tcp_connections_per_ip must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_quic_connections),
        "limits.max_quic_connections must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_quic_connections_per_ip),
        "limits.max_quic_connections_per_ip must be between 1 and 1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_tracked_client_ips),
        "limits.max_tracked_client_ips must be between 1 and 1000000"
    );
    Ok(())
}

fn normalize_authority(authority: &str) -> String {
    let value = authority.trim().to_ascii_lowercase();
    if value.starts_with('[') {
        return value
            .split(']')
            .next()
            .map(|s| format!("{}]", s))
            .unwrap_or(value);
    }
    let host = match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => value.as_str(),
    };
    host.trim_end_matches('.').to_owned()
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.')
    } else {
        pattern == host
    }
}

fn normalize_host_pattern(input: &str) -> Result<String> {
    let candidate = input.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(!candidate.is_empty(), "host names must not be empty");
    let hostname = candidate.strip_prefix("*.").unwrap_or(&candidate);
    anyhow::ensure!(
        !hostname.is_empty() && !hostname.contains('*'),
        "invalid host pattern {input:?}"
    );
    anyhow::ensure!(
        hostname.split('.').all(|label| !label.is_empty()),
        "invalid host pattern {input:?}"
    );
    anyhow::ensure!(
        hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')),
        "host pattern {input:?} contains unsupported characters; use ASCII/Punycode names"
    );
    anyhow::ensure!(
        !hostname.starts_with('-') && !hostname.ends_with('-'),
        "invalid host pattern {input:?}"
    );
    Ok(candidate)
}

fn normalize_exact_host(input: &str) -> Result<String> {
    let host = normalize_host_pattern(input)?;
    anyhow::ensure!(!host.starts_with("*."), "default_host cannot be a wildcard");
    Ok(host)
}

fn validate_index(index: &str) -> Result<()> {
    let path = Path::new(index);
    anyhow::ensure!(
        !index.is_empty()
            && path.components().count() == 1
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "static.index must be a single filename such as index.html"
    );
    anyhow::ensure!(
        !index.chars().any(|c| matches!(c, '/' | '\\' | '\0')),
        "static.index must be a single filename"
    );
    Ok(())
}

fn validate_route_pattern(path: &str) -> Result<()> {
    anyhow::ensure!(
        path.starts_with('/') && !path.chars().any(|c| matches!(c, '?' | '#' | '\\' | '\0')),
        "controller route path {path:?} must be an absolute path without query/fragment/backslash"
    );
    anyhow::ensure!(
        !path.contains("//"),
        "controller route path {path:?} cannot contain empty segments"
    );
    if path == "/" {
        return Ok(());
    }
    for segment in path.split('/').skip(1) {
        if segment.starts_with('{') || segment.ends_with('}') {
            anyhow::ensure!(
                segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2,
                "invalid path parameter in route {path:?}"
            );
            let name = &segment[1..segment.len() - 1];
            anyhow::ensure!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "invalid path parameter name in route {path:?}"
            );
        } else {
            anyhow::ensure!(
                !segment.is_empty() && segment != "." && segment != "..",
                "unsafe or empty segment in route {path:?}"
            );
        }
    }
    Ok(())
}

mod http_validation {
    use anyhow::{ensure, Result};

    pub fn validate_header_value(value: &str) -> Result<()> {
        ensure!(
            !value.chars().any(|c| c.is_control() && c != '\t'),
            "header value contains a control character"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{host_matches, normalize_authority};

    #[test]
    fn host_matching_supports_exact_and_wildcard_hosts() {
        assert!(host_matches(
            "example.com",
            &normalize_authority("EXAMPLE.COM:8443")
        ));
        assert!(host_matches(
            "*.example.com",
            &normalize_authority("api.example.com")
        ));
        assert!(!host_matches(
            "*.example.com",
            &normalize_authority("example.com")
        ));
        assert!(!host_matches(
            "*.example.com",
            &normalize_authority("badexample.com")
        ));
    }
}

#[cfg(test)]
mod protection_config_tests {
    use super::{
        parse_http_url, validate_limits, validate_rate_limit, validate_security, validate_timeouts,
        LimitConfig, RateLimitConfig, SecurityConfig, SecurityModuleConfig, TimeoutConfig,
    };
    use std::collections::BTreeMap;

    fn security_config() -> SecurityConfig {
        let mut modules = BTreeMap::new();
        modules.insert(
            "workos".to_owned(),
            SecurityModuleConfig {
                kind: "oauth2_workos".to_owned(),
                client_id: "client_123".to_owned(),
                client_secret: "secret".to_owned(),
                redirect_uri: "https://app.example.test/_htxpro/auth/workos/callback".to_owned(),
                authorization_endpoint: "https://api.workos.com/user_management/authorize"
                    .to_owned(),
                token_endpoint: "https://api.workos.com/user_management/authenticate".to_owned(),
                provider: "authkit".to_owned(),
                scopes: vec!["openid".to_owned(), "email".to_owned()],
                http_timeout_ms: 10_000,
            },
        );
        SecurityConfig {
            cookie_name: "htxpro_session".to_owned(),
            cookie_secure: true,
            session_ttl_seconds: 3_600,
            state_ttl_seconds: 600,
            session_secret: "0123456789abcdef0123456789abcdef".to_owned(),
            modules,
        }
    }

    #[test]
    fn default_protection_settings_are_valid() {
        validate_timeouts(&TimeoutConfig::default()).unwrap();
        validate_limits(&LimitConfig::default()).unwrap();
        validate_rate_limit(&RateLimitConfig::default()).unwrap();
        validate_security(&security_config()).unwrap();
    }

    #[test]
    fn timeout_and_limit_validation_rejects_zero_values() {
        let timeouts = TimeoutConfig {
            request_process_ms: 0,
            ..Default::default()
        };
        assert!(validate_timeouts(&timeouts).is_err());

        let limits = LimitConfig {
            max_inflight_requests: 0,
            ..Default::default()
        };
        assert!(validate_limits(&limits).is_err());

        let rate_limit = RateLimitConfig {
            global_burst: 0,
            ..Default::default()
        };
        assert!(validate_rate_limit(&rate_limit).is_err());
    }

    #[test]
    fn security_validation_rejects_weak_or_unsupported_settings() {
        let mut config = security_config();
        config.session_secret = "too-short".to_owned();
        assert!(validate_security(&config).is_err());

        let mut config = security_config();
        config.cookie_name = "__Host-htxpro_session".to_owned();
        config.cookie_secure = false;
        assert!(validate_security(&config).is_err());
        config.cookie_secure = true;
        validate_security(&config).unwrap();

        let mut config = security_config();
        config.modules.get_mut("workos").unwrap().kind = "oauth2_unknown".to_owned();
        assert!(validate_security(&config).is_err());

        let mut config = security_config();
        config.modules.get_mut("workos").unwrap().redirect_uri =
            "https://app.example.test/callback?next=/".to_owned();
        assert!(validate_security(&config).is_err());

        let mut config = security_config();
        config.modules.get_mut("workos").unwrap().redirect_uri =
            "https://app.example.test/".to_owned();
        assert!(validate_security(&config).is_err());

        let mut config = security_config();
        config.modules.get_mut("workos").unwrap().token_endpoint = "file:///etc/passwd".to_owned();
        assert!(validate_security(&config).is_err());

        let mut config = security_config();
        config.modules.get_mut("workos").unwrap().token_endpoint =
            "http://api.workos.com/user_management/authenticate".to_owned();
        assert!(validate_security(&config).is_err());

        let mut config = security_config();
        config.modules.get_mut("workos").unwrap().token_endpoint =
            "http://127.0.0.1:9/user_management/authenticate".to_owned();
        validate_security(&config).unwrap();
    }

    #[test]
    fn security_config_parses_yaml_defaults_and_type_key() {
        let parsed: SecurityConfig = yaml_serde::from_str(
            r#"
session_secret: "0123456789abcdef0123456789abcdef"
modules:
  workos:
    type: "oauth2_workos"
    client_id: "client_123"
    client_secret: "secret"
    redirect_uri: "https://app.example.test/_htxpro/auth/workos/callback"
"#,
        )
        .unwrap();
        assert_eq!(parsed.cookie_name, "htxpro_session");
        assert!(parsed.cookie_secure);
        assert_eq!(parsed.session_ttl_seconds, 3_600);
        assert_eq!(parsed.state_ttl_seconds, 600);
        let workos = &parsed.modules["workos"];
        assert_eq!(workos.kind, "oauth2_workos");
        assert_eq!(workos.provider, "authkit");
        assert_eq!(workos.http_timeout_ms, 10_000);
        assert_eq!(workos.scopes, ["openid", "profile", "email"]);
        validate_security(&parsed).unwrap();
    }

    #[test]
    fn tls_paths_accept_a_scalar_or_a_list() {
        use std::path::PathBuf;

        let one: super::TlsPaths = yaml_serde::from_str("\"certs/fullchain.pem\"").unwrap();
        assert_eq!(one.into_vec(), vec![PathBuf::from("certs/fullchain.pem")]);

        let many: super::TlsPaths =
            yaml_serde::from_str("[certs/google.pem, certs/apple.pem]").unwrap();
        assert_eq!(
            many.into_vec(),
            vec![
                PathBuf::from("certs/google.pem"),
                PathBuf::from("certs/apple.pem")
            ]
        );
    }

    #[test]
    fn http_url_parser_handles_ports_ipv6_and_query_strings() {
        let parsed = parse_http_url("https://[::1]:8443/callback?next=%2F").unwrap();
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.host, "::1");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.path_and_query, "/callback?next=%2F");

        assert!(parse_http_url("https://user@example.test/").is_err());
        assert!(parse_http_url("file:///etc/passwd").is_err());
        assert!(parse_http_url("https://example.test").is_ok());
        assert_eq!(
            parse_http_url("https://*.tenant.example.test/callback")
                .unwrap()
                .host,
            "*.tenant.example.test"
        );
        assert!(parse_http_url("https://example.test/caf\u{e9}").is_err());
        assert!(parse_http_url("https://example.test:0/").is_err());
        assert!(parse_http_url("https://example.test?query=1").is_err());
    }
}
