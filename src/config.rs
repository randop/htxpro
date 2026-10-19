use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use http_validation::validate_header_value;
use serde::Deserialize;

const DEFAULT_BODY_LIMIT: usize = 1 * 1024 * 1024;
const DEFAULT_STATIC_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_listen")]
    listen: String,
    /// Enables HTTP/1.1 over TLS on the secure TCP listener.
    #[serde(default = "default_http1_secure_enabled")]
    http1_secure_enabled: bool,
    /// Enables cleartext HTTP/1.1 on the shared plain listener.
    #[serde(default)]
    http1_plain_enabled: bool,
    #[serde(default = "default_plain_listen")]
    plain_listen: String,
    /// Enables HTTP/2 over TLS ALPN on the secure TCP listener.
    #[serde(default = "default_http2_secure_enabled")]
    http2_secure_enabled: bool,
    /// Enables cleartext HTTP/2 prior-knowledge (h2c) on the shared plain listener.
    #[serde(default)]
    http2_plain_enabled: bool,
    #[serde(default = "default_cert_path")]
    tls_cert: PathBuf,
    #[serde(default = "default_key_path")]
    tls_key: PathBuf,
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
    virtual_hosts: Vec<VirtualHostConfig>,
    #[serde(default)]
    controllers: std::collections::BTreeMap<String, ControllerConfig>,
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
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub max_request_body_bytes: usize,
    pub max_static_file_bytes: usize,
    pub timeouts: TimeoutConfig,
    pub limits: LimitConfig,
    pub rate_limit: RateLimitConfig,
    pub log_filter: String,
    pub default_host: Option<String>,
    pub virtual_hosts: Vec<VirtualHostConfig>,
    pub controllers: std::collections::BTreeMap<String, ControllerConfig>,
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

/// Resource bounds shared across all enabled transports.
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
    /// Exact hostname or wildcard such as `*.example.com`.
    pub host: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default, rename = "static")]
    pub static_site: Option<StaticSiteConfig>,
    /// Names a Rust controller route table declared under `controllers`.
    #[serde(default)]
    pub controller: Option<String>,
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
fn default_cert_path() -> PathBuf {
    PathBuf::from("certs/fullchain.pem")
}
fn default_key_path() -> PathBuf {
    PathBuf::from("certs/privkey.pem")
}
fn default_body_limit() -> usize {
    DEFAULT_BODY_LIMIT
}
fn default_static_limit() -> usize {
    DEFAULT_STATIC_LIMIT
}
fn default_log_filter() -> String {
    "info,websrv=info".to_owned()
}
fn default_index() -> String {
    "index.html".to_owned()
}
fn default_cache_control() -> String {
    "public, max-age=60".to_owned()
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
        raw.tls_cert = resolve_path(raw.tls_cert);
        raw.tls_key = resolve_path(raw.tls_key);

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
                anyhow::ensure!(matches!(route.handler.as_str(), "health" | "status" | "metrics" | "echo" | "items"),
                    "unknown handler {:?}; supported handlers are health, status, metrics, echo, items", route.handler);
                anyhow::ensure!(
                    route_keys.insert((method, route.path.clone())),
                    "duplicate route {:?} {:?} in controller {controller_name:?}",
                    route.method,
                    route.path
                );
            }
        }

        Ok(Self {
            listen,
            http1_secure_enabled: raw.http1_secure_enabled,
            http1_plain_enabled: raw.http1_plain_enabled,
            http2_secure_enabled: raw.http2_secure_enabled,
            http2_plain_enabled: raw.http2_plain_enabled,
            plain_listen,
            cert_path: raw.tls_cert,
            key_path: raw.tls_key,
            max_request_body_bytes: raw.max_request_body_bytes,
            max_static_file_bytes: raw.max_static_file_bytes,
            timeouts: raw.timeouts,
            limits: raw.limits,
            rate_limit: raw.rate_limit,
            log_filter: raw.log_filter,
            default_host: raw.default_host,
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

// Keep dependency-independent header validation in a tiny module for startup-time checks.
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
        validate_limits, validate_rate_limit, validate_timeouts, LimitConfig, RateLimitConfig,
        TimeoutConfig,
    };

    #[test]
    fn default_protection_settings_are_valid() {
        validate_timeouts(&TimeoutConfig::default()).unwrap();
        validate_limits(&LimitConfig::default()).unwrap();
        validate_rate_limit(&RateLimitConfig::default()).unwrap();
    }

    #[test]
    fn timeout_and_limit_validation_rejects_zero_values() {
        let mut timeouts = TimeoutConfig::default();
        timeouts.request_process_ms = 0;
        assert!(validate_timeouts(&timeouts).is_err());

        let mut limits = LimitConfig::default();
        limits.max_inflight_requests = 0;
        assert!(validate_limits(&limits).is_err());

        let mut rate_limit = RateLimitConfig::default();
        rate_limit.global_burst = 0;
        assert!(validate_rate_limit(&rate_limit).is_err());
    }
}
