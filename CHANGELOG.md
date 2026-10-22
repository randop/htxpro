# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1]

### Added
- `--version` / `-V` CLI flag, which prints the package name and version and exits before loading configuration. `--help` now lists it.
- Bundled third-party license texts for every crate in `Cargo.lock` under `licenses/`, plus `scripts/licenses.sh` to collect, check, list, or clean them.

## [0.7.0]

### Added
- Multi-domain TLS support: `tls_cert` and `tls_key` accept either a single path or a YAML list of paths, with certificates and keys supplied as concatenated PEM files or separate files.
- SNI-based certificate selection: exact DNS SAN names (or the CN when no DNS SAN is present) take precedence over single-label wildcards, and the first chain is the fallback for clients that omit SNI or request an unknown name.
- TLS chain handling that pairs leaf certificates with keys by public key regardless of file order and rebuilds issuer chains through subject/issuer links.
- Certificate resolver integration with rustls for HTTP/1.1 and HTTP/2, and with BoringSSL's certificate callback for HTTP/3.
- Deployment documentation for multi-domain certificates, including permissions, chain configuration, certificate mounting, and authentication redirects.

### Changed
- Single-path `tls_cert` and `tls_key` configurations remain supported and behave as before.
- Docker and systemd guidance updated for multi-domain TLS deployments.

## [0.6.0]

### Added
- Top-level `security` configuration and per-virtual-host `security.module` references, with support for multiple named security module instances.
- WorkOS AuthKit OAuth2 authorization-code flow using PKCE (S256).
- Signed OAuth state cookies and stateless HMAC-signed session cookies.
- `AuthIdentity` request context and a `whoami` controller endpoint.
- Response header support (`Location`, `Set-Cookie`) across HTTP/1.1, HTTP/2, and HTTP/3.

### Changed
- Protected and authentication-gate responses are sent with `Cache-Control: private, no-store` and `Vary: Cookie`.
- `config.example.yaml` and `ARCHITECTURE.md` updated with authentication configuration and guidance.

### Fixed
- Repeated `Cookie` headers in HTTP/3 requests are merged correctly.

### Security
- HTTPS is required for non-loopback authentication and token endpoints.
- Redirect paths cannot target the root, contain queries, or escape the same origin; encoded separators and control bytes are rejected.
- OAuth state comparison is constant-time.
- Secure cookie prefixes require `cookie_secure: true`.
- OAuth redirect hosts and refresh-token endpoint DNS are validated, with bounded connection retries.

## [0.5.1]

### Added
- HTTP/3 (QUIC), HTTP/2, and HTTP/1.1 listeners, with secure and plain variants and a mandatory io_uring/monoio runtime.
- Host-based routing on `Host` / `:authority`: exact names before wildcards, aliases, wildcard virtual hosts, and a default-host fallback.
- Per-virtual-host static site hosting with configurable index files, SPA fallback, and cache-control headers.
- Modular in-process REST controllers with method/path routing and path parameters; built-in health, status, metrics, echo, and items CRUD handlers.
- YAML configuration, PEM TLS loading, structured JSON logging, and configurable log filtering.
- Request, connection, and rate limits; per-IP and per-host caps; header and body size limits; request/response timeouts; and a static file size cap.
- Docker and systemd deployment examples and documentation, along with project licensing and ignore rules.
