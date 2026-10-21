# htxpro

`htxpro` is a Linux-only, QUIC-first Rust web server. Its runtime is **Monoio's `IoUringDriver`**, selected explicitly at startup. HTTP/3 over QUIC/UDP is the primary protocol and is implemented with `quiche`. HTTPS over TCP independently enables HTTP/2 and HTTP/1.1 through TLS ALPN; cleartext HTTP/1.1 and prior-knowledge HTTP/2 (h2c) share a configurable TCP listener. All TCP/UDP request-time networking and static content reads use the same mandatory Monoio `IoUringDriver`. Every protocol shares virtual-host routing, static sites, in-process Rust REST controllers, and an optional per-host authentication gate. TCP responses advertise the QUIC endpoint through `Alt-Svc` so compatible clients can upgrade to HTTP/3.

**There is no Tokio dependency, no epoll/legacy driver feature, and no request-time I/O backend fallback.** If `io_uring_setup` is unavailable or denied by a container seccomp policy, startup fails instead of silently changing drivers. Request-time UDP/TCP socket operations and static-content reads are driven by Monoio’s mandatory `IoUringDriver`. Configuration parsing, path canonicalization, and initial TLS PEM loading are bootstrap operations performed before traffic is accepted. `http1_secure_enabled: true` enables HTTPS HTTP/1.1 on the secure TCP listener; `http2_secure_enabled: true` independently enables HTTP/2 there. ALPN selects an enabled secure protocol. `http1_plain_enabled: true` enables cleartext HTTP/1.1 on `plain_listen`; `http2_plain_enabled: true` enables cleartext HTTP/2 prior-knowledge on the same listener (default `0.0.0.0:8080`). All listeners use Monoio's mandatory io_uring driver; disable individual protocol flags to disable them. Cleartext HTTP/2 supports prior-knowledge h2c, not the HTTP/1.1 Upgrade mechanism.

## Architecture

```text
UDP socket (Monoio IoUringDriver)             TCP socket (Monoio IoUringDriver)
             │                                               │
             ▼                                               ▼
       quiche QUIC + TLS                             rustls TLS + ALPN
             │                                       ┌───────┴───────┐
             ▼                                       ▼               ▼
       quiche HTTP/3                             monoio-http H2  HTTP/1.1 parser
             └──────────────────────┬────────────────────────┘
                                    ▼
                       authority / Host selection
                                    ▼
                    host security gate (optional)
                    │                      │
       authenticated/public         login redirect / 401
                    ▼
       ┌─────┴─────────┐
       ▼               ▼
 static-site module  Rust controller registry
       │               │
 Monoio file reads    async Rust handlers
   through ring       (health/status/echo/items/whoami)
```

- **Runtime:** `monoio` is built with `default-features = false` and the `iouring`, `utils`, and `sync` features; `utils` provides runtime utilities and `sync` supports wakeups from the DNS helper thread. These features do not enable a legacy I/O driver. The code constructs `RuntimeBuilder<IoUringDriver>` explicitly. Monoio is a thread-per-core runtime built around io_uring rather than a Tokio compatibility layer. See [Monoio's runtime documentation](https://docs.rs/monoio/latest/monoio/).
- **QUIC/HTTP/3:** `quiche` owns QUIC, TLS handshake, loss recovery, congestion control, HTTP/3 framing, and QPACK. Its API leaves UDP socket driving and the event loop to the application; htxpro drives those on Monoio. See [quiche HTTP/3 documentation](https://docs.rs/quiche/latest/quiche/h3/).
- **HTTPS protocol negotiation:** `src/http1_server.rs` terminates TLS with rustls and negotiates `h2` or `http/1.1` through ALPN. HTTP/2 uses `monoio-http` and `monoio-rustls`; HTTP/1.1 keeps its bounded parser. Both are driven by the mandatory Monoio `IoUringDriver`, and both dispatch into the same host/static/controller runtime. HTTP/1.1 accepts `Content-Length` request bodies, rejects `Transfer-Encoding` and `Expect`, bounds headers and bodies, and supports persistent connections.
- **HTTP/2 streams:** `src/http2_server.rs` accepts multiplexed request streams and routes each request to the shared dispatcher. Request bodies are bounded; response payloads are sent in flow-control-aware chunks rather than buffered without limit in the HTTP/2 library.
- **Virtual hosting:** exact names are checked before wildcard names; aliases are supported. Each host has exactly one serving target: a static root or a named Rust controller table.
- **Controller model:** controller routes are declared in YAML and map to Rust handler modules. No shell process, CGI, FastCGI daemon, or arbitrary configured executable is launched. Add business logic under `src/controllers/` and register its route handler explicitly. Authenticated requests carry an `AuthIdentity` (`module`, subject, email, name) into controller handlers.
- **Host security:** a virtual host may reference one named module from the top-level `security` registry. The gate runs before either static or controller dispatch, so the same configuration protects both workload types. Multiple named module instances can be configured; the only implemented module type is the WorkOS OAuth2 authorization-code web flow.
- **File reads:** static content is opened and read asynchronously using Monoio's file API. Static content roots should be owned by the publisher and not writable by the htxpro runtime user. Do not place untrusted symlinks under a served root.
- **Startup-only operations:** config parsing, TLS key loading, root canonicalization, tracing initialization, initial security endpoint DNS resolution, and the outbound TLS root store setup happen during bootstrap before serving traffic. Request-time UDP and TCP socket I/O plus static file reads use the mandatory io_uring runtime. If all cached security endpoint addresses fail, DNS is refreshed on a helper thread before retrying the connection.

## Requirements

- Linux with a kernel and configuration that permit `io_uring` (typically Linux 5.6+; a newer maintained kernel is recommended).
- A container/runtime seccomp policy that permits `io_uring_setup`, `io_uring_enter`, and the required registration calls.
- Rust stable and Cargo. The `quiche` build may need a C/C++ toolchain, CMake, Clang, Perl, and pkg-config to build its TLS dependency.
- A trusted certificate chain and matching private key in PEM format, covering every hostname you serve. The same certificate/key pair is used by QUIC and HTTPS (HTTP/2 and HTTP/1.1).
- UDP ingress for HTTP/3 and TCP ingress for HTTPS/HTTP/2 and HTTPS/1.1 on `0.0.0.0:8443`, plus configurable plain HTTP/1.1 and prior-knowledge HTTP/2 TCP on `0.0.0.0:8080` in the bundled config.

## Build and run

```bash
mkdir -p certs
# Install a trusted certificate chain at certs/fullchain.pem and its key at certs/privkey.pem.
# Edit virtual_hosts and controllers in config.yaml.
cargo fmt --all
cargo test
cargo build --release
./target/release/htxpro --config ./config.yaml
```

The default config path is `config.yaml` in the current working directory. Use `-c` or `--config` to specify another file. Relative certificate and static-root paths are resolved against the directory containing the YAML file. Environment variables do not override YAML settings and `.env` files are not loaded.

### Local HTTP/3 smoke test

The hostname in the `Host`/`:authority` header must match a configured virtual host. For local-only testing, create a development certificate with SANs for `example.test`, `api.example.test`, and any tenant names. Use a curl build that supports HTTP/3 for the primary protocol:

```bash
curl --http3-only --resolve example.test:8443:127.0.0.1 \
  --cacert certs/fullchain.pem https://example.test:8443/

curl --http3-only --resolve api.example.test:8443:127.0.0.1 \
  --cacert certs/fullchain.pem https://api.example.test:8443/healthz
```

The secure TCP listener shares the same certificate and hostname routing. To explicitly verify secure HTTP/1.1, use a curl build supporting standard TLS:

```bash
curl --http1.1 --resolve example.test:8443:127.0.0.1 \
  --cacert certs/fullchain.pem https://example.test:8443/

curl --http1.1 --resolve api.example.test:8443:127.0.0.1 \
  --cacert certs/fullchain.pem https://api.example.test:8443/healthz
```

### Local HTTPS/HTTP/2 smoke test

HTTP/2 is negotiated with TLS ALPN on TCP port 8443. Use a curl build compiled with HTTP/2 support; `--write-out` reports the negotiated protocol version:

```bash
curl --http2 --resolve example.test:8443:127.0.0.1 \
  --cacert certs/fullchain.pem \
  --write-out '\nHTTP version: %{http_version}\n' https://example.test:8443/

curl --http2 --resolve api.example.test:8443:127.0.0.1 \
  --cacert certs/fullchain.pem \
  --write-out '\nHTTP version: %{http_version}\n' https://api.example.test:8443/healthz
```

The reported HTTP version should be `2`. The `http2_secure_enabled` flag controls only secure HTTP/2; secure HTTP/1.1 is independently controlled by `http1_secure_enabled`.

### Local cleartext HTTP/1.1 and HTTP/2 prior-knowledge smoke test

The bundled config enables plain HTTP/1.1 and prior-knowledge HTTP/2 on TCP port 8080. Use the `Host` header (or `--resolve`) to exercise the same virtual-host routing without TLS:

```bash
curl --http1.1 --resolve example.test:8080:127.0.0.1 http://example.test:8080/
curl --http1.1 --resolve api.example.test:8080:127.0.0.1 http://api.example.test:8080/healthz
```

### Local cleartext HTTP/2 prior-knowledge (h2c) smoke test

When `http2_plain_enabled` is true, clients can connect directly using the HTTP/2 connection preface. This listener supports prior-knowledge h2c, not the HTTP/1.1 `Upgrade: h2c` mechanism.

```bash
curl --http2-prior-knowledge --resolve example.test:8080:127.0.0.1 \
  --write-out '\nHTTP version: %{http_version}\n' http://example.test:8080/

curl --http2-prior-knowledge --resolve api.example.test:8080:127.0.0.1 \
  --write-out '\nHTTP version: %{http_version}\n' http://api.example.test:8080/healthz
```

Both cleartext protocols share `plain_listen`; the server detects the HTTP/2 connection preface without losing bytes and routes all remaining requests to the same virtual-host dispatcher.

For a trusted local development CA, add the CA certificate to `--cacert`; do not expose development certificates to public traffic.

## `config.yaml`

The shipped config is executable documentation. This is the high-level shape:

```yaml
listen: "0.0.0.0:8443"
http1_secure_enabled: true
http1_plain_enabled: true
plain_listen: "0.0.0.0:8080"
http2_secure_enabled: true
http2_plain_enabled: true
tls_cert: "certs/fullchain.pem"
tls_key: "certs/privkey.pem"
max_request_body_bytes: 1048576
max_static_file_bytes: 16777216
log_filter: "info,htxpro=debug"
timeouts:
  tls_handshake_ms: 5000
  request_headers_ms: 5000
  request_body_ms: 10000
  request_process_ms: 5000
  response_write_ms: 10000
  keep_alive_idle_ms: 15000
limits:
  max_inflight_requests: 256
  max_inflight_requests_per_ip: 32
  max_inflight_requests_per_host: 128
  max_inflight_static_requests: 16
  max_inflight_controller_requests: 128
  max_concurrent_streams_per_connection: 128
  max_header_bytes: 65536
  max_tcp_connections: 256
  max_tcp_connections_per_ip: 32
  max_quic_connections: 512
  max_quic_connections_per_ip: 64
  max_tracked_client_ips: 65536
rate_limit:
  enabled: true
  global_requests_per_second: 1000
  global_burst: 2000
  requests_per_second_per_ip: 20
  burst_per_ip: 40
default_host: "example.test"
security:
  cookie_name: "htxpro_session"
  cookie_secure: true
  session_secret: "replace-with-at-least-32-random-bytes"
  session_ttl_seconds: 3600
  state_ttl_seconds: 600
  modules:
    workos:
      type: "oauth2_workos"
      client_id: "client_123456789"
      client_secret: "sk_example_123456789"
      redirect_uri: "https://api.example.test/_htxpro/auth/workos/callback"
      authorization_endpoint: "https://api.workos.com/user_management/authorize"
      token_endpoint: "https://api.workos.com/user_management/authenticate"
      provider: "authkit"
      scopes: ["openid", "profile", "email"]
      http_timeout_ms: 10000

virtual_hosts:
  - host: "example.test"
    aliases: ["www.example.test"]
    static:
      root: "public"
      index: "index.html"
      spa_fallback: false
      cache_control: "public, max-age=60"
  - host: "*.tenant.example.test"
    static:
      root: "sites/tenant"
      index: "index.html"
      spa_fallback: true
      cache_control: "public, max-age=300"
  - host: "api.example.test"
    controller: "public_api"
    # Uncomment to require authentication (also optional in config.example.yaml):
    # security:
    #   module: "workos"

controllers:
  public_api:
    routes:
      - { method: "GET", path: "/healthz", handler: "health" }
      - { method: "GET", path: "/status", handler: "status" }
      - { method: "GET", path: "/metrics", handler: "metrics" }
      - { method: "POST", path: "/echo", handler: "echo" }
      - { method: "GET", path: "/v1/whoami", handler: "whoami" }
      - { method: "GET", path: "/v1/items", handler: "items" }
      - { method: "POST", path: "/v1/items", handler: "items" }
      - { method: "GET", path: "/v1/items/{id}", handler: "items" }
      - { method: "PUT", path: "/v1/items/{id}", handler: "items" }
      - { method: "PATCH", path: "/v1/items/{id}", handler: "items" }
      - { method: "DELETE", path: "/v1/items/{id}", handler: "items" }
```

| Key | Meaning |
|---|---|
| `listen` | Socket address used for the HTTP/3 UDP listener and, if enabled, the HTTPS TCP listener |
| `http1_secure_enabled` | Enables HTTPS/1.1 through TLS ALPN; defaults to `true` |
| `http1_plain_enabled` | Enables cleartext HTTP/1.1 on the shared plain TCP listener |
| `plain_listen` | Shared TCP socket address for cleartext HTTP/1.1 and prior-knowledge HTTP/2 (bundled default `0.0.0.0:8080`) |
| `http2_secure_enabled` | Enables HTTP/2 through TLS ALPN (`h2`); defaults to `true` |
| `http2_plain_enabled` | Enables cleartext HTTP/2 prior-knowledge (h2c); defaults to `false` in custom configs |
| `tls_cert`, `tls_key` | PEM certificate chain and private key shared by QUIC TLS and rustls; certificate SANs must cover configured hosts |
| `max_request_body_bytes` | Request payload upper bound; validated at collection and dispatch, with a 16 MiB hard maximum |
| `max_static_file_bytes` | Maximum bytes read for one static file; validation caps it at 32 MiB |
| `timeouts.tls_handshake_ms` | Maximum TLS handshake duration; expired handshakes are dropped |
| `timeouts.request_headers_ms` | Maximum request-header collection window for HTTP/1.1 and HTTP/3; incomplete HTTP/2 headers are bounded by the connection idle deadline exposed by the HTTP/2 adapter |
| `timeouts.request_body_ms` | Absolute deadline for receiving one request body |
| `timeouts.request_process_ms` | Maximum asynchronous dispatch duration; the handler future is cancelled when this deadline expires |
| `timeouts.response_write_ms` | Maximum time spent sending a response or waiting for protocol flow-control capacity |
| `timeouts.keep_alive_idle_ms` | Maximum idle wait for reused HTTP/1.1, HTTP/2, and QUIC connections |
| `limits.max_inflight_requests` | Global bound on admitted requests across all protocols |
| `limits.max_inflight_requests_per_ip` | Per-peer-IP in-flight request bound |
| `limits.max_inflight_requests_per_host` | Per-virtual-host in-flight request bound |
| `limits.max_inflight_static_requests` | Separate static-file concurrency budget |
| `limits.max_inflight_controller_requests` | Separate Rust-controller concurrency budget |
| `limits.max_concurrent_streams_per_connection` | Per-connection stream concurrency advertised/enforced for HTTP/2 and QUIC |
| `limits.max_header_bytes` | Header section/list size cap enforced by each protocol adapter |
| `limits.max_tcp_connections`, `limits.max_tcp_connections_per_ip` | Global and per-IP TCP connection bounds |
| `limits.max_quic_connections`, `limits.max_quic_connections_per_ip` | Global and per-IP QUIC connection bounds |
| `limits.max_tracked_client_ips` | Maximum size of per-IP admission/rate-limit state |
| `rate_limit.enabled` | Enables both server-wide and per-peer-IP token buckets before request admission |
| `rate_limit.global_requests_per_second`, `rate_limit.global_burst` | Global request refill rate and burst ceiling; reduces distributed request storms |
| `rate_limit.requests_per_second_per_ip`, `rate_limit.burst_per_ip` | Per-peer-IP refill rate and burst capacity |
| `default_host` | Optional exact host (or alias) served for otherwise-unmatched authorities |
| `security.cookie_name` | Host-only session cookie name; defaults to `htxpro_session` |
| `security.cookie_secure` | Adds `Secure` to session/state cookies; defaults to `true`. Disable only for local plain-HTTP testing |
| `security.session_secret` | HMAC key for signed session and OAuth state cookies; at least 32 bytes, keep private |
| `security.session_ttl_seconds` | Lifetime of an authenticated session cookie |
| `security.state_ttl_seconds` | Lifetime of the short-lived OAuth state/PKCE cookie |
| `security.modules.<name>` | Named security module instance; multiple instances may be configured |
| `security.modules.<name>.type` | Module type; the only implemented value is `oauth2_workos` |
| `security.modules.<name>.client_id`, `client_secret` | WorkOS application credentials |
| `security.modules.<name>.redirect_uri` | Absolute callback URL; its path is handled by the auth gate and must match the WorkOS dashboard |
| `security.modules.<name>.authorization_endpoint`, `token_endpoint` | WorkOS OAuth2 endpoints; the defaults target `api.workos.com` |
| `security.modules.<name>.provider` | WorkOS connection selector; defaults to `authkit` |
| `security.modules.<name>.scopes` | OAuth scopes; defaults to `openid`, `profile`, `email` |
| `security.modules.<name>.http_timeout_ms` | Timeout for the server-side token exchange request |
| `virtual_hosts[].security.module` | Optional named security module required by this host; applies to static and controller hosts |
| `virtual_hosts[].host` | Exact host or wildcard, e.g. `*.example.com` |
| `virtual_hosts[].aliases` | Additional exact or wildcard host patterns |
| `virtual_hosts[].static.root` | Filesystem root for the static website |
| `virtual_hosts[].static.index` | Single filename served for `/` and directory-like paths |
| `virtual_hosts[].static.spa_fallback` | Serve the index page for unknown extension-less paths |
| `virtual_hosts[].controller` | Name of the in-process Rust controller route table |
| `controllers.<name>.routes[]` | Method + path pattern + registered Rust handler name |

Unknown YAML keys are rejected. A virtual host must configure exactly one of `static` or `controller`. Static path traversal attempts and encoded `..` segments are rejected. Keep served roots immutable to the server process; this project assumes trusted deployment content and does not claim a defense against a privileged local writer racing filesystem changes.

### Host authentication (WorkOS OAuth2)

A virtual host may add `security.module: "<name>"` to require authentication before either static or controller dispatch. The top-level `security` section defines the shared cookie policy and a registry of named modules; multiple module instances may be configured and referenced by different hosts. Only the `oauth2_workos` module type is implemented. A host that omits `security` remains public.

The WorkOS module implements the OAuth2 authorization-code flow with PKCE (`S256`):

1. An unauthenticated `GET` or `HEAD` request to a static host, or to any host when the client accepts `text/html`, receives a `302` to the WorkOS authorization endpoint. The redirect includes `state`, a PKCE challenge, the configured `redirect_uri`, provider, and scopes. A short-lived signed `HttpOnly` state cookie stores the state value, PKCE verifier, module name, expiry, and validated same-origin return path.
2. WorkOS redirects the browser to the callback path derived from `redirect_uri` (query strings in `redirect_uri` are rejected at startup). The auth gate handles this path before static/controller routing. It validates the signed state cookie and constant-time state match, then performs a server-to-server token exchange using the authorization code and PKCE verifier. The token endpoint's DNS is resolved during startup and refreshed on a helper thread if all cached addresses fail; connection attempts have individual deadlines within the overall exchange timeout. The exchange uses rustls over the Monoio io_uring runtime. The browser is sent directly to the authorization endpoint.
3. On success, the server sets a stateless HMAC-SHA256-signed, host-only session cookie containing the module name, WorkOS user ID, optional email/name, and expiry, then redirects with `303` to the original same-origin path. No access token or refresh token is stored in the browser. The cookie is `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` by default (`security.cookie_secure: false` is only for local plain-HTTP testing).
4. Authenticated requests continue to normal dispatch with `request.auth = Some(AuthIdentity)` populated for controller handlers. The bundled `whoami` handler exposes this identity as JSON. Each host-level check verifies that the session's module name matches the host's configured module.

Unauthenticated requests that are not `GET`/`HEAD`, or that do not prefer HTML on a controller host, receive `401` instead of a login redirect. This keeps API clients from receiving an HTML login page. Expired/tampered cookies are treated as unauthenticated, and callback errors return `400`, `401`, or `502` while clearing the state cookie. Responses handled by the auth gate or served on a protected host are marked `Cache-Control: private, no-store` with `Vary: Cookie`, so shared caches do not serve authenticated content or login states to other clients. Session lifetime is `security.session_ttl_seconds`; sessions are not centrally revocable before expiry. The module authenticates users only; application-level authorization, roles, and per-route policy remain the controller's responsibility.

`redirect_uri` must be registered exactly with WorkOS. Configuration loading requires its normalized hostname to match the protected virtual host or one of its aliases (including wildcard host patterns). For a login to complete, the callback must return to the same browser hostname that started the login, because both state and session cookies are host-only. A module sends one fixed `redirect_uri`; registering a wildcard redirect or using a shared canonical login host does not provide per-tenant callbacks or transfer state between hosts. Use separate concrete host/module configurations with a callback on each login host. Wildcard-host logins across tenants require per-host callback selection and state handoff, which this configuration does not support. The same restriction applies to logging in through an alias that differs from the callback hostname. `authorization_endpoint` and `token_endpoint` must use HTTPS unless they target a loopback host for local testing. `security.session_secret` is the HMAC key for both session and state cookies, must contain at least 32 bytes, and should be generated randomly and kept secret. Rotating it invalidates all existing sessions.

### Timeout, overload and metrics protection

The shared admission layer applies global, per-peer-IP, per-host, static-site, and controller in-flight limits. Per-IP token-bucket throttling returns `429`; the server-wide token bucket and capacity exhaustion return `503`. Request bodies and headers are byte-bounded, TCP and QUIC connections have global/per-IP caps, and per-IP tracking is bounded with inactive entries expired. Configure these thresholds for available memory and expected traffic before public deployment.

`timeouts` places explicit deadlines around TLS handshakes, HTTP/1.1 header/body reception, controller/static dispatch, response writes, and keep-alive waits. HTTP/3 has per-stream header/body/process/write handling; expired incomplete request-header streams are reset. The current `monoio-http` HTTP/2 adapter exposes completed requests rather than per-stream incomplete-header progress, so slow/incomplete HTTP/2 header parsing is bounded by its connection-level accept/idle timeout instead of a separate per-stream timer. An idle accept timeout will not close an HTTP/2 connection while already accepted request streams are still being processed. Timeout cancellation drops the request future; custom controller handlers must not detach unbounded background work and should cooperate with deadlines for CPU-heavy processing.

Expose `GET /metrics` on a controller host to inspect in-flight counts and cumulative rejections, rate limiting, timeouts, and client aborts. IP-based limits use the transport peer address, not untrusted forwarding headers. These application controls mitigate abusive request patterns but do not replace upstream DDoS filtering for volumetric network saturation.

## Built-in REST handlers

The example controller registry includes:

- `health`: JSON health response.
- `status`: build/runtime feature status.
- `metrics`: in-memory admission, timeout, rejection, and abort counters (configure `/metrics`).
- `echo`: JSON/text request echo with the configured request-body cap.
- `whoami`: returns the authenticated module, subject, email, and name when the host is protected; returns `401` when no identity is present.
- `items`: demonstration CRUD handler backed by an in-memory map (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`). This data is **not persistent** and is intended as a controller integration example, not a database replacement.

Controllers live in `src/controllers/`. The dispatcher receives a parsed HTTP/3, HTTP/2, or HTTP/1.1 request, matches method and route parameters, and invokes Rust functions as Monoio tasks. To add an application module, implement the handler, add its route name to the explicit registry and configuration validation, then declare routes under `controllers`.

## Docker and systemd

Docker image builds include a C toolchain for quiche and declare **UDP 8443, TCP 8443 (HTTP/2/HTTPS/1.1), and TCP 8080** (the latter when cleartext HTTP/1.1 and HTTP/2 prior-knowledge is enabled). Publish only the ports you intend to expose. Mount a certificate and key at `/run/secrets/tls_cert` and `/run/secrets/tls_key`, and make sure the container runtime's seccomp policy permits io_uring. Do not use `--privileged` as a workaround; use an explicit, reviewed seccomp profile.

The systemd unit runs as an unprivileged `htxpro` user. Install it and the binary under `/opt/htxpro`, edit `/opt/htxpro/config.yaml`, and ensure the service user can read the private key and static roots. The bundled config also listens for cleartext HTTP/1.1 and HTTP/2 prior-knowledge on TCP port 8080; firewall that port only if intended for public access.

## Security and production readiness

- Use valid TLS certificates and automate rotation; the server does not generate certificates. The configured certificate and private key are shared by QUIC and TCP TLS and must cover every configured hostname.
- Expose UDP for HTTP/3, TCP for secure HTTP when either `http1_secure_enabled` or `http2_secure_enabled` is true, and TCP on `plain_listen` when either `http1_plain_enabled` or `http2_plain_enabled` is true. Every listener uses the mandatory io_uring runtime. Plain HTTP is unencrypted; use it only when appropriate (for example, behind a trusted TLS-terminating proxy or for an intentional HTTP endpoint).
- Keep private keys readable only by the service account.
- Do not allow the serving account to modify website roots; avoid symlinks inside served roots.
- Configure edge rate limiting / DDoS protection and observe structured logs before exposing a public endpoint. Active connection migration is disabled in this version; connections are keyed by destination connection ID to allow multiple connections from one client UDP socket without conflation.
- Host authentication is opt-in per virtual host and only as strong as the WorkOS application and TLS configuration it references. Register the exact callback URI, protect `session_secret`, keep `cookie_secure: true` outside local testing, and do not expose plain HTTP to browsers that carry session cookies. The configuration file contains the WorkOS `client_secret` and session HMAC key; restrict its read permissions. Authenticated identity is not authorization: routes and controller handlers must still enforce roles or resource ownership.
- Audit controller handlers before enabling mutating API routes. The sample item store is in-memory and has no per-user authorization built in, even when a host requires authentication.
- Set resource limits, benchmark under representative traffic, and test overload behavior before production deployment.

## Validation status

The current source tree passes `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets` (30 unit tests) on Linux. It has not been load-tested, exercised against a live WorkOS tenant, or interoperability-tested with separate HTTP/3, HTTP/2, and HTTP/1.1 clients in this environment. The CI workflow repeats formatting, compilation, tests, and Clippy; passing those checks plus protocol interoperability and an end-to-end OAuth2 login test remains a release gate.
