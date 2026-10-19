//! HTTP/3 over QUIC on a Monoio runtime pinned to its io_uring driver.
//! No Tokio executor, epoll driver, or non-io_uring transport is linked by this crate.

use std::{
    cell::Cell,
    cell::RefCell,
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use futures::{
    channel::mpsc,
    future::{select, Either},
    SinkExt, StreamExt,
};
use monoio::net::udp::UdpSocket;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    controllers::ControllerRuntime,
    http_types::{HttpRequest, HttpResponse},
    static_site,
};

const UDP_READ_BUFFER: usize = 65_535;
const QUIC_PACKET_BUFFER: usize = 1350;
const TIMER_TICK: Duration = Duration::from_millis(5);
const RESPONSE_CHUNK: usize = 16 * 1024;

#[derive(Clone)]
pub(crate) struct AppRuntime {
    config: Rc<Config>,
    controllers: ControllerRuntime,
    protection: Rc<RefCell<ProtectionState>>,
}

pub(crate) struct RequestGuard {
    protection: Rc<RefCell<ProtectionState>>,
    client_ip: IpAddr,
    host_key: String,
    workload: WorkloadClass,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let mut state = self.protection.borrow_mut();
        state.active_requests = state.active_requests.saturating_sub(1);
        if let Some(client) = state.clients.get_mut(&self.client_ip) {
            client.in_flight = client.in_flight.saturating_sub(1);
            client.last_seen = Instant::now();
        }
        let remove_host_counter = if let Some(count) = state.hosts_in_flight.get_mut(&self.host_key)
        {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove_host_counter {
            state.hosts_in_flight.remove(&self.host_key);
        }
        match self.workload {
            WorkloadClass::Static => {
                state.active_static_requests = state.active_static_requests.saturating_sub(1)
            }
            WorkloadClass::Controller => {
                state.active_controller_requests =
                    state.active_controller_requests.saturating_sub(1)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AdmissionError {
    GlobalCapacity,
    PerIpCapacity,
    PerHostCapacity,
    WorkloadCapacity,
    RateLimited,
    GlobalRateLimited,
    ClientTableFull,
}

impl AdmissionError {
    pub(crate) fn response(self) -> HttpResponse {
        match self {
            Self::RateLimited => HttpResponse::error(429, "per-client request rate limit exceeded"),
            Self::GlobalRateLimited => {
                HttpResponse::error(503, "server request rate limit exceeded")
            }
            Self::GlobalCapacity
            | Self::PerIpCapacity
            | Self::PerHostCapacity
            | Self::WorkloadCapacity
            | Self::ClientTableFull => HttpResponse::error(503, "server request capacity reached"),
        }
    }
}

struct ClientBudget {
    in_flight: usize,
    tcp_connections: usize,
    quic_connections: usize,
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

fn take_rate_limit_token(
    tokens: &mut f64,
    last_refill: &mut Instant,
    now: Instant,
    requests_per_second: u32,
    burst: u32,
) -> bool {
    let elapsed = now.duration_since(*last_refill).as_secs_f64();
    *tokens = (*tokens + elapsed * f64::from(requests_per_second)).min(f64::from(burst));
    *last_refill = now;
    if *tokens < 1.0 {
        false
    } else {
        *tokens -= 1.0;
        true
    }
}

#[derive(Default)]
struct ProtectionCounters {
    rejected_global: u64,
    rejected_per_ip: u64,
    rejected_per_host: u64,
    rejected_workload: u64,
    rejected_client_table: u64,
    rate_limited: u64,
    global_rate_limited: u64,
    tls_handshake_timeouts: u64,
    request_header_timeouts: u64,
    request_body_timeouts: u64,
    request_process_timeouts: u64,
    response_write_timeouts: u64,
    keep_alive_timeouts: u64,
    client_aborts: u64,
    rejected_tcp_connections: u64,
    rejected_quic_connections: u64,
    http2_handshake_timeouts: u64,
}

struct ProtectionState {
    active_requests: usize,
    active_static_requests: usize,
    active_controller_requests: usize,
    active_tcp_connections: usize,
    active_quic_connections: usize,
    clients: HashMap<IpAddr, ClientBudget>,
    hosts_in_flight: HashMap<String, usize>,
    global_tokens: f64,
    global_last_refill: Instant,
    counters: ProtectionCounters,
}

impl ProtectionState {
    fn new(rate_limit: &crate::config::RateLimitConfig) -> Self {
        Self {
            active_requests: 0,
            active_static_requests: 0,
            active_controller_requests: 0,
            active_tcp_connections: 0,
            active_quic_connections: 0,
            clients: HashMap::new(),
            hosts_in_flight: HashMap::new(),
            global_tokens: rate_limit.global_burst as f64,
            global_last_refill: Instant::now(),
            counters: ProtectionCounters::default(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum WorkloadClass {
    Static,
    Controller,
}

pub(crate) struct TcpConnectionGuard {
    protection: Rc<RefCell<ProtectionState>>,
    client_ip: IpAddr,
}

impl Drop for TcpConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.protection.borrow_mut();
        state.active_tcp_connections = state.active_tcp_connections.saturating_sub(1);
        if let Some(client) = state.clients.get_mut(&self.client_ip) {
            client.tcp_connections = client.tcp_connections.saturating_sub(1);
            client.last_seen = Instant::now();
        }
    }
}

pub(crate) struct QuicConnectionGuard {
    protection: Rc<RefCell<ProtectionState>>,
    client_ip: IpAddr,
}

impl Drop for QuicConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.protection.borrow_mut();
        state.active_quic_connections = state.active_quic_connections.saturating_sub(1);
        if let Some(client) = state.clients.get_mut(&self.client_ip) {
            client.quic_connections = client.quic_connections.saturating_sub(1);
            client.last_seen = Instant::now();
        }
    }
}

impl AppRuntime {
    pub(crate) fn acquire_request(
        &self,
        client_ip: IpAddr,
        authority: &str,
    ) -> Result<RequestGuard, AdmissionError> {
        let (host_key, workload) = self
            .config
            .resolve_host(authority)
            .map(|vhost| {
                (
                    vhost.host.clone(),
                    if vhost.static_site.is_some() {
                        WorkloadClass::Static
                    } else {
                        WorkloadClass::Controller
                    },
                )
            })
            .unwrap_or_else(|| ("<unmatched-host>".to_owned(), WorkloadClass::Controller));
        let now = Instant::now();
        let mut state = self.protection.borrow_mut();

        if state.active_requests >= self.config.limits.max_inflight_requests {
            state.counters.rejected_global = state.counters.rejected_global.saturating_add(1);
            return Err(AdmissionError::GlobalCapacity);
        }

        if self.config.rate_limit.enabled {
            // Borrow the two token-bucket fields as disjoint fields of the state.
            // This keeps the refill timestamp updated even when a request is denied.
            let global_rate_allowed = {
                let ProtectionState {
                    global_tokens,
                    global_last_refill,
                    ..
                } = &mut *state;
                take_rate_limit_token(
                    global_tokens,
                    global_last_refill,
                    now,
                    self.config.rate_limit.global_requests_per_second,
                    self.config.rate_limit.global_burst,
                )
            };
            if !global_rate_allowed {
                state.counters.global_rate_limited =
                    state.counters.global_rate_limited.saturating_add(1);
                return Err(AdmissionError::GlobalRateLimited);
            }
        }

        // Expire inactive rate-limit entries before admitting a new source. The
        // table is bounded even when an attacker sprays random source addresses.
        state.clients.retain(|_, budget| {
            budget.in_flight > 0
                || budget.tcp_connections > 0
                || budget.quic_connections > 0
                || now.duration_since(budget.last_seen) < Duration::from_secs(60)
        });
        if !state.clients.contains_key(&client_ip)
            && state.clients.len() >= self.config.limits.max_tracked_client_ips
        {
            let oldest_inactive = state
                .clients
                .iter()
                .filter(|(_, budget)| {
                    budget.in_flight == 0
                        && budget.tcp_connections == 0
                        && budget.quic_connections == 0
                })
                .min_by_key(|(_, budget)| budget.last_seen)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest_inactive {
                state.clients.remove(&ip);
            } else {
                state.counters.rejected_client_table =
                    state.counters.rejected_client_table.saturating_add(1);
                return Err(AdmissionError::ClientTableFull);
            }
        }

        let (rate_limited, per_ip_full) = {
            let client = state
                .clients
                .entry(client_ip)
                .or_insert_with(|| ClientBudget {
                    in_flight: 0,
                    tcp_connections: 0,
                    quic_connections: 0,
                    tokens: self.config.rate_limit.burst_per_ip as f64,
                    last_refill: now,
                    last_seen: now,
                });
            client.last_seen = now;
            let rate_limited = self.config.rate_limit.enabled
                && !take_rate_limit_token(
                    &mut client.tokens,
                    &mut client.last_refill,
                    now,
                    self.config.rate_limit.requests_per_second_per_ip,
                    self.config.rate_limit.burst_per_ip,
                );
            let full = client.in_flight >= self.config.limits.max_inflight_requests_per_ip;
            (rate_limited, full)
        };
        if rate_limited {
            state.counters.rate_limited = state.counters.rate_limited.saturating_add(1);
            return Err(AdmissionError::RateLimited);
        }
        if per_ip_full {
            state.counters.rejected_per_ip = state.counters.rejected_per_ip.saturating_add(1);
            return Err(AdmissionError::PerIpCapacity);
        }
        if state.hosts_in_flight.get(&host_key).copied().unwrap_or(0)
            >= self.config.limits.max_inflight_requests_per_host
        {
            state.counters.rejected_per_host = state.counters.rejected_per_host.saturating_add(1);
            return Err(AdmissionError::PerHostCapacity);
        }
        let workload_full = match workload {
            WorkloadClass::Static => {
                state.active_static_requests >= self.config.limits.max_inflight_static_requests
            }
            WorkloadClass::Controller => {
                state.active_controller_requests
                    >= self.config.limits.max_inflight_controller_requests
            }
        };
        if workload_full {
            state.counters.rejected_workload = state.counters.rejected_workload.saturating_add(1);
            return Err(AdmissionError::WorkloadCapacity);
        }
        if let Some(client) = state.clients.get_mut(&client_ip) {
            client.in_flight += 1;
        }
        *state.hosts_in_flight.entry(host_key.clone()).or_insert(0) += 1;
        state.active_requests += 1;
        match workload {
            WorkloadClass::Static => state.active_static_requests += 1,
            WorkloadClass::Controller => state.active_controller_requests += 1,
        }
        Ok(RequestGuard {
            protection: self.protection.clone(),
            client_ip,
            host_key,
            workload,
        })
    }

    pub(crate) async fn dispatch(&self, request: HttpRequest) -> HttpResponse {
        if request.body_too_large || request.body.len() > self.config.max_request_body_bytes {
            return HttpResponse::error(413, "request body exceeds configured limit");
        }
        match monoio::time::timeout(
            Duration::from_millis(self.config.timeouts.request_process_ms),
            self.dispatch_inner(request),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                self.record_timeout("request_process");
                warn!(
                    phase = "request_process",
                    "request processing deadline exceeded; request future cancelled"
                );
                HttpResponse::error(504, "request processing deadline exceeded")
            }
        }
    }

    async fn dispatch_inner(&self, request: HttpRequest) -> HttpResponse {
        let Some(vhost) = self.config.resolve_host(&request.authority) else {
            return HttpResponse::error(421, "no virtual host is configured for this authority");
        };

        match (&vhost.static_site, &vhost.controller) {
            (Some(site), None) => {
                static_site::serve(site, &request, self.config.max_static_file_bytes).await
            }
            (None, Some(controller)) => {
                self.controllers
                    .dispatch(controller, request, self.metrics_snapshot())
                    .await
            }
            _ => HttpResponse::error(500, "invalid virtual-host configuration"),
        }
    }

    pub(crate) fn max_request_body_bytes(&self) -> usize {
        self.config.max_request_body_bytes
    }

    pub(crate) fn record_timeout(&self, phase: &'static str) {
        let mut state = self.protection.borrow_mut();
        let counter = match phase {
            "tls_handshake" => &mut state.counters.tls_handshake_timeouts,
            "http2_handshake" => &mut state.counters.http2_handshake_timeouts,
            "request_headers" => &mut state.counters.request_header_timeouts,
            "request_body" => &mut state.counters.request_body_timeouts,
            "request_process" => &mut state.counters.request_process_timeouts,
            "response_write" => &mut state.counters.response_write_timeouts,
            _ => &mut state.counters.keep_alive_timeouts,
        };
        *counter = counter.saturating_add(1);
    }

    pub(crate) fn record_client_abort(&self) {
        let mut state = self.protection.borrow_mut();
        state.counters.client_aborts = state.counters.client_aborts.saturating_add(1);
    }

    pub(crate) fn metrics_snapshot(&self) -> serde_json::Value {
        let state = self.protection.borrow();
        serde_json::json!({
            "requests_in_flight": state.active_requests,
            "static_requests_in_flight": state.active_static_requests,
            "controller_requests_in_flight": state.active_controller_requests,
            "tcp_connections_in_flight": state.active_tcp_connections,
            "quic_connections_in_flight": state.active_quic_connections,
            "tracked_client_ips": state.clients.len(),
            "requests_rejected_global_capacity_total": state.counters.rejected_global,
            "requests_rejected_per_ip_capacity_total": state.counters.rejected_per_ip,
            "requests_rejected_per_host_capacity_total": state.counters.rejected_per_host,
            "requests_rejected_workload_capacity_total": state.counters.rejected_workload,
            "requests_rejected_client_table_full_total": state.counters.rejected_client_table,
            "requests_rate_limited_total": state.counters.rate_limited,
            "requests_global_rate_limited_total": state.counters.global_rate_limited,
            "tls_handshake_timeouts_total": state.counters.tls_handshake_timeouts,
            "request_header_timeouts_total": state.counters.request_header_timeouts,
            "request_body_timeouts_total": state.counters.request_body_timeouts,
            "request_process_timeouts_total": state.counters.request_process_timeouts,
            "response_write_timeouts_total": state.counters.response_write_timeouts,
            "keep_alive_timeouts_total": state.counters.keep_alive_timeouts,
            "client_aborts_total": state.counters.client_aborts,
            "tcp_connections_rejected_total": state.counters.rejected_tcp_connections,
            "quic_connections_rejected_total": state.counters.rejected_quic_connections,
            "http2_handshake_timeouts_total": state.counters.http2_handshake_timeouts,
        })
    }

    pub(crate) fn timeout_ms(&self, phase: &'static str) -> u64 {
        match phase {
            "tls_handshake" => self.config.timeouts.tls_handshake_ms,
            "http2_handshake" => self.config.timeouts.request_headers_ms,
            "request_headers" => self.config.timeouts.request_headers_ms,
            "request_body" => self.config.timeouts.request_body_ms,
            "request_process" => self.config.timeouts.request_process_ms,
            "response_write" => self.config.timeouts.response_write_ms,
            _ => self.config.timeouts.keep_alive_idle_ms,
        }
    }

    pub(crate) fn max_header_bytes(&self) -> usize {
        self.config.limits.max_header_bytes
    }
    pub(crate) fn max_concurrent_streams_per_connection(&self) -> u32 {
        self.config.limits.max_concurrent_streams_per_connection
    }

    pub(crate) fn acquire_tcp_connection(&self, client_ip: IpAddr) -> Option<TcpConnectionGuard> {
        let now = Instant::now();
        let mut state = self.protection.borrow_mut();
        if state.active_tcp_connections >= self.config.limits.max_tcp_connections {
            state.counters.rejected_tcp_connections =
                state.counters.rejected_tcp_connections.saturating_add(1);
            return None;
        }
        state.clients.retain(|_, budget| {
            budget.in_flight > 0
                || budget.tcp_connections > 0
                || budget.quic_connections > 0
                || now.duration_since(budget.last_seen) < Duration::from_secs(60)
        });
        if !state.clients.contains_key(&client_ip)
            && state.clients.len() >= self.config.limits.max_tracked_client_ips
        {
            let oldest_inactive = state
                .clients
                .iter()
                .filter(|(_, budget)| {
                    budget.in_flight == 0
                        && budget.tcp_connections == 0
                        && budget.quic_connections == 0
                })
                .min_by_key(|(_, budget)| budget.last_seen)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest_inactive {
                state.clients.remove(&ip);
            } else {
                state.counters.rejected_tcp_connections =
                    state.counters.rejected_tcp_connections.saturating_add(1);
                return None;
            }
        }
        let client = state
            .clients
            .entry(client_ip)
            .or_insert_with(|| ClientBudget {
                in_flight: 0,
                tcp_connections: 0,
                quic_connections: 0,
                tokens: self.config.rate_limit.burst_per_ip as f64,
                last_refill: now,
                last_seen: now,
            });
        if client.tcp_connections >= self.config.limits.max_tcp_connections_per_ip {
            state.counters.rejected_tcp_connections =
                state.counters.rejected_tcp_connections.saturating_add(1);
            return None;
        }
        client.tcp_connections += 1;
        client.last_seen = now;
        state.active_tcp_connections += 1;
        Some(TcpConnectionGuard {
            protection: self.protection.clone(),
            client_ip,
        })
    }

    pub(crate) fn acquire_quic_connection(&self, client_ip: IpAddr) -> Option<QuicConnectionGuard> {
        let now = Instant::now();
        let mut state = self.protection.borrow_mut();
        if state.active_quic_connections >= self.config.limits.max_quic_connections {
            state.counters.rejected_quic_connections =
                state.counters.rejected_quic_connections.saturating_add(1);
            return None;
        }
        state.clients.retain(|_, budget| {
            budget.in_flight > 0
                || budget.tcp_connections > 0
                || budget.quic_connections > 0
                || now.duration_since(budget.last_seen) < Duration::from_secs(60)
        });
        if !state.clients.contains_key(&client_ip)
            && state.clients.len() >= self.config.limits.max_tracked_client_ips
        {
            let oldest_inactive = state
                .clients
                .iter()
                .filter(|(_, budget)| {
                    budget.in_flight == 0
                        && budget.tcp_connections == 0
                        && budget.quic_connections == 0
                })
                .min_by_key(|(_, budget)| budget.last_seen)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest_inactive {
                state.clients.remove(&ip);
            } else {
                state.counters.rejected_quic_connections =
                    state.counters.rejected_quic_connections.saturating_add(1);
                return None;
            }
        }
        let client = state
            .clients
            .entry(client_ip)
            .or_insert_with(|| ClientBudget {
                in_flight: 0,
                tcp_connections: 0,
                quic_connections: 0,
                tokens: self.config.rate_limit.burst_per_ip as f64,
                last_refill: now,
                last_seen: now,
            });
        if client.quic_connections >= self.config.limits.max_quic_connections_per_ip {
            state.counters.rejected_quic_connections =
                state.counters.rejected_quic_connections.saturating_add(1);
            return None;
        }
        client.quic_connections += 1;
        client.last_seen = now;
        state.active_quic_connections += 1;
        Some(QuicConnectionGuard {
            protection: self.protection.clone(),
            client_ip,
        })
    }
}

struct PendingRequest {
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    body_too_large: bool,
    body_deadline: Instant,
    cancel_token: Rc<Cell<bool>>,
    guard: RequestGuard,
}

impl PendingRequest {
    fn into_parts(self) -> (HttpRequest, RequestGuard, Rc<Cell<bool>>) {
        let request = HttpRequest {
            method: self.method,
            authority: self.authority,
            path: self.path,
            query: self.query,
            headers: self.headers,
            body: self.body,
            body_too_large: self.body_too_large,
        };
        (request, self.guard, self.cancel_token)
    }
}

struct OutgoingResponse {
    stream_id: u64,
    status: u16,
    content_type: String,
    cache_control: Option<String>,
    body: Vec<u8>,
    offset: usize,
    head_only: bool,
    headers_sent: bool,
    deadline: Instant,
    _guard: Option<RequestGuard>,
}

struct Session {
    conn: quiche::Connection,
    peer: SocketAddr,
    _connection_guard: QuicConnectionGuard,
    h3: Option<quiche::h3::Connection>,
    header_deadlines: HashMap<u64, Instant>,
    header_aborted_streams: std::collections::HashSet<u64>,
    pending_requests: HashMap<u64, PendingRequest>,
    active_cancellations: HashMap<u64, Rc<Cell<bool>>>,
    outgoing: VecDeque<OutgoingResponse>,
}

impl Session {
    fn new(
        conn: quiche::Connection,
        peer: SocketAddr,
        connection_guard: QuicConnectionGuard,
    ) -> Self {
        Self {
            conn,
            peer,
            _connection_guard: connection_guard,
            h3: None,
            header_deadlines: HashMap::new(),
            header_aborted_streams: std::collections::HashSet::new(),
            pending_requests: HashMap::new(),
            active_cancellations: HashMap::new(),
            outgoing: VecDeque::new(),
        }
    }
}

struct CompletedRequest {
    stream_id: u64,
    request: HttpRequest,
    guard: RequestGuard,
    cancel_token: Rc<Cell<bool>>,
}

enum ServerEvent {
    Datagram {
        bytes: Vec<u8>,
        peer: SocketAddr,
    },
    Response {
        connection_id: Vec<u8>,
        stream_id: u64,
        response: HttpResponse,
        guard: Option<RequestGuard>,
    },
    Tick,
    Shutdown,
}

pub fn make_quic_config(config: &Config) -> Result<quiche::Config> {
    let mut quic = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .context("could not create QUIC configuration")?;
    quic.set_application_protos(&[b"h3"])
        .context("could not configure HTTP/3 ALPN")?;
    let cert_path = config
        .cert_path
        .to_str()
        .context("tls_cert path is not valid UTF-8")?;
    let key_path = config
        .key_path
        .to_str()
        .context("tls_key path is not valid UTF-8")?;
    quic.load_cert_chain_from_pem_file(cert_path)
        .with_context(|| {
            format!(
                "could not load certificate chain {}",
                config.cert_path.display()
            )
        })?;
    quic.load_priv_key_from_pem_file(key_path)
        .with_context(|| format!("could not load private key {}", config.key_path.display()))?;
    quic.set_max_idle_timeout(config.timeouts.keep_alive_idle_ms);
    quic.set_max_recv_udp_payload_size(QUIC_PACKET_BUFFER);
    quic.set_max_send_udp_payload_size(QUIC_PACKET_BUFFER);
    quic.set_initial_max_data(4 * 1024 * 1024);
    quic.set_initial_max_stream_data_bidi_local(1024 * 1024);
    quic.set_initial_max_stream_data_bidi_remote(1024 * 1024);
    quic.set_initial_max_stream_data_uni(1024 * 1024);
    quic.set_initial_max_streams_bidi(u64::from(
        config.limits.max_concurrent_streams_per_connection,
    ));
    quic.set_initial_max_streams_uni(16);
    quic.set_disable_active_migration(true);
    Ok(quic)
}

pub async fn serve(
    config: Config,
    mut quic_config: quiche::Config,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let socket =
        Rc::new(UdpSocket::bind(config.listen).with_context(|| {
            format!("could not bind io_uring UDP listener at {}", config.listen)
        })?);
    let local_addr = socket
        .local_addr()
        .context("could not inspect QUIC socket address")?;
    let mut h3_config =
        quiche::h3::Config::new().context("could not create HTTP/3 configuration")?;
    h3_config.set_max_field_section_size(
        u64::try_from(config.limits.max_header_bytes).unwrap_or(u64::MAX),
    );
    let controllers = ControllerRuntime::new(&config.controllers, config.max_request_body_bytes)?;
    let http1_secure_enabled = config.http1_secure_enabled;
    let http1_plain_enabled = config.http1_plain_enabled;
    let http2_secure_enabled = config.http2_secure_enabled;
    let http2_plain_enabled = config.http2_plain_enabled;
    let secure_http_enabled = http1_secure_enabled || http2_secure_enabled;
    let plain_http_enabled = http1_plain_enabled || http2_plain_enabled;
    let secure_listen = config.listen;
    let plain_listen = config.plain_listen;
    let protection = Rc::new(RefCell::new(ProtectionState::new(&config.rate_limit)));
    let app = AppRuntime {
        config: Rc::new(config),
        controllers,
        protection,
    };

    if secure_http_enabled {
        let tls_config = crate::http1_server::make_tls_config(
            &app.config.cert_path,
            &app.config.key_path,
            http1_secure_enabled,
            http2_secure_enabled,
        )?;
        let listener = monoio::net::TcpListener::bind(secure_listen).with_context(|| {
            format!("could not bind io_uring secure HTTP TCP listener at {secure_listen}")
        })?;
        info!(
            listen = %secure_listen,
            http1_secure_enabled,
            http2_secure_enabled,
            "secure HTTP listener started on Monoio io_uring with TLS ALPN"
        );
        monoio::spawn(crate::http1_server::serve(
            listener,
            tls_config,
            app.clone(),
            secure_listen.port(),
            http1_secure_enabled,
        ));
    }

    if plain_http_enabled {
        let listener = monoio::net::TcpListener::bind(plain_listen).with_context(|| {
            format!("could not bind io_uring plain HTTP TCP listener at {plain_listen}")
        })?;
        info!(
            listen = %plain_listen,
            http1_plain_enabled,
            http2_plain_enabled,
            "plain HTTP listener started on Monoio io_uring"
        );
        monoio::spawn(crate::http1_server::serve_plain(
            listener,
            app.clone(),
            secure_listen.port(),
            http1_plain_enabled,
            http2_plain_enabled,
        ));
    }

    // A bounded channel provides backpressure between the io_uring receive loop,
    // the QUIC/HTTP3 state machine, and independently scheduled Rust request handlers.
    let (event_tx, mut event_rx) = mpsc::channel::<ServerEvent>(1024);
    let request_event_tx = event_tx.clone();

    let recv_socket = socket.clone();
    let mut recv_tx = event_tx.clone();
    monoio::spawn(async move {
        let mut buffer = vec![0u8; UDP_READ_BUFFER];
        loop {
            let (result, returned) = recv_socket.recv_from(buffer).await;
            buffer = returned;
            match result {
                Ok((read, peer)) => {
                    let event = ServerEvent::Datagram {
                        bytes: buffer[..read].to_vec(),
                        peer,
                    };
                    if recv_tx.send(event).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    warn!(%error, "io_uring UDP receive failed");
                    monoio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        }
    });

    let mut timer_tx = event_tx.clone();
    let timer_shutdown = shutdown.clone();
    monoio::spawn(async move {
        loop {
            monoio::time::sleep(TIMER_TICK).await;
            if timer_shutdown.load(Ordering::Relaxed) {
                let _ = timer_tx.send(ServerEvent::Shutdown).await;
                break;
            }
            if timer_tx.send(ServerEvent::Tick).await.is_err() {
                break;
            }
        }
    });
    drop(event_tx);

    let mut sessions: HashMap<Vec<u8>, Session> = HashMap::new();
    // Initial packets use a client-chosen original destination CID until the server's
    // source CID is observed. Keep that original CID as an alias for Initial retries.
    let mut cid_aliases: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    info!(
        listen = %local_addr,
        runtime = "monoio/IoUringDriver",
        protocol = "HTTP/3",
        http1_secure_enabled,
        http1_plain_enabled,
        http2_secure_enabled,
        http2_plain_enabled,
        secure_listen = %secure_listen,
        plain_listen = %plain_listen,
        "websrv started"
    );

    while let Some(event) = event_rx.next().await {
        match event {
            ServerEvent::Datagram { bytes, peer } => {
                handle_datagram(
                    bytes,
                    peer,
                    local_addr,
                    &mut quic_config,
                    &h3_config,
                    &mut sessions,
                    &mut cid_aliases,
                    &app,
                    request_event_tx.clone(),
                );
                pump_all(&socket, &mut sessions).await;
            }
            ServerEvent::Response {
                connection_id,
                stream_id,
                response,
                guard,
            } => {
                if let Some(session) = sessions.get_mut(&connection_id) {
                    session.active_cancellations.remove(&stream_id);
                    queue_response(
                        session,
                        stream_id,
                        response,
                        guard,
                        Duration::from_millis(app.timeout_ms("response_write")),
                    );
                    pump_outgoing(session);
                }
                // If the connection closed while the Rust handler was running, its guard is
                // dropped here and the response is discarded without touching another client.
                pump_all(&socket, &mut sessions).await;
            }
            ServerEvent::Tick => {
                tick_sessions(&mut sessions, &h3_config, &app);
                pump_all(&socket, &mut sessions).await;
                sessions.retain(|_, session| {
                    if session.conn.is_closed() {
                        for token in session.active_cancellations.values() {
                            token.set(true);
                        }
                        false
                    } else {
                        true
                    }
                });
                cid_aliases.retain(|_, session_id| sessions.contains_key(session_id));
            }
            ServerEvent::Shutdown => {
                info!(
                    connections = sessions.len(),
                    "shutdown requested; closing QUIC connections"
                );
                for session in sessions.values_mut() {
                    for token in session.active_cancellations.values() {
                        token.set(true);
                    }
                    session.conn.close(true, 0x100, b"server shutdown").ok();
                }
                pump_all(&socket, &mut sessions).await;
                break;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)] // This is the single-threaded QUIC state-machine boundary.
fn handle_datagram(
    mut bytes: Vec<u8>,
    peer: SocketAddr,
    local_addr: SocketAddr,
    quic_config: &mut quiche::Config,
    h3_config: &quiche::h3::Config,
    sessions: &mut HashMap<Vec<u8>, Session>,
    cid_aliases: &mut HashMap<Vec<u8>, Vec<u8>>,
    app: &AppRuntime,
    event_tx: mpsc::Sender<ServerEvent>,
) {
    // QUIC routing is by destination connection ID, not just the UDP peer tuple: a
    // browser can multiplex several QUIC connections through one UDP socket. This build
    // explicitly disables active migration, but CID routing avoids conflating connections.
    let (packet_type, packet_dcid) =
        match quiche::Header::from_slice(&mut bytes, quiche::MAX_CONN_ID_LEN) {
            Ok(header) => (header.ty, header.dcid.as_ref().to_vec()),
            Err(_) => return,
        };

    let connection_id = if let Some((key, _)) = sessions.get_key_value(&packet_dcid) {
        key.clone()
    } else if let Some(key) = cid_aliases.get(&packet_dcid) {
        key.clone()
    } else {
        if packet_type != quiche::Type::Initial {
            return;
        }
        let Some(connection_guard) = app.acquire_quic_connection(peer.ip()) else {
            debug!(%peer, "QUIC connection or client tracking limit reached; ignoring new peer");
            return;
        };
        let mut server_cid = [0u8; quiche::MAX_CONN_ID_LEN];
        if ring::rand::SystemRandom::new()
            .fill(&mut server_cid)
            .is_err()
        {
            error!(%peer, "secure random generation failed while creating QUIC connection id");
            return;
        }
        let scid = quiche::ConnectionId::from_ref(&server_cid);
        let key = server_cid.to_vec();
        match quiche::accept(&scid, None, local_addr, peer, quic_config) {
            Ok(conn) => {
                sessions.insert(key.clone(), Session::new(conn, peer, connection_guard));
                if !packet_dcid.is_empty() {
                    cid_aliases.insert(packet_dcid, key.clone());
                }
                key
            }
            Err(error) => {
                debug!(%peer, %error, "rejected QUIC Initial packet");
                return;
            }
        }
    };

    let Some(session) = sessions.get_mut(&connection_id) else {
        return;
    };
    let recv_info = quiche::RecvInfo {
        from: peer,
        to: local_addr,
    };
    if let Err(error) = session.conn.recv(&mut bytes, recv_info) {
        debug!(%peer, %error, "discarding invalid QUIC datagram");
        return;
    }
    // Start a header deadline when a client-initiated bidirectional stream first
    // becomes readable. Remove it once quiche has decoded the HEADERS event.
    for stream_id in session.conn.readable().collect::<Vec<_>>() {
        if stream_id % 4 == 0
            && !session.header_aborted_streams.contains(&stream_id)
            && !session.pending_requests.contains_key(&stream_id)
            && !session.active_cancellations.contains_key(&stream_id)
        {
            session
                .header_deadlines
                .entry(stream_id)
                .or_insert_with(Instant::now);
        }
    }
    if session.h3.is_none() && session.conn.is_established() {
        match quiche::h3::Connection::with_transport(&mut session.conn, h3_config) {
            Ok(h3) => {
                session.h3 = Some(h3);
                info!(%peer, "HTTP/3 connection established");
            }
            Err(error) => {
                warn!(%peer, %error, "could not initialize HTTP/3 on established QUIC connection");
                session
                    .conn
                    .close(true, 0x102, b"HTTP/3 initialization failed")
                    .ok();
                return;
            }
        }
    }

    let completed = drain_h3_events(session, app);
    for completed in completed {
        let CompletedRequest {
            stream_id,
            request,
            guard,
            cancel_token,
        } = completed;
        let mut tx = event_tx.clone();
        let app = app.clone();
        let connection_id = connection_id.clone();
        monoio::spawn(async move {
            let response_work = Box::pin(app.dispatch(request));
            let cancellation = Box::pin(wait_for_cancel(cancel_token.clone()));
            match select(response_work, cancellation).await {
                Either::Left((response, _cancellation)) => {
                    if cancel_token.get() {
                        app.record_client_abort();
                        return;
                    }
                    if tx
                        .send(ServerEvent::Response {
                            connection_id,
                            stream_id,
                            response,
                            guard: Some(guard),
                        })
                        .await
                        .is_err()
                    {
                        debug!(%peer, stream_id, "response discarded because QUIC event loop stopped");
                    }
                }
                Either::Right(((), _response_work)) => {
                    app.record_client_abort();
                    drop(guard);
                }
            }
        });
    }
    pump_outgoing(session);
}

fn drain_h3_events(session: &mut Session, app: &AppRuntime) -> Vec<CompletedRequest> {
    let mut completed = Vec::new();

    loop {
        let polled = match session.h3.as_mut() {
            Some(h3) => h3.poll(&mut session.conn),
            None => break,
        };
        let (stream_id, event) = match polled {
            Ok(value) => value,
            Err(quiche::h3::Error::Done) => break,
            Err(error) => {
                debug!(%error, "HTTP/3 event polling failed");
                break;
            }
        };
        match event {
            quiche::h3::Event::Headers { list, .. } => {
                session.header_deadlines.remove(&stream_id);
                // A later HEADERS event on the same stream is a trailer block; do not
                // replace the original request or double-count its request guard.
                if session.pending_requests.contains_key(&stream_id) {
                    continue;
                }

                let mut method = String::new();
                let mut authority = String::new();
                let mut path = "/".to_owned();
                let mut query = None;
                let mut headers = HashMap::new();
                for header in list {
                    let name = String::from_utf8_lossy(header.name()).to_ascii_lowercase();
                    let value = String::from_utf8_lossy(header.value()).into_owned();
                    match name.as_str() {
                        ":method" => method = value,
                        ":authority" => authority = value,
                        ":path" => {
                            let (request_path, request_query) = value
                                .split_once('?')
                                .map(|(path, query)| (path, Some(query.to_owned())))
                                .unwrap_or((value.as_str(), None));
                            path = request_path.to_owned();
                            query = request_query;
                        }
                        name if !name.starts_with(':') => {
                            headers.insert(name.to_owned(), value);
                        }
                        _ => {}
                    }
                }
                if authority.is_empty() {
                    authority = headers.get("host").cloned().unwrap_or_default();
                }
                let guard = match app.acquire_request(session.peer.ip(), &authority) {
                    Ok(guard) => guard,
                    Err(rejection) => {
                        session
                            .conn
                            .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x10)
                            .ok();
                        queue_response(
                            session,
                            stream_id,
                            rejection.response(),
                            None,
                            Duration::from_millis(app.timeout_ms("response_write")),
                        );
                        continue;
                    }
                };
                let cancel_token = Rc::new(Cell::new(false));
                session
                    .active_cancellations
                    .insert(stream_id, cancel_token.clone());
                let mut request = PendingRequest {
                    method,
                    authority,
                    path,
                    query,
                    headers,
                    body: Vec::new(),
                    body_too_large: false,
                    body_deadline: Instant::now()
                        + Duration::from_millis(app.timeout_ms("request_body")),
                    cancel_token,
                    guard,
                };
                if let Some(content_length) = request
                    .headers
                    .get("content-length")
                    .and_then(|v| v.parse::<usize>().ok())
                {
                    if content_length > app.config.max_request_body_bytes {
                        request.body_too_large = true;
                    }
                }
                session.pending_requests.insert(stream_id, request);
                if session
                    .pending_requests
                    .get(&stream_id)
                    .is_some_and(|request| request.body_too_large)
                {
                    if let Some(request) = session.pending_requests.remove(&stream_id) {
                        request.cancel_token.set(true);
                        session.active_cancellations.remove(&stream_id);
                        session
                            .conn
                            .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x10)
                            .ok();
                        queue_response(
                            session,
                            stream_id,
                            HttpResponse::error(413, "request body exceeds configured limit"),
                            Some(request.guard),
                            Duration::from_millis(app.timeout_ms("response_write")),
                        );
                    }
                }
            }
            quiche::h3::Event::Data => {
                let mut buffer = vec![0u8; 16 * 1024];
                let mut oversized = false;
                loop {
                    let read_result = match session.h3.as_mut() {
                        Some(h3) => h3.recv_body(&mut session.conn, stream_id, &mut buffer),
                        None => break,
                    };
                    match read_result {
                        Ok(0) | Err(quiche::h3::Error::Done) => break,
                        Ok(read) => {
                            if let Some(request) = session.pending_requests.get_mut(&stream_id) {
                                if !request.body_too_large {
                                    if request.body.len().saturating_add(read)
                                        > app.config.max_request_body_bytes
                                    {
                                        request.body_too_large = true;
                                        request.body.clear();
                                        oversized = true;
                                        break;
                                    } else {
                                        request.body.extend_from_slice(&buffer[..read]);
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            debug!(stream_id, %error, "could not read HTTP/3 request body");
                            if let Some(request) = session.pending_requests.get_mut(&stream_id) {
                                request.body_too_large = true;
                            }
                            break;
                        }
                    }
                }
                if oversized {
                    if let Some(request) = session.pending_requests.remove(&stream_id) {
                        request.cancel_token.set(true);
                        session.active_cancellations.remove(&stream_id);
                        session
                            .conn
                            .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x10)
                            .ok();
                        queue_response(
                            session,
                            stream_id,
                            HttpResponse::error(413, "request body exceeds configured limit"),
                            Some(request.guard),
                            Duration::from_millis(app.timeout_ms("response_write")),
                        );
                    }
                }
            }
            quiche::h3::Event::Finished => {
                session.header_deadlines.remove(&stream_id);
                if let Some(request) = session.pending_requests.remove(&stream_id) {
                    let (request, guard, cancel_token) = request.into_parts();
                    completed.push(CompletedRequest {
                        stream_id,
                        request,
                        guard,
                        cancel_token,
                    });
                }
            }
            quiche::h3::Event::Reset(_) => {
                session.header_deadlines.remove(&stream_id);
                session.pending_requests.remove(&stream_id);
                if let Some(cancel) = session.active_cancellations.remove(&stream_id) {
                    cancel.set(true);
                }
                app.record_client_abort();
            }
            _ => {}
        }
    }
    completed
}

fn queue_response(
    session: &mut Session,
    stream_id: u64,
    response: HttpResponse,
    guard: Option<RequestGuard>,
    response_timeout: Duration,
) {
    // Keep the response until both headers and body have been accepted by quiche.
    // In particular, a StreamBlocked result for headers must be retried on a later tick,
    // not silently turn into a hung HTTP/3 stream.
    session.outgoing.push_back(OutgoingResponse {
        stream_id,
        status: response.status,
        content_type: response.content_type,
        cache_control: response.cache_control,
        body: response.body,
        offset: 0,
        head_only: response.head_only,
        headers_sent: false,
        deadline: Instant::now() + response_timeout,
        _guard: guard,
    });
}

fn pump_outgoing(session: &mut Session) {
    let mut blocked_in_a_row = 0usize;

    loop {
        let queue_len = session.outgoing.len();
        if queue_len == 0 || blocked_in_a_row >= queue_len {
            break;
        }

        // Copy response metadata out of the queue before mutably borrowing quiche.
        // Header values must stay alive for send_response, so keep them independent
        // of the queue entry we may update or pop immediately afterwards.
        let Some((
            stream_id,
            status_code,
            content_type,
            cache_control,
            body_len,
            head_only,
            headers_sent,
        )) = session.outgoing.front().map(|front| {
            (
                front.stream_id,
                front.status,
                front.content_type.clone(),
                front.cache_control.clone(),
                front.body.len(),
                front.head_only,
                front.headers_sent,
            )
        })
        else {
            break;
        };
        let no_body = head_only || body_len == 0 || matches!(status_code, 204 | 304);

        if !headers_sent {
            let status = status_code.to_string();
            let content_length = body_len.to_string();
            let mut headers = vec![
                quiche::h3::Header::new(b":status", status.as_bytes()),
                quiche::h3::Header::new(b"server", b"websrv"),
                quiche::h3::Header::new(b"content-type", content_type.as_bytes()),
            ];
            if !matches!(status_code, 204 | 304) {
                headers.push(quiche::h3::Header::new(
                    b"content-length",
                    content_length.as_bytes(),
                ));
            }
            if let Some(cache_control) = cache_control.as_deref() {
                headers.push(quiche::h3::Header::new(
                    b"cache-control",
                    cache_control.as_bytes(),
                ));
            }
            let result = match session.h3.as_mut() {
                Some(h3) => h3.send_response(&mut session.conn, stream_id, &headers, no_body),
                None => break,
            };
            match result {
                Ok(()) => {
                    blocked_in_a_row = 0;
                    if let Some(front) = session.outgoing.front_mut() {
                        front.headers_sent = true;
                    }
                    if no_body {
                        session.outgoing.pop_front();
                        continue;
                    }
                }
                Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                    rotate_outgoing(session);
                    blocked_in_a_row += 1;
                    continue;
                }
                Err(error) => {
                    debug!(stream_id, %error, "failed to queue HTTP/3 response headers");
                    session.outgoing.pop_front();
                    blocked_in_a_row = 0;
                    continue;
                }
            }
        }

        // Refresh the current stream's body offset after possibly sending headers.
        let Some(front) = session.outgoing.front() else {
            break;
        };
        let start = front.offset;
        let end = (start + RESPONSE_CHUNK).min(front.body.len());
        let final_chunk = end == front.body.len();
        let chunk = front.body[start..end].to_vec();
        let result = match session.h3.as_mut() {
            Some(h3) => h3.send_body(&mut session.conn, stream_id, &chunk, final_chunk),
            None => break,
        };
        match result {
            Ok(0) => {
                // A zero-byte write means quiche accepted no body bytes. Keep the
                // response intact and give other queued streams a chance to progress.
                rotate_outgoing(session);
                blocked_in_a_row += 1;
            }
            Ok(written) => {
                blocked_in_a_row = 0;
                let accepted_end = start.saturating_add(written).min(body_len);
                if final_chunk && accepted_end == body_len {
                    session.outgoing.pop_front();
                } else if let Some(front) = session.outgoing.front_mut() {
                    front.offset = accepted_end;
                }
            }
            Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                rotate_outgoing(session);
                blocked_in_a_row += 1;
            }
            Err(error) => {
                debug!(stream_id, %error, "failed to queue HTTP/3 response body");
                session.outgoing.pop_front();
                blocked_in_a_row = 0;
            }
        }
    }
}

fn rotate_outgoing(session: &mut Session) {
    if let Some(response) = session.outgoing.pop_front() {
        session.outgoing.push_back(response);
    }
}

async fn wait_for_cancel(token: Rc<Cell<bool>>) {
    while !token.get() {
        monoio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn tick_sessions(
    sessions: &mut HashMap<Vec<u8>, Session>,
    h3_config: &quiche::h3::Config,
    app: &AppRuntime,
) {
    let now = Instant::now();
    for session in sessions.values_mut() {
        let finished_aborted_streams = session
            .header_aborted_streams
            .iter()
            .copied()
            .filter(|stream_id| session.conn.stream_finished(*stream_id))
            .collect::<Vec<_>>();
        for stream_id in finished_aborted_streams {
            session.header_aborted_streams.remove(&stream_id);
        }
        let expired_headers = session
            .header_deadlines
            .iter()
            .filter_map(|(stream_id, started)| {
                (now.duration_since(*started)
                    >= Duration::from_millis(app.timeout_ms("request_headers")))
                .then_some(*stream_id)
            })
            .collect::<Vec<_>>();
        for stream_id in expired_headers {
            session.header_deadlines.remove(&stream_id);
            session.header_aborted_streams.insert(stream_id);
            session
                .conn
                .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x10)
                .ok();
            session
                .conn
                .stream_shutdown(stream_id, quiche::Shutdown::Write, 0x10)
                .ok();
            app.record_timeout("request_headers");
            warn!(stream_id, client = %session.peer, "HTTP/3 request headers deadline exceeded; stream aborted");
        }

        let expired = session
            .pending_requests
            .iter()
            .filter_map(|(stream_id, request)| (now >= request.body_deadline).then_some(*stream_id))
            .collect::<Vec<_>>();
        for stream_id in expired {
            if let Some(request) = session.pending_requests.remove(&stream_id) {
                app.record_timeout("request_body");
                request.cancel_token.set(true);
                session.active_cancellations.remove(&stream_id);
                // Stop buffering request data, then try to return 408 on the write side.
                session
                    .conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x10)
                    .ok();
                queue_response(
                    session,
                    stream_id,
                    HttpResponse::error(408, "request body deadline exceeded"),
                    Some(request.guard),
                    Duration::from_millis(app.timeout_ms("response_write")),
                );
                warn!(stream_id, client = %session.peer, "HTTP/3 request body deadline exceeded; stream read side aborted");
            }
        }
        let queued = session.outgoing.len();
        for _ in 0..queued {
            let Some(response) = session.outgoing.pop_front() else {
                break;
            };
            if now >= response.deadline {
                session
                    .conn
                    .stream_shutdown(response.stream_id, quiche::Shutdown::Write, 0x10)
                    .ok();
                app.record_timeout("response_write");
                warn!(stream_id = response.stream_id, client = %session.peer, "HTTP/3 response deadline exceeded; stream write side aborted");
                // Dropping the response releases its request admission guard.
            } else {
                session.outgoing.push_back(response);
            }
        }
        if session
            .conn
            .timeout()
            .map(|duration| duration.is_zero())
            .unwrap_or(false)
        {
            session.conn.on_timeout();
        }
        if session.h3.is_none() && session.conn.is_established() {
            match quiche::h3::Connection::with_transport(&mut session.conn, h3_config) {
                Ok(h3) => {
                    session.h3 = Some(h3);
                    info!("HTTP/3 connection established after timer event");
                }
                Err(error) => {
                    warn!(%error, "could not initialize HTTP/3 after QUIC timer event");
                    session
                        .conn
                        .close(true, 0x102, b"HTTP/3 initialization failed")
                        .ok();
                }
            }
        }
        pump_outgoing(session);
    }
}

async fn pump_all(socket: &Rc<UdpSocket>, sessions: &mut HashMap<Vec<u8>, Session>) {
    let mut packets = Vec::<(SocketAddr, Vec<u8>)>::new();
    for session in sessions.values_mut() {
        loop {
            let mut packet = vec![0u8; QUIC_PACKET_BUFFER];
            match session.conn.send(&mut packet) {
                Ok((written, info)) => {
                    packet.truncate(written);
                    packets.push((info.to, packet));
                }
                Err(quiche::Error::Done) => break,
                Err(error) => {
                    debug!(%error, "QUIC packet generation stopped for a connection");
                    break;
                }
            }
        }
    }
    for (peer, packet) in packets {
        let packet_len = packet.len();
        let (result, _buffer) = socket.send_to(packet, peer).await;
        match result {
            Ok(sent) if sent == packet_len => {}
            Ok(sent) => warn!(%peer, expected = packet_len, sent, "short UDP datagram send"),
            Err(error) => warn!(%peer, %error, "io_uring UDP send failed"),
        }
    }
}

pub fn install_shutdown_handler() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone())
        .context("could not install SIGINT handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())
        .context("could not install SIGTERM handler")?;
    Ok(shutdown)
}

#[cfg(test)]
mod tests {
    use super::{take_rate_limit_token, PendingRequest};
    use std::time::{Duration, Instant};

    #[test]
    fn token_bucket_enforces_burst_and_refills() {
        let start = Instant::now();
        let mut tokens = 2.0;
        let mut last_refill = start;
        assert!(take_rate_limit_token(
            &mut tokens,
            &mut last_refill,
            start,
            1,
            2
        ));
        assert!(take_rate_limit_token(
            &mut tokens,
            &mut last_refill,
            start,
            1,
            2
        ));
        assert!(!take_rate_limit_token(
            &mut tokens,
            &mut last_refill,
            start,
            1,
            2
        ));
        assert!(take_rate_limit_token(
            &mut tokens,
            &mut last_refill,
            start + Duration::from_secs(1),
            1,
            2
        ));
    }

    #[test]
    fn request_builder_keeps_host_and_query_separate() {
        let request = PendingRequest {
            method: "GET".into(),
            authority: "example.com".into(),
            path: "/x".into(),
            query: Some("a=1".into()),
            headers: Default::default(),
            body: vec![],
            body_too_large: false,
            body_deadline: Instant::now() + Duration::from_secs(1),
            cancel_token: Rc::new(Cell::new(false)),
            guard: RequestGuard {
                protection: Rc::new(RefCell::new(ProtectionState::new(
                    &crate::config::RateLimitConfig::default(),
                ))),
                client_ip: "127.0.0.1".parse().unwrap(),
                host_key: "example.com".to_owned(),
                workload: WorkloadClass::Static,
            },
        }
        .into_parts()
        .0;
        assert_eq!(request.authority, "example.com");
        assert_eq!(request.path, "/x");
        assert_eq!(request.query.as_deref(), Some("a=1"));
    }
}
