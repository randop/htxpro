//! TLS ALPN dispatch for secure HTTP/2 and HTTP/1.1, plus cleartext HTTP/1.1 and h2c on Monoio io_uring.
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Cursor},
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt, PrefixedReadIo},
    net::{TcpListener, TcpStream},
};
use monoio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use tracing::{debug, info, warn};

use crate::{
    http_types::{HttpRequest, HttpResponse},
    quic_server::{AppRuntime, RequestGuard, TcpConnectionGuard},
};

const SOCKET_READ_BYTES: usize = 16 * 1024;

pub fn make_tls_config(
    cert_path: &Path,
    key_path: &Path,
    http1_secure_enabled: bool,
    http2_secure_enabled: bool,
) -> Result<Arc<ServerConfig>> {
    let mut cert_reader = BufReader::new(
        File::open(cert_path)
            .with_context(|| format!("cannot open TLS certificate {}", cert_path.display()))?,
    );
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("cannot parse TLS certificate chain {}", cert_path.display()))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "TLS certificate chain {} is empty",
        cert_path.display()
    );

    let mut key_reader = BufReader::new(
        File::open(key_path)
            .with_context(|| format!("cannot open TLS private key {}", key_path.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("cannot parse TLS private key {}", key_path.display()))?
        .context("TLS key PEM does not contain a supported private key")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("no safe TLS protocol versions are available")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS certificate and private key do not match or are unsupported")?;
    tls.alpn_protocols = [
        (http2_secure_enabled, b"h2".to_vec()),
        (http1_secure_enabled, b"http/1.1".to_vec()),
    ]
    .into_iter()
    .filter_map(|(enabled, protocol)| enabled.then_some(protocol))
    .collect();
    anyhow::ensure!(
        !tls.alpn_protocols.is_empty(),
        "at least one secure HTTP protocol must be enabled when building the TLS config"
    );
    Ok(Arc::new(tls))
}

/// A single secure listener negotiates only the enabled HTTP protocols via ALPN.
/// Clients without ALPN use HTTP/1.1 only when `http1_secure_enabled` is true.
pub async fn serve(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    app: AppRuntime,
    quic_port: u16,
    http1_secure_enabled: bool,
) {
    let acceptor = TlsAcceptor::from(tls_config);
    info!(
        protocol = "HTTPS (ALPN)",
        runtime = "monoio/IoUringDriver",
        "secure HTTP listener started on Monoio io_uring"
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let peer_ip = peer.ip();
                let Some(connection_guard) = app.acquire_tcp_connection(peer_ip) else {
                    debug!(%peer, "TLS TCP connection limit reached");
                    drop(stream);
                    continue;
                };
                let app = app.clone();
                let acceptor = acceptor.clone();
                monoio::spawn(async move {
                    let _connection_guard = connection_guard;
                    if let Err(error) = serve_tls_connection(
                        stream,
                        acceptor,
                        app,
                        quic_port,
                        http1_secure_enabled,
                        peer_ip,
                    )
                    .await
                    {
                        debug!(%peer, %error, "TLS connection ended");
                    }
                });
            }
            Err(error) => {
                warn!(%error, "io_uring TLS TCP accept failed");
                monoio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
    }
}

async fn serve_tls_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    app: AppRuntime,
    quic_port: u16,
    http1_secure_enabled: bool,
    peer_ip: IpAddr,
) -> Result<()> {
    let tls_stream = match monoio::time::timeout(
        Duration::from_millis(app.timeout_ms("tls_handshake")),
        acceptor.accept(stream),
    )
    .await
    {
        Ok(result) => result.context("TLS handshake failed")?,
        Err(_) => {
            app.record_timeout("tls_handshake");
            anyhow::bail!("TLS handshake deadline exceeded");
        }
    };
    let negotiated = tls_stream.alpn_protocol();
    match negotiated.as_deref() {
        Some(b"h2") => {
            crate::http2_server::serve_connection(tls_stream, app, quic_port, peer_ip).await
        }
        Some(b"http/1.1") => {
            anyhow::ensure!(
                http1_secure_enabled,
                "client negotiated HTTP/1.1 but HTTP/1.1 over TLS is disabled"
            );
            serve_http1_stream(tls_stream, app, quic_port, peer_ip).await?;
            Ok(())
        }
        None if http1_secure_enabled => {
            serve_http1_stream(tls_stream, app, quic_port, peer_ip).await?;
            Ok(())
        }
        None => anyhow::bail!("client did not negotiate ALPN and HTTP/1.1 over TLS is disabled"),
        Some(protocol) => anyhow::bail!("unsupported negotiated ALPN protocol: {:?}", protocol),
    }
}

/// Serve cleartext HTTP/1.1 and/or prior-knowledge HTTP/2 (h2c) over one TCP
/// listener. When both are enabled, the HTTP/2 connection preface selects H2;
/// all other prefixes are preserved and passed into the HTTP/1.1 parser.
pub async fn serve_plain(
    listener: TcpListener,
    app: AppRuntime,
    quic_port: u16,
    http1_plain_enabled: bool,
    http2_plain_enabled: bool,
) {
    info!(
        protocol = "cleartext HTTP/1.1 and/or HTTP/2 prior-knowledge",
        http1_plain_enabled,
        http2_plain_enabled,
        runtime = "monoio/IoUringDriver",
        "plain HTTP listener started on Monoio io_uring"
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let peer_ip = peer.ip();
                let Some(connection_guard) = app.acquire_tcp_connection(peer_ip) else {
                    debug!(%peer, "cleartext TCP connection limit reached");
                    drop(stream);
                    continue;
                };
                let app = app.clone();
                monoio::spawn(async move {
                    let _connection_guard: TcpConnectionGuard = connection_guard;
                    if let Err(error) = serve_plain_connection(
                        stream,
                        app,
                        quic_port,
                        http1_plain_enabled,
                        http2_plain_enabled,
                        peer_ip,
                    )
                    .await
                    {
                        debug!(%peer, %error, "plain HTTP connection ended");
                    }
                });
            }
            Err(error) => {
                warn!(%error, "io_uring cleartext TCP accept failed");
                monoio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
    }
}

const H2_PRIOR_KNOWLEDGE_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

async fn serve_plain_connection(
    mut stream: TcpStream,
    app: AppRuntime,
    quic_port: u16,
    http1_plain_enabled: bool,
    http2_plain_enabled: bool,
    peer_ip: IpAddr,
) -> Result<()> {
    match (http1_plain_enabled, http2_plain_enabled) {
        (true, false) => {
            serve_http1_stream(stream, app, quic_port, peer_ip).await?;
            Ok(())
        }
        (false, true) => {
            crate::http2_server::serve_connection(stream, app, quic_port, peer_ip).await
        }
        (false, false) => Ok(()),
        (true, true) => {
            let mut initial = Vec::with_capacity(SOCKET_READ_BYTES);
            let mut header_deadline: Option<Instant> = None;
            loop {
                match classify_h2_preface(&initial) {
                    Some(true) => {
                        // PrefixedReadIo replays the full preface and any coalesced
                        // SETTINGS frame bytes to the HTTP/2 state machine.
                        let prefixed = PrefixedReadIo::new(stream, Cursor::new(initial));
                        return crate::http2_server::serve_connection(
                            prefixed, app, quic_port, peer_ip,
                        )
                        .await;
                    }
                    Some(false) => {
                        // This is HTTP/1.1 (or another protocol); never discard the
                        // sniffed bytes before handing the connection to its parser.
                        let prefixed = PrefixedReadIo::new(stream, Cursor::new(initial));
                        serve_http1_stream(prefixed, app, quic_port, peer_ip).await?;
                        return Ok(());
                    }
                    None => {}
                }

                let read_result = if let Some(deadline) = header_deadline {
                    monoio::time::timeout_at(
                        deadline.into(),
                        stream.read(vec![0u8; SOCKET_READ_BYTES]),
                    )
                    .await
                    .map_err(|_| "request_headers")
                } else {
                    monoio::time::timeout(
                        Duration::from_millis(app.timeout_ms("keep_alive_idle")),
                        stream.read(vec![0u8; SOCKET_READ_BYTES]),
                    )
                    .await
                    .map_err(|_| "keep_alive")
                };
                let (result, buffer) = match read_result {
                    Ok(read) => read,
                    Err(phase) => {
                        app.record_timeout(phase);
                        debug!(%peer_ip, phase, "cleartext protocol preface deadline exceeded");
                        return Ok(());
                    }
                };
                match result {
                    Ok(0) => return Ok(()),
                    Ok(read) => {
                        initial.extend_from_slice(&buffer[..read]);
                        header_deadline.get_or_insert_with(|| {
                            Instant::now()
                                + Duration::from_millis(app.timeout_ms("request_headers"))
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

/// `Some(true)` is a complete HTTP/2 prior-knowledge preface, `Some(false)` is
/// definitively not HTTP/2, and `None` means the bytes are still a valid prefix.
fn classify_h2_preface(bytes: &[u8]) -> Option<bool> {
    let matched = bytes.len().min(H2_PRIOR_KNOWLEDGE_PREFACE.len());
    if bytes[..matched] != H2_PRIOR_KNOWLEDGE_PREFACE[..matched] {
        Some(false)
    } else if bytes.len() >= H2_PRIOR_KNOWLEDGE_PREFACE.len() {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod plain_protocol_tests {
    use super::{classify_h2_preface, H2_PRIOR_KNOWLEDGE_PREFACE};

    #[test]
    fn detects_h2_preface_even_when_it_arrives_in_fragments() {
        for end in 0..H2_PRIOR_KNOWLEDGE_PREFACE.len() {
            assert_eq!(
                classify_h2_preface(&H2_PRIOR_KNOWLEDGE_PREFACE[..end]),
                None,
                "valid partial preface of length {end} must wait for more bytes",
            );
        }
        assert_eq!(classify_h2_preface(H2_PRIOR_KNOWLEDGE_PREFACE), Some(true));
        assert_eq!(classify_h2_preface(b"GET / HTTP/1.1\r\n"), Some(false));
        assert_eq!(classify_h2_preface(b"POST / HTTP/1.1\r\n"), Some(false));
        assert_eq!(classify_h2_preface(b"PRI X HTTP/2.0\r\n"), Some(false));
    }
}

async fn serve_http1_stream<S>(
    mut stream: S,
    app: AppRuntime,
    quic_port: u16,
    peer_ip: IpAddr,
) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRentExt + Unpin,
{
    let mut plaintext = Vec::<u8>::new();
    let mut pending: Option<(RequestHead, RequestGuard, Instant)> = None;
    let mut header_deadline: Option<Instant> = None;

    loop {
        loop {
            if pending.is_none() {
                match parse_request_head(
                    &plaintext,
                    app.max_request_body_bytes(),
                    app.max_header_bytes(),
                ) {
                    HeadParse::Incomplete => break,
                    HeadParse::Reject(status, message) => {
                        let response = HttpResponse::error(status, message);
                        write_http1_response_with_timeout(
                            &mut stream,
                            &response,
                            true,
                            quic_port,
                            &app,
                        )
                        .await?;
                        return Ok(());
                    }
                    HeadParse::Complete(head) => {
                        plaintext.drain(..head.header_len);
                        header_deadline = None;
                        let guard = match app.acquire_request(peer_ip, &head.authority) {
                            Ok(guard) => guard,
                            Err(rejection) => {
                                write_http1_response_with_timeout(
                                    &mut stream,
                                    &rejection.response(),
                                    true,
                                    quic_port,
                                    &app,
                                )
                                .await?;
                                return Ok(());
                            }
                        };
                        let body_deadline =
                            Instant::now() + Duration::from_millis(app.timeout_ms("request_body"));
                        pending = Some((head, guard, body_deadline));
                    }
                }
            }

            let Some((head, _, _)) = pending.as_ref() else {
                continue;
            };
            if plaintext.len() < head.content_length {
                break;
            }

            let (head, guard, _) = pending.take().expect("pending request was checked above");
            let body = plaintext.drain(..head.content_length).collect::<Vec<_>>();
            let request = HttpRequest {
                method: head.method.clone(),
                authority: head.authority,
                path: head.path,
                query: head.query,
                headers: head.headers,
                body,
                body_too_large: false,
            };
            let is_head = request.method.eq_ignore_ascii_case("HEAD");
            let close_after = head.close_after;
            let mut response = app.dispatch(request).await;
            if is_head {
                response.head_only = true;
            }
            if let Err(error) = write_http1_response_with_timeout(
                &mut stream,
                &response,
                close_after,
                quic_port,
                &app,
            )
            .await
            {
                if error.kind() != io::ErrorKind::TimedOut {
                    app.record_client_abort();
                }
                drop(guard);
                return Err(error);
            }
            drop(guard);
            if close_after {
                return Ok(());
            }
            header_deadline = None;
        }

        let body_deadline = pending.as_ref().map(|(_, _, deadline)| *deadline);
        let header_deadline_for_read = if body_deadline.is_none() && !plaintext.is_empty() {
            Some(*header_deadline.get_or_insert_with(|| {
                Instant::now() + Duration::from_millis(app.timeout_ms("request_headers"))
            }))
        } else {
            None
        };
        let read_result = if let Some(deadline) = body_deadline {
            monoio::time::timeout_at(deadline.into(), stream.read(vec![0u8; SOCKET_READ_BYTES]))
                .await
                .map_err(|_| "request_body")
        } else if let Some(deadline) = header_deadline_for_read {
            monoio::time::timeout_at(deadline.into(), stream.read(vec![0u8; SOCKET_READ_BYTES]))
                .await
                .map_err(|_| "request_headers")
        } else {
            monoio::time::timeout(
                Duration::from_millis(app.timeout_ms("keep_alive_idle")),
                stream.read(vec![0u8; SOCKET_READ_BYTES]),
            )
            .await
            .map_err(|_| "keep_alive")
        };

        match read_result {
            Err("keep_alive") => {
                app.record_timeout("keep_alive");
                debug!(%peer_ip, "HTTP/1.1 keep-alive idle deadline exceeded");
                return Ok(());
            }
            Err(phase @ ("request_headers" | "request_body")) => {
                app.record_timeout(phase);
                warn!(%peer_ip, phase, "HTTP/1.1 request deadline exceeded");
                drop(pending.take()); // Drop any in-flight admission guard immediately.
                let response = HttpResponse::error(408, "request deadline exceeded");
                write_http1_response_with_timeout(&mut stream, &response, true, quic_port, &app)
                    .await?;
                return Ok(());
            }
            Err(_) => unreachable!("all timeout phases are enumerated above"),
            Ok((Ok(0), _buffer)) => {
                if pending.is_some() || !plaintext.is_empty() {
                    app.record_client_abort();
                }
                return Ok(());
            }
            Ok((Ok(amount), buffer)) => {
                plaintext.extend_from_slice(&buffer[..amount]);
                if pending.is_none() && header_deadline.is_none() {
                    header_deadline = Some(
                        Instant::now() + Duration::from_millis(app.timeout_ms("request_headers")),
                    );
                }
            }
            Ok((Err(error), _buffer)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok((Err(error), _buffer)) => {
                if pending.is_some() || !plaintext.is_empty() {
                    app.record_client_abort();
                }
                return Err(error);
            }
        }
    }
}

async fn write_http1_response_with_timeout<S>(
    stream: &mut S,
    response: &HttpResponse,
    close_after: bool,
    quic_port: u16,
    app: &AppRuntime,
) -> io::Result<()>
where
    S: AsyncWriteRentExt + Unpin,
{
    match monoio::time::timeout(
        Duration::from_millis(app.timeout_ms("response_write")),
        write_http1_response(stream, response, close_after, quic_port),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            app.record_timeout("response_write");
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP/1.1 response write deadline exceeded",
            ))
        }
    }
}

async fn write_http1_response<S>(
    stream: &mut S,
    response: &HttpResponse,
    close_after: bool,
    quic_port: u16,
) -> io::Result<()>
where
    S: AsyncWriteRentExt + Unpin,
{
    let reason = reason_phrase(response.status);
    let content_length = if matches!(response.status, 204 | 304) {
        0
    } else {
        response.body.len()
    };
    let connection = if close_after { "close" } else { "keep-alive" };
    let safe_content_type = if response.content_type.chars().any(char::is_control) {
        "application/octet-stream"
    } else {
        response.content_type.as_str()
    };
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\nserver: websrv\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: {}\r\nx-content-type-options: nosniff\r\nalt-svc: h3=\":{}\"; ma=86400\r\n",
        response.status, reason, safe_content_type, content_length, connection, quic_port,
    );
    if let Some(cache_control) = &response.cache_control {
        if !cache_control
            .chars()
            .any(|ch| ch.is_control() && ch != '\t')
        {
            headers.push_str(&format!("cache-control: {cache_control}\r\n"));
        }
    }
    headers.push_str("\r\n");
    write_all(stream, headers.as_bytes()).await?;
    if !response.head_only && !matches!(response.status, 204 | 304) {
        write_all(stream, &response.body).await?;
    }
    Ok(())
}

async fn write_all<S>(stream: &mut S, bytes: &[u8]) -> io::Result<()>
where
    S: AsyncWriteRentExt + Unpin,
{
    let (result, _returned_buffer) = stream.write_all(bytes.to_vec()).await;
    result.map(|_| ())
}

struct RequestHead {
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    headers: HashMap<String, String>,
    content_length: usize,
    header_len: usize,
    close_after: bool,
}

enum HeadParse {
    Incomplete,
    Complete(RequestHead),
    Reject(u16, &'static str),
}

fn parse_request_head(bytes: &[u8], max_body_bytes: usize, max_header_bytes: usize) -> HeadParse {
    let Some(separator) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return if bytes.len() > max_header_bytes {
            HeadParse::Reject(431, "request headers too large")
        } else {
            HeadParse::Incomplete
        };
    };
    let header_len = separator + 4;
    if header_len > max_header_bytes {
        return HeadParse::Reject(431, "request headers too large");
    }
    let text = match std::str::from_utf8(&bytes[..separator]) {
        Ok(text) => text,
        Err(_) => return HeadParse::Reject(400, "request headers must be valid ASCII/UTF-8"),
    };
    let mut lines = text.split("\r\n");
    let Some(request_line) = lines.next() else {
        return HeadParse::Reject(400, "missing request line");
    };
    let pieces = request_line.split(' ').collect::<Vec<_>>();
    if pieces.len() != 3 || pieces.iter().any(|piece| piece.is_empty()) {
        return HeadParse::Reject(400, "malformed request line");
    }
    let method = pieces[0];
    if !is_http_token(method) {
        return HeadParse::Reject(400, "invalid HTTP method");
    }
    if pieces[2] != "HTTP/1.1" {
        return HeadParse::Reject(505, "only HTTP/1.1 is supported on the TCP listener");
    }
    let target = pieces[1];
    if !target.starts_with('/')
        || target.starts_with("//")
        || target.contains('\\')
        || target.contains('#')
        || target.chars().any(char::is_control)
    {
        return HeadParse::Reject(400, "request target must be origin-form");
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_owned())),
        None => (target, None),
    };
    if path.is_empty() {
        return HeadParse::Reject(400, "empty request path");
    }

    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return HeadParse::Reject(400, "malformed request header");
        };
        if !is_http_token(name) {
            return HeadParse::Reject(400, "invalid HTTP header name");
        }
        let value = value.trim_matches(|ch| ch == ' ' || ch == '\t');
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return HeadParse::Reject(400, "invalid HTTP header value");
        }
        let name = name.to_ascii_lowercase();
        if headers.insert(name, value.to_owned()).is_some() {
            return HeadParse::Reject(400, "duplicate request header");
        }
    }
    let Some(authority) = headers.get("host").map(|value| value.trim().to_owned()) else {
        return HeadParse::Reject(400, "HTTP/1.1 requires a Host header");
    };
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'/' || byte == b'\\')
    {
        return HeadParse::Reject(400, "invalid Host header");
    }
    if headers.contains_key("expect") {
        return HeadParse::Reject(417, "Expect is not supported");
    }
    if headers.contains_key("transfer-encoding") {
        return HeadParse::Reject(
            501,
            "Transfer-Encoding is not supported; use Content-Length",
        );
    }
    let content_length = match headers.get("content-length") {
        Some(value) => match value.parse::<usize>() {
            Ok(length) => length,
            Err(_) => return HeadParse::Reject(400, "invalid Content-Length"),
        },
        None => 0,
    };
    if content_length > max_body_bytes {
        return HeadParse::Reject(413, "request body exceeds configured limit");
    }
    let close_after = headers.get("connection").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("close"))
    });
    HeadParse::Complete(RequestHead {
        method: method.to_owned(),
        authority,
        path: path.to_owned(),
        query,
        headers,
        content_length,
        header_len,
        close_after,
    })
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

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Response",
    }
}
