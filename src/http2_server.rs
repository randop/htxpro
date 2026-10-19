//! HTTP/2 request adapter using monoio-http on the mandatory Monoio io_uring runtime.
use std::{
    cell::Cell,
    collections::HashMap,
    future::poll_fn,
    net::IpAddr,
    rc::Rc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::future::{select, Either};
use http::{header, Response, StatusCode};
use monoio::io::{AsyncReadRent, AsyncWriteRent};
use monoio_http::h2::{server, RecvStream};
use tracing::debug;

use crate::{
    http_types::{HttpRequest, HttpResponse},
    quic_server::AppRuntime,
};

struct ActiveStreamGuard(Rc<Cell<usize>>);

impl ActiveStreamGuard {
    fn new(active: Rc<Cell<usize>>) -> Self {
        active.set(active.get().saturating_add(1));
        Self(active)
    }
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

pub async fn serve_connection<T>(
    stream: T,
    app: AppRuntime,
    quic_port: u16,
    peer_ip: IpAddr,
) -> anyhow::Result<()>
where
    T: AsyncReadRent + AsyncWriteRent + Unpin + 'static,
{
    let mut builder = server::Builder::new();
    builder
        .max_concurrent_streams(app.max_concurrent_streams_per_connection())
        .max_header_list_size(u32::try_from(app.max_header_bytes()).unwrap_or(u32::MAX))
        .max_send_buffer_size(64 * 1024);
    let handshake = monoio::time::timeout(
        Duration::from_millis(app.timeout_ms("http2_handshake")),
        builder.handshake(stream),
    )
    .await;
    let mut h2 = match handshake {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => return Err(anyhow::anyhow!("HTTP/2 handshake failed: {error}")),
        Err(_) => {
            app.record_timeout("http2_handshake");
            anyhow::bail!("HTTP/2 connection preface/handshake deadline exceeded");
        }
    };

    let active_streams = Rc::new(Cell::new(0usize));
    loop {
        // An idle keep-alive connection is bounded too. If no complete request
        // arrives in the idle budget, close the connection rather than retaining
        // a task and connection state indefinitely.
        let accepted = monoio::time::timeout(
            Duration::from_millis(app.timeout_ms("keep_alive_idle")),
            h2.accept(),
        )
        .await;
        match accepted {
            Err(_) => {
                if active_streams.get() != 0 {
                    // Do not tear down a multiplexed connection merely because no
                    // new stream completed while existing streams were still working.
                    debug!(%peer_ip, active_streams = active_streams.get(), "HTTP/2 accept wait elapsed while streams remain active");
                    continue;
                }
                app.record_timeout("keep_alive");
                debug!(%peer_ip, "HTTP/2 keep-alive idle deadline exceeded; closing connection");
                return Ok(());
            }
            Ok(None) => break,
            Ok(Some(Ok((request, responder)))) => {
                let app = app.clone();
                let stream_guard = ActiveStreamGuard::new(active_streams.clone());
                monoio::spawn(async move {
                    let _stream_guard = stream_guard;
                    if let Err(error) =
                        handle_request(request, responder, app, quic_port, peer_ip).await
                    {
                        debug!(%peer_ip, %error, "HTTP/2 request stream ended with an error");
                    }
                });
            }
            Ok(Some(Err(error))) => {
                debug!(%peer_ip, %error, "HTTP/2 stream rejected by protocol layer");
            }
        }
    }

    if let Err(error) = poll_fn(|cx| h2.poll_closed(cx)).await {
        debug!(%peer_ip, %error, "HTTP/2 connection closed with a protocol error");
    }
    Ok(())
}

async fn handle_request(
    request: http::Request<RecvStream>,
    mut responder: server::SendResponse<Bytes>,
    app: AppRuntime,
    quic_port: u16,
    peer_ip: IpAddr,
) -> anyhow::Result<()> {
    let (parts, mut incoming) = request.into_parts();
    let authority = parts
        .uri
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .or_else(|| {
            parts
                .headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    if authority.is_empty() {
        send_response_with_timeout(
            &mut responder,
            HttpResponse::error(400, "HTTP/2 request requires :authority or Host"),
            false,
            quic_port,
            &app,
        )
        .await?;
        return Ok(());
    }
    let guard = match app.acquire_request(peer_ip, &authority) {
        Ok(guard) => guard,
        Err(rejection) => {
            send_response_with_timeout(
                &mut responder,
                rejection.response(),
                false,
                quic_port,
                &app,
            )
            .await?;
            return Ok(());
        }
    };

    let raw_path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    if !raw_path.starts_with('/')
        || raw_path.starts_with("//")
        || raw_path.contains('#')
        || raw_path.contains('\\')
    {
        send_response_with_timeout(
            &mut responder,
            HttpResponse::error(400, "HTTP/2 :path must be origin-form"),
            false,
            quic_port,
            &app,
        )
        .await?;
        drop(guard);
        return Ok(());
    }
    let (path, query) = match raw_path.split_once('?') {
        Some((path, query)) => (path.to_owned(), Some(query.to_owned())),
        None => (raw_path.to_owned(), None),
    };

    let mut headers = HashMap::new();
    for (name, value) in parts.headers.iter() {
        let value = value
            .to_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned());
        headers.insert(name.as_str().to_ascii_lowercase(), value);
    }

    let body_limit = app.max_request_body_bytes();
    let mut body = Vec::with_capacity(body_limit.min(16 * 1024));
    let body_deadline = Instant::now() + Duration::from_millis(app.timeout_ms("request_body"));
    let mut body_too_large = false;
    loop {
        let next = match monoio::time::timeout_at(body_deadline.into(), incoming.data()).await {
            Ok(next) => next,
            Err(_) => {
                app.record_timeout("request_body");
                drop(incoming);
                send_response_with_timeout(
                    &mut responder,
                    HttpResponse::error(408, "request body deadline exceeded"),
                    false,
                    quic_port,
                    &app,
                )
                .await?;
                drop(guard);
                return Ok(());
            }
        };
        let Some(next) = next else { break };
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(error) => {
                app.record_client_abort();
                debug!(%peer_ip, %error, "HTTP/2 request body read failed or stream was reset");
                drop(guard);
                return Ok(());
            }
        };
        if body.len().saturating_add(chunk.len()) > body_limit {
            body_too_large = true;
            break;
        }
        body.extend_from_slice(&chunk);
        let _ = incoming.flow_control().release_capacity(chunk.len());
    }
    drop(incoming);

    let method = parts.method.as_str().to_owned();
    let is_head = method.eq_ignore_ascii_case("HEAD");
    let request = HttpRequest {
        method,
        authority,
        path,
        query,
        headers,
        body,
        body_too_large: false,
    };
    let app_for_dispatch = app.clone();
    let response_work = Box::pin(async move {
        if body_too_large {
            HttpResponse::error(413, "request body exceeds configured limit")
        } else {
            app_for_dispatch.dispatch(request).await
        }
    });
    // Observe peer resets while application work is running. Completing the
    // reset branch drops the processing future and therefore cancels its work.
    let reset_observer = Box::pin(poll_fn(|cx| responder.poll_reset(cx)));
    let mut response = match select(response_work, reset_observer).await {
        Either::Left((response, reset_observer)) => {
            drop(reset_observer);
            response
        }
        Either::Right((_reset, response_work)) => {
            drop(response_work);
            app.record_client_abort();
            drop(guard);
            return Ok(());
        }
    };
    if is_head {
        response.head_only = true;
    }
    let send_result =
        send_response_with_timeout(&mut responder, response, is_head, quic_port, &app).await;
    drop(guard);
    send_result?;
    Ok(())
}

async fn send_response_with_timeout(
    responder: &mut server::SendResponse<Bytes>,
    response: HttpResponse,
    is_head: bool,
    quic_port: u16,
    app: &AppRuntime,
) -> anyhow::Result<()> {
    match monoio::time::timeout(
        Duration::from_millis(app.timeout_ms("response_write")),
        send_response(responder, response, is_head, quic_port),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            app.record_timeout("response_write");
            anyhow::bail!("HTTP/2 response write deadline exceeded; dropping the stream aborts it");
        }
    }
}

async fn send_response(
    responder: &mut server::SendResponse<Bytes>,
    mut response: HttpResponse,
    is_head: bool,
    quic_port: u16,
) -> anyhow::Result<()> {
    let no_body_status = matches!(response.status, 204 | 304);
    let content_length = if no_body_status {
        0
    } else {
        response.body.len()
    };
    let safe_content_type = if response.content_type.chars().any(char::is_control) {
        "application/octet-stream"
    } else {
        response.content_type.as_str()
    };
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder()
        .status(status)
        .header(header::SERVER, "websrv")
        .header(header::CONTENT_TYPE, safe_content_type)
        .header(header::CONTENT_LENGTH, content_length.to_string())
        .header("x-content-type-options", "nosniff")
        .header("alt-svc", format!("h3=\":{quic_port}\"; ma=86400"));
    if let Some(cache_control) = &response.cache_control {
        if !cache_control
            .chars()
            .any(|ch| ch.is_control() && ch != '\t')
        {
            builder = builder.header(header::CACHE_CONTROL, cache_control.as_str());
        }
    }
    // HTTP/2 forbids connection-specific fields; only end the stream, never the connection.
    let head_only = is_head || response.head_only;
    if no_body_status {
        response.body.clear();
    }
    let end_stream = head_only || no_body_status || response.body.is_empty();
    let head = builder
        .body(())
        .map_err(|error| anyhow::anyhow!("invalid HTTP/2 response headers: {error}"))?;
    let mut outgoing = responder
        .send_response(head, end_stream)
        .map_err(|error| anyhow::anyhow!("could not send HTTP/2 response headers: {error}"))?;
    if !end_stream {
        // Respect both the per-stream and connection-level HTTP/2 send windows. Never
        // hand an entire potentially large static file to monoio-http's unbounded queue.
        let body = Bytes::from(std::mem::take(&mut response.body));
        let body_len = body.len();
        let mut offset = 0usize;

        while offset < body_len {
            let desired = (body_len - offset).min(16 * 1024);
            outgoing.reserve_capacity(desired);
            let assigned = if outgoing.capacity() > 0 {
                outgoing.capacity()
            } else {
                poll_fn(|cx| outgoing.poll_capacity(cx))
                    .await
                    .ok_or_else(|| {
                        anyhow::anyhow!("HTTP/2 stream closed while waiting for send capacity")
                    })?
                    .map_err(|error| anyhow::anyhow!("HTTP/2 send flow control failed: {error}"))?
            };
            anyhow::ensure!(assigned > 0, "HTTP/2 send flow control made no progress");
            let chunk_len = assigned.min(desired).min(body_len - offset);
            let end_of_stream = offset + chunk_len == body_len;
            let chunk = body.slice(offset..offset + chunk_len);
            outgoing
                .send_data(chunk, end_of_stream)
                .map_err(|error| anyhow::anyhow!("could not send HTTP/2 response body: {error}"))?;
            offset += chunk_len;
        }
    }
    Ok(())
}
