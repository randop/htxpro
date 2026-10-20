//! Minimal outbound HTTP/1.1 client for provider token exchange. Connections
//! and TLS I/O are driven by Monoio's mandatory io_uring runtime; endpoints are
//! resolved once during startup so request-time DNS does not block the reactor.

use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::TcpStream,
};
use monoio_rustls::TlsConnector;
use rustls::{pki_types::ServerName, ClientConfig};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    scheme: Scheme,
    host: String,
    port: u16,
    path_and_query: String,
    addresses: Vec<SocketAddr>,
}

impl Endpoint {
    pub fn resolve(url: &crate::config::ParsedHttpUrl) -> Result<Self> {
        let addresses = (url.host.as_str(), url.port)
            .to_socket_addrs()
            .with_context(|| {
                format!(
                    "could not resolve security endpoint host {:?}:{}",
                    url.host, url.port
                )
            })?
            .collect::<Vec<_>>();
        anyhow::ensure!(
            !addresses.is_empty(),
            "security endpoint host {:?} resolved to no addresses",
            url.host
        );
        Ok(Self {
            scheme: if url.scheme == "https" {
                Scheme::Https
            } else {
                Scheme::Http
            },
            host: url.host.clone(),
            port: url.port,
            path_and_query: url.path_and_query.clone(),
            addresses,
        })
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

pub fn make_tls_config() -> Result<Arc<ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("no safe TLS protocol versions are available for outbound security requests")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub async fn post_json(
    endpoint: &Endpoint,
    tls: &Arc<ClientConfig>,
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    let mut request = format!(
        "POST {} HTTP/1.1\r\nhost: {}\r\naccept: application/json\r\naccept-encoding: identity\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        endpoint.path_and_query,
        endpoint.host_header(),
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);

    let exchange = async {
        let tcp = connect(endpoint).await?;
        match endpoint.scheme {
            Scheme::Http => {
                let mut tcp = tcp;
                exchange_stream(&mut tcp, &request).await
            }
            Scheme::Https => {
                let server_name = ServerName::try_from(endpoint.host.clone())
                    .with_context(|| format!("invalid TLS server name {:?}", endpoint.host))?;
                let connector = TlsConnector::from(tls.clone());
                let mut stream = connector
                    .connect(server_name, tcp)
                    .await
                    .context("TLS handshake with security endpoint failed")?;
                exchange_stream(&mut stream, &request).await
            }
        }
    };
    let response = monoio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("security endpoint request timed out"))??;
    parse_response(&response)
}

async fn connect(endpoint: &Endpoint) -> Result<TcpStream> {
    let mut last_error = None;
    for address in &endpoint.addresses {
        match TcpStream::connect_addr(*address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("security endpoint has no usable address")))
    .context("could not connect to security endpoint")
}

async fn exchange_stream<S>(stream: &mut S, request: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncReadRent + AsyncWriteRentExt + Unpin,
{
    let (result, _buffer) = stream.write_all(request.to_vec()).await;
    result.context("could not send security endpoint request")?;

    let mut response = Vec::new();
    loop {
        let (result, buffer) = stream.read(vec![0u8; READ_CHUNK_BYTES]).await;
        let read = result.context("could not read security endpoint response")?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() > MAX_RESPONSE_BYTES {
            anyhow::bail!("security endpoint response exceeded the size limit");
        }
        if let Some(expected) = complete_response_len(&response)? {
            if response.len() >= expected {
                response.truncate(expected);
                break;
            }
        }
    }
    Ok(response)
}

/// Returns the total response length once headers and any declared body are
/// available. `None` means more bytes are required (or the body is delimited
/// by connection close).
fn complete_response_len(response: &[u8]) -> Result<Option<usize>> {
    let Some(header_end) = find_double_crlf(response) else {
        return Ok(None);
    };
    let body_offset = header_end + 4;
    let head = std::str::from_utf8(&response[..header_end])
        .context("security endpoint response headers were not valid UTF-8")?;
    let mut content_length = None;
    let mut chunked = false;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("invalid content-length from security endpoint")?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
    }
    if chunked {
        return Ok(chunked_body_len(&response[body_offset..])
            .map(|length| body_offset.saturating_add(length)));
    }
    Ok(content_length.map(|length| body_offset.saturating_add(length)))
}

fn parse_response(response: &[u8]) -> Result<(u16, Vec<u8>)> {
    let header_end = find_double_crlf(response)
        .context("security endpoint returned an incomplete HTTP response")?;
    let body_offset = header_end + 4;
    let head = std::str::from_utf8(&response[..header_end])
        .context("security endpoint response headers were not valid UTF-8")?;
    let status = head
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("security endpoint response status line is malformed")?
        .parse::<u16>()
        .context("security endpoint response status is invalid")?;
    let mut chunked = false;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
    }
    let body = if chunked {
        decode_chunked(&response[body_offset..])?
    } else {
        response[body_offset..].to_vec()
    };
    Ok((status, body))
}
fn find_double_crlf(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

fn find_crlf(input: &[u8]) -> Option<usize> {
    input.windows(2).position(|window| window == b"\r\n")
}

fn chunked_body_len(body: &[u8]) -> Option<usize> {
    let mut position = 0usize;
    loop {
        let line_end = position.checked_add(find_crlf(body.get(position..)?)?)?;
        let size_text = std::str::from_utf8(&body[position..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        position = line_end + 2;
        if size == 0 {
            if body.get(position..)?.starts_with(b"\r\n") {
                return Some(position + 2);
            }
            let trailer_end = find_double_crlf(body.get(position..)?)?;
            return Some(position + trailer_end + 4);
        }
        position = position.checked_add(size)?.checked_add(2)?;
        if position > body.len() {
            return None;
        }
        if body.get(position - 2..position)? != b"\r\n" {
            return Some(position);
        }
    }
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>> {
    let mut position = 0usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = find_crlf(body.get(position..).context("truncated chunked response")?)
            .context("truncated chunked response")?
            .saturating_add(position);
        let size_text = std::str::from_utf8(&body[position..line_end])
            .context("invalid chunk size in security endpoint response")?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .context("invalid chunk size in security endpoint response")?;
        position = line_end + 2;
        if size == 0 {
            break;
        }
        let end = position
            .checked_add(size)
            .context("chunk size overflow in security endpoint response")?;
        anyhow::ensure!(
            end <= body.len(),
            "truncated chunk body in security endpoint response"
        );
        decoded.extend_from_slice(&body[position..end]);
        anyhow::ensure!(
            body.get(end..end + 2) == Some(b"\r\n"),
            "invalid chunk terminator in security endpoint response"
        );
        position = end + 2;
        anyhow::ensure!(
            decoded.len() <= MAX_RESPONSE_BYTES,
            "decoded security endpoint response exceeded the size limit"
        );
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{chunked_body_len, complete_response_len, decode_chunked};

    #[test]
    fn content_length_responses_stop_at_the_declared_body() {
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nbody";
        assert_eq!(
            complete_response_len(response).unwrap(),
            Some(response.len())
        );
    }

    #[test]
    fn chunked_responses_are_detected_and_decoded() {
        let response =
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n4\r\n{\"ok\r\n0\r\n\r\n";
        assert_eq!(
            complete_response_len(response).unwrap(),
            Some(response.len())
        );
        let body = decode_chunked(b"4\r\n{\"ok\r\n0\r\n\r\n").unwrap();
        assert_eq!(body, b"{\"ok");
    }

    #[test]
    fn incomplete_chunked_response_waits_for_more_bytes() {
        assert_eq!(chunked_body_len(b"4\r\n{\"ok"), None);
    }
}
