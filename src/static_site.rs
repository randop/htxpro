//! Static site reads. File contents are read through Monoio's io_uring-backed file API.

use std::path::{Component, Path, PathBuf};

use crate::{
    config::StaticSiteConfig,
    http_types::{HttpRequest, HttpResponse},
};

const READ_CHUNK_BYTES: usize = 64 * 1024;

pub async fn serve(
    site: &StaticSiteConfig,
    request: &HttpRequest,
    max_file_bytes: usize,
) -> HttpResponse {
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        return HttpResponse::error(405, "static hosts support GET and HEAD only");
    }

    let decoded = match percent_encoding::percent_decode_str(&request.path).decode_utf8() {
        Ok(value) => value.into_owned(),
        Err(_) => return HttpResponse::not_found(),
    };
    if !decoded.starts_with('/') || decoded.chars().any(|c| matches!(c, '\\' | '\0')) {
        return HttpResponse::not_found();
    }

    let mut relative = PathBuf::new();
    for segment in decoded.split('/').skip(1) {
        if segment.is_empty() {
            continue;
        }
        if segment == "." || segment == ".." {
            return HttpResponse::not_found();
        }
        relative.push(segment);
    }
    if decoded.ends_with('/') || relative.as_os_str().is_empty() {
        relative.push(&site.index);
    }
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return HttpResponse::not_found();
    }

    let candidate = site.root.join(&relative);
    match read_bounded_file(&candidate, max_file_bytes).await {
        Ok(body) => {
            let mime = mime_guess::from_path(&candidate)
                .first_or_octet_stream()
                .essence_str()
                .to_owned();
            let mut response =
                HttpResponse::new(200, mime, body).with_cache(site.cache_control.clone());
            if request.method == "HEAD" {
                response.head_only = true;
            }
            response
        }
        Err(ReadError::TooLarge) => {
            HttpResponse::error(413, "static file exceeds configured size limit")
        }
        Err(ReadError::NotFound) if site.spa_fallback && relative.extension().is_none() => {
            let index = site.root.join(&site.index);
            match read_bounded_file(&index, max_file_bytes).await {
                Ok(body) => {
                    let mut response = HttpResponse::new(200, "text/html; charset=utf-8", body)
                        .with_cache(site.cache_control.clone());
                    if request.method == "HEAD" {
                        response.head_only = true;
                    }
                    response
                }
                Err(ReadError::TooLarge) => {
                    HttpResponse::error(413, "static file exceeds configured size limit")
                }
                Err(ReadError::NotFound) => HttpResponse::not_found(),
            }
        }
        Err(ReadError::NotFound) => HttpResponse::not_found(),
    }
}

enum ReadError {
    NotFound,
    TooLarge,
}

async fn read_bounded_file(path: &Path, max_file_bytes: usize) -> Result<Vec<u8>, ReadError> {
    let file = monoio::fs::File::open(path)
        .await
        .map_err(|_| ReadError::NotFound)?;
    let mut output = Vec::with_capacity(READ_CHUNK_BYTES.min(max_file_bytes));
    let mut buffer = vec![
        0u8;
        READ_CHUNK_BYTES
            .min(max_file_bytes.saturating_add(1))
            .max(1)
    ];
    let mut offset = 0u64;
    loop {
        // Monoio 0.2.4 exposes positional async reads on File; read_at is backed
        // by the configured io_uring driver and deliberately has no fallback.
        let (result, returned_buffer) = file.read_at(buffer, offset).await;
        buffer = returned_buffer;
        let read = result.map_err(|_| ReadError::NotFound)?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > max_file_bytes {
            return Err(ReadError::TooLarge);
        }
        output.extend_from_slice(&buffer[..read]);
        offset = offset.saturating_add(read as u64);
        buffer.fill(0);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::path::{Component, Path};

    #[test]
    fn normalized_path_components_do_not_allow_traversal() {
        let safe = Path::new("assets/app.js");
        assert!(safe
            .components()
            .all(|item| matches!(item, Component::Normal(_))));
        assert!(Path::new("../secret")
            .components()
            .any(|item| matches!(item, Component::ParentDir)));
    }
}
