use crate::respond::{error, full, ResBody};
use bytes::Bytes;
use http::{header, Method, Response, StatusCode};
use std::path::{Path, PathBuf};

/// Serve a static file request. path is the URL path (without the query string).
pub async fn serve(webroot: &Path, path: &str, method: &Method) -> Response<ResBody> {
    if method != Method::GET && method != Method::HEAD {
        let mut res = error(StatusCode::METHOD_NOT_ALLOWED, "405 Method Not Allowed\n");
        res.headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("GET, HEAD"));
        return res;
    }

    let decoded = percent_decode(path);

    // Guard against directory traversal: drop empty segments and ".", reject ".."
    let segments: Vec<&str> = decoded
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if segments.iter().any(|s| *s == "..") {
        return error(StatusCode::FORBIDDEN, "403 Forbidden\n");
    }

    let mut fs_path: PathBuf = webroot.to_path_buf();
    for seg in &segments {
        fs_path.push(seg);
    }
    // Directory requests fall back to index.html
    if decoded.ends_with('/') || fs_path.is_dir() {
        fs_path.push("index.html");
    }

    let data = match tokio::fs::read(&fs_path).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return error(StatusCode::NOT_FOUND, "404 Not Found\n");
        }
        Err(e) => {
            eprintln!("[static] failed to read {}: {e}", fs_path.display());
            return error(StatusCode::INTERNAL_SERVER_ERROR, "500 Internal Server Error\n");
        }
    };

    let len = data.len();
    let body = if *method == Method::HEAD {
        full(Bytes::new())
    } else {
        full(Bytes::from(data))
    };
    let mut res = Response::new(body);
    *res.status_mut() = StatusCode::OK;
    res.headers_mut().insert(header::CONTENT_TYPE, mime_type(&fs_path));
    res.headers_mut().insert(header::CONTENT_LENGTH, header::HeaderValue::from(len));
    res
}

/// Guess the MIME type from the file extension
fn mime_type(path: &Path) -> header::HeaderValue {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mime = match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    };
    header::HeaderValue::from_static(mime)
}

/// Percent-decode a URL path
fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
