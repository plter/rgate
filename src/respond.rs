use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::io;

/// Unified response body type: streaming, with errors unified as io::Error
pub type ResBody = BoxBody<Bytes, io::Error>;

fn never_to_io(e: std::convert::Infallible) -> io::Error {
    match e {}
}

/// Wrap an in-memory buffer into a ResBody
pub fn full(data: Bytes) -> ResBody {
    Full::new(data).map_err(never_to_io).boxed()
}

/// Plain-text response
pub fn text(status: StatusCode, msg: &str) -> Response<ResBody> {
    let mut res = Response::new(full(Bytes::copy_from_slice(msg.as_bytes())));
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

/// Error response
pub fn error(status: StatusCode, msg: &str) -> Response<ResBody> {
    text(status, msg)
}
