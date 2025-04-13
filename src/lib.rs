mod base64;
pub mod components;
pub mod digest;
pub mod errors;
pub mod sign;

#[cfg(test)]
pub(crate) mod test {
    use bytes::Bytes;
    use http::Request;
    use http_body_util::Full;
    use http_body_util::combinators::BoxBody;
    use std::convert::Infallible;

    pub fn create_body() -> Full<Bytes> {
        Full::new(Bytes::from_static(b"{\"hello\": \"world\"}"))
    }

    pub fn create_request() -> Request<BoxBody<Bytes, Infallible>> {
        Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header("date", "Tue, 07 Jun 2014 20:51:35 GMT")
            .header("content-type", "application/json")
            .body(BoxBody::new(create_body()))
            .unwrap()
    }
}
