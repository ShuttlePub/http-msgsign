use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use http_msgsign_draft::digest::{ContentHasher, Digest, DigestHash};
use std::convert::Infallible;

pub struct Sha256Hasher;

impl ContentHasher for Sha256Hasher {
    const DIGEST_ALG: &'static str = "SHA-256";

    fn hash(content: &[u8]) -> DigestHash {
        use sha2::Digest;
        let mut hasher = <sha2::Sha256 as Digest>::new();
        hasher.update(content);
        DigestHash::new(hasher.finalize().to_vec())
    }
}

pub fn create_body() -> Full<Bytes> {
    Full::new(Bytes::from_static(b"{\"hello\": \"world\"}"))
}

pub fn create_request() -> Request<BoxBody<Bytes, Infallible>> {
    Request::builder()
        .method("GET")
        .uri("https://example.com/")
        .header("host", "example.com")
        .header("date", "Tue, 07 Jun 2014 20:51:35 GMT")
        .header("content-type", "application/json")
        .body(BoxBody::new(create_body()))
        .unwrap()
}

#[tokio::test]
async fn digest() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await;
    assert!(request.is_ok());

    println!("{:#?}", request);
}

#[tokio::test]
async fn verify_digest() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await;
    assert!(request.is_ok());
    
    let request = request.unwrap();
    let request = request.verify_digest::<Sha256Hasher>().await;
    
    assert!(request.is_ok());
}