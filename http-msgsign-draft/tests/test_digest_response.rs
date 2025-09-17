use std::convert::Infallible;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::Full;
use http_content_digest::{ContentHasher, DigestHash};
use http_msgsign_draft::digest::Digest;

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

pub fn create_response() -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(BoxBody::new(create_body()))
        .unwrap()
}

#[tokio::test]
async fn digest() {
    let res = create_response();
    let res = res.digest::<Sha256Hasher>().await;
    assert!(res.is_ok());
    
    println!("{:#?}", res);
}

#[tokio::test]
async fn verify() {
    let res = create_response();
    let res = res.digest::<Sha256Hasher>().await;
    assert!(res.is_ok());
    
    let res = res.unwrap();
    let res = res.verify_digest::<Sha256Hasher>().await;
    assert!(res.is_ok());
}