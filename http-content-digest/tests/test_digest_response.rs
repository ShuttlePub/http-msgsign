use std::convert::Infallible;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use http_content_digest::{ContentDigest, ContentHasher, DigestHash};
use sha2::Digest;

pub struct Sha256Hasher;

impl ContentHasher for Sha256Hasher {
    const DIGEST_ALG: &'static str = "sha-256";

    fn hash(content: &[u8]) -> DigestHash {
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
        .header("date", "Tue, 07 Jun 2014 20:51:36 GMT")
        .header("content-type", "application/json")
        .body(BoxBody::new(create_body()))
        .unwrap()
}

//noinspection SpellCheckingInspection
#[tokio::test]
async fn digest() {
    let res = create_response();
    let res = res.digest::<Sha256Hasher>().await;

    assert!(res.is_ok());

    let res = res.unwrap();
    assert!(res.headers().contains_key("content-digest"));

    println!("{:#?}", res);

    let digest = res
        .headers()
        .get("content-digest")
        .unwrap()
        .to_str()
        .unwrap();

    assert_eq!(
        digest,
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
    );
}

//noinspection SpellCheckingInspection
#[tokio::test]
async fn verify() {
    let res = create_response();
    let res = res.digest::<Sha256Hasher>().await;
    let res = res.unwrap();

    let res = res.verify_digest::<Sha256Hasher>().await;
    assert!(res.is_ok())
}
