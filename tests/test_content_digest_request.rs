use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use http_msgsign::digest::{ContentHasher, DigestHash};
use sha2::Digest;
use std::convert::Infallible;

pub struct Sha256Hasher;

impl ContentHasher for Sha256Hasher {
    const DIGEST_TYPE: &'static str = "sha-256";

    fn hash(content: &[u8]) -> DigestHash {
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
        .header("date", "Tue, 07 Jun 2014 20:51:35 GMT")
        .header("content-type", "application/json")
        .body(BoxBody::new(create_body()))
        .unwrap()
}

//noinspection SpellCheckingInspection
#[tokio::test]
pub async fn body_digest() {
    use http_msgsign::digest::BodyDigest;

    let body = create_body();
    let hashed = body.digest::<Sha256Hasher>().await.unwrap();

    assert_eq!(
        hashed.digest.to_base64().as_ref(),
        "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
    );
}

//noinspection SpellCheckingInspection
#[tokio::test]
pub async fn request_digest() {
    use http_msgsign::digest::ContentDigest;

    let req = create_request();
    let req = req.digest::<Sha256Hasher>().await.unwrap();

    assert!(req.headers().contains_key("content-digest"));

    println!("{:#?}", req);

    let digest = req
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
pub async fn verify_request_digest() {
    use http_msgsign::digest::ContentDigest;

    let req = create_request();
    let req = req.digest::<Sha256Hasher>().await.unwrap();

    let verified = req.verify_digest::<Sha256Hasher>().await;

    assert!(verified.is_ok());
}
