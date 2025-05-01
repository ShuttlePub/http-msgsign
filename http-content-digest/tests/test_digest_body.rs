use bytes::Bytes;
use http_body_util::Full;
use sha2::Digest;
use http_content_digest::{ContentHasher, DigestHash};

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

//noinspection SpellCheckingInspection
#[tokio::test]
pub async fn digest() {
    use http_content_digest::BodyDigest;
    
    let body = create_body();
    let hashed = body.digest::<Sha256Hasher>().await.unwrap();
    
    assert_eq!(
        hashed.digest.to_base64().as_ref(),
        "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
    );
}
