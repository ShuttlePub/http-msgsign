# http-content-digest

This library enables a process, 
`Content-Digest` of [RFC 9530 - Digest Fields](https://datatracker.ietf.org/doc/html/rfc9530) 
to Request/Response in [`http`](https://github.com/hyperium/http) crate.

### Usage
```rust
pub struct Sha256Hasher;

// Trait representing the algorithm for taking the Digest of a Body.
impl ContentHasher for Sha256Hasher {
    const DIGEST_ALG: &'static str = "sha-256";
    
    fn hash(content: &[u8]) -> DigestHash {
        let mut hasher = <sha2::Sha256 as Digest>::new();
        hasher.update(content);
        DigestHash::new(hasher.finalize().to_vec())
    }
}

// {"hello": "world"}
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

#[tokio::main]
async fn main() {
    let request = create_request();    
    
    // Digest of `Request<B>` can be done with this, 
    // but note that after execution it becomes `Request<BoxBody<Bytes, DigestError>>`.
    // This is because Content-Digest is expected to be 
    // the last processing of the request or response.
    let request: Request<BoxBody<Bytes, DigestError>> = request.digest::<Sha256Hasher>().await.unwrap();
    
    assert!(request.headers().contains_key("content-digest"));
    
    let digest = request.headers().get("content-digest").unwrap().to_str().unwrap();
    
    assert_eq!(digest, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
}
```
