use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use http_msgsign_draft::digest::{ContentHasher, Digest, DigestHash};
use http_msgsign_draft::errors::VerificationError;
use http_msgsign_draft::sign::SignatureParams;
use http_msgsign_draft::sign::{RequestSign, SignerKey, VerifierKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pss::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha512;
use std::convert::Infallible;
use std::time::Duration;

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

pub struct RsaSignerKey(SigningKey<Sha512>);

impl Default for RsaSignerKey {
    fn default() -> Self {
        let key = RsaPrivateKey::from_pkcs8_pem(include_str!("./keys/rsa_private.pem")).unwrap();
        let key = SigningKey::new(key);
        RsaSignerKey(key)
    }
}

impl SignerKey for RsaSignerKey {
    fn id(&self) -> String {
        "rsassa-pss-1".to_string()
    }

    fn algorithm(&self) -> String {
        "hs2019".to_string()
    }

    fn sign(&self, target: &[u8]) -> Vec<u8> {
        self.0
            .sign_with_rng(&mut rand::thread_rng(), target)
            .to_vec()
    }
}

pub struct RsaVerifierKey(VerifyingKey<Sha512>);

impl Default for RsaVerifierKey {
    fn default() -> Self {
        let key = RsaPublicKey::from_public_key_pem(include_str!("keys/rsa_public.pem")).unwrap();
        let key = VerifyingKey::new(key);
        RsaVerifierKey(key)
    }
}

impl VerifierKey for RsaVerifierKey {
    fn id(&self) -> String {
        "rsassa-pss-1".to_string()
    }

    fn algorithm(&self) -> String {
        "hs2019".to_string()
    }

    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), VerificationError> {
        let signature = rsa::pss::Signature::try_from(signature).unwrap();
        self.0.verify(target, &signature).unwrap();
        Ok(())
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

fn create_signature_params() -> SignatureParams {
    SignatureParams::builder()
        .add_request_target()
        .add_header("host")
        .add_header("date")
        .add_header("digest")
        .add_header("content-type")
        .set_created()
        .set_expires(Duration::from_secs(1000))
        .build()
        .unwrap()
}

#[tokio::test]
async fn sign() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await.unwrap();

    let signer = RsaSignerKey::default();
    let params = create_signature_params();
    let request = request.sign(&signer, &params).await;

    assert!(request.is_ok());

    println!("{:#?}", request.unwrap());
}

#[tokio::test]
async fn proof() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await.unwrap();

    let signer = RsaSignerKey::default();
    let params = create_signature_params();
    let request = request.proof(&signer, &params).await;

    assert!(request.is_ok());

    println!("{:#?}", request.unwrap());
}

#[tokio::test]
async fn verify_sign() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await.unwrap();

    let signer = RsaSignerKey::default();
    let params = create_signature_params();
    let request = request.sign(&signer, &params).await;

    assert!(request.is_ok());

    let request = request.unwrap();

    let verifier = RsaVerifierKey::default();
    let request = request.verify_sign(&verifier).await;

    assert!(request.is_ok())
}
