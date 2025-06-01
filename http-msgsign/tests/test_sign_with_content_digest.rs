use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response, header};
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use http_msgsign::components::Derive;
use http_msgsign::digest::{ContentDigest, ContentHasher, DigestHash};
use http_msgsign::errors::VerificationError;
use http_msgsign::params;
use http_msgsign::{
    BindRequest, ExchangeRecordSign, RequestSign, ResponseSign, SignatureParams, SignerKey,
    VerifierKey,
};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pss::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha512};

pub struct Sha256Hasher;

impl ContentHasher for Sha256Hasher {
    const DIGEST_ALG: &'static str = "sha-256";

    fn hash(content: &[u8]) -> DigestHash {
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
    const ALGORITHM: &'static str = "RSASSA-PSS";

    fn key_id(&self) -> String {
        "rsassa-pss-1".to_string()
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
    const ALGORITHM: &'static str = "RSASSA-PSS";

    fn key_id(&self) -> String {
        "rsassa-pss-1".to_string()
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
        .header("date", "Tue, 07 Jun 2014 20:51:35 GMT")
        .header("content-type", "application/json")
        .body(BoxBody::new(create_body()))
        .unwrap()
}

pub fn create_response() -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(200)
        .header("date", "Tue, 07 Jun 2014 20:51:36 GMT")
        .header("content-type", "application/json")
        .body(BoxBody::new(create_body()))
        .unwrap()
}

pub fn create_signature_params_for_request() -> SignatureParams {
    SignatureParams::builder()
        .add_derive(Derive::Method, params![])
        .add_header(header::DATE, params![])
        .add_header(header::CONTENT_TYPE, params![])
        .add_header("content-digest", params![key("sha-256")])
        .build()
        .unwrap()
}

pub fn create_signature_params_for_response() -> SignatureParams {
    SignatureParams::builder()
        .add_derive(Derive::Status, params![])
        .add_header(header::DATE, params![])
        .add_header(header::CONTENT_TYPE, params![])
        .add_header("content-digest", params![])
        .build()
        .unwrap()
}

pub fn create_signature_params_for_record() -> SignatureParams {
    SignatureParams::builder()
        .add_derive(Derive::Status, params![])
        .add_derive(Derive::Method, params![req])
        .add_header(header::DATE, params![])
        .add_header(header::CONTENT_TYPE, params![])
        .add_header("content-digest", params![])
        .add_header("content-digest", params![req])
        .build()
        .unwrap()
}

#[tokio::test]
async fn sign_request_with_content_digest() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await.unwrap();
    let signer = RsaSignerKey::default();
    let param = create_signature_params_for_request();
    let request = request.sign(&signer, "sig", &param).await;
    assert!(request.is_ok());

    let request = request.unwrap();
    println!("{:#?}", request);
}

#[tokio::test]
async fn verify_request_with_content_digest() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await;
    assert!(request.is_ok());

    let request = request.unwrap();
    let signer = RsaSignerKey::default();
    let param = create_signature_params_for_request();
    let request = request.sign(&signer, "sig", &param).await;
    assert!(request.is_ok());

    let request = request.unwrap();
    let request = request.verify_digest::<Sha256Hasher>().await;
    assert!(request.is_ok());

    let request = request.unwrap();
    let verifier = RsaVerifierKey::default();
    let request = request.verify_sign(&verifier, "sig").await;
    assert!(request.is_ok());
}

#[tokio::test]
async fn sign_response_with_content_digest() {
    let response = create_response();
    let response = response.digest::<Sha256Hasher>().await.unwrap();
    let signer = RsaSignerKey::default();
    let param = create_signature_params_for_response();
    let response = response.sign(&signer, "sig", &param).await;
    assert!(response.is_ok());

    let response = response.unwrap();
    println!("{:#?}", response);
}

#[tokio::test]
async fn verify_response_with_content_digest() {
    let response = create_response();
    let response = response.digest::<Sha256Hasher>().await;
    assert!(response.is_ok());

    let response = response.unwrap();
    let signer = RsaSignerKey::default();
    let param = create_signature_params_for_response();
    let response = response.sign(&signer, "sig", &param).await;
    assert!(response.is_ok());

    let response = response.unwrap();
    let verifier = RsaVerifierKey::default();
    let response = response.verify_sign(&verifier, "sig").await;
    assert!(response.is_ok());
}

#[tokio::test]
async fn sign_exchange_record_with_content_digest() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await.unwrap();
    let response = create_response();
    let response = response.digest::<Sha256Hasher>().await.unwrap();

    let signer = RsaSignerKey::default();
    let param = create_signature_params_for_record();
    let record = response.bind_request(&request);
    let record = record.sign(&signer, "sig", &param).await;
    assert!(record.is_ok());

    let exchange_record = record.unwrap();
    println!("{:#?}", exchange_record);
}

#[tokio::test]
async fn verify_exchange_record_with_content_digest() {
    let request = create_request();
    let request = request.digest::<Sha256Hasher>().await;
    assert!(request.is_ok());

    let request = request.unwrap();
    let response = create_response();
    let response = response.digest::<Sha256Hasher>().await;
    assert!(response.is_ok());

    let response = response.unwrap();
    let signer = RsaSignerKey::default();
    let param = create_signature_params_for_record();
    let record = response.bind_request(&request);
    let record = record.sign(&signer, "sig", &param).await;
    assert!(record.is_ok());

    let exchange_record = record.unwrap();
    let verifier = RsaVerifierKey::default();
    let exchange_record = exchange_record.verify_sign(&verifier, "sig").await;
    assert!(exchange_record.is_ok());
}
