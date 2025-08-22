use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, header};
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use http_msgsign::components::Derive;
use http_msgsign::errors::VerificationError;
use http_msgsign::params;
use http_msgsign::{RequestSign, SignatureParams, SignerKey, VerifierKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pss::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha512;

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
        .header("x-empty-header", "")
        .body(BoxBody::new(create_body()))
        .unwrap()
}

pub fn create_signature_params() -> SignatureParams {
    SignatureParams::builder()
        .gen_created()
        .add_derive(Derive::Method, params![])
        .add_header(header::DATE, params![])
        .add_header(header::CONTENT_TYPE, params![])
        .add_header("x-empty-header", params![])
        .build()
        .unwrap()
}

#[tokio::test]
async fn sign_request() {
    let request = create_request();
    let signer = RsaSignerKey::default();
    let params = create_signature_params();
    let request = request.sign(&signer, "sig", &params).await;
    assert!(request.is_ok());

    let request = request.unwrap();
    println!("{:#?}", request);
}

#[tokio::test]
async fn verify_request() {
    let request = create_request();
    let signer = RsaSignerKey::default();
    let params = create_signature_params();
    let request = request.sign(&signer, "sig", &params).await;
    assert!(request.is_ok());

    let verifier = RsaVerifierKey::default();
    let request = request.unwrap();
    let request = request.verify_sign(&verifier, "sig").await;
    assert!(request.is_ok());
}
