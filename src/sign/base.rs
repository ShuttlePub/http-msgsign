use crate::base64::Base64EncodedString;
use crate::components::HttpComponent;
use crate::errors::{HttpFieldComponentError, VerificationError};
use crate::sign::{SignatureParams, SignerKey, VerifierKey};
use http::HeaderMap;
use indexmap::IndexSet;
use std::fmt::Display;

#[derive(Debug)]
pub struct SignatureBase<'a> {
    params: &'a SignatureParams,
    covered: IndexSet<HttpComponent>,
}

impl<'a> SignatureBase<'a> {
    pub fn from_request<B>(
        request: &http::Request<B>,
        params: &'a SignatureParams,
    ) -> Result<Self, HttpFieldComponentError> {
        Ok(Self {
            params,
            covered: params.request_to_component(request)?,
        })
    }

    pub fn from_request_with_signer_key<B>(
        request: &http::Request<B>,
        params: &'a SignatureParams,
        key: &impl SignerKey,
    ) -> Result<Self, HttpFieldComponentError> {
        Ok(Self {
            params,
            covered: params
                .override_with_signer_key(key)
                .request_to_component(request)?,
        })
    }

    pub fn from_response<B>(
        response: &http::Response<B>,
        params: &'a SignatureParams,
    ) -> Result<Self, HttpFieldComponentError> {
        Ok(Self {
            params,
            covered: params.response_to_component(response)?,
        })
    }

    pub fn from_response_with_signer_key<B>(
        response: &http::Response<B>,
        params: &'a SignatureParams,
        key: &impl SignerKey,
    ) -> Result<Self, HttpFieldComponentError> {
        Ok(Self {
            params,
            covered: params
                .override_with_signer_key(key)
                .response_to_component(response)?,
        })
    }

    pub fn into_header<S: SignerKey>(self, key: &S, label: &str) -> HeaderMap {
        let overridden = self.params.override_with_signer_key(key);
        let mut header = HeaderMap::new();
        header.insert(
            crate::sign::header::SIGNATURE_INPUT,
            format!("{}={}", label, overridden).parse().unwrap(),
        );
        header.insert(
            crate::sign::header::SIGNATURE,
            format!("{}=:{}:", label, self.sign_base(key))
                .parse()
                .unwrap(),
        );
        header
    }

    fn sign_base(&self, signer: &impl SignerKey) -> Base64EncodedString {
        Base64EncodedString::new(signer.sign(self.to_string().as_bytes()))
    }

    pub fn verify(
        &self,
        verifier: &impl VerifierKey,
        signature: &[u8],
    ) -> Result<(), VerificationError> {
        verifier.verify(self.to_string().as_bytes(), signature)
    }
}

impl Display for SignatureBase<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(sign_base) = self
            .covered
            .iter()
            .map(|component| component.to_string())
            .reduce(|mut acc, next| {
                acc += &format!("\n{next}");
                acc
            })
        else {
            unreachable!(
                "There should always be @signature-params. In other words, there should never be an empty string."
            )
        };
        write!(f, "{}", sign_base)
    }
}
