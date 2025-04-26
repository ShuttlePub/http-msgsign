use std::fmt::Display;

use http::HeaderMap;
use indexmap::IndexSet;

use crate::base64::Base64EncodedString;
use crate::components::HttpComponent;
use crate::errors::{HttpComponentError, VerificationError};
use crate::sign::{ExchangeRecord, SignatureParams, SignerKey, VerifierKey};

#[derive(Debug)]
pub struct SignatureBase<'a> {
    params: &'a SignatureParams,
    covered: IndexSet<HttpComponent>,
}

impl<'a> SignatureBase<'a> {
    pub fn from_request<B>(
        request: &http::Request<B>,
        params: &'a SignatureParams,
    ) -> Result<Self, HttpComponentError> {
        Ok(Self {
            params,
            covered: params.request_to_component(request)?,
        })
    }

    pub fn from_request_with_signer_key<B>(
        request: &http::Request<B>,
        params: &'a SignatureParams,
        key: &impl SignerKey,
    ) -> Result<Self, HttpComponentError> {
        Ok(Self {
            params,
            covered: params
                .load_signer_key(key)
                .request_to_component(request)?,
        })
    }

    pub fn from_response<B>(
        response: &http::Response<B>,
        params: &'a SignatureParams,
    ) -> Result<Self, HttpComponentError> {
        Ok(Self {
            params,
            covered: params.response_to_component(response)?,
        })
    }

    pub fn from_response_with_signer_key<B>(
        response: &http::Response<B>,
        params: &'a SignatureParams,
        key: &impl SignerKey,
    ) -> Result<Self, HttpComponentError> {
        Ok(Self {
            params,
            covered: params
                .load_signer_key(key)
                .response_to_component(response)?,
        })
    }
    
    pub fn from_exchange_record<Req, Res>(
        exchange_record: &ExchangeRecord<Req, Res>,
        params: &'a SignatureParams,
    ) -> Result<Self, HttpComponentError> {
        Ok(Self {
            params,
            covered: params
                .record_to_component(exchange_record)?,
        })
    }
    
    pub fn from_exchange_record_with_signer_key<Req, Res>(
        exchange_record: &ExchangeRecord<Req, Res>,
        params: &'a SignatureParams,
        key: &impl SignerKey,
    ) -> Result<Self, HttpComponentError> {
        Ok(Self {
            params,
            covered: params
                .load_signer_key(key)
                .record_to_component(exchange_record)?,
        })
    }

    pub fn into_header<S: SignerKey>(self, key: &S, label: &str) -> HeaderMap {
        let loaded = self.params.load_signer_key(key);
        let mut header = HeaderMap::new();
        header.insert(
            crate::sign::header::SIGNATURE_INPUT,
            format!("{}={}", label, loaded).parse().unwrap(),
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

    pub fn verify(&self, verifier: &impl VerifierKey, signature: &[u8]) -> Result<(), VerificationError> { 
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
