use http::{HeaderName, HeaderValue};
use indexmap::IndexSet;

use crate::base64::Base64EncodedString;
use crate::errors::VerificationError;
use crate::sign::component::SignBaseComponent;
use crate::sign::field::{CREATED, EXPIRES};
use crate::sign::{SignerKey, VerifierKey};

#[derive(Debug, Clone)]
pub(crate) struct SignatureBase {
    base: String,
    targets: String,
    created: Option<String>,
    expires: Option<String>,
}

impl SignatureBase {
    pub fn from_components(components: IndexSet<SignBaseComponent>) -> Self {
        let created = find_component(CREATED, &components).clone();
        let expires = find_component(EXPIRES, &components).clone();

        let targets = components
            .iter()
            .map(|SignBaseComponent { id, .. }| id.to_string())
            .reduce(|mut acc, next| {
                acc += &format!(" {next}");
                acc
            });

        let base = components
            .iter()
            .map(SignBaseComponent::to_string)
            .reduce(|mut acc, next| {
                acc += &format!("\n{next}");
                acc
            });

        Self {
            base: base.unwrap(),
            targets: targets.unwrap(),
            created,
            expires,
        }
    }

    pub fn to_authorization_header(&self, key: &impl SignerKey) -> (HeaderName, HeaderValue) {
        (
            http::header::AUTHORIZATION,
            self.to_signature_value(key, "Signature ".to_string()),
        )
    }

    pub fn to_signature_header(&self, key: &impl SignerKey) -> (HeaderName, HeaderValue) {
        (
            HeaderName::from_static("signature"),
            self.to_signature_value(key, String::new()),
        )
    }

    pub fn to_signature_value(&self, key: &impl SignerKey, mut start_with: String) -> HeaderValue {
        start_with += &format!("keyId=\"{}\"", key.id());
        start_with += &format!(",algorithm=\"{}\"", key.algorithm());

        if let Some(created) = &self.created {
            start_with += &format!(",created={}", created);
        }

        if let Some(expires) = &self.expires {
            start_with += &format!(",expires={}", expires);
        }

        start_with += &format!(",headers=\"{}\"", self.targets);
        start_with += &format!(",signature=\"{}\"", self.sign(key));

        start_with.parse().unwrap()
    }

    pub fn sign(&self, key: &impl SignerKey) -> Base64EncodedString {
        Base64EncodedString::new(key.sign(self.as_bytes()))
    }

    pub fn verify(
        &self,
        key: &impl VerifierKey,
        signature: &[u8],
    ) -> Result<(), VerificationError> {
        key.verify(self.as_bytes(), signature)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.base.as_bytes()
    }
}

fn find_component<'a>(
    field: &str,
    components: &'a IndexSet<SignBaseComponent>,
) -> &'a Option<String> {
    match components
        .iter()
        .find(|SignBaseComponent { id, .. }| id.eq(field))
    {
        Some(SignBaseComponent { value, .. }) => value,
        _ => &None,
    }
}
