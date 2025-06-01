use crate::errors::{SignError, VerificationError};
use crate::sign::{SignatureInput, SignatureParams};
use crate::sign::{SignerKey, VerifierKey};

//noinspection DuplicatedCode
pub trait ResponseSign {
    fn sign<S: SignerKey>(
        self,
        key: &S,
        params: &SignatureParams,
    ) -> impl Future<Output = Result<Self, SignError>> + Send
    where
        Self: Sized;

    fn verify_sign<V: VerifierKey>(
        self,
        key: &V,
    ) -> impl Future<Output = Result<Self, VerificationError>> + Send
    where
        Self: Sized;
}

impl<B> ResponseSign for http::Response<B>
where
    B: http_body::Body + Send + Sync,
    B::Data: Send,
{
    async fn sign<S: SignerKey>(
        self,
        key: &S,
        params: &SignatureParams,
    ) -> Result<Self, SignError> {
        let base = params.seek_response(&self)?;
        let (mut parts, body) = self.into_parts();
        let (name, value) = base.to_signature_header(key);
        parts.headers.insert(name, value);

        Ok(Self::from_parts(parts, body))
    }

    async fn verify_sign<V: VerifierKey>(self, key: &V) -> Result<Self, VerificationError> {
        let (parts, body) = self.into_parts();
        let input = SignatureInput::from_header(&parts.headers)?;

        let res = Self::from_parts(parts, body);
        let seeked = input.seek_response(&res)?;

        seeked.verify(key, &input.signature)?;

        Ok(res)
    }
}
