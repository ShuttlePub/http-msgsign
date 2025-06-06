use crate::errors::{SignError, VerificationError};
use crate::sign::{SignatureInput, SignatureParams};
use crate::sign::{SignerKey, VerifierKey};
use http::Request;

//noinspection DuplicatedCode
pub trait RequestSign {
    fn sign<S: SignerKey>(
        self,
        key: &S,
        params: &SignatureParams,
    ) -> impl Future<Output = Result<Self, SignError>> + Send
    where
        Self: Sized;

    fn proof<S: SignerKey>(
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

impl<B> RequestSign for Request<B>
where
    B: http_body::Body + Send,
    B::Data: Send,
{
    async fn sign<S: SignerKey>(
        self,
        key: &S,
        params: &SignatureParams,
    ) -> Result<Self, SignError> {
        let base = params.seek_request(&self)?;
        let (mut parts, body) = self.into_parts();
        let (name, value) = base.to_signature_header(key);
        parts.headers.insert(name, value);

        Ok(Self::from_parts(parts, body))
    }

    async fn proof<S: SignerKey>(
        self,
        key: &S,
        params: &SignatureParams,
    ) -> Result<Self, SignError> {
        let base = params.seek_request(&self)?;
        let (mut parts, body) = self.into_parts();
        let (name, value) = base.to_authorization_header(key);
        parts.headers.insert(name, value);

        Ok(Self::from_parts(parts, body))
    }

    async fn verify_sign<V: VerifierKey>(self, key: &V) -> Result<Self, VerificationError> {
        let (parts, body) = self.into_parts();
        let input = SignatureInput::from_header(&parts.headers)?;

        let req = Self::from_parts(parts, body);
        let seeked = input.seek_request(&req)?;

        seeked.verify(key, &input.signature)?;

        Ok(req)
    }
}
