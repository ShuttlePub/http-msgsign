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
        &self,
        key: &V,
    ) -> impl Future<Output = Result<(), VerificationError>> + Send
    where
        Self: Sized + Sync;
}

impl<B> ResponseSign for http::Response<B>
where
    B: http_body::Body + Send,
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

    async fn verify_sign<V: VerifierKey>(&self, key: &V) -> Result<(), VerificationError> {
        let input = SignatureInput::try_from(self)?;
        let seeked = input.seek_response(self)?;
        seeked.verify(key, &input.signature)?;
        Ok(())
    }
}
