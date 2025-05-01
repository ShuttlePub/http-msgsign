use crate::errors::{SignError, VerificationError};
use crate::sign::signature::Signatures;
use crate::sign::{SignatureBase, SignatureInput, SignatureParams, SignerKey, VerifierKey};
use http::Request;

pub trait RequestSign {
    fn sign<S: SignerKey>(
        self,
        key: &S,
        label: &str,
        params: &SignatureParams,
    ) -> impl Future<Output = Result<Self, SignError>> + Send
    where
        Self: Sized;
    fn verify_sign<V: VerifierKey>(
        self,
        key: &V,
        label: &str,
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
        label: &str,
        params: &SignatureParams,
    ) -> Result<Self, SignError> {
        let base = SignatureBase::from_request_with_signer_key(&self, params, key)?
            .into_header(key, label);
        let (mut parts, body) = self.into_parts();
        parts.headers.extend(base);

        Ok(Request::from_parts(parts, body))
    }

    async fn verify_sign<V: VerifierKey>(
        self,
        key: &V,
        label: &str,
    ) -> Result<Self, VerificationError> {
        let (parts, body) = self.into_parts();
        let signatures = Signatures::from_header(&parts.headers)?;
        let inputs = SignatureInput::from_header(&parts.headers)?;
        let signature = signatures.get(label)?;
        let Some(params) = inputs.get(label).map(SignatureParams::from) else {
            return Err(VerificationError::MissingSignatureInput(label.to_string()));
        };

        let request = Request::from_parts(parts, body);
        SignatureBase::from_request(&request, &params)?.verify(key, signature)?;

        Ok(request)
    }
}
