use crate::errors::{SignError, VerificationError};
use crate::sign::signature::Signatures;
use crate::sign::{SignatureBase, SignatureInput, SignatureParams, SignerKey, VerifierKey};
use http::{Request, Response};

//noinspection DuplicatedCode
pub trait ResponseSign {
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

impl<B> ResponseSign for Response<B>
where
    B: http_body::Body + Send + Sync,
    B::Data: Send,
{
    async fn sign<S: SignerKey>(
        self,
        key: &S,
        label: &str,
        params: &SignatureParams,
    ) -> Result<Self, SignError> {
        let base = SignatureBase::from_response_with_signer_key(&self, params, key)?
            .into_header(key, label);

        let (mut parts, body) = self.into_parts();
        parts.headers.extend(base);

        Ok(Response::from_parts(parts, body))
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

        let response = Response::from_parts(parts, body);
        SignatureBase::from_response(&response, &params)?.verify(key, signature)?;

        Ok(response)
    }
}

pub trait ExchangeRecordSign<R>: Sync + Send {
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

#[derive(Debug)]
pub struct ExchangeRecord<'a, Req, Res> {
    pub(crate) request: &'a Request<Req>,
    pub(crate) response: Response<Res>,
}

impl<Req, Res> From<ExchangeRecord<'_, Req, Res>> for Response<Res> {
    fn from(value: ExchangeRecord<'_, Req, Res>) -> Self {
        value.response
    }
}

pub trait BindRequest<Req, Res> {
    fn bind_request(self, request: &Request<Req>) -> ExchangeRecord<Req, Res>;
}

impl<Req, Res> BindRequest<Req, Res> for Response<Res> {
    fn bind_request(self, request: &Request<Req>) -> ExchangeRecord<Req, Res> {
        ExchangeRecord {
            request,
            response: self,
        }
    }
}

impl<Req, Res> ExchangeRecordSign<Res> for ExchangeRecord<'_, Req, Res>
where
    Req: http_body::Body + Send + Sync,
    Req::Data: Send,
    Res: http_body::Body + Send + Sync,
    Res::Data: Send,
{
    async fn sign<S: SignerKey>(
        mut self,
        key: &S,
        label: &str,
        params: &SignatureParams,
    ) -> Result<Self, SignError> {
        let base = SignatureBase::from_exchange_record_with_signer_key(&self, params, key)?
            .into_header(key, label);
        let (mut parts, body) = self.response.into_parts();
        parts.headers.extend(base);

        self.response = Response::from_parts(parts, body);
        Ok(self)
    }

    async fn verify_sign<V: VerifierKey>(
        mut self,
        key: &V,
        label: &str,
    ) -> Result<Self, VerificationError> {
        let (parts, body) = self.response.into_parts();
        let signatures = Signatures::from_header(&parts.headers)?;
        let inputs = SignatureInput::from_header(&parts.headers)?;
        let signature = signatures.get(label)?;
        let Some(params) = inputs.get(label).map(SignatureParams::from) else {
            return Err(VerificationError::MissingSignatureInput(label.to_string()));
        };

        self.response = Response::from_parts(parts, body);
        SignatureBase::from_exchange_record(&self, &params)?.verify(key, signature)?;

        Ok(self)
    }
}
