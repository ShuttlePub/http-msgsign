use http_content_digest::errors::ExtractHeaderError;

#[derive(Debug, thiserror::Error)]
#[error("Invalid `Digest` header format. {reason}")]
pub struct InvalidDigestDataFormat {
    pub reason: &'static str,
}

impl From<InvalidDigestDataFormat> for ExtractHeaderError {
    fn from(value: InvalidDigestDataFormat) -> Self {
        Self::InvalidHeaderValue(Box::new(value))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureInputError {
    #[error("No `Signature` / `Authorization` header was found.")]
    NotExist,
    #[error(transparent)]
    InvalidValue(#[from] InvalidValue),
    #[error("{0} is required but not defined.")]
    RequireParameter(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureParamsError {
    #[error(transparent)]
    InvalidHeaderName(#[from] http::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum HttpPayloadSeekError {
    #[error("`{incompatible}` cannot be applied to {target}.")]
    InvalidTarget {
        target: &'static str,
        incompatible: &'static str,
    },
    #[error(transparent)]
    InvalidValue(#[from] InvalidValue),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidValue {
    #[error("`String` type was expected, but another data format is used.")]
    String,
    #[error("`Integer` type was expected, but another data format is used.")]
    Integer,
    #[error("An array with some value was expected, but there was no content.")]
    NonEmptyArray,
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error(transparent)]
    SeekPayload(#[from] HttpPayloadSeekError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    ParseSignature(#[from] SignatureInputError),
    #[error(transparent)]
    SeekPayload(#[from] HttpPayloadSeekError),
    #[error(transparent)]
    Crypto(Box<dyn std::error::Error + Sync + Send>),
}
