#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("Http body error")]
    Body,

    #[error("Mismatched content digest.")]
    Mismatch,

    #[error(transparent)]
    ExtractHeader(#[from] ExtractHeaderError),

    #[error("Algorithm not supported.")]
    AlgorithmNotSupported,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractHeaderError {
    #[error("No {header_name} header found.")]
    NoExist { header_name: &'static str },

    #[error("Failed to convert header value into str: {0}")]
    FailedToStr(http::header::ToStrError),

    #[error(transparent)]
    InvalidHeaderValue(Box<dyn std::error::Error + Sync + Send + 'static>),
}

#[derive(Debug, thiserror::Error)]
#[error("Content-Digest header should have only one value.")]
pub struct TooManyDigestValues;

impl From<TooManyDigestValues> for ExtractHeaderError {
    fn from(error: TooManyDigestValues) -> Self {
        ExtractHeaderError::InvalidHeaderValue(Box::new(error))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid Content-Digest header value.")]
pub struct InvalidContentDigest;

impl From<InvalidContentDigest> for ExtractHeaderError {
    fn from(error: InvalidContentDigest) -> Self {
        ExtractHeaderError::InvalidHeaderValue(Box::new(error))
    }
}

impl From<sfv::Error> for ExtractHeaderError {
    fn from(e: sfv::Error) -> Self {
        ExtractHeaderError::InvalidHeaderValue(Box::new(e))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("`Signature` for the specified Label(`{0}`) is missing.")]
    NotExist(String),
    #[error("`Signature` does not exist in header.")]
    NotExistInHeader,
    #[error("`Signature` is not a valid `Dictionary`. {0}")]
    InvalidFormat(#[from] InvalidFormat),
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureInputError {
    #[error("`Signature-Input` does not exist in header.")]
    NotExistInHeader,
    #[error(transparent)]
    InvalidDataFormat(#[from] InvalidFormat),
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureParamsError {
    #[error(transparent)]
    InvalidHeaderName(#[from] http::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidFormat {
    #[error("Type `Dictionary` was expected. {0}")]
    Dictionary(sfv::Error),
    #[error("Type `InnerList` was expected")]
    InnerList,
    #[error("Type `Integer` was expected. {0}")]
    Integer(sfv::Error),
    #[error("Type `String` was expected.")]
    String,
    #[error(transparent)]
    HeaderName(http::Error),
    #[error("Type `ByteSequence` was expected.")]
    ByteSequence,
    #[error(transparent)]
    DerivedComponent(#[from] InvalidDerivedComponent),
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid derived component.")]
pub struct InvalidDerivedComponent;

#[derive(Debug, thiserror::Error)]
#[error("invalid component parameter: {0}={1:?}")]
pub struct InvalidComponentParameter(pub sfv::Key, pub sfv::BareItem);

#[derive(Debug, thiserror::Error)]
pub enum HttpFieldComponentError {
    #[error("Necessary requirement have not been met. {reason}")]
    UnmetRequirement { reason: &'static str },
    #[error("DerivedComponent({0}) not supported.")]
    UnsupportedComponent(String),
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error(transparent)]
    FailedBuildSignatureBase(#[from] HttpFieldComponentError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    MissingSignature(#[from] SignatureError),
    #[error("`Signature-Input` for the specified Label(`{0}`) is missing.")]
    MissingSignatureInput(String),
    #[error(transparent)]
    FailedParseSignatureInput(#[from] SignatureInputError),
    #[error("Failed to decode signature. {0}")]
    FailedDecodeSignature(#[from] base64::DecodeError),
    #[error(transparent)]
    FailedBuildSignatureBase(#[from] HttpFieldComponentError),
    #[error("Failed to verify signature")]
    FailedVerifySignature,
}
