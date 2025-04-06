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
#[error("Invalid derived component.")]
pub struct InvalidDerivedComponent;

#[derive(Debug, thiserror::Error)]
pub enum SignatureParamsError {
    #[error(transparent)]
    InvalidHeaderName(#[from] http::Error),
}